use std::fs::File;
use std::io::BufReader;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

static DEBUG_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_debug_mode(val: bool) {
    DEBUG_MODE.store(val, std::sync::atomic::Ordering::SeqCst);
}

pub fn is_debug_mode() -> bool {
    DEBUG_MODE.load(std::sync::atomic::Ordering::SeqCst)
}

// LogData schema is shared with the rest of masstin.
use crate::parse::LogData;
use crate::parse::WinRec;

/// `winlog.event_id`: a number in Winlogbeat 7, a string from 8.0 on.
fn winlog_event_id(json: &Value) -> Option<i64> {
    let v = json.get("winlog")?.get("event_id")?;
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// UserData is written by Winlogbeat as `winlog.user_data`, the children of
/// its single element (`EventXML`, `EventData`, `Operation_ClientFailure`)
/// lifted one level, with the element name in `xml_name`. Leaves are taken
/// by name at any depth so either shape reads the same.
fn flatten_user_data(v: &Value, out: &mut HashMap<String, String>) {
    if let Value::Object(m) = v {
        for (k, x) in m {
            if k == "xml_name" {
                continue;
            }
            match x {
                Value::Object(_) => flatten_user_data(x, out),
                _ => {
                    if let Some(s) = scalar(x) {
                        out.insert(k.clone(), s);
                    }
                }
            }
        }
    }
}

/// One Winlogbeat document as the record parse-windows maps: the same
/// event, the same fields, so the same row.
fn rec_from_json(json: &Value) -> Option<(String, WinRec)> {
    let w = json.get("winlog")?;
    let event_id = winlog_event_id(json)?.to_string();
    let mut fields = HashMap::new();
    let ed = w.get("event_data").filter(|e| e.is_object());
    if let Some(Value::Object(m)) = ed {
        for (k, x) in m {
            if let Some(s) = scalar(x) {
                fields.insert(k.clone(), s);
            }
        }
    }
    if let Some(ud) = w.get("user_data") {
        flatten_user_data(ud, &mut fields);
    }
    let text = |v: Option<&Value>| v.and_then(|x| x.as_str()).unwrap_or("").to_string();
    // the machine that wrote the event; host.name is the shipper, which is
    // the collector under Windows Event Forwarding
    let mut computer = text(w.get("computer_name"));
    if computer.is_empty() {
        computer = text(json.get("host").and_then(|h| h.get("name")));
    }
    let channel = text(w.get("channel"));
    Some((channel, WinRec {
        event_id,
        // @timestamp is the event's time in Winlogbeat output; documents
        // taken before ingest may carry only winlog.time_created
        time: {
            let t = text(json.get("@timestamp"));
            if t.is_empty() { text(w.get("time_created")) } else { t }
        },
        computer,
        user_sid: text(w.get("user").and_then(|u| u.get("identifier"))),
        fields,
        has_event_data: ed.is_some(),
    }))
}

/// One Winlogbeat document to a row, through the parse-windows mapping of
/// its channel (or of its event id when the export carries no channel).
pub(crate) fn winlogbeat_row(json: &Value, file_path: &str) -> Option<LogData> {
    let (channel, rec) = rec_from_json(json)?;
    let map = if channel.is_empty() {
        crate::parse::mapper_for_id(&rec.event_id)?
    } else {
        crate::parse::mapper_for_channel(&channel, &rec.event_id)?
    };
    map(&rec, file_path)
}

/// **Processes a Winlogbeat JSON file and extracts relevant events**
fn parse_winlogbeat_json(file_path: &str) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[INFO] Processing Winlogbeat JSON file: {}", file_path);
    }

    let mut log_data = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            crate::banner::print_warning(&format!("  cannot open {}: {}", file_path, e));
            return log_data;
        }
    };
    let mut lines = crate::textlines::EvidenceLines::new(BufReader::new(file));

    for line in &mut lines {
        if let Ok(json) = serde_json::from_str::<Value>(&line) {
            if let Some(row) = winlogbeat_row(&json, file_path) {
                log_data.push(row);
            }
        }
    }
    if let Some(p) = lines.problem(Path::new(file_path)) {
        crate::banner::print_warning(&format!("  {}", p));
    }

    log_data
}

/// **Filters, sorts and writes the extracted events as CSV**
fn write_rows(log_data: Vec<LogData>, output: Option<&String>) {
    // logoffs take the origin of their logon, as parse-windows does
    let (log_data, filled, dropped) = crate::parse::pair_logoffs(log_data);
    crate::parse::report_logoff_pairing(filled, dropped);
    // Apply noise filter (--ignore-local / --exclude-*).
    let log_data: Vec<LogData> = log_data
        .into_iter()
        .filter(|r| crate::filter::should_keep_record(r))
        .collect();
    if log_data.is_empty() {
        println!("[WARNING] No relevant events found.");
        return;
    }

    // Same order polars gave: ascending on the time_created text.
    let mut log_data = log_data;
    log_data.sort_by(|a, b| a.time_created.cmp(&b.time_created));
    match crate::csv_out::write_timeline(&log_data, output) {
        Ok(()) => {
            if let Some(output_path) = output {
                println!("[INFO] CSV file generated: {}", output_path);
            }
        }
        Err(e) => eprintln!("[ERROR] Cannot write output: {}", e),
    }
}

/// **Main function called from `lib.rs` to parse Winlogbeat events**
pub fn parse_events_elastic(files: &Vec<String>, directories: &Vec<String>, output: Option<&String>) {
    let start_time = std::time::Instant::now();

    if is_debug_mode() {
        println!("[INFO] Starting Winlogbeat event processing...");
    }

    let mut log_data: Vec<LogData> = vec![];
    let mut all_files: Vec<String> = files.clone();

    // Phase 1: Search for artifacts
    crate::banner::print_search_start();

    for directory in directories {
        let path = Path::new(directory);
        if path.exists() && path.is_dir() {
            let entries = match std::fs::read_dir(path) {
                Ok(e) => e,
                Err(e) => {
                    crate::banner::print_warning(&format!("  cannot list {}: {}", directory, e));
                    continue;
                }
            };
            for entry in entries.flatten() {
                let file_path = entry.path();
                if file_path.is_file() {
                    all_files.push(file_path.to_string_lossy().to_string());
                }
            }
        }
    }

    crate::banner::print_search_results_labeled(all_files.len(), 0, directories.len(), files.len(), "Winlogbeat artifacts");

    // Phase 2: Process artifacts
    crate::banner::print_processing_start();
    let pb = crate::banner::create_progress_bar(all_files.len() as u64);
    let mut parsed_count: usize = 0;
    let mut skipped: usize = 0;
    let mut artifact_details: Vec<(String, usize)> = Vec::new();

    for file in &all_files {
        crate::banner::progress_set_message(&pb, file);
        let parsed_logs = parse_winlogbeat_json(file);
        let count = parsed_logs.len();
        if count == 0 {
            skipped += 1;
        } else {
            parsed_count += 1;
            artifact_details.push((file.clone(), count));
        }
        log_data.extend(parsed_logs);
        pb.inc(1);
    }

    pb.finish_and_clear();
    crate::banner::print_artifact_detail(&artifact_details);

    if is_debug_mode() {
        println!("[INFO] Extracted events: {}", log_data.len());
    }

    // Phase 3: Generate output
    crate::banner::print_output_start();
    let total_events = log_data.len();
    write_rows(log_data, output);

    crate::banner::print_summary(total_events, parsed_count, skipped, output.map(|s| s.as_str()), start_time);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(doc: &str) -> Option<LogData> {
        winlogbeat_row(&serde_json::from_str::<Value>(doc).unwrap(), "wlb.json")
    }

    // From the Elastic integrations test fixture for 4778 (Winlogbeat 8:
    // the event id is a string).
    const W4778: &str = r#"{"@timestamp":"2020-04-05T16:33:32.388Z","host":{"name":"DC_TEST2k12.TEST.SAAS"},"winlog":{"channel":"Security","computer_name":"DC_TEST2k12.TEST.SAAS","event_id":"4778","provider_name":"Microsoft-Windows-Security-Auditing","event_data":{"AccountDomain":"TEST","AccountName":"at_adm","ClientAddress":"10.100.150.9","ClientName":"EQP01777","LogonID":"0x76fea87","SessionName":"RDP-Tcp#127"}}}"#;

    #[test]
    fn rdp_reconnect_keeps_account_and_origin() {
        let r = row(W4778).expect("4778 is a row");
        assert_eq!((r.target_user_name.as_str(), r.target_domain_name.as_str()), ("at_adm", "TEST"));
        assert_eq!((r.workstation_name.as_str(), r.ip_address.as_str()), ("EQP01777", "10.100.150.9"));
        assert_eq!((r.logon_type.as_str(), r.logon_id.as_str()), ("10", "0x76fea87"));
    }

    #[test]
    fn explicit_credentials_point_at_the_target_server() {
        let doc = r#"{"@timestamp":"2026-01-01T00:00:00Z","winlog":{"channel":"Security","computer_name":"WS01.corp","event_id":4648,"event_data":{"TargetUserName":"admin","TargetDomainName":"CORP","TargetServerName":"SRV02.corp","IpAddress":"10.0.0.20","ProcessName":"C:\\Windows\\System32\\runas.exe"}}}"#;
        let r = row(doc).unwrap();
        assert_eq!(r.computer, "SRV02.corp");
        assert_eq!(r.workstation_name, "WS01.corp");
        assert_eq!(r.ip_address, "");
    }

    #[test]
    fn smb_and_rdp_client_events_go_from_the_client_to_the_server() {
        let smb = r#"{"@timestamp":"2026-01-01T00:00:00Z","winlog":{"channel":"Microsoft-Windows-SmbClient/Security","computer_name":"WS01","event_id":"31001","event_data":{"UserName":"CORP\\bob","ServerName":"\\\\192.0.2.31","ShareName":"\\\\192.0.2.31\\C$"}}}"#;
        let r = row(smb).unwrap();
        assert_eq!((r.computer.as_str(), r.workstation_name.as_str()), ("192.0.2.31", "WS01"));
        assert_eq!((r.target_user_name.as_str(), r.target_domain_name.as_str(), r.detail.as_str()), ("bob", "CORP", "C$"));
        let rdp = r#"{"@timestamp":"2026-01-01T00:00:00Z","winlog":{"channel":"Microsoft-Windows-TerminalServices-RDPClient/Operational","computer_name":"WS01","event_id":1024,"user":{"identifier":"S-1-5-21-1-2-3-1001"},"event_data":{"Value":"SRV02"}}}"#;
        let r = row(rdp).unwrap();
        assert_eq!((r.computer.as_str(), r.workstation_name.as_str()), ("SRV02", "WS01"));
    }

    #[test]
    fn user_data_events_are_read_from_user_data() {
        let doc = r#"{"@timestamp":"2026-01-01T00:00:00Z","winlog":{"channel":"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational","computer_name":"SRV02","event_id":"1149","user_data":{"xml_name":"EventXML","Param1":"alice","Param2":"CORP","Param3":"10.0.0.5"}}}"#;
        let r = row(doc).unwrap();
        assert_eq!((r.target_user_name.as_str(), r.target_domain_name.as_str(), r.ip_address.as_str()), ("alice", "CORP", "10.0.0.5"));
        let lsm = r#"{"@timestamp":"2026-01-01T00:00:00Z","winlog":{"channel":"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational","computer_name":"SRV02","event_id":"21","user_data":{"xml_name":"EventXML","User":"CORP\\alice","SessionID":"3","Address":"10.0.0.5"}}}"#;
        let r = row(lsm).unwrap();
        assert_eq!((r.target_user_name.as_str(), r.ip_address.as_str(), r.logon_id.as_str()), ("alice", "10.0.0.5", "3"));
    }

    #[test]
    fn the_channel_decides_the_family() {
        // Sysmon 22 (DNS query) is not an RDP reconnection, Security 1102
        // (log cleared) is not an RDP client event
        let dns = r#"{"@timestamp":"2026-01-01T00:00:00Z","winlog":{"channel":"Microsoft-Windows-Sysmon/Operational","computer_name":"WS01","event_id":"22","event_data":{"QueryName":"example.org"}}}"#;
        assert!(row(dns).is_none());
        let cleared = r#"{"@timestamp":"2026-01-01T00:00:00Z","winlog":{"channel":"Security","computer_name":"DC01","event_id":"1102","user_data":{"SubjectUserName":"admin"}}}"#;
        assert!(row(cleared).is_none());
        // without a channel, only the ids that belong to one family
        let bare = r#"{"@timestamp":"2026-01-01T00:00:00Z","winlog":{"computer_name":"WS01","event_id":"22"}}"#;
        assert!(row(bare).is_some());
        let bare6 = r#"{"@timestamp":"2026-01-01T00:00:00Z","winlog":{"computer_name":"WS01","event_id":"6","event_data":{"connection":"srv/wsman"}}}"#;
        assert!(row(bare6).is_none());
    }
}
