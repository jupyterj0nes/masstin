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
        pid: w.get("process").and_then(|p| p.get("pid")).map(|p| p.to_string().trim_matches('"').to_string()).unwrap_or_default(),
        fields,
        has_event_data: ed.is_some(),
    }))
}

// ───────────── the same events, as other tools write them ─────────────
//
// A Windows event exported as JSON keeps its fields whatever the tool; what
// changes is where they sit. Three more shapes are read into the record
// parse-windows maps, so each gives the row its EVTX would:
//
//   evtx_dump      {"Event": {"System": {...}, "EventData": {...}}}
//                  (evtx_dump, and the tools built on the same library)
//   Velociraptor   {"System": {"EventID": {"Value": n}, ...}, "EventData": {...}}
//   flat           {"EventID": n, "Channel": "...", "Hostname" | "Computer": "...",
//                   "TargetUserName": "...", ...}: NXLog (and the OTRF
//                  Security-Datasets), Microsoft Sentinel's SecurityEvent
//
// Anything else goes through a custom rule (`parse-custom`, the rule studio).

/// Events whose only time is a local one with no zone, written as UTC.
static LOCAL_TIMES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

const ISO: &str = "%Y-%m-%dT%H:%M:%S%.6fZ";

/// A time that says its zone (or is an epoch), as the UTC text the rows carry.
fn utc_time(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::Number(n) => {
            let f = n.as_f64()?;
            // seconds, or milliseconds from year 2001 on
            let secs = if f > 1.0e11 { f / 1000.0 } else { f };
            chrono::DateTime::from_timestamp(secs.floor() as i64, ((secs - secs.floor()) * 1e9) as u32).map(|d| d.format(ISO).to_string())
        }
        Value::String(t) => {
            let t = t.trim();
            if let Ok(d) = chrono::DateTime::parse_from_rfc3339(t) {
                return Some(d.with_timezone(&chrono::Utc).format(ISO).to_string());
            }
            if let Ok(d) = chrono::DateTime::parse_from_rfc3339(&t.replacen(' ', "T", 1)) {
                return Some(d.with_timezone(&chrono::Utc).format(ISO).to_string());
            }
            // "2026-11-10 08:02:11.123 UTC"
            if let Some(base) = t.strip_suffix(" UTC") {
                if let Ok(n) = chrono::NaiveDateTime::parse_from_str(base, "%Y-%m-%d %H:%M:%S%.f") {
                    return Some(n.format(ISO).to_string());
                }
            }
            // Sentinel's export from the portal: "3/31/2022, 10:51:35.857 AM", UTC
            if let Ok(n) = chrono::NaiveDateTime::parse_from_str(t, "%m/%d/%Y, %I:%M:%S%.f %p") {
                return Some(n.format(ISO).to_string());
            }
            None
        }
        _ => None,
    }
}

/// A time with no zone ("2020-08-06 11:56:07"), as written.
fn naive_time(v: Option<&Value>) -> Option<chrono::NaiveDateTime> {
    let t = v?.as_str()?.trim().replacen('T', " ", 1);
    chrono::NaiveDateTime::parse_from_str(&t, "%Y-%m-%d %H:%M:%S%.f").ok()
}

/// The time of a flat record. A field that says its zone wins. NXLog writes
/// the event's time as the host's local time with no zone (`EventTime`) and
/// the same for when it received it (`EventReceivedTime`), while the
/// shipper's `@timestamp` is that reception in UTC: the two receptions give
/// the host's offset (to the quarter of an hour), and the event's time is
/// `EventTime` plus that. `@timestamp` itself is the reception, seconds
/// after the event, and is used only when nothing better exists.
fn flat_time(j: &Value) -> Option<String> {
    for k in ["TimeCreated", "SystemTime", "TimeGenerated"] {
        if let Some(t) = utc_time(j.get(k)) {
            return Some(t);
        }
    }
    if let Some(t) = utc_time(j.get("EventTime")) {
        return Some(t);
    }
    if let Some(local) = naive_time(j.get("EventTime")) {
        let received_utc = j.get("@timestamp").and_then(|v| v.as_str()).and_then(|t| chrono::DateTime::parse_from_rfc3339(t.trim()).ok()).map(|d| d.naive_utc());
        if let (Some(utc), Some(rec)) = (received_utc, naive_time(j.get("EventReceivedTime"))) {
            let quarter = 15 * 60;
            let secs = (utc - rec).num_seconds();
            let offset = (secs + if secs >= 0 { quarter / 2 } else { -quarter / 2 }) / quarter * quarter;
            return Some((local + chrono::Duration::seconds(offset)).format(ISO).to_string());
        }
        if let Some(t) = utc_time(j.get("@timestamp")) {
            return Some(t);
        }
        LOCAL_TIMES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Some(local.format(ISO).to_string());
    }
    utc_time(j.get("@timestamp"))
}

/// A number or a string, or the value an exporter wraps it in
/// (`{"#text": 4624, "#attributes": ...}`, `{"Value": 4624}`).
fn unwrapped(v: Option<&Value>) -> Option<String> {
    let v = v?;
    scalar(v).or_else(|| v.get("#text").and_then(scalar)).or_else(|| v.get("Value").and_then(scalar))
}

/// EventData / UserData of an export: named values, at any depth, without
/// the XML attributes.
fn data_fields(v: Option<&Value>, out: &mut HashMap<String, String>) {
    if let Some(Value::Object(m)) = v {
        for (k, x) in m {
            if k == "#attributes" || k == "xmlns" {
                continue;
            }
            match x {
                Value::Object(_) => data_fields(Some(x), out),
                _ => {
                    if let Some(s) = scalar(x) {
                        out.insert(k.clone(), s);
                    }
                }
            }
        }
    }
}

/// `{"System": {...}, "EventData": {...}}`: evtx_dump (under "Event", values
/// with their attributes beside them) and Velociraptor (at the top, the
/// event id under "Value", the time as an epoch).
fn rec_from_system(ev: &Value) -> Option<(String, WinRec)> {
    let sys = ev.get("System").filter(|s| s.is_object())?;
    let event_id = unwrapped(sys.get("EventID"))?.trim().to_string();
    let attr = |node: &str, name: &str| -> Option<&Value> {
        let n = sys.get(node)?;
        n.get("#attributes").and_then(|a| a.get(name)).or_else(|| n.get(name))
    };
    let mut fields = HashMap::new();
    let ed = ev.get("EventData").filter(|e| e.is_object());
    data_fields(ed, &mut fields);
    data_fields(ev.get("UserData"), &mut fields);
    Some((
        sys.get("Channel").and_then(scalar).unwrap_or_default(),
        WinRec {
            event_id,
            time: utc_time(attr("TimeCreated", "SystemTime")).unwrap_or_default(),
            computer: sys.get("Computer").and_then(scalar).unwrap_or_default(),
            user_sid: attr("Security", "UserID").and_then(scalar).unwrap_or_default(),
            pid: attr("Execution", "ProcessID").and_then(scalar).unwrap_or_default(),
            fields,
            has_event_data: ed.is_some(),
        },
    ))
}

/// The flat shape: the event's own fields at the top, beside the header's.
fn rec_from_flat(j: &Value) -> Option<(String, WinRec)> {
    let m = j.as_object()?;
    let event_id = unwrapped(m.get("EventID"))?.trim().to_string();
    if event_id.is_empty() || !event_id.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let text = |k: &str| m.get(k).and_then(scalar).unwrap_or_default();
    let computer = [text("Hostname"), text("Computer"), text("ComputerName")].into_iter().find(|c| !c.is_empty())?;
    let mut fields = HashMap::new();
    for (k, x) in m {
        if let Some(v) = scalar(x) {
            fields.insert(k.clone(), v);
        }
    }
    Some((
        text("Channel"),
        WinRec {
            event_id,
            time: flat_time(j).unwrap_or_default(),
            computer,
            user_sid: text("UserID"),
            pid: [text("ExecutionProcessID"), text("ProcessID")].into_iter().find(|c| !c.is_empty()).unwrap_or_default(),
            fields,
            has_event_data: true,
        },
    ))
}

/// A Windows event in any of the shapes read, as the record parse-windows maps.
pub(crate) fn windows_json_record(json: &Value) -> Option<(String, WinRec)> {
    if json.get("winlog").is_some() {
        return rec_from_json(json);
    }
    if let Some(ev) = json.get("Event") {
        return rec_from_system(ev);
    }
    if json.get("System").map_or(false, |s| s.is_object()) {
        return rec_from_system(json);
    }
    rec_from_flat(json)
}

/// The JSON documents of a file: one per line (NDJSON), one array, or
/// evtx_dump's default output (a `Record N` line, then the document over
/// several lines). `each` returns false to stop.
pub(crate) fn json_documents(file_path: &str, mut each: impl FnMut(Value) -> bool) -> Option<String> {
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => return Some(format!("cannot open {}: {}", file_path, e)),
    };
    let mut lines = crate::textlines::EvidenceLines::new(BufReader::new(file));
    let mut doc = String::new();
    let mut whole = false;
    let mut first = true;
    for line in &mut lines {
        if whole {
            doc.push_str(&line);
            doc.push('\n');
            continue;
        }
        if doc.is_empty() {
            let t = line.trim();
            if t.is_empty() || (t.starts_with("Record ") && !t.contains('{')) {
                continue;
            }
            if first && t.starts_with('[') {
                // one array holding every event: read whole
                whole = true;
                doc.push_str(&line);
                doc.push('\n');
                continue;
            }
            first = false;
            if let Ok(v) = serde_json::from_str::<Value>(t) {
                if !each(v) {
                    return None;
                }
                continue;
            }
            if !t.starts_with('{') {
                continue;
            }
        }
        doc.push_str(&line);
        doc.push('\n');
        // a document over several lines ends with its brace at the margin
        if line.starts_with('}') {
            if let Ok(v) = serde_json::from_str::<Value>(&doc) {
                if !each(v) {
                    return None;
                }
            }
            doc.clear();
        }
    }
    if whole {
        if let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&doc) {
            for v in a {
                if !each(v) {
                    return None;
                }
            }
        }
    }
    lines.problem(Path::new(file_path))
}

/// Whether a file holds Windows events as JSON, in a shape read here: its
/// first documents decide, the file is not read whole.
pub(crate) fn holds_windows_events(file_path: &str) -> bool {
    let mut seen = 0usize;
    let mut found = false;
    json_documents(file_path, |v| {
        seen += 1;
        found = windows_json_record(&v).is_some();
        !found && seen < 1000
    });
    found
}

/// The same, from the first bytes of a file (the look `parse` takes).
pub(crate) fn head_holds_windows_events(head: &str) -> bool {
    head.contains("\"winlog\"")
        || head.contains("\"event_id\"") && head.contains("\"@timestamp\"")
        || head.contains("\"EventID\"") && (head.contains("\"Channel\"") || head.contains("\"System\""))
}

/// One document to a row, through the parse-windows mapping of its channel
/// (or of its event id when the export carries no channel).
pub(crate) fn winlogbeat_row(json: &Value, file_path: &str) -> Option<LogData> {
    let (channel, rec) = windows_json_record(json)?;
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
    let problem = json_documents(file_path, |json| {
        if let Some(row) = winlogbeat_row(&json, file_path) {
            log_data.push(row);
        }
        true
    });
    if let Some(p) = problem {
        crate::banner::print_warning(&format!("  {}", p));
    }
    let local = LOCAL_TIMES.swap(0, std::sync::atomic::Ordering::Relaxed);
    if local > 0 {
        crate::banner::print_warning(&format!("  {}: {} event(s) carry only a local time with no zone (EventTime) and nothing to tell the host's offset; written as if it were UTC", file_path, local));
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

    crate::banner::print_search_results_labeled(all_files.len(), 0, directories.len(), files.len(), "Windows-event JSON artifacts");

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

    fn any(doc: &str) -> (String, String, String, String, String, String) {
        let r = row(doc).expect("a row");
        (r.time_created, r.computer, r.event_type, r.event_id, r.target_user_name, r.ip_address)
    }

    #[test]
    fn the_same_logon_reads_the_same_in_every_shape() {
        let want = ("2020-08-06T15:56:07.000000Z", "SRV01.corp.local", "SUCCESSFUL_LOGON", "4624", "ana", "10.0.0.5");
        let want = (want.0.to_string(), want.1.to_string(), want.2.to_string(), want.3.to_string(), want.4.to_string(), want.5.to_string());
        // NXLog / OTRF: local EventTime, the two receptions give the offset (-4 h)
        assert_eq!(any(r#"{"@timestamp":"2020-08-06T15:56:10.187Z","EventTime":"2020-08-06 11:56:07","EventReceivedTime":"2020-08-06 11:56:10","Hostname":"SRV01.corp.local","Channel":"Security","EventID":"4624","LogonType":"3","TargetUserName":"ana","TargetDomainName":"CORP","IpAddress":"10.0.0.5","WorkstationName":"WS07"}"#), want);
        // Sentinel SecurityEvent, exported from the portal
        assert_eq!(any(r#"{"TimeGenerated":"8/6/2020, 3:56:07.000 PM","Computer":"SRV01.corp.local","Channel":"Security","EventID":4624,"LogonType":3,"TargetUserName":"ana","TargetDomainName":"CORP","IpAddress":"10.0.0.5","WorkstationName":"WS07"}"#), want);
        // evtx_dump
        assert_eq!(any(r##"{"Event":{"#attributes":{"xmlns":"http://schemas.microsoft.com/win/2004/08/events/event"},"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Security-Auditing"}},"EventID":4624,"TimeCreated":{"#attributes":{"SystemTime":"2020-08-06T15:56:07.000000Z"}},"Channel":"Security","Computer":"SRV01.corp.local","Security":null},"EventData":{"TargetUserName":"ana","TargetDomainName":"CORP","LogonType":3,"IpAddress":"10.0.0.5","WorkstationName":"WS07"}}}"##), want);
        // Velociraptor
        assert_eq!(any(r#"{"System":{"Provider":{"Name":"Microsoft-Windows-Security-Auditing"},"EventID":{"Value":4624},"TimeCreated":{"SystemTime":1596729367},"Channel":"Security","Computer":"SRV01.corp.local"},"EventData":{"TargetUserName":"ana","TargetDomainName":"CORP","LogonType":3,"IpAddress":"10.0.0.5","WorkstationName":"WS07"}}"#), want);
    }

    #[test]
    fn a_flat_time_takes_the_field_that_says_its_zone() {
        let t = |doc: &str| flat_time(&serde_json::from_str::<Value>(doc).unwrap()).unwrap_or_default();
        assert_eq!(t(r#"{"TimeCreated":"2020-08-06T17:56:07.5+02:00","@timestamp":"2020-08-06T16:00:00Z"}"#), "2020-08-06T15:56:07.500000Z");
        // east of UTC: the reception in UTC is earlier than the local one
        assert_eq!(t(r#"{"EventTime":"2020-08-06 17:56:07","EventReceivedTime":"2020-08-06 17:56:09","@timestamp":"2020-08-06T12:26:09.400Z"}"#), "2020-08-06T12:26:07.000000Z");
        // only the reception: used, it is all there is
        assert_eq!(t(r#"{"@timestamp":"2020-08-06T15:56:10.187Z"}"#), "2020-08-06T15:56:10.187000Z");
        // a local time and nothing else: as written, and counted
        LOCAL_TIMES.store(0, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(t(r#"{"EventTime":"2020-08-06 11:56:07"}"#), "2020-08-06T11:56:07.000000Z");
        assert_eq!(LOCAL_TIMES.swap(0, std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn documents_come_by_line_as_an_array_or_as_evtx_dump_prints_them() {
        let doc = r#"{"EventID":4624,"Channel":"Security","Hostname":"S","TargetUserName":"u"}"#;
        let dir = std::env::temp_dir();
        let count = |name: &str, text: String| {
            let p = dir.join(format!("masstin_json_{}_{}", std::process::id(), name));
            std::fs::write(&p, text).unwrap();
            let mut n = 0;
            json_documents(p.to_str().unwrap(), |v| {
                assert_eq!(v["EventID"], 4624);
                n += 1;
                true
            });
            assert!(holds_windows_events(p.to_str().unwrap()));
            let _ = std::fs::remove_file(&p);
            n
        };
        assert_eq!(count("lines", format!("{}\n{}\n", doc, doc)), 2);
        assert_eq!(count("array", format!("[\n  {},\n  {}\n]\n", doc, doc)), 2);
        let pretty = "{\n  \"EventID\": 4624,\n  \"Channel\": \"Security\",\n  \"Hostname\": \"S\"\n}\n";
        assert_eq!(count("dump", format!("Record 1\n{}Record 2\n{}", pretty, pretty)), 2);
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
        // the attempt, not the access: a wrong password writes a 4648 too
        assert_eq!(r.event_type, "CONNECT");
        assert_eq!(r.detail, r"explicit credentials (outcome not recorded here): C:\Windows\System32\runas.exe");
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
