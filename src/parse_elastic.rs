use std::fs::File;
use std::io::{BufRead, BufReader};
use serde_json::Value;
use std::{collections::HashMap, error::Error};
use std::path::Path;

static DEBUG_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_debug_mode(val: bool) {
    DEBUG_MODE.store(val, std::sync::atomic::Ordering::SeqCst);
}

pub fn is_debug_mode() -> bool {
    DEBUG_MODE.load(std::sync::atomic::Ordering::SeqCst)
}

/// **Event IDs sorted by log type**
/// 5145 intentionally excluded — see parse.rs::SECURITY_EVENT_IDS for rationale
/// (file-access audit noise that adds no lateral-movement signal beyond 5140).
const SECURITY_EVENT_IDS: &[&str] = &["4624","4625","4634","4647","4648","4768","4769","4770","4771","4776","4778","4779","5140"];
const SMBCLIENT_EVENT_IDS: &[&str] = &["31001"];
const SMBCLIENT_CONNECTIVITY_EVENT_IDS: &[&str] = &["30803","30804","30805","30806","30807","30808"];
const SMBSERVER_EVENT_IDS: &[&str] = &["1009","551"];
const RDPCLIENT_EVENT_IDS: &[&str] = &["1024","1102"];
const RDPCONNMANAGER_EVENT_IDS: &[&str] = &["1149"];
const RDPLOCALSESSION_EVENT_IDS: &[&str] = &["21","22","24","25"];
const RDPKORE_EVENT_IDS: &[&str] = &["131"];

// LogData schema is shared with the rest of masstin. We re-export here so
// local functions that construct records can use the short name.
use crate::parse::LogData;

/// `winlog.event_id`: a number in Winlogbeat 7, a string from 8.0 on.
fn winlog_event_id(json: &Value) -> Option<i64> {
    let v = json.get("winlog")?.get("event_id")?;
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
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
            if let Some(event_id) = winlog_event_id(&json) {
                let event_id_str = event_id.to_string();

                if SECURITY_EVENT_IDS.contains(&event_id_str.as_str()) {
                    log_data.push(parse_security_event(&json, file_path));
                } else if SMBCLIENT_EVENT_IDS.contains(&event_id_str.as_str()) {
                    log_data.push(parse_smb_client_event(&json, file_path));
                } else if SMBCLIENT_CONNECTIVITY_EVENT_IDS.contains(&event_id_str.as_str()) {
                    log_data.push(parse_smb_client_connectivity_event(&json, file_path));
                } else if SMBSERVER_EVENT_IDS.contains(&event_id_str.as_str()) {
                    log_data.push(parse_smb_server_event(&json, file_path));
                } else if RDPCLIENT_EVENT_IDS.contains(&event_id_str.as_str()) {
                    log_data.push(parse_rdp_client_event(&json, file_path));
                } else if RDPCONNMANAGER_EVENT_IDS.contains(&event_id_str.as_str()) {
                    log_data.push(parse_rdp_connmanager_event(&json, file_path));
                } else if RDPLOCALSESSION_EVENT_IDS.contains(&event_id_str.as_str()) {
                    log_data.push(parse_rdp_localsession_event(&json, file_path));
                } else if RDPKORE_EVENT_IDS.contains(&event_id_str.as_str()) {
                    log_data.push(parse_rdpkore_event(&json, file_path));
                }
            }
        }
    }
    if let Some(p) = lines.problem(Path::new(file_path)) {
        crate::banner::print_warning(&format!("  {}", p));
    }

    log_data
}

/// **Specific functions to extract data by event type**
fn parse_security_event(json: &Value, file_path: &str) -> LogData {
    let event_id_str = winlog_event_id(&json).unwrap_or(0).to_string();
    let ed = json.get("winlog").and_then(|w| w.get("event_data"));
    let status = ed.and_then(|d| d.get("Status")).and_then(|s| s.as_str()).unwrap_or("");
    let sub_status = ed.and_then(|d| d.get("SubStatus")).and_then(|s| s.as_str()).unwrap_or("");
    let process_name = ed.and_then(|d| d.get("ProcessName")).and_then(|n| n.as_str()).unwrap_or("");
    let target_logon_id = ed.and_then(|d| d.get("TargetLogonId")).and_then(|n| n.as_str()).unwrap_or("");

    let event_type = match event_id_str.as_str() {
        "4624" => "SUCCESSFUL_LOGON".to_string(),
        "4625" => "FAILED_LOGON".to_string(),
        "4634" => "LOGOFF".to_string(),
        "4647" => "LOGOFF".to_string(),
        "4648" => "SUCCESSFUL_LOGON".to_string(),
        "4768" | "4769" | "4776" => {
            if status == "0x0" { "SUCCESSFUL_LOGON".to_string() } else { "FAILED_LOGON".to_string() }
        },
        "4770" => "SUCCESSFUL_LOGON".to_string(),
        "4771" => "FAILED_LOGON".to_string(),
        "4778" => "SUCCESSFUL_LOGON".to_string(),
        "4779" => "LOGOFF".to_string(),
        "5140" => "SUCCESSFUL_LOGON".to_string(),
        _ => "CONNECT".to_string(),
    };

    let share_name = ed.and_then(|d| d.get("ShareName")).and_then(|s| s.as_str()).unwrap_or("");
    let logon_type = crate::parse::infer_logon_type(&event_id_str, ed.and_then(|d| d.get("LogonType")).and_then(|lt| lt.as_str()).unwrap_or(""));

    let detail = match event_id_str.as_str() {
        "4624" | "4648" => process_name.to_string(),
        "4625" => sub_status.to_string(),
        "5140" => share_name.to_string(),
        _ => String::new(),
    };

    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_type,
        event_id: event_id_str,
        subject_user_name: ed.and_then(|d| d.get("SubjectUserName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        subject_domain_name: ed.and_then(|d| d.get("SubjectDomainName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        target_user_name: ed.and_then(|d| d.get("TargetUserName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        target_domain_name: ed.and_then(|d| d.get("TargetDomainName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        logon_type,
        workstation_name: ed.and_then(|d| d.get("WorkstationName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: ed.and_then(|d| d.get("IpAddress")).and_then(|ip| ip.as_str()).unwrap_or("").to_string(),
        logon_id: target_logon_id.to_string(),
        detail,
        filename: file_path.to_string(),
    }
}

fn parse_smb_client_event(json: &Value, file_path: &str) -> LogData {
    let ed = json.get("winlog").and_then(|w| w.get("event_data"));
    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_type: "FAILED_LOGON".to_string(), // 31001: client failed to authenticate
        event_id: winlog_event_id(&json).unwrap_or(0).to_string(),
        subject_user_name: "".to_string(),
        subject_domain_name: "".to_string(),
        target_user_name: ed.and_then(|d| d.get("UserName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        target_domain_name: "".to_string(),
        logon_type: "3".to_string(),
        workstation_name: ed.and_then(|d| d.get("ServerName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
        logon_id: "".to_string(),
        detail: ed.and_then(|d| d.get("ShareName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        filename: file_path.to_string(),
    }
}

fn parse_smb_client_connectivity_event(json: &Value, file_path: &str) -> LogData {
    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_type: "CONNECT".to_string(),
        event_id: winlog_event_id(&json).unwrap_or(0).to_string(),
        subject_user_name: "".to_string(),
        subject_domain_name: "".to_string(),
        target_user_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("UserName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        target_domain_name: "".to_string(),
        logon_type: "3".to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("ServerName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
        logon_id: "".to_string(),
        detail: "".to_string(),
        filename: file_path.to_string(),
    }
}

fn parse_smb_server_event(json: &Value, file_path: &str) -> LogData {
    let event_id_str = winlog_event_id(&json).unwrap_or(0).to_string();
    let event_type = match event_id_str.as_str() {
        "1009" => "FAILED_LOGON".to_string(), // server denied anonymous access
        "551" => "FAILED_LOGON".to_string(),
        _ => "CONNECT".to_string(),
    };
    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_type,
        event_id: event_id_str,
        subject_user_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("UserName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        subject_domain_name: "".to_string(),
        target_user_name: "".to_string(),
        target_domain_name: "".to_string(),
        logon_type: "3".to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("ClientName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
        logon_id: "".to_string(),
        detail: "".to_string(),
        filename: file_path.to_string(),
    }
}

fn parse_rdp_client_event(json: &Value, file_path: &str) -> LogData {
    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_type: "CONNECT".to_string(),
        event_id: winlog_event_id(&json).unwrap_or(0).to_string(),
        subject_user_name: "".to_string(),
        subject_domain_name: "".to_string(),
        target_user_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("UserID")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        target_domain_name: "".to_string(),
        logon_type: "10".to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("Value")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
        logon_id: "".to_string(),
        detail: "".to_string(),
        filename: file_path.to_string(),
    }
}

fn parse_rdp_connmanager_event(json: &Value, file_path: &str) -> LogData {
    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_type: "SUCCESSFUL_LOGON".to_string(),
        event_id: winlog_event_id(&json).unwrap_or(0).to_string(),
        subject_user_name: "".to_string(),
        subject_domain_name: "".to_string(),
        target_user_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("Param1")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        target_domain_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("Param2")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        logon_type: "10".to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("Param3")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
        logon_id: "".to_string(),
        detail: "".to_string(),
        filename: file_path.to_string(),
    }
}

fn parse_rdp_localsession_event(json: &Value, file_path: &str) -> LogData {
    let remote_user = json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("User")).and_then(|n| n.as_str()).unwrap_or("").to_string();
    let (target_domain_name, target_user_name) = if remote_user.contains("\\") {
        let parts: Vec<&str> = remote_user.split('\\').collect();
        (parts[0].to_string(), parts[1].to_string())
    } else {
        ("".to_string(), remote_user)
    };

    let event_id_str = winlog_event_id(&json).unwrap_or(0).to_string();
    let event_type = match event_id_str.as_str() {
        "21" | "22" | "25" => "SUCCESSFUL_LOGON".to_string(),
        "24" => "LOGOFF".to_string(),
        _ => "CONNECT".to_string(),
    };

    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_type,
        event_id: event_id_str,
        subject_user_name: "".to_string(),
        subject_domain_name: "".to_string(),
        target_user_name,
        target_domain_name,
        logon_type: "10".to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("Address")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
        logon_id: "".to_string(),
        detail: "".to_string(),
        filename: file_path.to_string(),
    }
}

fn parse_rdpkore_event(json: &Value, file_path: &str) -> LogData {
    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_type: "CONNECT".to_string(),
        event_id: winlog_event_id(&json).unwrap_or(0).to_string(),
        subject_user_name: "".to_string(),
        subject_domain_name: "".to_string(),
        target_user_name: "".to_string(),
        target_domain_name: "".to_string(),
        logon_type: "10".to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("ClientIP")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
        logon_id: "".to_string(),
        detail: "".to_string(),
        filename: file_path.to_string(),
    }
}

/// **Filters, sorts and writes the extracted events as CSV**
fn write_rows(log_data: Vec<LogData>, output: Option<&String>) {
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
