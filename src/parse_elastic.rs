use std::fs::File;
use std::io::{BufRead, BufReader};
use serde_json::Value;
use std::{collections::HashMap, error::Error};
use polars::prelude::*;
use std::path::Path;
use std::io::Write;

static DEBUG_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_debug_mode(val: bool) {
    DEBUG_MODE.store(val, std::sync::atomic::Ordering::SeqCst);
}

pub fn is_debug_mode() -> bool {
    DEBUG_MODE.load(std::sync::atomic::Ordering::SeqCst)
}

/// **Event IDs sorted by log type**
const SECURITY_EVENT_IDS: &[&str] = &["4624","4625","4634","4647","4648","4768","4769","4770","4771","4776","4778","4779"];
const SMBCLIENT_EVENT_IDS: &[&str] = &["31001"];
const SMBCLIENT_CONNECTIVITY_EVENT_IDS: &[&str] = &["30803","30804","30805","30806","30807","30808"];
const SMBSERVER_EVENT_IDS: &[&str] = &["1009","551"];
const RDPCLIENT_EVENT_IDS: &[&str] = &["1024","1102"];
const RDPCONNMANAGER_EVENT_IDS: &[&str] = &["1149"];
const RDPLOCALSESSION_EVENT_IDS: &[&str] = &["21","22","24","25"];
const RDPKORE_EVENT_IDS: &[&str] = &["131"];

#[derive(Debug, serde::Serialize)]
struct LogData {
    time_created: String,
    computer: String,
    event_id: String,
    subject_user_name: String,
    subject_domain_name: String,
    target_user_name: String,
    target_domain_name: String,
    logon_type: String,
    workstation_name: String,
    ip_address: String,
    filename: String,
}

/// **Processes a Winlogbeat JSON file and extracts relevant events**
fn parse_winlogbeat_json(file_path: &str) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[INFO] Processing Winlogbeat JSON file: {}", file_path);
    }

    let file = File::open(file_path).unwrap();
    let reader = BufReader::new(file);
    let mut log_data = Vec::new();

    for line in reader.lines().flatten() {
        if let Ok(json) = serde_json::from_str::<Value>(&line) {
            if let Some(event_id) = json.get("winlog").and_then(|w| w.get("event_id")).and_then(|e| e.as_i64()) {
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

    log_data
}

/// **Specific functions to extract data by event type**
fn parse_security_event(json: &Value, file_path: &str) -> LogData {
    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_id: json.get("winlog").and_then(|w| w.get("event_id")).and_then(|e| e.as_i64()).unwrap_or(0).to_string(),
        subject_user_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("SubjectUserName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        subject_domain_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("SubjectDomainName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        target_user_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("TargetUserName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        target_domain_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("TargetDomainName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        logon_type: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("LogonType")).and_then(|lt| lt.as_str()).unwrap_or("").to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("WorkstationName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("IpAddress")).and_then(|ip| ip.as_str()).unwrap_or("").to_string(),
        filename: file_path.to_string(),
    }
}

fn parse_smb_client_event(json: &Value, file_path: &str) -> LogData {
    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_id: json.get("winlog").and_then(|w| w.get("event_id")).and_then(|e| e.as_i64()).unwrap_or(0).to_string(),
        subject_user_name: "".to_string(),
        subject_domain_name: "".to_string(),
        target_user_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("UserName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        target_domain_name: "".to_string(),
        logon_type: "3".to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("ServerName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
        filename: file_path.to_string(),
    }
}

fn parse_smb_client_connectivity_event(json: &Value, file_path: &str) -> LogData {
    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_id: json.get("winlog").and_then(|w| w.get("event_id")).and_then(|e| e.as_i64()).unwrap_or(0).to_string(),
        subject_user_name: "".to_string(),
        subject_domain_name: "".to_string(),
        target_user_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("UserName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        target_domain_name: "".to_string(),
        logon_type: "3".to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("ServerName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
        filename: file_path.to_string(),
    }
}

fn parse_smb_server_event(json: &Value, file_path: &str) -> LogData {
    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_id: json.get("winlog").and_then(|w| w.get("event_id")).and_then(|e| e.as_i64()).unwrap_or(0).to_string(),
        subject_user_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("UserName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        subject_domain_name: "".to_string(),
        target_user_name: "".to_string(),
        target_domain_name: "".to_string(),
        logon_type: "3".to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("ClientName")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
        filename: file_path.to_string(),
    }
}

fn parse_rdp_client_event(json: &Value, file_path: &str) -> LogData {
    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_id: json.get("winlog").and_then(|w| w.get("event_id")).and_then(|e| e.as_i64()).unwrap_or(0).to_string(),
        subject_user_name: "".to_string(),
        subject_domain_name: "".to_string(),
        target_user_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("UserID")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        target_domain_name: "".to_string(),
        logon_type: "10".to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("Value")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
        filename: file_path.to_string(),
    }
}

fn parse_rdp_connmanager_event(json: &Value, file_path: &str) -> LogData {
    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_id: json.get("winlog").and_then(|w| w.get("event_id")).and_then(|e| e.as_i64()).unwrap_or(0).to_string(),
        subject_user_name: "".to_string(),
        subject_domain_name: "".to_string(),
        target_user_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("Param1")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        target_domain_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("Param2")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        logon_type: "10".to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("Param3")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
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

    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_id: json.get("winlog").and_then(|w| w.get("event_id")).and_then(|e| e.as_i64()).unwrap_or(0).to_string(),
        subject_user_name: "".to_string(),
        subject_domain_name: "".to_string(),
        target_user_name,
        target_domain_name,
        logon_type: "10".to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("Address")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
        filename: file_path.to_string(),
    }
}

fn parse_rdpkore_event(json: &Value, file_path: &str) -> LogData {
    LogData {
        time_created: json.get("@timestamp").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        computer: json.get("host").and_then(|h| h.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        event_id: json.get("winlog").and_then(|w| w.get("event_id")).and_then(|e| e.as_i64()).unwrap_or(0).to_string(),
        subject_user_name: "".to_string(),
        subject_domain_name: "".to_string(),
        target_user_name: "".to_string(),
        target_domain_name: "".to_string(),
        logon_type: "10".to_string(),
        workstation_name: json.get("winlog").and_then(|w| w.get("event_data")).and_then(|d| d.get("ClientIP")).and_then(|n| n.as_str()).unwrap_or("").to_string(),
        ip_address: "".to_string(),
        filename: file_path.to_string(),
    }
}

/// **Converts extracted events into a Polars DataFrame and saves CSV**
fn vector_to_polars(log_data: Vec<LogData>, output: Option<&String>) {
    if log_data.is_empty() {
        println!("[WARNING] No relevant events found.");
        return;
    }

    let df = df_from_logdata(&log_data);
    if let Some(output_path) = output {
        let mut output_file = File::create(output_path).unwrap();
        CsvWriter::new(&mut output_file)
            .has_header(true)
            .finish(&mut df.clone())
            .unwrap();
        println!("[INFO] CSV file generated: {}", output_path);
    } else {
        CsvWriter::new(std::io::stdout())
            .has_header(true)
            .finish(&mut df.clone())
            .unwrap();
    }
}

/// **Converts `Vec<LogData>` to a Polars DataFrame**
fn df_from_logdata(log_data: &[LogData]) -> DataFrame {
    let time_created = Series::new("time_created", log_data.iter().map(|x| x.time_created.clone()).collect::<Vec<String>>());
    let computer = Series::new("dst_computer", log_data.iter().map(|x| x.computer.clone()).collect::<Vec<String>>());
    let event_id = Series::new("event_id", log_data.iter().map(|x| x.event_id.clone()).collect::<Vec<String>>());
    let subject_user_name = Series::new("subject_user_name", log_data.iter().map(|x| x.subject_user_name.clone()).collect::<Vec<String>>());
    let subject_domain_name = Series::new("subject_domain_name", log_data.iter().map(|x| x.subject_domain_name.clone()).collect::<Vec<String>>());
    let target_user_name = Series::new("target_user_name", log_data.iter().map(|x| x.target_user_name.clone()).collect::<Vec<String>>());
    let target_domain_name = Series::new("target_domain_name", log_data.iter().map(|x| x.target_domain_name.clone()).collect::<Vec<String>>());
    let logon_type = Series::new("logon_type", log_data.iter().map(|x| x.logon_type.clone()).collect::<Vec<String>>());
    let workstation_name = Series::new("src_computer", log_data.iter().map(|x| x.workstation_name.clone()).collect::<Vec<String>>());
    let ip_address = Series::new("src_ip", log_data.iter().map(|x| x.ip_address.clone()).collect::<Vec<String>>());
    let filename = Series::new("log_filename", log_data.iter().map(|x| x.filename.clone()).collect::<Vec<String>>());

    let df = DataFrame::new(vec![
        time_created,
        computer,
        event_id,
        subject_user_name,
        subject_domain_name,
        target_user_name,
        target_domain_name,
        logon_type,
        workstation_name,
        ip_address,
        filename,
    ])
    .unwrap();

    df.sort(["time_created"], false).unwrap()
}

/// **Main function called from `lib.rs` to parse Winlogbeat events**
pub fn parse_events_elastic(files: &Vec<String>, directories: &Vec<String>, output: Option<&String>) {
    if is_debug_mode() {
        println!("[INFO] Starting Winlogbeat event processing...");
    }

    let mut log_data: Vec<LogData> = vec![];

    // Process individual files
    for file in files {
        let parsed_logs = parse_winlogbeat_json(file);
        log_data.extend(parsed_logs);
    }

    // Process directories
    for directory in directories {
        let path = Path::new(directory);
        if path.exists() && path.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let file_path = entry.path();
                if file_path.is_file() {
                    let parsed_logs = parse_winlogbeat_json(file_path.to_str().unwrap());
                    log_data.extend(parsed_logs);
                }
            }
        }
    }

    if is_debug_mode() {
        println!("[INFO] Extracted events: {}", log_data.len());
    }

    vector_to_polars(log_data, output);
}
