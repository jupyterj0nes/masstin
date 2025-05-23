use std::{path::PathBuf, fs::File};
use evtx::EvtxParser;
extern crate serde;
extern crate quick_xml;
use serde::{Serialize, Deserialize};
use quick_xml::de::from_str;
use std::{error::Error, collections::HashMap};
use polars::prelude::*;
use walkdir::WalkDir;
use std::path::Path;
use std::io::{self, Write};
use ::zip::read::ZipArchive;
use std::io::{Read, Cursor, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};

// Global atomic variable to store whether we are in debug mode
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_debug_mode(val: bool) {
    DEBUG_MODE.store(val, Ordering::SeqCst);
}

pub fn is_debug_mode() -> bool {
    DEBUG_MODE.load(Ordering::SeqCst)
}

// Event IDs for various logs
const SECURITY_EVENT_IDS: &[&str] = &["4624","4625","4634","4647","4648","4768","4769","4770","4771","4776","4778","4779"];
const SMBCLIENT_EVENT_IDS: &[&str] = &["31001"];
const SMBCLIENT_CONNECTIVITY_EVENT_IDS: &[&str] = &["30803","30804","30805","30806","30807","30808"];
const SMBSERVER_EVENT_IDS: &[&str] = &["1009","551"];
const RDPCLIENT_EVENT_IDS: &[&str] = &["1024","1102"];
const RDPCONNMANAGER_EVENT_IDS: &[&str] = &["1149"];
const RDPLOCALSESSION_EVENT_IDS: &[&str] = &["21","22","24","25"];
const RDPKORE_EVENT_IDS: &[&str] = &["131"];

pub mod parse {}

// Updated LogData struct with a new "process" column.
#[derive(Serialize, Deserialize, Debug)]
pub struct LogData {
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
    process: String,
}

#[derive(Debug, Clone)]
enum EvtxLocation {
    File(String), // Normal file in disk
    ZipEntry {
        zip_path: String,  // Path of the .zip file
        evtx_name: String, // Name of the EVTX inside the .zip
    },
}

// ---------------------------------------------------------------------------------------
// SECURITY LOG PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_security_log(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            // If there's an error initializing, return empty
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event = match from_str(&data) {
                    Ok(event) => event,
                    Err(_) => {
                        continue;
                    },
                };
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        // Extend the map with a ProcessName key.
                        let mut data_values: HashMap<String, String> = [
                            ("SubjectUserName".to_string(), String::from("")),
                            ("SubjectDomainName".to_string(), String::from("")),
                            ("TargetUserName".to_string(), String::from("")),
                            ("TargetDomainName".to_string(), String::from("")),
                            ("LogonType".to_string(), String::from("")),
                            ("WorkstationName".to_string(), String::from("")),
                            ("IpAddress".to_string(), String::from("")),
                            ("ProcessName".to_string(), String::from("")),  // New key for process
                        ].iter().cloned().collect();

                        if let Some(event_data) = event.EventData {
                            for data in event_data.Datas {
                                if let Some(name) = data.Name {
                                    if let Some(data_value) = data_values.get_mut(&name) {
                                        *data_value = data.body.as_ref().unwrap_or(&"default_value".to_string()).clone();
                                    }
                                }
                            }
                        }

                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: event.System.Computer.unwrap(),
                            event_id,
                            subject_user_name: data_values.get("SubjectUserName").unwrap().to_string(),
                            subject_domain_name: data_values.get("SubjectDomainName").unwrap().to_string(),
                            target_user_name: data_values.get("TargetUserName").unwrap().to_string(),
                            target_domain_name: data_values.get("TargetDomainName").unwrap().to_string(),
                            logon_type: data_values.get("LogonType").unwrap().to_string(),
                            workstation_name: data_values.get("WorkstationName").unwrap().to_string(),
                            ip_address: data_values.get("IpAddress").unwrap().to_string(),
                            filename: file.to_string(),
                            process: data_values.get("ProcessName").unwrap().to_string(), // New column
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// SMB SERVER PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_smb_server(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event2 = from_str(&data).unwrap();
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: event.System.Computer.unwrap(),
                            event_id,
                            subject_user_name: event.System.Security.unwrap().UserID.as_ref().unwrap_or(&String::from("")).to_owned(),
                            subject_domain_name: String::from(""),
                            target_user_name: event.UserData.as_ref().unwrap().EventData.as_ref().unwrap().UserName.as_ref().unwrap_or(&String::from("")).to_owned(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("3"),
                            workstation_name: event.UserData.as_ref().unwrap().EventData.as_ref().unwrap().ClientName.as_ref().unwrap_or(&String::from("")).to_owned(),
                            ip_address: event.UserData.as_ref().unwrap().EventData.as_ref().unwrap().ClientName.as_ref().unwrap_or(&String::from("")).to_owned(),
                            filename: file.to_string(),
                            process: String::from(""), // Not available in SMBServer
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// SMB CLIENT PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_smb_client(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event = from_str(&data).unwrap();
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        let mut data_values: HashMap<String, String> = [
                            ("UserName".to_string(), String::from("")),
                            ("ServerName".to_string(), String::from(""))
                        ].iter().cloned().collect();

                        for data in event.EventData.unwrap().Datas {
                            if let Some(name) = data.Name {
                                if let Some(data_value) = data_values.get_mut(&name) {
                                    *data_value = data.body.as_ref().unwrap_or(&"default_value".to_string()).clone();
                                }
                            }
                        }

                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: data_values.get("ServerName").unwrap().to_string(),
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: data_values.get("UserName").unwrap().to_string(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("3"),
                            workstation_name: event.System.Computer.as_ref().unwrap().to_owned(),
                            ip_address: event.System.Computer.as_ref().unwrap().to_owned(),
                            filename: file.to_string(),
                            process: String::from(""),
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// SMB CLIENT CONNECTIVITY PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_smb_client_connectivity(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event = from_str(&data).unwrap();
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        let mut data_values: HashMap<String, String> = [
                            ("UserName".to_string(), String::from("")),
                            ("ServerName".to_string(), String::from(""))
                        ].iter().cloned().collect();

                        for data in event.EventData.unwrap().Datas {
                            if let Some(name) = data.Name {
                                if let Some(data_value) = data_values.get_mut(&name) {
                                    *data_value = data.body.as_ref().unwrap_or(&"default_value".to_string()).clone();
                                }
                            }
                        }

                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: data_values.get("ServerName").unwrap().to_string(),
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: data_values.get("UserName").unwrap().to_string(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("3"),
                            workstation_name: event.System.Computer.as_ref().unwrap().to_owned(),
                            ip_address: event.System.Computer.as_ref().unwrap().to_owned(),
                            filename: file.to_string(),
                            process: String::from(""),
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// RDP CLIENT PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_rdp_client(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event = from_str(&data).unwrap();
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        let mut data_values: HashMap<String, String> = [
                            ("Value".to_string(), String::from(""))
                        ].iter().cloned().collect();

                        for data in event.EventData.unwrap().Datas {
                            if let Some(name) = data.Name {
                                if let Some(data_value) = data_values.get_mut(&name) {
                                    *data_value = data.body.as_ref().unwrap_or(&"default_value".to_string()).clone();
                                }
                            }
                        }

                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: data_values.get("Value").unwrap().to_string(),
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: event.System.Security.unwrap().UserID.unwrap(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("10"),
                            workstation_name: event.System.Computer.as_ref().unwrap().to_owned(),
                            ip_address: event.System.Computer.as_ref().unwrap().to_owned(),
                            filename: file.to_string(),
                            process: String::from(""),
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// RDP CONNECTION MANAGER PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_rdp_connmanager(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    let mut log_data = Vec::new();

    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing RDP ConnManager {}", file);
    }
    let (mut parser, _) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((p, _)) => (p, ()),
        Err(_) => return log_data,
    };

    for record in parser.records() {
        let r = match record {
            Ok(r) => r,
            Err(_) => continue,
        };
        let xml = r.data.as_str();
        let event: Event2 = match from_str(&xml) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // 1) EventID presente y coincidente
        let event_id = match event.System.EventID {
            Some(ref id) if lateral_event_ids.contains(&id.as_str()) => id.clone(),
            _ => continue,
        };

        // 2) TimeCreated y Computer (salen siempre en System)
        let time_created = event
            .System
            .TimeCreated
            .SystemTime
            .unwrap_or_else(|| {
                if is_debug_mode() {
                    println!("[DEBUG] Missing TimeCreated in RDP ConnManager record, skipping");
                }
                return String::new();
            });
        if time_created.is_empty() {
            continue;
        }

        let computer = event.System.Computer.unwrap_or_else(|| {
            if is_debug_mode() {
                println!("[DEBUG] Missing Computer in RDP ConnManager record, skipping");
            }
            String::new()
        });
        if computer.is_empty() {
            continue;
        }

        // 3) UserData → EventData → UserName / ClientName
        let (target_user, client) = if let Some(ud) = event.UserData.as_ref() {
            if let Some(ed) = ud.EventData.as_ref() {
                let u = ed.UserName.clone().unwrap_or_default();
                let c = ed.ClientName.clone().unwrap_or_default();
                (u, c)
            } else {
                if is_debug_mode() {
                    println!("[DEBUG] Missing EventData in RDP ConnManager record, skipping");
                }
                continue;
            }
        } else {
            if is_debug_mode() {
                println!("[DEBUG] Missing UserData in RDP ConnManager record, skipping");
            }
            continue;
        };

        // Finalmente, construimos el LogData
        log_data.push(LogData {
            time_created,
            computer,
            event_id,
            subject_user_name: String::new(),
            subject_domain_name: String::new(),
            target_user_name: target_user,
            target_domain_name: String::new(),
            logon_type: "10".into(),
            workstation_name: client.clone(),
            ip_address: client,
            filename: file.to_string(),
            process: String::new(),
        });
    }

    log_data
}


// ---------------------------------------------------------------------------------------
// RDP LOCAL SESSION MANAGER PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_rdp_localsession(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event2 = from_str(&data).unwrap();
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        let mut remotedomain = String::from("");
                        let mut remoteuser = event.UserData.as_ref().unwrap().EventXML.as_ref().unwrap().User.as_ref().unwrap().to_owned();

                        if remoteuser.contains("\\") {
                            let parts: Vec<&str> = remoteuser.split("\\").collect();
                            remotedomain = parts[0].to_string();
                            remoteuser = parts[1].to_string();
                        }

                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: event.System.Computer.unwrap(),
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: remoteuser,
                            target_domain_name: remotedomain,
                            logon_type: String::from("10"),
                            workstation_name: event.UserData.as_ref().unwrap().EventXML.as_ref().unwrap().Address.as_ref().unwrap().to_owned(),
                            ip_address: event.UserData.as_ref().unwrap().EventXML.as_ref().unwrap().Address.as_ref().unwrap().to_owned(),
                            filename: file.to_string(),
                            process: String::from(""),
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// RDP KORE PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_rdpkore(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event = from_str(&data).unwrap();
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        let mut data_values: HashMap<String, String> = [
                            ("ClientIP".to_string(), String::from(""))
                        ].iter().cloned().collect();

                        for data in event.EventData.unwrap().Datas {
                            if let Some(name) = data.Name {
                                if let Some(data_value) = data_values.get_mut(&name) {
                                    *data_value = data.body.as_ref().unwrap_or(&"default_value".to_string()).clone();
                                }
                            }
                        }
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: event.System.Computer.unwrap(),
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: String::from(""),
                            target_domain_name: String::from(""),
                            logon_type: String::from("10"),
                            workstation_name: data_values.get("ClientIP").unwrap().to_string(),
                            ip_address: data_values.get("ClientIP").unwrap().to_string(),
                            filename: file.to_string(),
                            process: String::from(""),
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// UNKNOWN PARSER (AUTODETECT PROVIDER)
// ---------------------------------------------------------------------------------------
pub fn parse_unknown(file: &str) -> Vec<LogData> {
    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    let mut provider = String::from("");
    if let Some(Ok(r)) = parser.records().nth(1) {
        let data = r.data.as_str();
        let event: Event = from_str(&data).unwrap();
        provider = event.System.Provider.Name.unwrap();
    }

    match provider.as_str() {
        "Microsoft-Windows-Security-Auditing" => {
            log_data = parse_security_log(file, SECURITY_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-SMBServer" => {
            log_data = parse_smb_server(file, SMBSERVER_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-SMBClient" => {
            log_data = parse_smb_client(file, SMBCLIENT_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-TerminalServices-ClientActiveXCore" => {
            log_data = parse_rdp_client(file, RDPCLIENT_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager" => {
            log_data = parse_rdp_connmanager(file, RDPCONNMANAGER_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-TerminalServices-LocalSessionManager" => {
            log_data = parse_rdp_localsession(file, RDPLOCALSESSION_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS" => {
            log_data = parse_rdpkore(file, RDPKORE_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-SmbClient%4Connectivity.evtx" => {
            log_data = parse_smb_client_connectivity(file, SMBCLIENT_CONNECTIVITY_EVENT_IDS.to_vec())
        },
        _ => (),
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// PREPARE PARSE (DISK FILE OR ZIP FILE)
// ---------------------------------------------------------------------------------------
fn prep_parse(file: EvtxLocation) -> Result<(EvtxParser<Cursor<Vec<u8>>>, Vec<LogData>), Box<dyn Error>> {
    let log_data: Vec<LogData> = vec![];

    match file {
        EvtxLocation::File(path) => {
            if path.contains(" -> ") {
                let zip_parts: Vec<&str> = path.split(" -> ").collect();
                let evtx_name = zip_parts.last().unwrap().to_string(); // The last element is the EVTX file
                let zip_path = zip_parts[..zip_parts.len() - 1].join(" -> "); // All nested ZIP paths

                if is_debug_mode() {
                    println!("[INFO] Detected an EVTX file inside a nested ZIP: {}", evtx_name);
                    println!("[INFO] ZIP paths: {:?}", zip_parts);
                }

                // Call the correct function for the list of ZIPs
                if zip_parts.len() == 2 {
                    return open_evtx_from_zip(&zip_parts[0], &evtx_name);
                } else {
                    return open_evtx_from_nested_zip(zip_parts[..zip_parts.len() - 1].to_vec(), &evtx_name);
                }
            }

            // Normal file in disk
            if is_debug_mode() {
                println!("[DEBUG] Opening EVTX file in disk: {}", path);
            }
            let mut file = File::open(&path)?;
            let mut file_data = Vec::new();
            file.read_to_end(&mut file_data)?;

            let cursor = Cursor::new(file_data);
            let parser = EvtxParser::from_read_seek(cursor)?;
            Ok((parser, log_data))
        },
        EvtxLocation::ZipEntry { zip_path, evtx_name } => {
            let zip_parts: Vec<&str> = zip_path.split(" -> ").collect();
            if is_debug_mode() {
                println!("[INFO] Processing a file inside ZIP: {} -> {}", zip_path, evtx_name);
            }
            if zip_parts.len() == 1 {
                return open_evtx_from_zip(&zip_path, &evtx_name);
            } else {
                return open_evtx_from_nested_zip(zip_parts, &evtx_name);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// OPEN EVTX FROM ZIP
// ---------------------------------------------------------------------------------------
fn open_evtx_from_zip(zip_path: &str, evtx_name: &str) -> Result<(EvtxParser<Cursor<Vec<u8>>>, Vec<LogData>), Box<dyn Error>> {
    if is_debug_mode() {
        println!("[DEBUG] Opening ZIP: {}", zip_path);
    }

    let mut zip_file = File::open(zip_path).map_err(|e| {
        println!("[ERROR] Could not open ZIP {}: {}", zip_path, e);
        e
    })?;
    let mut archive = ZipArchive::new(zip_file).map_err(|e| {
        println!("[ERROR] Could not read ZIP {}: {}", zip_path, e);
        e
    })?;

    let mut file_data = Vec::new();
    let mut found = false;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.name() == evtx_name {
            if is_debug_mode() {
                println!("[INFO] EVTX found inside the ZIP: {}", evtx_name);
            }
            file.read_to_end(&mut file_data)?;
            found = true;
            break;
        }
    }

    if !found {
        println!("[ERROR] EVTX file '{}' not found in ZIP '{}'", evtx_name, zip_path);
        return Err(format!("EVTX not found in ZIP: {}", evtx_name).into());
    }

    let cursor = Cursor::new(file_data);
    let parser = EvtxParser::from_read_seek(cursor)?;
    if is_debug_mode() {
        println!("[DEBUG] EVTX {} opened successfully from ZIP.", evtx_name);
    }

    Ok((parser, vec![]))
}

// ---------------------------------------------------------------------------------------
// OPEN EVTX FROM NESTED ZIP
// ---------------------------------------------------------------------------------------
fn open_evtx_from_nested_zip(zip_parts: Vec<&str>, evtx_name: &str) -> Result<(EvtxParser<Cursor<Vec<u8>>>, Vec<LogData>), Box<dyn Error>> {
    let mut current_zip_path = zip_parts[0].to_string();
    let mut nested_zip_data: Vec<u8> = vec![];

    for i in 1..zip_parts.len() {
        if is_debug_mode() {
            println!("[DEBUG] Opening nested ZIP: {} inside {}", zip_parts[i], current_zip_path);
        }

        let mut zip_file = File::open(&current_zip_path).map_err(|e| {
            println!("[ERROR] Could not open parent ZIP {}: {}", current_zip_path, e);
            e
        })?;
        let mut archive = ZipArchive::new(zip_file).map_err(|e| {
            println!("[ERROR] Could not read parent ZIP {}: {}", current_zip_path, e);
            e
        })?;

        let mut found = false;
        for j in 0..archive.len() {
            let mut file = archive.by_index(j)?;
            if file.name() == zip_parts[i] {
                if is_debug_mode() {
                    println!("[DEBUG] Nested ZIP found: {}", zip_parts[i]);
                }
                file.read_to_end(&mut nested_zip_data)?;
                found = true;
                break;
            }
        }

        if !found {
            println!("[ERROR] Nested ZIP {} not found inside {}", zip_parts[i], current_zip_path);
            return Err(format!("Nested ZIP not found: {}", zip_parts[i]).into());
        }
        current_zip_path = zip_parts[i].to_string();
    }

    let cursor = Cursor::new(nested_zip_data);
    let mut archive = ZipArchive::new(cursor).map_err(|e| {
        println!("[ERROR] Could not open final nested ZIP {}: {}", current_zip_path, e);
        e
    })?;

    let mut evtx_data = Vec::new();
    let mut found = false;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.name() == evtx_name {
            if is_debug_mode() {
                println!("[DEBUG] EVTX found inside nested ZIP: {}", evtx_name);
            }
            file.read_to_end(&mut evtx_data)?;
            found = true;
            break;
        }
    }

    if !found {
        println!("[ERROR] EVTX file '{}' not found in nested ZIP '{}'", evtx_name, current_zip_path);
        return Err(format!("EVTX not found in nested ZIP: {}", evtx_name).into());
    }

    let cursor = Cursor::new(evtx_data);
    let parser = EvtxParser::from_read_seek(cursor)?;
    if is_debug_mode() {
        println!("[DEBUG] EVTX {} opened successfully from nested ZIP.", evtx_name);
    }

    Ok((parser, vec![]))
}

// ---------------------------------------------------------------------------------------
// CREATE POLARS DATAFRAME AND WRITE/PRINT CSV
// ---------------------------------------------------------------------------------------
fn vector_to_polars(log_data: Vec<LogData>, output: Option<&String>) {
    let time_created_vec: Vec<String> = log_data.iter().map(|x| x.time_created.to_string()).collect();
    let time_created = Series::new("time_created", time_created_vec);

    let computer_vec: Vec<String> = log_data.iter().map(|x| x.computer.to_string()).collect();
    let computer = Series::new("dst_computer", computer_vec);

    let event_id_vec: Vec<String> = log_data.iter().map(|x| x.event_id.to_string()).collect();
    let event_id = Series::new("event_id", event_id_vec);

    let subject_user_name_vec: Vec<String> = log_data.iter().map(|x| x.subject_user_name.to_string()).collect();
    let subject_user_name = Series::new("subject_user_name", subject_user_name_vec);

    let subject_domain_name_vec: Vec<String> = log_data.iter().map(|x| x.subject_domain_name.to_string()).collect();
    let subject_domain_name = Series::new("subject_domain_name", subject_domain_name_vec);

    let target_user_name_vec: Vec<String> = log_data.iter().map(|x| x.target_user_name.to_string()).collect();
    let target_user_name = Series::new("target_user_name", target_user_name_vec);

    let target_domain_name_vec: Vec<String> = log_data.iter().map(|x| x.target_domain_name.to_string()).collect();
    let target_domain_name = Series::new("target_domain_name", target_domain_name_vec);

    let logon_type_vec: Vec<String> = log_data.iter().map(|x| x.logon_type.to_string()).collect();
    let logon_type = Series::new("logon_type", logon_type_vec);

    let workstation_name_vec: Vec<String> = log_data.iter().map(|x| x.workstation_name.to_string()).collect();
    let workstation_name = Series::new("src_computer", workstation_name_vec);

    let ip_address_vec: Vec<String> = log_data.iter().map(|x| x.ip_address.to_string()).collect();
    let ip_address = Series::new("src_ip", ip_address_vec);

    let filename_vec: Vec<String> = log_data.iter().map(|x| x.filename.to_string()).collect();
    let filename = Series::new("log_filename", filename_vec);
    
    let process_vec: Vec<String> = log_data.iter().map(|x| x.process.to_string()).collect();
    let process = Series::new("process", process_vec);

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
        process,
        filename
    ]);
    let df = df.unwrap().sort(["time_created"], false);

    match output {
        Some(output_path) => {
            let mut output_file = File::create(output_path).unwrap();
            CsvWriter::new(&mut output_file)
                .has_header(true)
                .finish(&mut df.unwrap())
                .unwrap();
            println!("Output written to {}", output_path);
        },
        None => {
            CsvWriter::new(io::stdout())
                .has_header(true)
                .finish(&mut df.unwrap())
                .unwrap();
        },
    }
}

// ---------------------------------------------------------------------------------------
// SEARCH FOR EVTX FILES IN DIRECTORIES (AND ZIP)
// ---------------------------------------------------------------------------------------
fn find_evtx_files(directories: &Vec<String>) -> Vec<EvtxLocation> {
    let mut evtx_files = vec![];
    let keywords = ["triage", "kape", "velociraptor"];

    for directory in directories {
        let path = Path::new(directory);
        if is_debug_mode() {
            println!("[DEBUG] Exploring directory: {}", directory);
        }

        for entry in WalkDir::new(path) {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() {
                    let ext = path.extension().and_then(|e| e.to_str());

                    // Case 1: If it's an EVTX file in the filesystem
                    if ext == Some("evtx") {
                        if let Some(path_str) = path.to_str() {
                            evtx_files.push(EvtxLocation::File(path_str.to_string()));
                        }
                    }

                    // Case 2: If it's a ZIP with a keyword, search for EVTX inside
                    if ext == Some("zip") {
                        if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
                            if keywords.iter().any(|&kw| file_name.to_lowercase().contains(kw)) {
                                if is_debug_mode() {
                                    println!("[DEBUG] ZIP detected with keyword: {}", file_name);
                                }
                                if let Some(zip_evtx_files) = list_evtx_in_zip(path, None) {
                                    evtx_files.extend(zip_evtx_files);
                                } else {
                                    if is_debug_mode() {
                                        println!("[DEBUG] No EVTX files found in ZIP: {}", file_name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if is_debug_mode() {
        println!("[DEBUG] Total EVTX files found: {}", evtx_files.len());
    }

    evtx_files
}

// ---------------------------------------------------------------------------------------
// LIST EVTX FILES INSIDE A ZIP
// ---------------------------------------------------------------------------------------
fn list_evtx_in_zip(zip_path: &Path, parent_zip: Option<String>) -> Option<Vec<EvtxLocation>> {
    if is_debug_mode() {
        println!("[DEBUG] Exploring ZIP: {:?}", zip_path);
    }

    let file = match File::open(zip_path) {
        Ok(f) => f,
        Err(e) => {
            println!("[ERROR] Could not open ZIP: {:?} -> {}", zip_path, e);
            return None;
        }
    };

    let mut archive = match ZipArchive::new(file) {
        Ok(a) => a,
        Err(e) => {
            println!("[ERROR] Could not read ZIP: {:?} -> {}", zip_path, e);
            return None;
        }
    };

    let mut evtx_files = vec![];
    let mut nested_zips = vec![];

    for i in 0..archive.len() {
        match archive.by_index(i) {
            Ok(mut file) => {
                let file_name = file.name().to_string();
                if file_name.ends_with(".evtx") {
                    // Build the full path preserving the hierarchy
                    let full_zip_path = match &parent_zip {
                        Some(parent) => format!("{} -> {}", parent, zip_path.to_string_lossy()),
                        None => zip_path.to_string_lossy().to_string(),
                    };
                    if is_debug_mode() {
                        println!("[INFO] EVTX found inside the ZIP: {}", file_name);
                    }
                    evtx_files.push(EvtxLocation::ZipEntry {
                        zip_path: full_zip_path,
                        evtx_name: file_name,
                    });
                } else if file_name.ends_with(".zip") {
                    if is_debug_mode() {
                        println!("[DEBUG] Nested ZIP detected: {}", file_name);
                    }
                    let mut nested_zip_data = Vec::new();
                    if let Err(e) = file.read_to_end(&mut nested_zip_data) {
                        println!("[ERROR] Could not read nested ZIP: {} -> {}", file_name, e);
                        continue;
                    }
                    nested_zips.push((file_name, nested_zip_data));
                }
            },
            Err(e) => {
                println!("[ERROR] Could not read a file in the ZIP: {} -> {}", i, e);
            }
        }
    }

    // Process nested ZIPs
    for (nested_zip_name, nested_zip_data) in nested_zips {
        if is_debug_mode() {
            println!("[INFO] Exploring nested ZIP: {}", nested_zip_name);
        }

        let cursor = Cursor::new(nested_zip_data);
        match ZipArchive::new(cursor) {
            Ok(mut nested_archive) => {
                for j in 0..nested_archive.len() {
                    if let Ok(nested_file) = nested_archive.by_index(j) {
                        let nested_file_name = nested_file.name().to_string();
                        if nested_file_name.ends_with(".evtx") {
                            let full_zip_path = match &parent_zip {
                                Some(parent) => format!("{} -> {} -> {}", parent, zip_path.to_string_lossy(), nested_zip_name),
                                None => format!("{} -> {}", zip_path.to_string_lossy(), nested_zip_name),
                            };
                            if is_debug_mode() {
                                println!("[INFO] EVTX found in nested ZIP: {}", nested_file_name);
                            }
                            evtx_files.push(EvtxLocation::ZipEntry {
                                zip_path: full_zip_path,
                                evtx_name: nested_file_name,
                            });
                        }
                    }
                }
            },
            Err(e) => {
                println!("[ERROR] Could not open the nested ZIP: {} -> {}", nested_zip_name, e);
            }
        }
    }

    if evtx_files.is_empty() {
        println!("[WARNING] No EVTX files found in ZIP: {:?}", zip_path);
        None
    } else {
        println!("[INFO] Total EVTX files found (including nested ZIPs): {}", evtx_files.len());
        Some(evtx_files)
    }
}

// ---------------------------------------------------------------------------------------
// GENERIC PARSE FUNCTION FOR A GIVEN EvtxLocation
// ---------------------------------------------------------------------------------------
pub fn parselog(file: EvtxLocation) -> Vec<LogData> {
    let file_origin = match &file {
        EvtxLocation::File(path) => path.clone(),
        EvtxLocation::ZipEntry { zip_path, evtx_name } => format!("{} -> {}", zip_path, evtx_name),
    };

    // Extract only the filename without paths
    let file_name = match &file {
        EvtxLocation::File(path) => Path::new(path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("")
            .to_string(),
        EvtxLocation::ZipEntry { evtx_name, .. } => {
            Path::new(evtx_name)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("")
                .to_string()
        }
    };

    // Check existence only for disk files, not for ZIP entries
    if let EvtxLocation::File(ref path) = file {
        if File::open(PathBuf::from(path)).is_err() {
            println!("[ERROR] Could not access file: {}", path);
            return Vec::new();
        }
    }

    // Decide parsing based on known filenames
    let parsed_data = match file_name.as_str() {
        "Security.evtx" => parse_security_log(&file_origin, SECURITY_EVENT_IDS.to_vec()),
        "Microsoft-Windows-SMBServer%4Security.evtx" => parse_smb_server(&file_origin, SMBSERVER_EVENT_IDS.to_vec()),
        "Microsoft-Windows-SmbClient%4Security.evtx" => parse_smb_client(&file_origin, SMBCLIENT_EVENT_IDS.to_vec()),
        "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx" => {
            parse_rdp_client(&file_origin, RDPCLIENT_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx" => {
            parse_rdp_connmanager(&file_origin, RDPCONNMANAGER_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx" => {
            parse_rdp_localsession(&file_origin, RDPLOCALSESSION_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx" => {
            parse_rdpkore(&file_origin, RDPKORE_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-SmbClient%4Connectivity.evtx" => {
            parse_smb_client_connectivity(&file_origin, SMBCLIENT_CONNECTIVITY_EVENT_IDS.to_vec())
        },
        _ => {
            // parse_unknown(&file_origin)
            Vec::new()
        }
    };

    if parsed_data.is_empty() {
        if is_debug_mode() {
            println!("[WARNING] No events found in {}", file_origin);
        }
    }

    parsed_data
}

// ---------------------------------------------------------------------------------------
// MAIN FUNCTION TO PARSE EVENTS
// ---------------------------------------------------------------------------------------
pub fn parse_events(files: &Vec<String>, directories: &Vec<String>, output: Option<&String>) {
    if is_debug_mode() {
        println!("[INFO] Starting event processing...");
    }

    let mut log_data: Vec<LogData> = vec![];
    let mut vec_filenames: Vec<EvtxLocation> = vec![];

    if is_debug_mode() {
        println!("[INFO] Adding individual EVTX files...");
    }
    vec_filenames.extend(files.iter().map(|s| EvtxLocation::File(s.to_string())));

    if is_debug_mode() {
        println!("[INFO] Searching for EVTX files in provided directories...");
    }
    vec_filenames.extend(find_evtx_files(directories)); // includes EVTX in ZIP

    if is_debug_mode() {
        println!("[INFO] Total EVTX files to process: {}", vec_filenames.len());
    }

    for evtxfile in &vec_filenames {
        match &evtxfile {
            EvtxLocation::File(path) => {
                // Optionally log processing info
            },
            EvtxLocation::ZipEntry { zip_path, evtx_name } => {
                if is_debug_mode() {
                    println!("[INFO] Processing EVTX inside ZIP:");
                    println!("       ZIP: {}", zip_path);
                    println!("       EVTX: {}", evtx_name);
                }
            }
        }

        let parsed_logs = parselog(evtxfile.clone());
        if is_debug_mode() {
            println!("[INFO] Obtained {} events from the file.", parsed_logs.len());
        }
        log_data.extend(parsed_logs);
    }

    if is_debug_mode() {
        println!("[INFO] Parsing finished. Total events collected: {}", log_data.len());
    }

    vector_to_polars(log_data, output);
}

// ---------------------------------------------------------------------------------------
// STRUCTS TO MAP EVTX XML
// ---------------------------------------------------------------------------------------
#[derive(Debug, Deserialize, PartialEq)]
struct Event {
    System: System,
    EventData: Option<EventData>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Event2 {
    System: System,
    UserData: Option<UserData>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct System {
    TimeCreated: TimeCreated,
    Provider: Provider,
    EventID: Option<String>,
    Computer: Option<String>,
    Security: Option<Security>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct TimeCreated {
    SystemTime: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Provider {
    Name: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct EventData {
    #[serde(rename = "Data", default)]
    Datas: Vec<Data>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Data {
    Name: Option<String>,
    #[serde(rename = "$value")]
    pub body: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct UserData {
    EventData: Option<EventDataSMBServer>,
    EventXML: Option<EventXML>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Security {
    UserID: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct EventDataSMBServer {
    ClientName: Option<String>,
    UserName: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct EventXML {
    Param1: Option<String>,
    Param2: Option<String>,
    Param3: Option<String>,
    User: Option<String>,
    Address: Option<String>,
}
