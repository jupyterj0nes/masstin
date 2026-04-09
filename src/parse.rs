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

/// Translate Windows SubStatus hex codes to human-readable failure reasons
fn translate_substatus(code: &str) -> String {
    let desc = match code.to_lowercase().as_str() {
        "0xc000006a" => "Wrong password",
        "0xc0000064" => "User does not exist",
        "0xc0000072" => "Account disabled",
        "0xc0000234" => "Account locked out",
        "0xc0000070" => "Logon outside allowed hours",
        "0xc000006d" => "Bad username or auth info",
        "0xc0000071" => "Expired password",
        "0xc0000224" => "Password must change",
        "0xc0000193" => "Account expired",
        "0xc000015b" => "Logon type not granted",
        "0xc000006e" => "Unknown user or bad password",
        "0xc0000133" => "Clock skew too great",
        "0xc0000005" => "Access denied",
        _ => "",
    };
    if desc.is_empty() {
        code.to_string()
    } else {
        format!("{} ({})", desc, code)
    }
}

// Event IDs for various logs
const SECURITY_EVENT_IDS: &[&str] = &["4624","4625","4634","4647","4648","4768","4769","4770","4771","4776","4778","4779","5140","5145"];
const SMBCLIENT_EVENT_IDS: &[&str] = &["31001"];
const SMBCLIENT_CONNECTIVITY_EVENT_IDS: &[&str] = &["30803","30804","30805","30806","30807","30808"];
const SMBSERVER_EVENT_IDS: &[&str] = &["1009","551"];
const RDPCLIENT_EVENT_IDS: &[&str] = &["1024","1102"];
const RDPCONNMANAGER_EVENT_IDS: &[&str] = &["1149"];
const RDPLOCALSESSION_EVENT_IDS: &[&str] = &["21","22","24","25"];
const RDPKORE_EVENT_IDS: &[&str] = &["131"];

pub mod parse {}

// Updated LogData struct with event_type, logon_id, and detail columns.
#[derive(Serialize, Deserialize, Debug)]
pub struct LogData {
    pub time_created: String,
    pub computer: String,
    pub event_type: String,
    pub event_id: String,
    pub subject_user_name: String,
    pub subject_domain_name: String,
    pub target_user_name: String,
    pub target_domain_name: String,
    pub logon_type: String,
    pub workstation_name: String,
    pub ip_address: String,
    pub logon_id: String,
    pub filename: String,
    pub detail: String,
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
                        // Extend the map with ProcessName, Status, SubStatus, TargetLogonId keys.
                        let mut data_values: HashMap<String, String> = [
                            ("SubjectUserName".to_string(), String::from("")),
                            ("SubjectDomainName".to_string(), String::from("")),
                            ("TargetUserName".to_string(), String::from("")),
                            ("TargetDomainName".to_string(), String::from("")),
                            ("LogonType".to_string(), String::from("")),
                            ("WorkstationName".to_string(), String::from("")),
                            ("IpAddress".to_string(), String::from("")),
                            ("ProcessName".to_string(), String::from("")),
                            ("Status".to_string(), String::from("")),
                            ("SubStatus".to_string(), String::from("")),
                            ("TargetLogonId".to_string(), String::from("")),
                            ("ShareName".to_string(), String::from("")),
                            ("RelativeTargetName".to_string(), String::from("")),
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

                        // Classify event_type based on event ID
                        let status = data_values.get("Status").unwrap().as_str();
                        let event_type = match event_id.as_str() {
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
                            "5140" | "5145" => "SUCCESSFUL_LOGON".to_string(),
                            _ => "CONNECT".to_string(),
                        };

                        // Determine detail column
                        let share_name = data_values.get("ShareName").unwrap().to_string();
                        let relative_target = data_values.get("RelativeTargetName").unwrap().to_string();
                        let detail = match event_id.as_str() {
                            "4624" | "4648" => data_values.get("ProcessName").unwrap().to_string(),
                            "4625" => translate_substatus(data_values.get("SubStatus").unwrap()),
                            "5140" => share_name,
                            "5145" => {
                                if relative_target.is_empty() {
                                    share_name
                                } else {
                                    format!("{}\\{}", share_name, relative_target)
                                }
                            },
                            _ => String::from(""),
                        };

                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: event.System.Computer.unwrap(),
                            event_type,
                            event_id,
                            subject_user_name: data_values.get("SubjectUserName").unwrap().to_string(),
                            subject_domain_name: data_values.get("SubjectDomainName").unwrap().to_string(),
                            target_user_name: data_values.get("TargetUserName").unwrap().to_string(),
                            target_domain_name: data_values.get("TargetDomainName").unwrap().to_string(),
                            logon_type: data_values.get("LogonType").unwrap().to_string(),
                            workstation_name: data_values.get("WorkstationName").unwrap().to_string(),
                            ip_address: data_values.get("IpAddress").unwrap().to_string(),
                            logon_id: data_values.get("TargetLogonId").unwrap().to_string(),
                            filename: file.to_string(),
                            detail,
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
                        let event_type = match event_id.as_str() {
                            "1009" => "SUCCESSFUL_LOGON".to_string(),
                            "551" => "FAILED_LOGON".to_string(),
                            _ => "CONNECT".to_string(),
                        };
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: event.System.Computer.unwrap(),
                            event_type,
                            event_id,
                            subject_user_name: event.System.Security.unwrap().UserID.as_ref().unwrap_or(&String::from("")).to_owned(),
                            subject_domain_name: String::from(""),
                            target_user_name: event.UserData.as_ref().unwrap().EventData.as_ref().unwrap().UserName.as_ref().unwrap_or(&String::from("")).to_owned(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("3"),
                            workstation_name: event.UserData.as_ref().unwrap().EventData.as_ref().unwrap().ClientName.as_ref().unwrap_or(&String::from("")).to_owned(),
                            ip_address: event.UserData.as_ref().unwrap().EventData.as_ref().unwrap().ClientName.as_ref().unwrap_or(&String::from("")).to_owned(),
                            logon_id: String::from(""),
                            filename: file.to_string(),
                            detail: String::from(""),
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
                            ("ServerName".to_string(), String::from("")),
                            ("ShareName".to_string(), String::from("")),
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
                            event_type: "SUCCESSFUL_LOGON".to_string(),
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: data_values.get("UserName").unwrap().to_string(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("3"),
                            workstation_name: event.System.Computer.as_ref().unwrap().to_owned(),
                            ip_address: event.System.Computer.as_ref().unwrap().to_owned(),
                            logon_id: String::from(""),
                            filename: file.to_string(),
                            detail: data_values.get("ShareName").unwrap().to_string(),
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
                            event_type: "CONNECT".to_string(),
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: data_values.get("UserName").unwrap().to_string(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("3"),
                            workstation_name: event.System.Computer.as_ref().unwrap().to_owned(),
                            ip_address: event.System.Computer.as_ref().unwrap().to_owned(),
                            logon_id: String::from(""),
                            filename: file.to_string(),
                            detail: String::from(""),
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
                            event_type: "CONNECT".to_string(),
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: event.System.Security.unwrap().UserID.unwrap(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("10"),
                            workstation_name: event.System.Computer.as_ref().unwrap().to_owned(),
                            ip_address: event.System.Computer.as_ref().unwrap().to_owned(),
                            logon_id: String::from(""),
                            filename: file.to_string(),
                            detail: String::from(""),
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
            event_type: "SUCCESSFUL_LOGON".to_string(),
            event_id,
            subject_user_name: String::new(),
            subject_domain_name: String::new(),
            target_user_name: target_user,
            target_domain_name: String::new(),
            logon_type: "10".into(),
            workstation_name: client.clone(),
            ip_address: client,
            logon_id: String::new(),
            filename: file.to_string(),
            detail: String::new(),
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

                        let event_type = match event_id.as_str() {
                            "21" | "22" | "25" => "SUCCESSFUL_LOGON".to_string(),
                            "24" => "LOGOFF".to_string(),
                            _ => "CONNECT".to_string(),
                        };
                        // Try to extract SessionId for logon_id
                        let session_id = event.UserData.as_ref()
                            .and_then(|ud| ud.EventXML.as_ref())
                            .and_then(|xml| xml.Param1.as_ref())
                            .cloned()
                            .unwrap_or_default();
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: event.System.Computer.unwrap(),
                            event_type,
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: remoteuser,
                            target_domain_name: remotedomain,
                            logon_type: String::from("10"),
                            workstation_name: event.UserData.as_ref().unwrap().EventXML.as_ref().unwrap().Address.as_ref().unwrap().to_owned(),
                            ip_address: event.UserData.as_ref().unwrap().EventXML.as_ref().unwrap().Address.as_ref().unwrap().to_owned(),
                            logon_id: session_id,
                            filename: file.to_string(),
                            detail: String::from(""),
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
                            event_type: "CONNECT".to_string(),
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: String::from(""),
                            target_domain_name: String::from(""),
                            logon_type: String::from("10"),
                            workstation_name: data_values.get("ClientIP").unwrap().to_string(),
                            ip_address: data_values.get("ClientIP").unwrap().to_string(),
                            logon_id: String::from(""),
                            filename: file.to_string(),
                            detail: String::from(""),
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
        if is_debug_mode() { eprintln!("[DEBUG] Could not read ZIP {}: {}", zip_path, e); }
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
fn vector_to_polars(log_data: Vec<LogData>, output: Option<&String>) -> usize {
    // Deduplicate events (e.g., same event from live volume and VSS snapshot)
    // Key: (time_created, dst_computer, event_id, event_type, target_user_name, src_ip)
    // Prefer live volume events over VSS (shorter filename = no "vss_" in path)
    let log_data = {
        let mut seen = std::collections::HashSet::new();
        let mut deduped: Vec<LogData> = Vec::with_capacity(log_data.len());
        // Sort: live events first (shorter filenames), VSS after
        let mut sorted = log_data;
        sorted.sort_by(|a, b| a.filename.len().cmp(&b.filename.len()));
        for item in sorted {
            let key = format!("{}|{}|{}|{}|{}|{}",
                item.time_created, item.computer, item.event_id,
                item.event_type, item.target_user_name, item.ip_address);
            if seen.insert(key) {
                deduped.push(item);
            }
        }
        deduped
    };

    let deduped_count = log_data.len();

    let time_created_vec: Vec<String> = log_data.iter().map(|x| x.time_created.to_string()).collect();
    let time_created = Series::new("time_created", time_created_vec);

    let computer_vec: Vec<String> = log_data.iter().map(|x| x.computer.to_string()).collect();
    let computer = Series::new("dst_computer", computer_vec);

    let event_type_vec: Vec<String> = log_data.iter().map(|x| x.event_type.to_string()).collect();
    let event_type = Series::new("event_type", event_type_vec);

    let event_id_vec: Vec<String> = log_data.iter().map(|x| x.event_id.to_string()).collect();
    let event_id = Series::new("event_id", event_id_vec);

    let logon_type_vec: Vec<String> = log_data.iter().map(|x| x.logon_type.to_string()).collect();
    let logon_type = Series::new("logon_type", logon_type_vec);

    let target_user_name_vec: Vec<String> = log_data.iter().map(|x| x.target_user_name.to_string()).collect();
    let target_user_name = Series::new("target_user_name", target_user_name_vec);

    let target_domain_name_vec: Vec<String> = log_data.iter().map(|x| x.target_domain_name.to_string()).collect();
    let target_domain_name = Series::new("target_domain_name", target_domain_name_vec);

    let workstation_name_vec: Vec<String> = log_data.iter().map(|x| x.workstation_name.to_string()).collect();
    let workstation_name = Series::new("src_computer", workstation_name_vec);

    let ip_address_vec: Vec<String> = log_data.iter().map(|x| x.ip_address.to_string()).collect();
    let ip_address = Series::new("src_ip", ip_address_vec);

    let subject_user_name_vec: Vec<String> = log_data.iter().map(|x| x.subject_user_name.to_string()).collect();
    let subject_user_name = Series::new("subject_user_name", subject_user_name_vec);

    let subject_domain_name_vec: Vec<String> = log_data.iter().map(|x| x.subject_domain_name.to_string()).collect();
    let subject_domain_name = Series::new("subject_domain_name", subject_domain_name_vec);

    let logon_id_vec: Vec<String> = log_data.iter().map(|x| x.logon_id.to_string()).collect();
    let logon_id = Series::new("logon_id", logon_id_vec);

    let detail_vec: Vec<String> = log_data.iter().map(|x| x.detail.to_string()).collect();
    let detail = Series::new("detail", detail_vec);

    let filename_vec: Vec<String> = log_data.iter().map(|x| x.filename.to_string()).collect();
    let filename = Series::new("log_filename", filename_vec);

    let df = DataFrame::new(vec![
        time_created,
        computer,
        event_type,
        event_id,
        logon_type,
        target_user_name,
        target_domain_name,
        workstation_name,
        ip_address,
        subject_user_name,
        subject_domain_name,
        logon_id,
        detail,
        filename
    ]);
    let df = df.unwrap().sort(["time_created"], false);

    match output {
        Some(output_path) => {
            let mut output_file = match File::create(output_path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[ERROR] Cannot create output file {}: {}", output_path, e);
                    return 0;
                }
            };
            CsvWriter::new(&mut output_file)
                .has_header(true)
                .finish(&mut df.unwrap())
                .unwrap();
        },
        None => {
            CsvWriter::new(io::stdout())
                .has_header(true)
                .finish(&mut df.unwrap())
                .unwrap();
        },
    }

    deduped_count
}

// ---------------------------------------------------------------------------------------
// SEARCH FOR EVTX FILES IN DIRECTORIES (AND ZIP)
// ---------------------------------------------------------------------------------------
fn find_evtx_files(directories: &[String]) -> Vec<EvtxLocation> {
    let mut evtx_files = Vec::new();

    for directory in directories {
        let path = Path::new(directory);
        if is_debug_mode() {
            println!("[DEBUG] Exploring directory: {}", directory);
        }

        for entry in WalkDir::new(path) {
            if let Ok(entry) = entry {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                match path.extension().and_then(|e| e.to_str()) {
                    Some("evtx") => {
                        if let Some(path_str) = path.to_str() {
                            evtx_files.push(EvtxLocation::File(path_str.to_string()));
                        }
                    }
                    Some("zip") => {
                        if is_debug_mode() {
                            println!("[DEBUG] ZIP detected: {}", path.display());
                        }
                        if let Some(found) = list_evtx_in_zip(path, None) {
                            evtx_files.extend(found);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if is_debug_mode() {
        println!("[DEBUG] Total EVTX files found: {}", evtx_files.len());
    }

    evtx_files
}

// -----------------------------------------------------------------------------
// LIST EVTX FILES INSIDE A ZIP
// -----------------------------------------------------------------------------
fn list_evtx_in_zip(zip_path: &Path, parent_chain: Option<String>) -> Option<Vec<EvtxLocation>> {
    let mut evtx_files = Vec::<EvtxLocation>::new();

    // Abrimos el ZIP raíz
    let file = File::open(zip_path).map_err(|e| {
        if is_debug_mode() { eprintln!("[DEBUG] Could not open ZIP {:?}: {}", zip_path, e); }
    }).ok()?;
    let mut archive = ZipArchive::new(file).map_err(|e| {
        if is_debug_mode() { eprintln!("[DEBUG] Could not read ZIP {:?}: {}", zip_path, e); }
    }).ok()?;

    // Ruta acumulada:  zip1 -> zip2 -> ... -> actual.zip
    let this_chain = match &parent_chain {
        Some(c) => format!("{} -> {}", c, zip_path.to_string_lossy()),
        None     => zip_path.to_string_lossy().to_string(),
    };

    // Recorremos todas las entradas
    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(f)  => f,
            Err(e) => {
                if is_debug_mode() { eprintln!("[DEBUG] Reading file {} in {:?}: {}", i, zip_path, e); }
                continue;
            }
        };

        let name = entry.name().to_owned();

        if name.ends_with(".evtx") {
            // Encontrado un EVTX
            if is_debug_mode() {
                println!("[INFO] EVTX found: {} inside {}", name, zip_path.display());
            }
            evtx_files.push(EvtxLocation::ZipEntry {
                zip_path: this_chain.clone(),
                evtx_name: name,
            });
        } else if name.ends_with(".zip") {
            // ZIP anidado → lo leemos en memoria y llamamos recursivamente
            let mut nested_data = Vec::with_capacity(entry.size() as usize);
            if entry.read_to_end(&mut nested_data).is_err() {
                println!("[ERROR] Could not read nested ZIP {}", name);
                continue;
            }
            let mut nested_archive = match ZipArchive::new(Cursor::new(nested_data)) {
                Ok(a)  => a,
                Err(e) => {
                    if is_debug_mode() { eprintln!("[DEBUG] Opening nested ZIP {}: {}", name, e); }
                    continue;
                }
            };

            // Creamos un Cursor temporal para pasarlo a la función recursiva
            let tmp_path = zip_path.with_file_name(name.clone());
            // El Cursor anterior ya tiene los datos, sólo necesitamos una ruta “ficticia”
            // para llevar la cuenta de la jerarquía.
            if let Some(mut deeper) =
                recurse_zip(&mut nested_archive, &this_chain, &name)
            {
                evtx_files.append(&mut deeper);
            }
        }
    }

    if evtx_files.is_empty() {
        None
    } else {
        Some(evtx_files)
    }
}

// -----------------------------------------------------------------------------
// Helper recursivo para ZIPs anidados ilimitadamente
// -----------------------------------------------------------------------------
fn recurse_zip<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    parent_chain: &str,
    current_zip_name: &str,
) -> Option<Vec<EvtxLocation>> {
    let mut evtx_files = Vec::<EvtxLocation>::new();

    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(f)  => f,
            Err(_) => continue,
        };
        let name = entry.name().to_owned();

        if name.ends_with(".evtx") {
            evtx_files.push(EvtxLocation::ZipEntry {
                zip_path: format!("{} -> {}", parent_chain, current_zip_name),
                evtx_name: name,
            });
        } else if name.ends_with(".zip") {
            // ZIP dentro de ZIP dentro de ZIP…​
            let mut nested_data = Vec::with_capacity(entry.size() as usize);
            if entry.read_to_end(&mut nested_data).is_err() {
                continue;
            }
            if let Ok(mut deeper_archive) = ZipArchive::new(Cursor::new(nested_data)) {
                if let Some(mut deeper) = recurse_zip(
                    &mut deeper_archive,
                    &format!("{} -> {}", parent_chain, current_zip_name),
                    &name,
                ) {
                    evtx_files.append(&mut deeper);
                }
            }
        }
    }

    if evtx_files.is_empty() {
        None
    } else {
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
            if is_debug_mode() {
                println!("[ERROR] Could not access file: {}", path);
            }
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
    let start_time = std::time::Instant::now();

    if is_debug_mode() {
        println!("[INFO] Starting event processing...");
    }

    let mut log_data: Vec<LogData> = vec![];
    let mut vec_filenames: Vec<EvtxLocation> = vec![];

    // Detect drive root paths and suggest parse-image-windows for VSS
    // parse-windows passes "X:\" (normalized), parse-image-windows passes "X:" (no trailing \)
    for dir in directories {
        let d = dir.replace('/', "\\");
        let is_drive_with_backslash = d.len() == 3
            && d.as_bytes()[0].is_ascii_alphabetic()
            && d.as_bytes()[1] == b':'
            && d.as_bytes()[2] == b'\\';
        if is_drive_with_backslash {
            let letter = &d[..2];
            crate::banner::print_info(&format!(
                "Drive {} detected — scanning as filesystem (EVTX + UAL only).", letter
            ));
            crate::banner::print_info(&format!(
                "Tip: use '-a parse-image-windows -d {}' to also recover events from VSS shadow copies.", letter
            ));
        }
    }

    // Phase 1: Search for artifacts
    crate::banner::print_search_start();

    if is_debug_mode() {
        println!("[INFO] Adding individual EVTX files...");
    }
    vec_filenames.extend(files.iter().map(|s| EvtxLocation::File(s.to_string())));

    if is_debug_mode() {
        println!("[INFO] Searching for EVTX files in provided directories...");
    }
    let dir_count = directories.len();
    let file_count = files.len();
    vec_filenames.extend(find_evtx_files(directories)); // includes EVTX in ZIP

    // Count ZIPs vs direct files for the summary
    let zip_count = vec_filenames.iter().filter(|f| matches!(f, EvtxLocation::ZipEntry { .. })).count();
    let total_evtx = vec_filenames.len();

    // Detect UAL databases early so we can include them in the artifact count
    let mut all_ual_files: Vec<std::path::PathBuf> = Vec::new();
    for dir in directories {
        all_ual_files.extend(crate::parse_ual::find_ual_databases(dir));
    }
    for f in files {
        if f.to_lowercase().ends_with(".mdb") && std::path::Path::new(f).exists() {
            all_ual_files.push(std::path::PathBuf::from(f));
        }
    }
    all_ual_files.sort();
    all_ual_files.dedup();

    if all_ual_files.is_empty() {
        crate::banner::print_search_results_labeled(total_evtx, zip_count, dir_count, file_count, "EVTX artifacts");
    } else {
        crate::banner::print_search_results_labeled(total_evtx, zip_count, dir_count, file_count,
            &format!("EVTX artifacts + {} UAL databases", all_ual_files.len()));
    }

    if is_debug_mode() {
        println!("[INFO] Total EVTX files to process: {}", vec_filenames.len());
    }

    // Phase 2: Process artifacts
    crate::banner::print_processing_start();
    let pb = crate::banner::create_progress_bar(vec_filenames.len() as u64);
    let mut skipped: usize = 0;
    let mut parsed_files: usize = 0;
    let mut artifact_details: Vec<(String, usize)> = Vec::new();

    for evtxfile in &vec_filenames {
        let name = match &evtxfile {
            EvtxLocation::File(path) => path.clone(),
            EvtxLocation::ZipEntry { evtx_name, .. } => evtx_name.clone(),
        };
        crate::banner::progress_set_message(&pb, &name);

        let parsed_logs = parselog(evtxfile.clone());
        let count = parsed_logs.len();
        if count == 0 {
            skipped += 1;
        } else {
            parsed_files += 1;
            artifact_details.push((name.clone(), count));
            if is_debug_mode() {
                println!("[INFO] {} events from {}", count, name);
            }
        }
        log_data.extend(parsed_logs);
        pb.inc(1);
    }

    pb.finish_and_clear();
    crate::banner::print_artifact_detail(&artifact_details);

    // Parse UAL databases (detected earlier during artifact search)
    if !all_ual_files.is_empty() {
        let source = directories.first().map(|s| s.as_str()).unwrap_or("UAL");
        let ual_events = crate::parse_ual::parse_ual_databases(&all_ual_files, source);
        if !ual_events.is_empty() {
            crate::banner::print_info(&format!(
                "  {} UAL access records extracted (3-year server logon history)",
                ual_events.len()
            ));
            artifact_details.push(("UAL (User Access Logging)".to_string(), ual_events.len()));
            log_data.extend(ual_events);
        }
    }

    if is_debug_mode() {
        println!("[INFO] Parsing finished. Total events collected: {}", log_data.len());
    }

    // Phase 3: Generate output
    crate::banner::print_output_start();
    let total_before_dedup = log_data.len();
    let total_after_dedup = vector_to_polars(log_data, output);
    let deduped = total_before_dedup - total_after_dedup;
    if deduped > 0 {
        crate::banner::print_info(&format!("{} duplicate events removed (live + VSS overlap)", deduped));
    }

    crate::banner::print_summary(total_after_dedup, parsed_files, skipped, output.map(|s| s.as_str()), start_time);
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
