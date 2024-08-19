use std::{path::PathBuf, fs::File};
use evtx::{err::EvtxError, EvtxParser, ParserSettings, SerializedEvtxRecord};
extern crate serde;
extern crate quick_xml;
use serde::{Serialize,Deserialize};
use quick_xml::de::{from_str, DeError};
use std::{error::Error, collections::HashMap};
use polars::prelude::*;
use walkdir::WalkDir;
use std::path::Path;
use std::io::{self, Write};

const SECURITY_EVENT_IDS: &[&str] = &["4624","4625","4634","4647","4648","4768","4769","4770","4771","4776","4778","4779"];
const SMBCLIENT_EVENT_IDS: &[&str] = &["31001"];
const SMBCLIENT_CONNECTIVITY_EVENT_IDS: &[&str] = &["30803","30804","30805","30806","30807","30808"];
const SMBSERVER_EVENT_IDS: &[&str] = &["1009","551"];
const RDPCLIENT_EVENT_IDS: &[&str] = &["1024","1102"];
const RDPCONNMANAGER_EVENT_IDS: &[&str] = &["1149"];
const RDPLOCALSESSION_EVENT_IDS: &[&str] = &["21","22","24","25"];
const RDPKORE_EVENT_IDS: &[&str] = &["131"];

pub mod parse {
    }
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
    }

pub fn parse_security_log(file: &str, lateral_eventIDs: Vec<&str>) -> Vec<LogData> {
    //println!("MASSTIN: Parsing {}",file);
    let (mut parser, mut log_data) = prep_parse(file);
    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                //println!("{}",data);
                let event: Event = match from_str(&data) {
                    Ok(event) => event,
                    Err(e) => {
                        //println!("Error parsing event: {}", data);
                        //println!("Error code: {}", e);
                        continue; 
                    },
                };
                if let Some(eventID) = event.System.EventID {
                    if lateral_eventIDs.contains(&eventID.as_str()) {
                        let mut data_values: HashMap<String, String> = [
                            ("SubjectUserName".to_string(), String::from("")),
                            ("SubjectDomainName".to_string(), String::from("")),
                            ("TargetUserName".to_string(), String::from("")),
                            ("TargetDomainName".to_string(), String::from("")),
                            ("LogonType".to_string(), String::from("")),
                            ("WorkstationName".to_string(), String::from("")),
                            ("IpAddress".to_string(), String::from(""))
                        ].iter().cloned().collect();
                                            
                        if let Some(event_data) = event.EventData {
                            for data in event_data.Datas {
                                match data.Name {
                                    Some(name) => {
                                        if let Some(data_value) = data_values.get_mut(&name) {
                                            *data_value = data.body.as_ref().unwrap_or(&"default_value".to_string()).clone();
                                        }
                                    },
                                    None => (),
                                }
                            }
                        }
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: event.System.Computer.unwrap(),
                            event_id: eventID,
                            subject_user_name: data_values.get("SubjectUserName").unwrap().to_string(),
                            subject_domain_name: data_values.get("SubjectDomainName").unwrap().to_string(),
                            target_user_name: data_values.get("TargetUserName").unwrap().to_string(),
                            target_domain_name: data_values.get("TargetDomainName").unwrap().to_string(),
                            logon_type: data_values.get("LogonType").unwrap().to_string(),
                            workstation_name: data_values.get("WorkstationName").unwrap().to_string(),
                            ip_address: data_values.get("IpAddress").unwrap().to_string(),
                            filename: file.to_string(),
                        });
                    }
                }
            },
            Err(e) => (),
        }
    }
    log_data
}

pub fn parse_smb_server(file: &str,lateral_eventIDs: Vec<&str>) -> Vec<LogData> {
    //println!("MASSTIN: Parsing {}",file);
    //let lateral_eventIDs = vec!["1009","551"];
    let (mut parser, mut log_data) = prep_parse(file);
    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                //println!("{}",data);
                let event: Event2 = from_str(&data).unwrap();
                if let Some(eventID) = event.System.EventID {
                    if lateral_eventIDs.contains(&eventID.as_str()) {
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: event.System.Computer.unwrap(),
                            event_id: eventID,
                            subject_user_name: event.System.Security.unwrap().UserID.as_ref().unwrap_or(&String::from("")).to_owned(),
                            subject_domain_name: String::from(""),
                            target_user_name: event.UserData.as_ref().unwrap().EventData.as_ref().unwrap().UserName.as_ref().unwrap_or(&String::from("")).to_owned(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("3"),
                            workstation_name: event.UserData.as_ref().unwrap().EventData.as_ref().unwrap().ClientName.as_ref().unwrap_or(&String::from("")).to_owned(),
                            ip_address: event.UserData.as_ref().unwrap().EventData.as_ref().unwrap().ClientName.as_ref().unwrap_or(&String::from("")).to_owned(),
                            filename: file.to_string(),
                        });
                    }
                }
            },
            Err(e) => (),
        }
    }
    log_data
}

pub fn parse_smb_client(file: &str, lateral_eventIDs: Vec<&str>) -> Vec<LogData> {
    //println!("MASSTIN: Parsing {}",file);
    let (mut parser, mut log_data) = prep_parse(file);
    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                //println!("{}",data);
                let event: Event = from_str(&data).unwrap();
                if let Some(eventID) = event.System.EventID {
                    if lateral_eventIDs.contains(&eventID.as_str()) {
                        let mut data_values: HashMap<String, String> = [
                            ("UserName".to_string(), String::from("")),
                            ("ServerName".to_string(), String::from("")),
                        ].iter().cloned().collect();
                                            
                        for data in event.EventData.unwrap().Datas {
                            match data.Name {
                                Some(name) => {
                                    if let Some(data_value) = data_values.get_mut(&name) {
                                        *data_value = data.body.as_ref().unwrap_or(&"default_value".to_string()).clone();
                                    }
                                },
                                None => (),
                            }
                        }
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: data_values.get("ServerName").unwrap().to_string(),
                            event_id: eventID,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: data_values.get("UserName").unwrap().to_string(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("3"),
                            workstation_name: event.System.Computer.as_ref().unwrap().to_owned(),
                            ip_address: event.System.Computer.as_ref().unwrap().to_owned(),
                            filename: file.to_string(),
                        });
                    }
                }
            },
            Err(e) => (),
        }
    }
    log_data
}

pub fn parse_smb_client_connectivity(file: &str, lateral_eventIDs: Vec<&str>) -> Vec<LogData> {
    //println!("MASSTIN: Parsing {}",file);
    let (mut parser, mut log_data) = prep_parse(file);
    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                //println!("{}",data);
                let event: Event = from_str(&data).unwrap();
                if let Some(eventID) = event.System.EventID {
                    if lateral_eventIDs.contains(&eventID.as_str()) {
                        let mut data_values: HashMap<String, String> = [
                            ("UserName".to_string(), String::from("")),
                            ("ServerName".to_string(), String::from("")),
                        ].iter().cloned().collect();
                                            
                        for data in event.EventData.unwrap().Datas {
                            match data.Name {
                                Some(name) => {
                                    if let Some(data_value) = data_values.get_mut(&name) {
                                        *data_value = data.body.as_ref().unwrap_or(&"default_value".to_string()).clone();
                                    }
                                },
                                None => (),
                            }
                        }
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: data_values.get("ServerName").unwrap().to_string(),
                            event_id: eventID,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: data_values.get("UserName").unwrap().to_string(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("3"),
                            workstation_name: event.System.Computer.as_ref().unwrap().to_owned(),
                            ip_address: event.System.Computer.as_ref().unwrap().to_owned(),
                            filename: file.to_string(),
                        });
                    }
                }
            },
            Err(e) => (),
        }
    }
    log_data
}

pub fn parse_rdp_client(file: &str, lateral_eventIDs: Vec<&str>) -> Vec<LogData> {
    //println!("MASSTIN: Parsing {}",file);
    let (mut parser, mut log_data) = prep_parse(file);
    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                //println!("{}",data);
                let event: Event = from_str(&data).unwrap();
                if let Some(eventID) = event.System.EventID {
                    if lateral_eventIDs.contains(&eventID.as_str()) {
                        let mut data_values: HashMap<String, String> = [
                            ("Value".to_string(), String::from("")),
                        ].iter().cloned().collect();
                                            
                        for data in event.EventData.unwrap().Datas {
                            match data.Name {
                                Some(name) => {
                                    if let Some(data_value) = data_values.get_mut(&name) {
                                        *data_value = data.body.as_ref().unwrap_or(&"default_value".to_string()).clone();
                                    }
                                },
                                None => (),
                            }
                        }
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: data_values.get("Value").unwrap().to_string(),
                            event_id: eventID,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: event.System.Security.unwrap().UserID.unwrap(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("10"),
                            workstation_name: event.System.Computer.as_ref().unwrap().to_owned(),
                            ip_address: event.System.Computer.as_ref().unwrap().to_owned(),
                            filename: file.to_string(),
                        });
                    }
                }
            },
            Err(e) => (),
        }
    }
    log_data
}

pub fn parse_rdp_connmanager(file: &str, lateral_eventIDs: Vec<&str>) -> Vec<LogData> {
    //println!("MASSTIN: Parsing {}",file);
    let (mut parser, mut log_data) = prep_parse(file);
    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                //println!("{}",data);
                let event: Event2 = from_str(&data).unwrap();
                if let Some(eventID) = event.System.EventID {
                    if lateral_eventIDs.contains(&eventID.as_str()) {
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: event.System.Computer.unwrap(),
                            event_id: eventID,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: event.UserData.as_ref().unwrap().EventXML.as_ref().unwrap().Param1.as_ref().unwrap().to_owned(),
                            target_domain_name: event.UserData.as_ref().unwrap().EventXML.as_ref().unwrap().Param2.as_ref().unwrap().to_owned(),
                            logon_type: String::from("10"),
                            workstation_name: event.UserData.as_ref().unwrap().EventXML.as_ref().unwrap().Param3.as_ref().unwrap().to_owned(),
                            ip_address: event.UserData.as_ref().unwrap().EventXML.as_ref().unwrap().Param3.as_ref().unwrap().to_owned(),
                            filename: file.to_string(),
                        });
                    }
                }
            },
            Err(e) => (),
        }
    }
    log_data
}

pub fn parse_rdp_localsession(file: &str, lateral_eventIDs: Vec<&str>) -> Vec<LogData> {
    //println!("MASSTIN: Parsing {}",file);
    let (mut parser, mut log_data) = prep_parse(file);
    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                //println!("{}",data);
                let event: Event2 = from_str(&data).unwrap();
                if let Some(eventID) = event.System.EventID {
                    if lateral_eventIDs.contains(&eventID.as_str()) {
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
                            event_id: eventID,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: remoteuser,
                            target_domain_name: remotedomain,
                            logon_type: String::from("10"),
                            workstation_name: event.UserData.as_ref().unwrap().EventXML.as_ref().unwrap().Address.as_ref().unwrap().to_owned(),
                            ip_address: event.UserData.as_ref().unwrap().EventXML.as_ref().unwrap().Address.as_ref().unwrap().to_owned(),
                            filename: file.to_string(),
                        });
                    }
                }
            },
            Err(e) => (),
        }
    }
    log_data
}

pub fn parse_rdpkore(file: &str, lateral_eventIDs: Vec<&str>) -> Vec<LogData> {
    //println!("MASSTIN: Parsing {}",file);
    let (mut parser, mut log_data) = prep_parse(file);
    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                //println!("{}",data);
                let event: Event = from_str(&data).unwrap();
                if let Some(eventID) = event.System.EventID {
                    if lateral_eventIDs.contains(&eventID.as_str()) {
                        let mut data_values: HashMap<String, String> = [
                            ("ClientIP".to_string(), String::from("")),
                        ].iter().cloned().collect();            
                        for data in event.EventData.unwrap().Datas {
                            match data.Name {
                                Some(name) => {
                                    if let Some(data_value) = data_values.get_mut(&name) {
                                        *data_value = data.body.as_ref().unwrap_or(&"default_value".to_string()).clone();
                                    }
                                },
                                None => (),
                            }
                        }
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap(),
                            computer: event.System.Computer.unwrap(),
                            event_id: eventID,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: String::from(""),
                            target_domain_name: String::from(""),
                            logon_type: String::from("10"),
                            workstation_name: data_values.get("ClientIP").unwrap().to_string(),
                            ip_address: data_values.get("ClientIP").unwrap().to_string(),
                            filename: file.to_string(),
                        });
                    }
                }
            },
            Err(e) => (),
        }
    }
    log_data
}



pub fn parse_unknown(file: &str) -> Vec<LogData> {
    let (mut parser, mut log_data) = prep_parse(file);
    let mut provider = String::from("");
    //if let Some(Ok(r)) = parser.records().next() {
    if let Some(Ok(r)) = parser.records().nth(1) {
        let data = r.data.as_str();
        let event: Event = from_str(&data).unwrap();
        provider = event.System.Provider.Name.unwrap();
    }

    match provider.as_str() {
        "Microsoft-Windows-Security-Auditing" => log_data=parse_security_log(file,SECURITY_EVENT_IDS.to_vec()),
        "Microsoft-Windows-SMBServer" => log_data=parse_smb_server(file,SMBSERVER_EVENT_IDS.to_vec()),
        "Microsoft-Windows-SMBClient" => log_data=parse_smb_client(file,SMBCLIENT_EVENT_IDS.to_vec()),
        "Microsoft-Windows-TerminalServices-ClientActiveXCore" => log_data=parse_rdp_client(file,RDPCLIENT_EVENT_IDS.to_vec()),
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager" => log_data=parse_rdp_connmanager(file,RDPCONNMANAGER_EVENT_IDS.to_vec()),
        "Microsoft-Windows-TerminalServices-LocalSessionManager" => log_data=parse_rdp_localsession(file,RDPLOCALSESSION_EVENT_IDS.to_vec()),
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS" => log_data=parse_rdpkore(file,RDPKORE_EVENT_IDS.to_vec()),
        _ => (),
    }
    log_data
}

fn prep_parse(file: &str) -> (EvtxParser<std::fs::File>, Vec<LogData>) {
    let fp = PathBuf::from(file);
    let settings = ParserSettings::default()
    .separate_json_attributes(true)
    .num_threads(0);
    let mut parser = EvtxParser::from_path(fp).unwrap();
    let mut log_data: Vec<LogData> = vec![];
    (parser, log_data)
}

fn vector_to_polars(log_data: Vec<LogData>, output : Option<&String>)  {
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
    let ip_filename_vec: Vec<String> = log_data.iter().map(|x| x.filename.to_string()).collect();
    let filename = Series::new("log_filename", ip_filename_vec);
    let df = DataFrame::new(vec![time_created,computer,event_id,subject_user_name,subject_domain_name,target_user_name,target_domain_name,logon_type,workstation_name,ip_address,filename]);
    //println!("Log Data is {:?}",df);
    let df = df.unwrap().sort(["time_created"],false);
    //let df = df.unwrap();
    //df.unwrap()write_csv("path2/file.csv");
    match output {
        Some(output_path) => {
            // Escribir df en el archivo
            let mut output_file = File::create(output_path).unwrap();
            CsvWriter::new(&mut output_file)
                .has_header(true)
                .finish(&mut df.unwrap())
                .unwrap();
            println!("Output written to {}", output_path);
        },
        None => {
            // Imprimir df por la salida estándar
            CsvWriter::new(io::stdout())
                .has_header(true)
                .finish(&mut df.unwrap())
                .unwrap();
            //println!("Output written to stdout");
        },
    }
}

fn find_evtx_files(directories: &Vec<String>) -> Vec<String> {
    let mut evtx_files = vec![];
    for directory in directories {
        let path = Path::new(&directory);
        for entry in WalkDir::new(path) {
            // Usa if let para continuar en caso de error
            if let Ok(entry) = entry {
                if entry.file_type().is_file() {
                    let path = entry.path();
                    if path.extension() == Some(std::ffi::OsStr::new("evtx")) {
                        if let Some(path_str) = path.to_str() {
                            evtx_files.push(path_str.to_string());
                        }
                    }
                }
            }
            // En caso de Err, simplemente continua con el próximo elemento
        }
    }
    evtx_files
}


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

pub fn parselog(file: &str) -> Vec<LogData> {
    let path = PathBuf::from(file);

    // Verify if file exists and can read 
    if let Ok(_) = File::open(&path) {
        let file_name = path.file_name().and_then(|f| f.to_str());

        match file_name {
            Some("Security.evtx") => parse_security_log(file, SECURITY_EVENT_IDS.to_vec()),
            Some("Microsoft-Windows-SMBServer%4Security.evtx") => parse_smb_server(file, SMBSERVER_EVENT_IDS.to_vec()),
            Some("Microsoft-Windows-SmbClient%4Security.evtx") => parse_smb_client(file, SMBCLIENT_EVENT_IDS.to_vec()),
            Some("Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx") => parse_rdp_client(file, RDPCLIENT_EVENT_IDS.to_vec()),
            Some("Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx") => parse_rdp_connmanager(file, RDPCONNMANAGER_EVENT_IDS.to_vec()),
            Some("Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx") => parse_rdp_localsession(file, RDPLOCALSESSION_EVENT_IDS.to_vec()),
            Some("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx") => parse_rdpkore(file, RDPKORE_EVENT_IDS.to_vec()),
            Some("Microsoft-Windows-SmbClient%4Connectivity.evtx") => parse_smb_client_connectivity(file, SMBCLIENT_CONNECTIVITY_EVENT_IDS.to_vec()),
            _ => parse_unknown(file),
        }
    } else {
        // Si el archivo no existe o no es accesible, retorna un vector vacío
        Vec::new()
    }
}

pub fn parse_events(files : &Vec<String>, directories : &Vec<String>, output : Option<&String>){
    let mut log_data: Vec<LogData> = vec![];
    let mut vec_filenames: Vec<String> = vec![];
    vec_filenames.extend(files.iter().map(|s| s.to_string()));
    vec_filenames.extend(find_evtx_files(directories));
    for evtxfile in vec_filenames {
        log_data.extend(parselog(&evtxfile));
    }
    vector_to_polars(log_data,output);
}