use chrono::{DateTime, TimeZone, Utc};
use csv::WriterBuilder;
use flate2::read::GzDecoder;
use reqwest::{Client, header::HeaderMap};
use serde_json::{json, Value};
use std::error::Error;
use std::io::{BufReader, Read, stdin, stdout, Write};
use std::time::Duration;
use tokio::time::sleep;
use std::sync::atomic::{AtomicBool, Ordering};

// ----------------------------------------------
// Debug mode global
// ----------------------------------------------
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_debug_mode(val: bool) {
    DEBUG_MODE.store(val, Ordering::SeqCst);
}

pub fn is_debug_mode() -> bool {
    DEBUG_MODE.load(Ordering::SeqCst)
}

// ----------------------------------------------
// Columns for final CSV
// Adaptar según tu formato deseado
// ----------------------------------------------
static FINAL_COLUMNS: &[&str] = &[
    "time_created",
    "dst_computer",
    "event_id",
    "subject_user_name",
    "subject_domain_name",
    "target_user_name",
    "target_domain_name",
    "logon_type",
    "src_computer",
    "src_ip",
    "process",
    "log_filename",
];

// ----------------------------------------------
// Main function to parse the new Cortex data
// using the custom XQL query for EVTX forensics
// ----------------------------------------------
pub async fn parse_cortex_evtx_forensics_data(
    base_url: &str,
    output: Option<&String>,
    debug: bool,
    start_time: Option<&String>,
    end_time: Option<&String>,
) -> Result<(), Box<dyn Error>> {
    let token = prompt_for_api_key()?;

    // Convert user-supplied date/time (UTC) to epoch ms
    let from_time_epoch = if let Some(s) = start_time {
        datetime_to_epoch_millis(s)?
    } else {
        (Utc::now() - chrono::Duration::days(30)).timestamp_millis()
    };
    let to_time_epoch = if let Some(s) = end_time {
        datetime_to_epoch_millis(s)?
    } else {
        Utc::now().timestamp_millis()
    };

    if debug {
        eprintln!("[DEBUG] from_time_epoch: {}", from_time_epoch);
        eprintln!("[DEBUG] to_time_epoch: {}", to_time_epoch);
    }

    let client = Client::new();

    // Endpoints
    let start_query_url = format!("{}/public_api/v1/xql/start_xql_query/", base_url.trim_end_matches('/'));
    let get_results_url = format!("{}/public_api/v1/xql/get_query_results/", base_url.trim_end_matches('/'));
    let get_stream_url = format!("{}/public_api/v1/xql/get_query_results_stream", base_url.trim_end_matches('/'));

    // Headers
    let headers = build_headers(&token);

    // NUEVA QUERY basada en tu especificación
    let query_payload = json!({
        "request_data": {
            "query": r#"dataset = forensics_event_log 
                    | filter event_id in (4624,4625,4648,21,22,24,25,1009,551,31001,30803,30804,30805,30806,30807,30808,1024,1102,1149) and source in ("Security","Microsoft-Windows-TerminalServices-LocalSessionManager/Operational","Microsoft-Windows-SMBServer/Security","Microsoft-Windows-SmbClient/Security","Microsoft-Windows-TerminalServices-RDPClient/Operational","Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational") 
                    | filter message not in ("""::""", null, """""","-")
                    | alter lt = if(event_id in (4624,4625), arrayindex(regextract(message, "(?i)(?:Logon Type|Tipo de inicio de sesión):\s*(\d+)"), 0),event_id=4648,"runas",event_id in (21,22,24,25,1024,1102,1149),"10","3")
                    | alter srcip = if(event_id in (4624,4625,21,22,24,25,1149,1009,551),arrayindex(regextract(message, "(?i)(?:Source Network Address|Dirección de red de origen|Client Name|Nombre de.? cliente):\s*([\w.-]+)"), 0))
                    | alter process = if(event_id in (4624,4625,4648),arrayindex(regextract(message, "(?i)(?:Process Name|Nombre de proceso):\s*([^\r\n]+)"), 0))
                    | alter source_host = if(event_id in (4624,4625),arrayindex(regextract(message, "(?i)(?:Workstation Name|Nombre de estación de trabajo):\s*([\w.-]+)"), 0),event_id in (4648,31001,30803,30804,30805,30806,30807,30808,1024,1102),host_name)
                    | alter subject_name = if(event_id in (4624,4625,4648),arrayindex(regextract(message, "(?si)(?:Subject:.*?Account Name|Firmante:.*?Nombre de cuenta):\s*([\w.\-$]+)"), 0))
                    | alter subject_domain = if(event_id in (4624,4625,4648),arrayindex(regextract(message , "(?si)(?:Subject:.*?Account Domain|Firmante:.*?Dominio de cuenta):\s*([\w.\-$ ]+)"), 0))
                    | alter target_user = if(event_id in (4624,4625,4648),arrayindex(regextract(message, "(?si)(?:New Logon:.*?Account Name|Nuevo inicio de sesión:.*?Nombre de cuenta|Account For Which Logon Failed:.*?Account Name|Cuenta con error de inicio de sesión:.*?Nombre de cuenta|Account Whose Credentials Were Used:.*?Account Name|Cuenta cuyas credenciales se usaron:.*?Nombre de cuenta):\s*([\w.\-$]+)"), 0),event_id in (1009,551,31001,21,22,24,25,1149), arrayindex(regextract(message, "(?:User Name|Nombre de.? usuario|User|Usuario):\s(?:[^\s\\]+)\\([^\s]+)"), 0))
                    | alter target_domain = if(event_id in (4624,4625,4648),arrayindex(regextract(message , "(?si)(?:New Logon:.*?Account Domain|Nuevo inicio de sesión:.*?Dominio de cuenta|Account For Which Logon Failed:.*?Account Domain|Cuenta con error de inicio de sesión:.*?Dominio de cuenta|Account Whose Credentials Were Used:.*?Account Domain|Cuenta cuyas credenciales se usaron:.*?Dominio de cuenta):\s*([\w.\-$]+)"), 0),event_id in (1009,551,31001,21,22,24,25,1149), arrayindex(regextract(message, "(?:User Name|Nombre de.? usuario|User|Usuario):\s([^\s\\]+)\\(?:[^\s]+)"), 0))
                    | alter dst_host = if(event_id in (4624,4625,21,22,24,25,1149),host_name,event_id=4648,arrayindex(regextract(message, "(?i)(?:Target Server Name|Nombre de servidor de destino):\s*([\w.-]+)"), 0),event_id in (31001,30803,30804,30805,30806,30807),arrayindex(regextract(message, "(?i)(?:Server Name|Nombre de servidor):\s\\(.+)"), 0),event_id=30808,arrayindex(regextract(message, "(?i)(?:Share Name|Nombre del recurso compartido):\s\\(.+)"), 0),event_id in (1102),arrayindex(regextract(message, "(?i)(?:server|servidor)\s+([\w.-]+)\b"), 0))
                    | fields _time, dst_host, event_id, subject_name, subject_domain, target_user, target_domain,lt, source_host, srcip, process"#,
            "tenants": [],
            "timeframe": {
                "from": from_time_epoch,
                "to": to_time_epoch
            }
        }
    });

    if debug {
        eprintln!("[DEBUG] POSTing query to: {}", start_query_url);
        eprintln!("[DEBUG] Payload: {}", query_payload);
    }

    // 1) Start the query
    let resp = client.post(&start_query_url)
        .headers(headers.clone())
        .json(&query_payload)
        .send().await?;

    if resp.status() != 200 {
        return Err(format!("start_xql_query failed with status: {}", resp.status()).into());
    }

    let resp_json: Value = resp.json().await?;
    if debug {
        eprintln!("[DEBUG] start_xql_query response: {}", resp_json);
    }

    let query_id = resp_json
        .get("reply")
        .and_then(|r| r.as_str())
        .ok_or("Could not retrieve 'query_id' from start query response")?
        .to_string();

    if debug {
        eprintln!("[DEBUG] Query ID: {}", query_id);
    }

    // 2) Poll for results
    let poll_payload = json!({
        "request_data": {
            "query_id": query_id,
            "offset": 0
        }
    });

    let mut all_data: Vec<Value> = Vec::new();
    let max_retries = 10;
    for attempt in 0..max_retries {
        if debug {
            eprintln!("[DEBUG] Attempt {} to get results", attempt + 1);
        }
        let poll_resp = client.post(&get_results_url)
            .headers(headers.clone())
            .json(&poll_payload)
            .send().await?;

        if poll_resp.status() != 200 {
            eprintln!("[DEBUG] get_query_results status: {}", poll_resp.status());
            break;
        }
        let poll_json: Value = poll_resp.json().await?;
        if debug {
            eprintln!("[DEBUG] poll_json: {}", poll_json);
        }

        let status = poll_json.pointer("/reply/status").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
        if status == "SUCCESS" {
            // Check results in poll_json["reply"]["results"]["data"] (optional)
            if let Some(results_data) = poll_json.pointer("/reply/results/data") {
                if results_data.is_array() {
                    if let Some(arr) = results_data.as_array() {
                        all_data.extend_from_slice(arr);
                    }
                }
            }
            // If there's a "stream_id"
            if let Some(stream_id) = poll_json.pointer("/reply/results/stream_id").and_then(|v| v.as_str()) {
                if debug {
                    eprintln!("[DEBUG] Large dataset. Using stream_id: {}", stream_id);
                }
                let more_data = fetch_stream_data(&client, &get_stream_url, &headers, stream_id, debug).await?;
                all_data.extend(more_data);
            }
            break;
        } else if status == "PENDING" || status == "RUNNING" {
            if debug { eprintln!("[DEBUG] Query still {}, sleeping 5s...", status); }
            sleep(Duration::from_secs(5)).await;
        } else {
            if debug { eprintln!("[DEBUG] Unexpected status: {}", status); }
            break;
        }
    }

    // Sort by _time
    all_data.sort_by(|a, b| {
        let a_ts = get_timestamp(a).unwrap_or(0);
        let b_ts = get_timestamp(b).unwrap_or(0);
        a_ts.cmp(&b_ts)
    });

    // Write CSV
    if debug {
        eprintln!("[DEBUG] Total final records: {}", all_data.len());
    }
    let out_path = match output {
        Some(path) => path,
        None => "cortex_evtx_forensics_output.csv",
    };
    if debug {
        eprintln!("[DEBUG] Writing results to: {}", out_path);
    }

    write_processed_csv(&all_data, out_path, debug)?;

    Ok(())
}

// ----------------------------------------------
// Stream fetch if large dataset
// (Misma lógica que parse_cortex, se conserva)
// ----------------------------------------------
async fn fetch_stream_data(
    client: &Client,
    url: &str,
    headers: &HeaderMap,
    stream_id: &str,
    debug: bool
) -> Result<Vec<Value>, Box<dyn Error>> {
    let payload = json!({
        "request_data": {
            "stream_id": stream_id
        }
    });

    if debug {
        eprintln!("[DEBUG] GET stream data from: {}", url);
    }

    let resp = client.post(url)
        .headers(headers.clone())
        .json(&payload)
        .send()
        .await?;

    if resp.status() != 200 {
        return Err(format!("get_query_results_stream failed: {}", resp.status()).into());
    }

    let bytes = resp.bytes().await?;
    // Check if it's gzip
    if bytes.len() > 2 && bytes[0] == 0x1F && bytes[1] == 0x8B {
        if debug { eprintln!("[DEBUG] GZIP detected"); }
        let gz = GzDecoder::new(&bytes[..]);
        let mut decompressed = String::new();
        BufReader::new(gz).read_to_string(&mut decompressed)?;
        parse_ndjson(&decompressed, debug)
    } else {
        let data_str = String::from_utf8_lossy(&bytes).to_string();
        parse_ndjson(&data_str, debug)
    }
}

fn parse_ndjson(data: &str, debug: bool) -> Result<Vec<Value>, Box<dyn Error>> {
    let mut out = Vec::new();
    for line in data.lines() {
        let trim = line.trim();
        if trim.is_empty() { continue; }
        match serde_json::from_str::<Value>(trim) {
            Ok(json_val) => out.push(json_val),
            Err(e) => {
                if debug {
                    eprintln!("[DEBUG] Could not parse JSON line: {} => {}", e, trim);
                }
            }
        }
    }
    Ok(out)
}

// ----------------------------------------------
// Time extraction
// ----------------------------------------------
fn get_timestamp(record: &Value) -> Option<i64> {
    if let Some(ts) = record.get("_time").and_then(|v| v.as_i64()) {
        Some(ts)
    } else if let Some(ts_str) = record.get("_time").and_then(|v| v.as_str()) {
        if let Ok(dt) = Utc.datetime_from_str(ts_str, "%Y-%m-%d %H:%M:%S%.f UTC") {
            Some(dt.timestamp_millis())
        } else if let Ok(dt) = DateTime::parse_from_rfc3339(ts_str) {
            Some(dt.timestamp_millis())
        } else {
            None
        }
    } else {
        None
    }
}

// ----------------------------------------------
// CSV writing
// ----------------------------------------------
fn write_processed_csv(records: &[Value], filename: &str, debug: bool) -> Result<(), Box<dyn Error>> {
    let mut wtr = WriterBuilder::new().from_path(filename)?;
    // Write header
    wtr.write_record(FINAL_COLUMNS)?;

    // Process each record
    for record in records {
        let row = process_record(record, debug);
        wtr.write_record(&row)?;
    }
    wtr.flush()?;
    Ok(())
}

// ----------------------------------------------
// Example of a simpler "process_record"
// Tomado de tu query, ajusta la lógica real
// ----------------------------------------------
fn process_record(record: &Value, debug: bool) -> Vec<String> {
    // Extraer `_time` como timestamp formateado en RFC 3339 (UTC)
    let time_created = if let Some(ts) = record.get("_time").and_then(|v| v.as_i64()) {
        let dt = Utc.timestamp_millis(ts);
        dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
    } else if let Some(time_str) = record.get("_time").and_then(|v| v.as_str()) {
        // Try to parse a string in the format "YYYY-MM-DD HH:MM:SS.mmm UTC"
        if let Ok(dt) = Utc.datetime_from_str(time_str, "%Y-%m-%d %H:%M:%S%.f UTC") {
            dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
        } else {
            // Fallback: return the original string if parsing fails.
            time_str.to_string()
        }
    } else {
        "".to_string()
    };

    // Extraer los valores esperados de la query
    let dst_computer = record.get("dst_host").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let event_id = record.get("event_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    
    let subject_user_name = record.get("subject_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let subject_domain_name = record.get("subject_domain").and_then(|v| v.as_str()).unwrap_or("").to_string();
    
    let target_user_name = record.get("target_user").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let target_domain_name = record.get("target_domain").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let logon_type = record.get("lt").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let src_computer = record.get("source_host").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let src_ip = record.get("srcip").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let process = record.get("process").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Nombre del log fijo
    let log_filename = "cortex_evtx_forensics".to_string();

    // Devolver la fila en el orden esperado por `FINAL_COLUMNS`
    vec![
        time_created,
        dst_computer,
        event_id,
        subject_user_name,
        subject_domain_name,
        target_user_name,
        target_domain_name,
        logon_type,
        src_computer,
        src_ip,
        process,
        log_filename,
    ]
}


// ----------------------------------------------
// Pide la API key al usuario
// ----------------------------------------------
fn prompt_for_api_key() -> Result<String, Box<dyn Error>> {
    print!("Enter your Cortex/XDR API Key: ");
    stdout().flush()?;
    let mut token = String::new();
    stdin().read_line(&mut token)?;
    Ok(token.trim().to_string())
}

// ----------------------------------------------
// Construye los headers
// ----------------------------------------------
fn build_headers(token: &str) -> HeaderMap {
    use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
    let mut headers = HeaderMap::new();
    headers.insert("x-xdr-auth-id", HeaderValue::from_str("5").unwrap());
    headers.insert("Authorization", HeaderValue::from_str(token).unwrap());
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert("Accept-Encoding", HeaderValue::from_static("gzip"));
    headers
}

// ----------------------------------------------
// Convierte "YYYY-MM-DD HH:MM:SS" a epoch ms
// ----------------------------------------------
fn datetime_to_epoch_millis(dt_str: &str) -> Result<i64, Box<dyn Error>> {
    let naive = chrono::NaiveDateTime::parse_from_str(dt_str, "%Y-%m-%d %H:%M:%S")?;
    Ok(DateTime::<Utc>::from_utc(naive, Utc).timestamp_millis())
}
