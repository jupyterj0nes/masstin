use chrono::{DateTime, TimeZone, Utc};
use csv::WriterBuilder;
use flate2::read::GzDecoder;
use reqwest::{Client, header::HeaderMap};
use serde_json::{json, Value};
use std::cmp::Ordering;
use std::error::Error;
use std::io::{BufReader, Read, stdin, stdout, Write};
use std::time::Duration;
use tokio::time::sleep;

/// Final CSV columns
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

/// Main function to parse Cortex data.
/// - `base_url`: e.g., "https://api-pac.xdr.eu.paloaltonetworks.com"
/// - `output`: path to output CSV file
/// - `debug`: whether to print debug statements
/// - `start_time`: optional UTC datetime string "YYYY-MM-DD HH:MM:SS"
/// - `end_time`: optional UTC datetime string "YYYY-MM-DD HH:MM:SS"
pub async fn parse_cortex_data(
    base_url: &str,
    output: Option<&String>,
    debug: bool,
    start_time: Option<&String>,
    end_time: Option<&String>,
    filter_ip: Option<&String>
) -> Result<(), Box<dyn Error>> {
    let (token, x_xdr_auth_id) = prompt_for_api_key_and_id()?;

    let default_start = String::new();
    let cortex_start_str = start_time.unwrap_or(&default_start);

    let default_end = String::new();
    let cortex_end_str = end_time.unwrap_or(&default_end);

    

    if debug {
        eprintln!("[DEBUG] Start date: {}", cortex_start_str);
        eprintln!("[DEBUG] End date: {}", cortex_end_str);
    }

    let client = Client::new();

    // Build URL endpoints
    let start_query_url = format!(
        "{}/public_api/v1/xql/start_xql_query/",
        base_url.trim_end_matches('/')
    );
    let get_results_url = format!(
        "{}/public_api/v1/xql/get_query_results/",
        base_url.trim_end_matches('/')
    );
    let get_stream_url = format!(
        "{}/public_api/v1/xql/get_query_results_stream",
        base_url.trim_end_matches('/')
    );

    // Typically, XDR sets "x-xdr-auth-id" to a static integer, e.g., "5"
    let headers = build_headers(&token, &x_xdr_auth_id)?;


    let filter_ip_clause = match filter_ip {
        Some(ip) => format!(
            "filter ((`action_local_ip` in (\"{ip}\")) or (`action_remote_ip` in (\"{ip}\"))) |"
        ),
        None => "".to_string(),
    };

    let query_string = format!(
        r#"config case_sensitive = false timeframe between "{cortex_start_str}" and "{cortex_end_str}" | dataset = xdr_data |
        filter event_type = NETWORK and (action_local_port in (3389,445,22) or action_remote_port in (3389,445,22)) |
        filter ((`action_local_ip` not in ("""::""", null, """""")) and (`action_remote_ip` not in ("""::""", null, """"""))) |
        {filter_ip_clause}
        fields agent_hostname, action_local_ip, action_local_port, actor_primary_username, action_remote_ip, action_remote_port, actor_process_image_name, actor_process_command_line, action_download, action_upload, action_total_download, action_total_upload"#
    );

    let query_payload = json!({
        "request_data": {
            "query": query_string,
            "tenants": []
        }
    });


    // 2) Start the query
    if debug {
        eprintln!("[DEBUG] Starting query with payload: {}", query_payload);
        eprintln!("[DEBUG] POST to: {}", start_query_url);
    }

    let resp = client
        .post(&start_query_url)
        .headers(headers.clone())
        .json(&query_payload)
        .send()
        .await?;

    if debug {
        eprintln!("[DEBUG] Start query response status: {}", resp.status());
    }
    if resp.status() != 200 {
        return Err(format!(
            "Unexpected status from start_xql_query: {}",
            resp.status()
        )
        .into());
    }

    let resp_json: Value = resp.json().await?;
    if debug {
        eprintln!("[DEBUG] Start query response JSON: {}", resp_json);
    }

    // 3) Extract query_id from the response
    let query_id = match resp_json.get("reply") {
        Some(v) if !v.is_null() => v.as_str().unwrap_or("").to_string(),
        _ => {
            return Err("Could not retrieve 'query_id' from the start query response.".into());
        }
    };

    if debug {
        eprintln!("[DEBUG] Query ID: {}", query_id);
    }

    // 4) Poll for results (up to 10 times with 5s interval)
    let mut all_data: Vec<Value> = Vec::new();
    let mut attempt = 0;
    let max_retries = 10;
    let poll_payload = json!({
        "request_data": {
            "query_id": query_id,
            "offset": 0
        }
    });

    while attempt < max_retries {
        if debug {
            eprintln!("[DEBUG] Attempt {} to retrieve query results", attempt + 1);
        }

        let poll_resp = client
            .post(&get_results_url)
            .headers(headers.clone())
            .json(&poll_payload)
            .send()
            .await?;

        if poll_resp.status() != 200 {
            if debug {
                eprintln!(
                    "[DEBUG] Non-200 status from get_query_results: {}",
                    poll_resp.status()
                );
            }
            break;
        }

        let poll_json: Value = poll_resp.json().await?;
        if debug {
            eprintln!("[DEBUG] Poll response JSON: {}", poll_json);
        }

        // Check query status
        let status = poll_json
            .pointer("/reply/status")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");

        if status == "SUCCESS" {
            // We have results or possibly a stream
            let reply_obj = poll_json.get("reply").unwrap_or(&Value::Null);

            // If there's a "results" object with "data", append them
            if let Some(results_data) = reply_obj.pointer("/results/data") {
                if results_data.is_array() {
                    if let Some(arr) = results_data.as_array() {
                        all_data.extend_from_slice(arr);
                    }
                }
            }

            // Check for a "stream_id" if the dataset is large
            if let Some(stream_id_val) = reply_obj.pointer("/results/stream_id") {
                if let Some(s_id) = stream_id_val.as_str() {
                    if debug {
                        eprintln!("[DEBUG] Large dataset. Fetching stream results...");
                    }
                    let more_data = fetch_stream_data(&client, &get_stream_url, &headers, s_id, debug).await?;
                    all_data.extend(more_data);
                }
            }
            break;
        } else if status == "PENDING" || status == "RUNNING" {
            if debug {
                eprintln!("[DEBUG] Query still pending or running. Sleeping 5 seconds...");
            }
            attempt += 1;
            sleep(Duration::from_secs(5)).await;
        } else {
            if debug {
                eprintln!("[DEBUG] Unexpected status: {}", status);
            }
            break;
        }
    }

    // Sort all_data by _time (oldest to most recent)
    all_data.sort_by(|a, b| {
        let a_ts = get_timestamp(a).unwrap_or(0);
        let b_ts = get_timestamp(b).unwrap_or(0);
        a_ts.cmp(&b_ts)
    });

    // 5) Write processed data to CSV
    if debug {
        eprintln!("[DEBUG] Final total records: {}", all_data.len());
    }
    let out_path = match output {
        Some(path) => path.as_str(),
        None => "cortex_output.csv",
    };
    if debug {
        eprintln!("[DEBUG] Writing to CSV: {}", out_path);
    }

    write_processed_csv(&all_data, out_path, debug)?;

    Ok(())
}

/// Helper function to retrieve a timestamp (in milliseconds) from a record.
/// It tries to get the value as an integer; if not, it attempts to parse the string.
fn get_timestamp(record: &Value) -> Option<i64> {
    if let Some(ts) = record.get("_time").and_then(|v| v.as_i64()) {
        Some(ts)
    } else if let Some(time_str) = record.get("_time").and_then(|v| v.as_str()) {
        // Try to parse using the known format "YYYY-MM-DD HH:MM:SS.mmm UTC"
        if let Ok(dt) = Utc.datetime_from_str(time_str, "%Y-%m-%d %H:%M:%S%.f UTC") {
            Some(dt.timestamp_millis())
        } else if let Ok(dt) = DateTime::parse_from_rfc3339(time_str) {
            Some(dt.timestamp_millis())
        } else {
            None
        }
    } else {
        None
    }
}

/// Prompts the user for an API key and returns it as a `String`.
fn prompt_for_api_key_and_id() -> Result<(String, String), Box<dyn Error>> {
    // Prompt for API Key ID
    print!("Enter your Cortex/XDR API Key ID (numeric): ");
    stdout().flush()?;
    let mut api_key_id_input = String::new();
    stdin().read_line(&mut api_key_id_input)?;
    let api_key_id: u32 = api_key_id_input.trim().parse()?; // 👈 fuerza número

    // Prompt for API Key
    print!("Enter your Cortex/XDR API Key: ");
    stdout().flush()?;
    let mut api_key = String::new();
    stdin().read_line(&mut api_key)?;
    let api_key = api_key.trim().to_string();

    Ok((api_key, api_key_id.to_string())) // 👈 lo devuelves como string
}

/// Builds the necessary headers for the Cortex/XDR API requests.
fn build_headers(token: &str, x_xdr_auth_id: &str) -> Result<HeaderMap, Box<dyn Error>> {

    use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
    let mut headers = HeaderMap::new();

    // Example: "x-xdr-auth-id" is often a static integer, e.g., "5".
    //headers.insert("x-xdr-auth-id", HeaderValue::from_str("194").unwrap());
    headers.insert("x-xdr-auth-id", HeaderValue::from_str(x_xdr_auth_id.trim())?);
    headers.insert("Authorization", HeaderValue::from_str(token)?);

    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    // If the server supports gzip, add this header.
    headers.insert("Accept-Encoding", HeaderValue::from_static("gzip"));
    Ok(headers)
}

/// Helper function to retrieve a port value as i64 from a record.
/// It tries to extract the value as a number first, then as a string.
fn get_port(record: &Value, key: &str) -> Option<i64> {
    if let Some(n) = record.get(key).and_then(|v| v.as_i64()) {
        Some(n)
    } else if let Some(s) = record.get(key).and_then(|v| v.as_str()) {
        s.parse::<i64>().ok()
    } else {
        None
    }
}

/// Fetches large datasets from the "stream" endpoint and returns a `Vec<Value>`.
pub async fn fetch_stream_data(
    client: &Client,
    stream_url: &str,
    headers: &HeaderMap,
    stream_id: &str,
    debug: bool,
) -> Result<Vec<Value>, Box<dyn Error>> {
    // Build the JSON payload.
    let payload = json!({
        "request_data": {
            "stream_id": stream_id
        }
    });

    if debug {
        eprintln!("[DEBUG] Fetching stream from: {}", stream_url);
        eprintln!("[DEBUG] Stream payload: {}", payload);
    }

    // Send the request.
    let resp = client
        .post(stream_url)
        .headers(headers.clone())
        .json(&payload)
        .send()
        .await?;

    if debug {
        eprintln!("[DEBUG] Stream response status: {}", resp.status());
        eprintln!("[DEBUG] Stream response headers:");
        for (key, value) in resp.headers().iter() {
            eprintln!("    {}: {:?}", key, value);
        }
    }

    if resp.status() != 200 {
        return Err(format!(
            "Unexpected status from get_query_results_stream: {}",
            resp.status()
        )
        .into());
    }

    // Read the full body.
    let bytes = resp.bytes().await?;

    // Check for GZIP signature (first two bytes: 0x1F, 0x8B).
    let data_str = if bytes.len() >= 2 && bytes[0] == 0x1F && bytes[1] == 0x8B {
        if debug {
            eprintln!("[DEBUG] Detected GZIP signature in the first two bytes. Decompressing...");
        }
        let gz = GzDecoder::new(&bytes[..]);
        let mut decompressed = String::new();
        BufReader::new(gz).read_to_string(&mut decompressed)?;
        decompressed
    } else {
        if debug {
            eprintln!("[DEBUG] No GZIP signature found. Treating as plain text.");
        }
        // If not GZIP, convert bytes to string allowing invalid UTF-8.
        String::from_utf8_lossy(&bytes).to_string()
    };

    // Each line should be a separate JSON object.
    let mut records = Vec::new();
    for line in data_str.lines() {
        let line_trim = line.trim();
        if line_trim.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line_trim) {
            Ok(val) => records.push(val),
            Err(e) => {
                if debug {
                    eprintln!("[DEBUG] Failed to parse JSON line: {} => {:?}", e, line_trim);
                }
            }
        }
    }

    if debug {
        eprintln!("[DEBUG] Stream records count: {}", records.len());
    }

    Ok(records)
}

/// Processes a JSON record and returns a vector of strings representing the final CSV columns.
/// Final columns are:
/// 1) time_created: in RFC 3339 format with microsecond precision (e.g., "2014-12-12T01:56:56.251091Z").
/// 2) dst_computer: agent_hostname if action_local_port is 3389, 445, or 22; else action_remote_ip.
/// 3) event_id: fixed value "xdr_network".
/// 4) subject_user_name: empty string.
/// 5) subject_domain_name: empty string.
/// 6) target_user_name and target_domain_name: derived from actor_primary_username.
///    If actor_primary_username contains a "\", splits it into domain and user.
/// 7) logon_type: determined by action_local_port (or action_remote_port): 3389 -> "10", 445 -> "3", 22 -> "SSH".
/// 8) src_computer: agent_hostname if action_local_port is NOT one of the destination ports.
/// 9) src_ip: action_local_ip if action_local_port is NOT one of the destination ports; else action_remote_ip.
/// 10) process: actor_process_command_line (with commas replaced by semicolons).
/// 11) log_filename: fixed value "cortex_xdr_network".
fn process_record(record: &Value, debug: bool) -> Vec<String> {
    // time_created: try to format the time as "YYYY-MM-DDTHH:MM:SS.microsecondsZ"
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

    // Retrieve port values using the helper function.
    let local_port = get_port(record, "action_local_port");
    let remote_port = get_port(record, "action_remote_port");

    let agent_hostname = record
        .get("agent_hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let action_local_ip = record
        .get("action_local_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let action_remote_ip = record
        .get("action_remote_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let actor_primary_username = record
        .get("actor_primary_username")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let actor_process_command_line = record
        .get("actor_process_command_line")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Determine if the local port is one of the destination ports.
    let dst_ports = [3389, 445, 22];
    let is_dst_port = if let Some(port) = local_port {
        dst_ports.contains(&(port as i32))
    } else {
        false
    };

    // If local port is a destination port, use agent_hostname; otherwise, use action_remote_ip.
    let dst_computer = if is_dst_port {
        agent_hostname.clone()
    } else {
        action_remote_ip.clone()
    };

    // event_id fixed.
    let event_id = "xdr_network".to_string();

    // subject_user_name and subject_domain_name empty.
    let subject_user_name = "".to_string();
    let subject_domain_name = "".to_string();

    // target_user_name and target_domain_name derived from actor_primary_username.
    let (target_domain_name, target_user_name) = if actor_primary_username.contains("\\") {
        let parts: Vec<&str> = actor_primary_username.split('\\').collect();
        if parts.len() >= 2 {
            (parts[0].to_string(), parts[1].to_string())
        } else {
            ("".to_string(), actor_primary_username)
        }
    } else {
        ("".to_string(), actor_primary_username)
    };

    // Determine logon_type using local_port first, then remote_port.
    let logon_type = if let Some(port) = local_port {
        match port {
            3389 => "10".to_string(),
            445 => "3".to_string(),
            22 => "SSH".to_string(),
            _ => {
                if let Some(rport) = remote_port {
                    match rport {
                        3389 => "10".to_string(),
                        445 => "3".to_string(),
                        22 => "SSH".to_string(),
                        _ => "".to_string(),
                    }
                } else {
                    "".to_string()
                }
            }
        }
    } else if let Some(rport) = remote_port {
        match rport {
            3389 => "10".to_string(),
            445 => "3".to_string(),
            22 => "SSH".to_string(),
            _ => "".to_string(),
        }
    } else {
        "".to_string()
    };

    // If logon_type is empty and debug is enabled, print a verbose message.
    if debug && logon_type.is_empty() {
        eprintln!("[DEBUG] logon_type is empty for record: {:?}", record);
    }

    // For src_computer and src_ip: if the record is NOT a destination record, use action_local_ip; otherwise, use action_remote_ip.
    let (src_computer, src_ip) = if !is_dst_port {
        (agent_hostname.clone(), action_local_ip.clone())
    } else {
        ("".to_string(), action_remote_ip.clone())
    };

    // Process: use actor_process_command_line, replacing commas with semicolons.
    let process = actor_process_command_line.replace(",", ";");

    // log_filename fixed.
    let log_filename = "cortex_xdr_network".to_string();

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

/// Writes the processed records to a CSV file using the final structure.
/// The debug flag is passed to process_record to enable verbose logging.
fn write_processed_csv(records: &[Value], filename: &str, debug: bool) -> Result<(), Box<dyn Error>> {
    let mut wtr = WriterBuilder::new().from_path(filename)?;

    // Write header row
    wtr.write_record(FINAL_COLUMNS)?;

    // Process each record and write the resulting row.
    for record in records {
        let processed = process_record(record, debug);
        wtr.write_record(&processed)?;
    }

    wtr.flush()?;
    Ok(())
}
