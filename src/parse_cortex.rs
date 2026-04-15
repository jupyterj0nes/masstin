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
    "event_type",
    "event_id",
    "logon_type",
    "target_user_name",
    "target_domain_name",
    "src_computer",
    "src_ip",
    "subject_user_name",
    "subject_domain_name",
    "logon_id",
    "detail",
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
    filter_ip: Option<&String>,
    ignore_local: bool,
    admin_ports: bool,
    min_window_secs: i64,
    max_passes: usize,
) -> Result<(), Box<dyn Error>> {
    let start_clock = std::time::Instant::now();

    // Phase 1: API Authentication
    crate::banner::print_phase("1", "3", "Authenticating with Cortex XDR API...");
    let (token, x_xdr_auth_id) = prompt_for_api_key_and_id()?;

    let default_start = String::new();
    let cortex_start_str = start_time.unwrap_or(&default_start);

    let default_end: String = String::new();
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

    // Port list pushed into the XQL. Default covers the core lateral-movement
    // ports (SSH, SMB, RDP, WinRM) — WinRM 5985/5986 was added to the default
    // after live validation showed PSRemoting flows missed by the narrower set.
    // --admin-ports widens further to the full admin set (RPC 135, NetBIOS 139,
    // VNC 5900, SQL 1433/3306) for wider pivot visibility at the cost of volume.
    let port_list = if admin_ports {
        "22,135,139,445,1433,3306,3389,5900,5985,5986"
    } else {
        "22,445,3389,5985,5986"
    };

    // --ignore-local pushed server-side: exclude loopback, link-local and
    // self-connections (same src/dst IP) so we don't drag that noise across
    // the 1M API cap. Post-filter `filter::should_keep_record` still runs.
    let ignore_local_clause = if ignore_local {
        r#"filter ((`action_local_ip` not in ("127.0.0.1","::1","0.0.0.0","localhost")) and (`action_remote_ip` not in ("127.0.0.1","::1","0.0.0.0","localhost"))) |
        filter (action_local_ip != action_remote_ip) |"#.to_string()
    } else {
        String::new()
    };

    let build_query = |s: &str, e: &str| -> String {
        format!(
            r#"config case_sensitive = false timeframe between "{s}" and "{e}" | dataset = xdr_data |
        filter event_type = NETWORK and (action_local_port in ({port_list}) or action_remote_port in ({port_list})) |
        filter ((`action_local_ip` not in ("""::""", null, """""")) and (`action_remote_ip` not in ("""::""", null, """"""))) |
        {ignore_local_clause}
        {filter_ip_clause}
        fields agent_hostname, action_local_ip, action_local_port, actor_primary_username, action_remote_ip, action_remote_port, actor_process_image_name, actor_process_command_line, action_download, action_upload, action_total_download, action_total_upload"#
        )
    };


    // Phase 2: Query API
    crate::banner::print_phase("2", "3", "Querying Cortex XDR Network API...");
    crate::banner::print_phase_detail("Ports:", port_list);
    if ignore_local {
        crate::banner::print_phase_detail("Ignore local:", "loopback, link-local, self-connections filtered server-side");
    }
    if filter_ip.is_some() {
        crate::banner::print_phase_detail("Filter IP:", filter_ip.unwrap());
    }
    if !cortex_start_str.is_empty() {
        crate::banner::print_phase_detail("Time range:", &format!("{} to {}", cortex_start_str, cortex_end_str));
    }

    // Auto-pagination by time splitting. If the API returns at/near the 1M cap,
    // the window is bisected and each half re-queried. Only kicks in when both
    // time bounds are present; otherwise a single query runs as before.
    //
    // The two knobs exposed to the user:
    //   --cortex-min-window-secs : floor for bisection (don't split below this)
    //   --cortex-max-passes      : hard cap on queue iterations
    //
    // We never block on user input; every decision is printed verbosely so a
    // watching analyst can Ctrl-C at will if they see something they dislike.
    const API_CAP: usize = 1_000_000;
    const SATURATION_THRESHOLD: usize = 999_000;

    let mut all_data: Vec<Value> = Vec::new();
    let has_bounds = !cortex_start_str.is_empty() && !cortex_end_str.is_empty();
    let mut work: Vec<(String, String)> =
        vec![(cortex_start_str.to_string(), cortex_end_str.to_string())];
    let mut pass = 0usize;
    let mut truncated_passes = 0usize;
    let mut max_cap_hit = false;

    if has_bounds {
        crate::banner::print_phase_detail(
            "Auto-pagination:",
            &format!(
                "min window {}s, max {} passes, saturation threshold {}",
                min_window_secs, max_passes, SATURATION_THRESHOLD
            ),
        );
    }

    while let Some((w_start, w_end)) = work.pop() {
        pass += 1;

        // Pre-pass status line: which window, queue depth, running totals.
        if has_bounds {
            let span_secs = bisect_time_window(&w_start, &w_end, 0)
                .map(|(_, half)| half * 2)
                .unwrap_or(-1);
            let span_label = if span_secs < 0 {
                "?".to_string()
            } else if span_secs < 3600 {
                format!("{}m", span_secs / 60)
            } else if span_secs < 86400 {
                format!("{}h {}m", span_secs / 3600, (span_secs % 3600) / 60)
            } else {
                format!("{}d {}h", span_secs / 86400, (span_secs % 86400) / 3600)
            };
            crate::banner::print_phase_detail(
                &format!("Pass {}/{}", pass, max_passes),
                &format!(
                    "window {} → {}  (span {})  queue={}  collected={}",
                    w_start,
                    w_end,
                    span_label,
                    work.len(),
                    all_data.len()
                ),
            );
        }

        let pass_start = std::time::Instant::now();
        let batch = run_network_query(
            &client,
            &start_query_url,
            &get_results_url,
            &get_stream_url,
            &headers,
            &build_query(&w_start, &w_end),
            debug,
        )
        .await?;
        let batch_len = batch.len();
        let elapsed = pass_start.elapsed().as_secs();

        // Post-pass status: how many records, saturation, decision.
        if has_bounds {
            crate::banner::print_phase_detail(
                "  ↳",
                &format!("retrieved {} events in {}s", batch_len, elapsed),
            );
        }

        if has_bounds && batch_len >= SATURATION_THRESHOLD {
            // Saturated. Decide: hit the pass cap? hit the window floor? or split?
            if pass >= max_passes {
                max_cap_hit = true;
                crate::banner::print_warning(&format!(
                    "Pass cap {} reached — accepting saturated window as-is. Raise --cortex-max-passes if you need deeper recovery.",
                    max_passes
                ));
                all_data.extend(batch);
                truncated_passes += 1;
                continue;
            }
            match bisect_time_window(&w_start, &w_end, min_window_secs) {
                Some((mid_str, half)) => {
                    crate::banner::print_warning(&format!(
                        "Saturated at {}/{} — bisecting at {} (half-span {}s). Queue will grow by 1.",
                        batch_len, API_CAP, mid_str, half
                    ));
                    // Push later half first so we pop the earlier half next
                    // (gives a chronologically coherent running total in logs).
                    work.push((mid_str.clone(), w_end));
                    work.push((w_start, mid_str));
                    continue;
                }
                None => {
                    truncated_passes += 1;
                    crate::banner::print_warning(&format!(
                        "Saturated at {} but window is already at the {}s floor — accepting truncation. Lower --cortex-min-window-secs to go finer (CAUTION: may explode pass count).",
                        batch_len, min_window_secs
                    ));
                    all_data.extend(batch);
                }
            }
        } else {
            all_data.extend(batch);
        }
    }

    if has_bounds {
        crate::banner::print_phase_detail(
            "Auto-pagination complete:",
            &format!(
                "{} passes, {} events collected, {} windows truncated",
                pass, all_data.len(), truncated_passes
            ),
        );
        if max_cap_hit {
            crate::banner::print_warning(
                "One or more windows hit --cortex-max-passes. Consider raising it or narrowing --start-time/--end-time."
            );
        }
    }

    // Count by port type for summary. SMB bucket aggregates SMB+RPC+NetBIOS+WinRM+SQL
    // so the existing 3-bucket banner stays meaningful when --admin-ports is set.
    let mut rdp_count = 0usize;
    let mut smb_count = 0usize;
    let mut ssh_count = 0usize;
    for record in &all_data {
        let lp = get_port(record, "action_local_port").unwrap_or(0);
        let rp = get_port(record, "action_remote_port").unwrap_or(0);
        let is = |p: i64| lp == p || rp == p;
        if is(3389) || is(5900) { rdp_count += 1; }
        else if is(445) || is(135) || is(139) || is(5985) || is(5986) || is(1433) || is(3306) { smb_count += 1; }
        else if is(22) { ssh_count += 1; }
    }
    crate::banner::print_cortex_network_summary(all_data.len(), rdp_count, smb_count, ssh_count);

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

    // Phase 3: Generate output
    crate::banner::print_phase("3", "3", "Generating output...");
    write_processed_csv(&all_data, out_path, debug)?;

    crate::banner::print_summary(all_data.len(), all_data.len(), 0, Some(out_path), start_clock);
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

/// Runs a single XQL query against the Cortex network endpoint and returns
/// all records (inline + streamed). Extracted from `parse_cortex_data` so
/// the outer function can auto-paginate by time splitting when the API 1M
/// cap is hit.
async fn run_network_query(
    client: &Client,
    start_query_url: &str,
    get_results_url: &str,
    get_stream_url: &str,
    headers: &HeaderMap,
    query_string: &str,
    debug: bool,
) -> Result<Vec<Value>, Box<dyn Error>> {
    let query_payload = json!({
        "request_data": { "query": query_string, "tenants": [] }
    });

    if debug {
        eprintln!("[DEBUG] POST to: {}", start_query_url);
        eprintln!("[DEBUG] Query: {}", query_string);
    }

    let resp = client
        .post(start_query_url)
        .headers(headers.clone())
        .json(&query_payload)
        .send()
        .await?;
    if resp.status() != 200 {
        return Err(format!("Unexpected status from start_xql_query: {}", resp.status()).into());
    }
    let resp_json: Value = resp.json().await?;
    let query_id = match resp_json.get("reply") {
        Some(v) if !v.is_null() => v.as_str().unwrap_or("").to_string(),
        _ => return Err("Could not retrieve 'query_id' from the start query response.".into()),
    };

    let spinner = crate::banner::create_spinner("Waiting for query results...");
    let mut out: Vec<Value> = Vec::new();
    let poll_payload = json!({
        "request_data": { "query_id": query_id, "offset": 0 }
    });

    // Poll up to 10 minutes (120 * 5s) — large saturated windows can take a while.
    let max_retries = 120;
    for attempt in 0..max_retries {
        if debug {
            eprintln!("[DEBUG] Poll attempt {}", attempt + 1);
        }
        let poll_resp = client
            .post(get_results_url)
            .headers(headers.clone())
            .json(&poll_payload)
            .send()
            .await?;
        if poll_resp.status() != 200 {
            break;
        }
        let poll_json: Value = poll_resp.json().await?;
        let status = poll_json
            .pointer("/reply/status")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");

        if status == "SUCCESS" {
            let reply_obj = poll_json.get("reply").unwrap_or(&Value::Null);
            if let Some(results_data) = reply_obj.pointer("/results/data") {
                if let Some(arr) = results_data.as_array() {
                    out.extend_from_slice(arr);
                }
            }
            if let Some(stream_id_val) = reply_obj.pointer("/results/stream_id") {
                if let Some(s_id) = stream_id_val.as_str() {
                    let more = fetch_stream_data(client, get_stream_url, headers, s_id, debug).await?;
                    out.extend(more);
                }
            }
            break;
        } else if status == "PENDING" || status == "RUNNING" {
            sleep(Duration::from_secs(5)).await;
        } else {
            break;
        }
    }
    spinner.finish_and_clear();
    Ok(out)
}

/// Bisects a time window expressed as "YYYY-MM-DD HH:MM:SS[ TZ]" strings.
/// Returns the midpoint formatted identically plus the half-duration in seconds.
/// Returns `None` if parsing fails or the window is smaller than `min_window_secs`.
fn bisect_time_window(
    start: &str,
    end: &str,
    min_window_secs: i64,
) -> Option<(String, i64)> {
    let parse = |s: &str| -> Option<DateTime<Utc>> {
        let t = s.trim();
        if let Ok(dt) = DateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S %z") {
            return Some(dt.with_timezone(&Utc));
        }
        if let Ok(nd) = chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S") {
            return Some(DateTime::<Utc>::from_utc(nd, Utc));
        }
        None
    };
    let s_dt = parse(start)?;
    let e_dt = parse(end)?;
    let span = (e_dt - s_dt).num_seconds();
    if span < min_window_secs * 2 {
        return None;
    }
    let half = span / 2;
    let mid = s_dt + chrono::Duration::seconds(half);
    // Keep the same format the CLI accepts so it round-trips.
    let mid_str = mid.format("%Y-%m-%d %H:%M:%S -0000").to_string();
    Some((mid_str, half))
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
    let dst_ports = [22, 135, 139, 445, 1433, 3306, 3389, 5900, 5985, 5986];
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
    fn lt_for(p: i64) -> Option<&'static str> {
        match p {
            3389 | 5900 => Some("10"),
            445 | 135 | 139 | 5985 | 5986 | 1433 | 3306 => Some("3"),
            22 => Some("SSH"),
            _ => None,
        }
    }
    let logon_type = local_port
        .and_then(lt_for)
        .or_else(|| remote_port.and_then(lt_for))
        .unwrap_or("")
        .to_string();

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

    // detail: use actor_process_command_line, replacing commas with semicolons.
    let detail = actor_process_command_line.replace(",", ";");

    // event_type fixed for Cortex network.
    let event_type = "CONNECT".to_string();

    // logon_id empty for Cortex.
    let logon_id = "".to_string();

    // log_filename fixed.
    let log_filename = "cortex_xdr_network".to_string();

    vec![
        time_created,
        dst_computer,
        event_type,
        event_id,
        logon_type,
        target_user_name,
        target_domain_name,
        src_computer,
        src_ip,
        subject_user_name,
        subject_domain_name,
        logon_id,
        detail,
        log_filename,
    ]
}

/// Writes the processed records to a CSV file using the final structure.
/// The debug flag is passed to process_record to enable verbose logging.
fn write_processed_csv(records: &[Value], filename: &str, debug: bool) -> Result<(), Box<dyn Error>> {
    let mut wtr = WriterBuilder::new().from_path(filename)?;

    // Write header row
    wtr.write_record(FINAL_COLUMNS)?;

    // Process each record and write the resulting row. Applies the global
    // noise filter (--ignore-local / --exclude-*) by reconstructing a
    // minimal LogData view of the processed row — FINAL_COLUMNS order
    // matches the canonical masstin CSV header, so indices are fixed.
    for record in records {
        let processed = process_record(record, debug);
        if processed.len() >= 14 {
            let ld = crate::parse::LogData {
                time_created: processed[0].clone(),
                computer: processed[1].clone(),
                event_type: processed[2].clone(),
                event_id: processed[3].clone(),
                logon_type: processed[4].clone(),
                target_user_name: processed[5].clone(),
                target_domain_name: processed[6].clone(),
                workstation_name: processed[7].clone(),
                ip_address: processed[8].clone(),
                subject_user_name: processed[9].clone(),
                subject_domain_name: processed[10].clone(),
                logon_id: processed[11].clone(),
                detail: processed[12].clone(),
                filename: processed[13].clone(),
            };
            if !crate::filter::should_keep_record(&ld) {
                continue;
            }
        }
        wtr.write_record(&processed)?;
    }

    wtr.flush()?;
    Ok(())
}
