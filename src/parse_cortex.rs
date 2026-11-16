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

    // a time written without a zone is UTC, here as in the forensics sources
    let cortex_start_str = utc_bound(start_time.map(|s| s.as_str()).unwrap_or(""));
    let cortex_end_str = utc_bound(end_time.map(|s| s.as_str()).unwrap_or(""));

    

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
    let headers = crate::cortex_auth::Auth::connect(&client, base_url, &token, &x_xdr_auth_id).await?;


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
    // A connection of a machine to itself (loopback, or its own address on
    // both ends) is never lateral movement: left out in the query, so it
    // does not count against the API's cap either, whatever --ignore-local.
    let _ = ignore_local;
    let ignore_local_clause = r#"filter ((`action_local_ip` not in ("127.0.0.1","::1","0.0.0.0","localhost")) and (`action_remote_ip` not in ("127.0.0.1","::1","0.0.0.0","localhost"))) |
        filter (action_local_ip != action_remote_ip) |"#.to_string();

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
    crate::banner::print_phase_detail("Left out:", "loopback and a machine's connections to itself (never lateral movement)");
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
        let batch = run_xql(
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
    api_key_and_id()
}

/// The API key and its id: from `$CORTEX_API_KEY_ID` and `$CORTEX_API_KEY`
/// when both are set (how masstin's window passes them, never on the
/// command line), else asked on the console.
pub(crate) fn api_key_and_id() -> Result<(String, String), Box<dyn Error>> {
    static ASKED: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
    if let Some(pair) = ASKED.get() {
        return Ok(pair.clone());
    }
    let pair = ask_key_and_id()?;
    Ok(ASKED.get_or_init(|| pair).clone())
}

fn ask_key_and_id() -> Result<(String, String), Box<dyn Error>> {
    if let Some(pair) = key_from_env(std::env::var("CORTEX_API_KEY_ID").ok(), std::env::var("CORTEX_API_KEY").ok())? {
        crate::banner::print_phase_detail("Auth:", "API key from $CORTEX_API_KEY (id from $CORTEX_API_KEY_ID)");
        return Ok(pair);
    }
    // Prompt for API Key ID
    print!("Enter your Cortex/XDR API Key ID (numeric): ");
    stdout().flush()?;
    let mut api_key_id_input = String::new();
    stdin().read_line(&mut api_key_id_input)?;
    let api_key_id: u32 = api_key_id_input.trim().parse()?;

    // Prompt for API Key
    print!("Enter your Cortex/XDR API Key: ");
    stdout().flush()?;
    let mut api_key = String::new();
    stdin().read_line(&mut api_key)?;
    let api_key = api_key.trim().to_string();

    Ok((api_key, api_key_id.to_string()))
}

/// (key, id) from the two variables, both set and not blank; the id is a
/// number, as the console prompt demands.
fn key_from_env(id: Option<String>, key: Option<String>) -> Result<Option<(String, String)>, Box<dyn Error>> {
    match (id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()), key.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())) {
        (Some(id), Some(key)) => {
            let id: u32 = id.parse().map_err(|_| "$CORTEX_API_KEY_ID is not a number")?;
            Ok(Some((key, id.to_string())))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod key_tests {
    use super::key_from_env;

    #[test]
    fn the_key_comes_from_the_environment_when_both_are_set() {
        assert_eq!(key_from_env(Some(" 12 ".into()), Some(" abc ".into())).unwrap(), Some(("abc".to_string(), "12".to_string())));
        assert_eq!(key_from_env(Some("12".into()), None).unwrap(), None);
        assert_eq!(key_from_env(Some("12".into()), Some("  ".into())).unwrap(), None);
        assert!(key_from_env(Some("twelve".into()), Some("abc".into())).is_err());
    }
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
pub(crate) async fn run_xql(
    client: &Client,
    start_query_url: &str,
    get_results_url: &str,
    get_stream_url: &str,
    headers: &crate::cortex_auth::Auth,
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
        .headers(headers.fresh())
        .json(&query_payload)
        .send()
        .await?;
    if resp.status() != 200 {
        return Err(crate::cortex_auth::refusal(resp, "the query (start_xql_query)").await.into());
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
    let mut finished = false;
    for attempt in 0..max_retries {
        if debug {
            eprintln!("[DEBUG] Poll attempt {}", attempt + 1);
        }
        let poll_resp = client
            .post(get_results_url)
            .headers(headers.fresh())
            .json(&poll_payload)
            .send()
            .await?;
        if poll_resp.status() != 200 {
            spinner.finish_and_clear();
            return Err(crate::cortex_auth::refusal(poll_resp, "the results (get_query_results)").await.into());
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
            finished = true;
            break;
        } else if status == "PENDING" || status == "RUNNING" {
            sleep(Duration::from_secs(5)).await;
        } else {
            spinner.finish_and_clear();
            return Err(crate::cortex_auth::query_failure(status, &poll_json).into());
        }
    }
    spinner.finish_and_clear();
    if !finished {
        // not "no events": the answer never came
        return Err(format!("Cortex was still running the query after {} minutes and masstin stopped waiting: no result was received (this is not an empty result). Narrow the time range (--start-time / --end-time) and run it again.", max_retries * 5 / 60).into());
    }
    Ok(out)
}

/// Bisects a time window expressed as "YYYY-MM-DD HH:MM:SS[ TZ]" strings.
/// Returns the midpoint formatted identically plus the half-duration in seconds.
/// Returns `None` if parsing fails or the window is smaller than `min_window_secs`.
pub(crate) fn bisect_time_window(
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
    headers: &crate::cortex_auth::Auth,
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
        .headers(headers.fresh())
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
            3389 => Some("10"),
            445 | 135 | 139 => Some("3"),
            5985 | 5986 => Some("WinRM"),
            1433 | 3306 => Some("SQL"),
            5900 => Some("VNC"),
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

    // detail: the service port, then the process's command line (commas as
    // semicolons).
    let service_port = if is_dst_port { local_port } else { remote_port };
    let cmd = actor_process_command_line.replace(",", ";");
    let detail = match service_port {
        Some(p) if cmd.trim().is_empty() => format!("port {}", p),
        Some(p) => format!("port {} | {}", p, cmd),
        None => cmd,
    };

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
    wtr.write_record(FINAL_COLUMNS.iter().copied().chain(crate::csv_out::TAIL_COLUMNS.iter().copied()))?;

    // Process each record and write the resulting row. Applies the global
    // noise filter (--ignore-local / --exclude-*) by reconstructing a
    // minimal LogData view of the processed row — FINAL_COLUMNS order
    // matches the canonical masstin CSV header, so indices are fixed.
    let names = agent_names(records);
    let mut named = 0usize;
    let mut selfs = 0usize;
    let mut dups = 0usize;
    let mut seen: std::collections::HashSet<Vec<String>> = std::collections::HashSet::new();
    for record in records {
        let mut processed = process_record(record, debug);
        if processed.len() >= 14 {
            // an address Cortex has an agent on is named: the same connection
            // seen by the client's agent and by the server's is then one edge
            if let Some(n) = names.get(processed[1].as_str()) {
                processed[1] = n.clone();
                named += 1;
            }
            if processed[7].is_empty() {
                if let Some(n) = names.get(processed[8].as_str()) {
                    processed[7] = n.clone();
                    named += 1;
                }
            }
            if !processed[7].is_empty() && processed[7].eq_ignore_ascii_case(&processed[1]) {
                selfs += 1;
                continue;
            }
            if !seen.insert(processed.clone()) {
                dups += 1;
                continue;
            }
        }
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
        wtr.write_record(processed.iter().map(|s| s.as_str()).chain(std::iter::repeat("").take(crate::csv_out::TAIL_COLUMNS.len())))?;
    }

    wtr.flush()?;
    if named + selfs + dups > 0 {
        crate::banner::print_info(&format!(
            "{} address(es) named from the agents' own records; {} connection(s) of a machine to itself and {} duplicate(s) left out",
            named, selfs, dups
        ));
    }
    Ok(())
}

/// address -> host name, from the records themselves: every record carries
/// the agent's name and its local address. An address seen under two names
/// (DHCP, NAT) is left as an address.
fn agent_names(records: &[Value]) -> std::collections::HashMap<String, String> {
    let mut seen: std::collections::HashMap<String, Option<String>> = std::collections::HashMap::new();
    for r in records {
        let host = r.get("agent_hostname").and_then(|v| v.as_str()).unwrap_or("").trim();
        let ip = r.get("action_local_ip").and_then(|v| v.as_str()).unwrap_or("").trim();
        if host.is_empty() || ip.is_empty() {
            continue;
        }
        match seen.get(ip) {
            None => {
                seen.insert(ip.to_string(), Some(host.to_string()));
            }
            Some(Some(h)) if !h.eq_ignore_ascii_case(host) => {
                seen.insert(ip.to_string(), None);
            }
            _ => {}
        }
    }
    seen.into_iter().filter_map(|(ip, h)| h.map(|h| (ip, h))).collect()
}

// ─── parse-cortex: every source of the tenant, one timeline ─────────────────

/// What a tenant holds that masstin reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    /// the endpoints' network connections (`xdr_data`, NETWORK)
    Network,
    /// the Windows event logs the agents send by themselves (`xdr_data`, EVENT_LOG)
    EventLog,
    /// the event logs collected by the forensics add-on (`forensics_event_log`)
    Forensics,
}

impl Source {
    pub const ALL: [Source; 3] = [Source::Network, Source::EventLog, Source::Forensics];

    pub fn name(self) -> &'static str {
        match self {
            Source::Network => "network",
            Source::EventLog => "eventlog",
            Source::Forensics => "forensics",
        }
    }

    pub fn what(self) -> &'static str {
        match self {
            Source::Network => "the endpoints' network connections",
            Source::EventLog => "the Windows event logs the agents send",
            Source::Forensics => "the event logs collected by the forensics add-on",
        }
    }
}

/// `--cortex-sources`: a comma-separated list of `network`, `eventlog`,
/// `forensics` (or `all`, the default).
pub fn sources_from(spec: Option<&str>) -> Result<Vec<Source>, String> {
    let spec = spec.unwrap_or("all").trim().to_ascii_lowercase();
    if spec.is_empty() || spec == "all" {
        return Ok(Source::ALL.to_vec());
    }
    let mut out = Vec::new();
    for part in spec.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let s = match part {
            "network" | "net" => Source::Network,
            "eventlog" | "eventlogs" | "event-log" | "evtx" => Source::EventLog,
            "forensics" | "forensic" => Source::Forensics,
            other => return Err(format!("unknown Cortex source '{}': network, eventlog, forensics (or all)", other)),
        };
        if !out.contains(&s) {
            out.push(s);
        }
    }
    if out.is_empty() {
        return Err("--cortex-sources names no source: network, eventlog, forensics (or all)".to_string());
    }
    Ok(out)
}

/// A bound of the time range as Cortex is sent it: always with an explicit
/// UTC offset. "YYYY-MM-DD HH:MM:SS" with no zone is UTC (what the forensics
/// sources already assumed; sent bare, the tenant decided), and a bound
/// with another offset is converted. Anything else goes as written.
pub(crate) fn utc_bound(s: &str) -> String {
    let t = s.trim();
    if let Ok(dt) = DateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S %z") {
        return dt.with_timezone(&Utc).format("%Y-%m-%d %H:%M:%S -0000").to_string();
    }
    if let Ok(nd) = chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S") {
        return nd.format("%Y-%m-%d %H:%M:%S -0000").to_string();
    }
    t.to_string()
}

/// The window when none is given: the last seven days (the forensics event
/// logs, which come from triages of any date, keep their own year).
fn default_window() -> (String, String) {
    let end = Utc::now();
    let start = end - chrono::Duration::days(7);
    let f = |d: DateTime<Utc>| d.format("%Y-%m-%d %H:%M:%S -0000").to_string();
    (f(start), f(end))
}

/// `parse-cortex`: every source asked for, each into a part, the parts
/// merged into one timeline. A source the tenant does not have (no forensics
/// add-on, no permission) is said and left out; the run fails only when no
/// source gives a row.
#[allow(clippy::too_many_arguments)]
pub async fn parse_cortex_sources(
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
    event_ids: Option<&String>,
    sources: &[Source],
) -> Result<(), Box<dyn Error>> {
    let given = start_time.map_or(false, |s| !s.is_empty()) && end_time.map_or(false, |s| !s.is_empty());
    let (def_start, def_end) = default_window();
    let (net_start, net_end) = if given { (utc_bound(start_time.unwrap()), utc_bound(end_time.unwrap())) } else { (def_start, def_end) };
    if !given {
        crate::banner::print_info(&format!("No time window given: the last 7 days ({} to {}); the forensics event logs, the last year", net_start, net_end));
    }
    // the network alone is the run it always was
    if sources == [Source::Network] {
        return parse_cortex_data(base_url, output, debug, Some(&net_start), Some(&net_end), filter_ip, ignore_local, admin_ports, min_window_secs, max_passes).await;
    }
    let names: Vec<&str> = sources.iter().map(|s| s.name()).collect();
    crate::banner::print_info(&format!("Cortex sources: {} -> one timeline", names.join(", ")));
    let tmp = std::env::temp_dir().join(format!("masstin_cortex_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let mut parts: Vec<String> = Vec::new();
    let mut said: Vec<String> = Vec::new();
    crate::banner::set_parse_part(true);
    for (i, src) in sources.iter().enumerate() {
        crate::banner::print_info(&format!("Source {} of {}: {}", i + 1, sources.len(), src.what()));
        let part = tmp.join(format!("{}.csv", src.name())).to_string_lossy().to_string();
        let r: Result<(), Box<dyn Error>> = match src {
            Source::Network => parse_cortex_data(base_url, Some(&part), debug, Some(&net_start), Some(&net_end), filter_ip, ignore_local, admin_ports, min_window_secs, max_passes).await,
            Source::EventLog => {
                async {
                    let (key, id) = api_key_and_id()?;
                    let client = Client::new();
                    let auth = crate::cortex_auth::Auth::connect(&client, base_url, &key, &id).await?;
                    crate::parse_cortex_eventlog::parse_cortex_eventlog_data(&client, base_url, &auth, &part, debug, &net_start, &net_end, min_window_secs, max_passes).await.map(|_| ())
                }
                .await
            }
            Source::Forensics => {
                crate::parse_cortex_evtx_forensics::parse_cortex_evtx_forensics_data(base_url, Some(&part), debug, if given { start_time } else { None }, if given { end_time } else { None }, ignore_local, event_ids, min_window_secs, max_passes).await
            }
        };
        // with the forensics event logs: User Access Logging and MountPoints2,
        // the other artefacts of the add-on masstin reads from a disk
        if *src == Source::Forensics {
            let extra = tmp.join("forensics-artifacts.csv").to_string_lossy().to_string();
            let a: Result<usize, Box<dyn Error>> = async {
                let (key, id) = api_key_and_id()?;
                let client = Client::new();
                let auth = crate::cortex_auth::Auth::connect(&client, base_url, &key, &id).await?;
                crate::parse_cortex_artifacts::parse_cortex_artifacts_data(&client, base_url, &auth, &extra, debug, if given { start_time } else { None }, if given { end_time } else { None }).await
            }
            .await;
            match a {
                Ok(n) if n > 0 => {
                    said.push(format!("{} forensics artefacts (UAL, MountPoints2)", n));
                    parts.push(extra);
                }
                Ok(_) => {}
                Err(e) => crate::banner::print_warning(&format!("Forensics artefacts (UAL, MountPoints2) left out: {}", e)),
            }
        }
        match r {
            Ok(()) => {
                let rows = csv::Reader::from_path(&part).map(|mut r| r.records().count()).unwrap_or(0);
                said.push(format!("{} {}", rows, src.name()));
                if rows > 0 {
                    parts.push(part);
                }
            }
            Err(e) => {
                crate::banner::print_warning(&format!("Source left out ({}): {}", src.name(), e));
                said.push(format!("{} left out", src.name()));
            }
        }
    }
    crate::banner::set_parse_part(false);
    if parts.is_empty() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(format!("no source gave a row ({}): nothing to write", said.join(", ")).into());
    }
    crate::banner::print_info(&format!("Merging the sources into one timeline ({})", said.join(", ")));
    let r = crate::merge::merge_files(&parts, output, None, None, None);
    let _ = std::fs::remove_dir_all(&tmp);
    r?;
    if let Some(out) = output {
        let rows = csv::Reader::from_path(out).map(|mut r| r.records().count()).unwrap_or(0);
        crate::banner::print_phase_result(&format!("Timeline: {} ({} events: {})", crate::banner::normalize_display_path(out), rows, said.join(", ")));
        if !ignore_local && sources.contains(&Source::EventLog) {
            crate::banner::print_info("Most of the agents' logon events are local to their machine (console, unlocks, services): --ignore-local leaves only the ones that came from another machine");
        }
        crate::banner::print_load_hint(out);
    }
    Ok(())
}

#[cfg(test)]
mod utc_bound_tests {
    use super::utc_bound;

    #[test]
    fn a_bound_without_a_zone_is_sent_as_utc() {
        assert_eq!(utc_bound("2026-10-01 00:00:00"), "2026-10-01 00:00:00 -0000");
        assert_eq!(utc_bound(" 2026-10-01 00:00:00 -0000 "), "2026-10-01 00:00:00 -0000");
        assert_eq!(utc_bound("2026-10-01 01:30:00 +0200"), "2026-09-30 23:30:00 -0000");
        assert_eq!(utc_bound(""), "");
        assert_eq!(utc_bound("yesterday"), "yesterday");
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;

    #[test]
    fn the_sources_asked_for_by_name() {
        assert_eq!(sources_from(None).unwrap(), Source::ALL.to_vec());
        assert_eq!(sources_from(Some("all")).unwrap(), Source::ALL.to_vec());
        assert_eq!(sources_from(Some(" Network , forensics,network ")).unwrap(), vec![Source::Network, Source::Forensics]);
        assert_eq!(sources_from(Some("eventlog")).unwrap(), vec![Source::EventLog]);
        assert!(sources_from(Some("network,ual")).unwrap_err().contains("ual"));
        assert!(sources_from(Some(" , ")).is_err());
    }

    #[test]
    fn the_default_window_is_a_week_ending_now() {
        let (s, e) = default_window();
        let p = |t: &str| chrono::DateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S %z").unwrap();
        assert_eq!((p(&e) - p(&s)).num_days(), 7);
        assert!(bisect_time_window(&s, &e, 300).is_some());
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;
    use serde_json::json;

    fn rec(host: &str, lip: &str, lport: i64, rip: &str, rport: i64, user: &str) -> Value {
        json!({"_time": 1794000000000i64, "agent_hostname": host, "action_local_ip": lip, "action_local_port": lport,
               "action_remote_ip": rip, "action_remote_port": rport, "actor_primary_username": user, "actor_process_command_line": "x.exe"})
    }

    fn rows(records: &[Value]) -> Vec<Vec<String>> {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!("masstin_cortex_net_{}_{}.csv", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        write_processed_csv(records, p.to_str().unwrap(), false).unwrap();
        let mut rdr = csv::Reader::from_path(&p).unwrap();
        let out = rdr.records().map(|r| r.unwrap().iter().map(|s| s.to_string()).collect()).collect();
        let _ = std::fs::remove_file(&p);
        out
    }

    #[test]
    fn both_ends_of_a_connection_become_the_same_named_edge() {
        // the client's agent sees it going out, the server's agent coming in
        let recs = vec![rec("WS1", "10.0.0.5", 50123, "10.0.0.9", 3389, "CORP\\ana"), rec("SRV9", "10.0.0.9", 3389, "10.0.0.5", 50123, "NT AUTHORITY\\NETWORK SERVICE")];
        let r = rows(&recs);
        assert_eq!(r.len(), 2);
        for row in &r {
            assert_eq!((row[1].as_str(), row[7].as_str(), row[8].as_str()), ("SRV9", "WS1", "10.0.0.5"), "{:?}", row);
            assert_eq!(row[4], "10");
            assert!(row[12].starts_with("port 3389 | "), "{}", row[12]);
        }
    }

    #[test]
    fn an_address_under_two_names_stays_an_address() {
        let recs = vec![rec("A", "10.0.0.7", 50000, "10.0.0.9", 445, "u"), rec("B", "10.0.0.7", 50001, "10.0.0.9", 445, "u")];
        assert!(agent_names(&recs).get("10.0.0.7").is_none());
        assert_eq!(rows(&recs)[0][1], "10.0.0.9");
    }

    #[test]
    fn a_machine_reaching_itself_and_exact_duplicates_are_left_out() {
        let recs = vec![
            rec("SQL1", "10.0.0.20", 1433, "10.0.0.21", 50000, "svc"), // SQL1 serving its own second address
            rec("SQL1", "10.0.0.21", 50000, "10.0.0.20", 1433, "svc"),
            rec("WS1", "10.0.0.5", 50123, "10.0.0.9", 445, "ana"),
            rec("WS1", "10.0.0.5", 50123, "10.0.0.9", 445, "ana"),
        ];
        let r = rows(&recs);
        assert_eq!(r.len(), 1, "{:?}", r);
        assert_eq!(r[0][7], "WS1");
    }

    #[test]
    fn the_service_gives_the_logon_type() {
        let lt = |port: i64| process_record(&rec("S", "10.0.0.1", port, "10.0.0.2", 50000, "u"), false)[4].clone();
        assert_eq!((lt(3389).as_str(), lt(445).as_str(), lt(22).as_str()), ("10", "3", "SSH"));
        assert_eq!((lt(1433).as_str(), lt(5900).as_str(), lt(5985).as_str()), ("SQL", "VNC", "WinRM"));
    }
}
