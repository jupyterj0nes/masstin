//! The Windows event logs the Cortex XDR agents send by themselves.
//!
//! Besides its own telemetry, every agent forwards a fixed list of Security
//! events (logons, logoffs, explicit credentials, Kerberos and NTLM on the
//! domain controllers, share access) to the tenant, where they sit in
//! `xdr_data` with `event_type = EVENT_LOG`: no forensics add-on, no triage,
//! every machine with an agent, as far back as the tenant keeps its data.
//! Each record carries the event's own EventData as JSON
//! (`action_evtlog_data_fields`), so it is turned into the record
//! parse-windows maps and goes through the same mapping: an event read here
//! gives the row the same event gives from an EVTX file.
//!
//! One of the sources of `parse-cortex` (`--cortex-sources eventlog`).

use std::collections::HashMap;
use std::error::Error;

use chrono::{TimeZone, Utc};
use reqwest::Client;
use serde_json::Value;

use crate::cortex_auth::Auth;
use crate::parse::{LogData, WinRec};

/// The Security events of lateral movement (parse-windows' own list), and
/// the RDP client's 1024.
pub const EVENT_IDS: &str = "4624,4625,4634,4647,4648,4768,4769,4770,4771,4776,4778,4779,5140,5145,1024";

const SATURATION_THRESHOLD: usize = 999_000;

/// The query for one window.
pub fn query(start: &str, end: &str) -> String {
    format!(
        r#"config case_sensitive = false timeframe between "{start}" and "{end}" | dataset = xdr_data |
        filter event_type = ENUM.EVENT_LOG and action_evtlog_event_id in ({EVENT_IDS}) |
        alter masstin_ms = to_epoch(_time, "MILLIS") |
        fields _time, masstin_ms, agent_hostname, action_evtlog_event_id, action_evtlog_provider_name, action_evtlog_data_fields"#
    )
}

/// One record of the API as the record parse-windows maps.
pub fn rec_from_api(r: &Value) -> Option<WinRec> {
    let event_id = match r.get("action_evtlog_event_id")? {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.trim().to_string(),
        _ => return None,
    };
    // EventData: an object, or the object as text
    let data: Option<Value> = match r.get("action_evtlog_data_fields") {
        Some(Value::Object(m)) => Some(Value::Object(m.clone())),
        Some(Value::String(s)) => serde_json::from_str::<Value>(s).ok().filter(|v| v.is_object()),
        _ => None,
    };
    let mut fields = HashMap::new();
    if let Some(Value::Object(m)) = &data {
        for (k, v) in m {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => continue,
            };
            fields.insert(k.clone(), s);
        }
    }
    let time = event_time(r).unwrap_or_default();
    Some(WinRec {
        event_id,
        time,
        computer: r.get("agent_hostname").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        user_sid: String::new(),
        pid: String::new(),
        fields,
        has_event_data: data.is_some(),
    })
}

/// The event's time as masstin writes it. The query asks for it in epoch
/// milliseconds (`masstin_ms`); `_time` is the fallback, a number or the
/// text the API gives ("2026-11-10 08:02:11.123 UTC", RFC 3339).
pub fn event_time(r: &Value) -> Option<String> {
    let fmt = |ms: i64| Utc.timestamp_millis_opt(ms).single().map(|d| d.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string());
    for key in ["masstin_ms", "_time"] {
        match r.get(key) {
            Some(Value::Number(n)) => {
                if let Some(t) = n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).and_then(fmt) {
                    return Some(t);
                }
            }
            Some(Value::String(s)) => {
                let s = s.trim();
                if let Ok(ms) = s.parse::<i64>() {
                    if let Some(t) = fmt(ms) {
                        return Some(t);
                    }
                }
                if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f UTC") {
                    return fmt(dt.and_utc().timestamp_millis());
                }
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                    return fmt(dt.timestamp_millis());
                }
            }
            _ => {}
        }
    }
    None
}

/// One record to a row, through parse-windows' mapping of its event.
pub fn row(r: &Value) -> Option<LogData> {
    let rec = rec_from_api(r)?;
    // no agent name, or no EventData: nothing to make a row of
    if rec.computer.trim().is_empty() || !rec.has_event_data {
        return None;
    }
    let map = crate::parse::mapper_for_id(&rec.event_id)?;
    map(&rec, "cortex_xdr_eventlog")
}

/// Read the window (bisected when a pass returns the API's maximum) and
/// write the rows; returns how many.
#[allow(clippy::too_many_arguments)]
pub async fn parse_cortex_eventlog_data(
    client: &Client,
    base_url: &str,
    auth: &Auth,
    output: &String,
    debug: bool,
    start: &str,
    end: &str,
    min_window_secs: i64,
    max_passes: usize,
) -> Result<usize, Box<dyn Error>> {
    let base = base_url.trim_end_matches('/');
    let start_url = format!("{}/public_api/v1/xql/start_xql_query/", base);
    let results_url = format!("{}/public_api/v1/xql/get_query_results/", base);
    let stream_url = format!("{}/public_api/v1/xql/get_query_results_stream", base);
    crate::banner::print_phase_detail("Events:", EVENT_IDS);
    crate::banner::print_phase_detail("Time range:", &format!("{} to {}", start, end));

    let mut all: Vec<Value> = Vec::new();
    let mut work: Vec<(String, String)> = vec![(start.to_string(), end.to_string())];
    let mut pass = 0usize;
    let mut truncated = 0usize;
    while let Some((w_start, w_end)) = work.pop() {
        pass += 1;
        let batch = crate::parse_cortex::run_xql(client, &start_url, &results_url, &stream_url, auth, &query(&w_start, &w_end), debug).await?;
        crate::banner::print_phase_detail(&format!("Pass {}", pass), &format!("{} → {}: {} events", w_start, w_end, batch.len()));
        if batch.len() >= SATURATION_THRESHOLD && pass < max_passes {
            if let Some((mid, _)) = crate::parse_cortex::bisect_time_window(&w_start, &w_end, min_window_secs) {
                // the later half first, so the earlier one is read next
                work.push((mid.clone(), w_end));
                work.push((w_start, mid));
                continue;
            }
            truncated += 1;
        } else if batch.len() >= SATURATION_THRESHOLD {
            truncated += 1;
        }
        all.extend(batch);
    }
    if truncated > 0 {
        crate::banner::print_warning(&format!("{} window(s) returned the API's maximum and may be cut: narrow the time range or lower --cortex-min-window-secs", truncated));
    }

    if debug {
        // the shape of what came, never its content
        if let Some(Value::Object(first)) = all.first() {
            let kind = |v: Option<&Value>| match v { None => "absent", Some(Value::Null) => "null", Some(Value::Number(_)) => "number", Some(Value::String(_)) => "text", Some(Value::Object(_)) => "object", Some(_) => "other" };
            eprintln!("[DEBUG] first record: keys {:?}; _time {}, masstin_ms {}, data_fields {}", first.keys().collect::<Vec<_>>(), kind(first.get("_time")), kind(first.get("masstin_ms")), kind(first.get("action_evtlog_data_fields")));
        }
    }
    let mut rows: Vec<LogData> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut unmapped = 0usize;
    let mut timeless = 0usize;
    for r in &all {
        match row(r) {
            Some(ld) if ld.time_created.trim().is_empty() => timeless += 1,
            Some(ld) => {
                if !crate::filter::should_keep_record(&ld) {
                    continue;
                }
                let key = format!("{:?}", ld);
                if seen.insert(key) {
                    rows.push(ld);
                }
            }
            None => unmapped += 1,
        }
    }
    rows.sort_by(|a, b| a.time_created.cmp(&b.time_created));
    crate::banner::print_phase_result(&format!(
        "{} events from the agents' own event logs, {} rows{}",
        all.len(),
        rows.len(),
        if unmapped > 0 { format!(" ({} carried no event data to map)", unmapped) } else { String::new() }
    ));
    if timeless > 0 {
        crate::banner::print_warning(&format!("{} event(s) came without a time masstin can read and were left out", timeless));
    }
    crate::csv_out::write_timeline(&rows, Some(output))?;
    Ok(rows.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn logon(data: Value) -> Value {
        json!({"masstin_ms": 1794000000000i64, "agent_hostname": "SRV01", "action_evtlog_event_id": 4624,
               "action_evtlog_provider_name": "Microsoft-Windows-Security-Auditing", "action_evtlog_data_fields": data})
    }

    #[test]
    fn a_logon_read_from_the_api_is_the_row_parse_windows_gives() {
        let fields = json!({"TargetUserName": "ana", "TargetDomainName": "CORP", "LogonType": "3", "IpAddress": "10.0.0.5",
                            "WorkstationName": "WS07", "SubjectUserName": "-", "SubjectDomainName": "-", "TargetLogonId": "0x1f4a", "ProcessName": "-"});
        let ld = row(&logon(fields.clone())).expect("a row");
        assert_eq!(ld.event_type, "SUCCESSFUL_LOGON");
        assert_eq!((ld.computer.as_str(), ld.target_user_name.as_str(), ld.target_domain_name.as_str()), ("SRV01", "ana", "CORP"));
        assert_eq!((ld.workstation_name.as_str(), ld.ip_address.as_str(), ld.logon_type.as_str()), ("WS07", "10.0.0.5", "3"));
        assert_eq!(ld.filename, "cortex_xdr_eventlog");
        assert!(ld.time_created.starts_with("2026-"));
        // the same event built by hand as parse-windows would
        let mut f = HashMap::new();
        for (k, v) in fields.as_object().unwrap() {
            f.insert(k.clone(), v.as_str().unwrap().to_string());
        }
        let rec = WinRec { event_id: "4624".into(), time: ld.time_created.clone(), computer: "SRV01".into(), user_sid: String::new(), pid: String::new(), fields: f, has_event_data: true };
        let native = crate::parse::map_security(&rec, "cortex_xdr_eventlog").unwrap();
        assert_eq!(format!("{:?}", native), format!("{:?}", ld));
    }

    #[test]
    fn the_event_data_as_text_reads_the_same() {
        let obj = json!({"TargetUserName": "ana", "TargetDomainName": "CORP", "LogonType": "10", "IpAddress": "10.0.0.5", "WorkstationName": "WS07"});
        let a = row(&logon(obj.clone())).unwrap();
        let b = row(&logon(Value::String(obj.to_string()))).unwrap();
        assert_eq!(format!("{:?}", a), format!("{:?}", b));
        assert_eq!(a.logon_type, "10");
    }

    #[test]
    fn a_record_without_event_data_or_host_makes_no_row() {
        let mut r = logon(Value::Null);
        assert!(row(&r).is_none());
        r = logon(json!({"TargetUserName": "ana", "LogonType": "3", "IpAddress": "10.0.0.5"}));
        r["agent_hostname"] = json!("");
        assert!(row(&r).is_none());
        // an event masstin does not map
        let mut other = logon(json!({"x": "y"}));
        other["action_evtlog_event_id"] = json!(4672);
        assert!(row(&other).is_none());
    }

    #[test]
    fn the_time_is_read_however_the_api_gives_it() {
        let want = "2026-11-10T08:02:11.123000Z";
        let ms = 1794297731123i64;
        assert_eq!(event_time(&json!({"masstin_ms": ms})).as_deref(), Some(want));
        assert_eq!(event_time(&json!({"masstin_ms": ms.to_string()})).as_deref(), Some(want));
        assert_eq!(event_time(&json!({"_time": ms})).as_deref(), Some(want));
        assert_eq!(event_time(&json!({"_time": "2026-11-10 08:02:11.123 UTC"})).as_deref(), Some(want));
        assert_eq!(event_time(&json!({"_time": "2026-11-10T08:02:11.123Z"})).as_deref(), Some(want));
        assert_eq!(event_time(&json!({"masstin_ms": null, "_time": "Nov 10th"})), None);
        assert_eq!(event_time(&json!({})), None);
    }

    #[test]
    fn the_query_asks_for_the_event_logs_in_the_window() {
        let q = query("2026-11-01 00:00:00 -0000", "2026-11-02 00:00:00 -0000");
        assert!(q.contains(r#"timeframe between "2026-11-01 00:00:00 -0000" and "2026-11-02 00:00:00 -0000""#));
        assert!(q.contains("event_type = ENUM.EVENT_LOG") && q.contains("4624,4625") && q.contains("action_evtlog_data_fields"));
        assert!(q.contains(r#"to_epoch(_time, "MILLIS")"#) && q.contains("fields _time, masstin_ms"));
    }
}
