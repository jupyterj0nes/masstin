//! What the Cortex XDR forensics add-on holds beyond the event logs, of the
//! artefacts masstin reads from a disk for lateral movement:
//!
//! - **User Access Logging** (`forensics_user_access_logging`): who reached a
//!   server role from which address, the first and the last time, as the
//!   UAL databases (`Sum\*.mdb`) say. Mapped as parse-windows maps a UAL
//!   database: a row at the first access and one at the last.
//! - **MountPoints2** (`forensics_registry`): the network shares an account
//!   mounted (`##SERVER#SHARE` under Explorer\MountPoints2), at the time the
//!   key was last written. Mapped as the NTUSER.DAT reader maps it.
//!
//! Read with the forensics source of `parse-cortex`. The datasets are filled
//! by triages and hunts only; one that is missing or empty gives no row.

use std::collections::HashSet;
use std::error::Error;

use chrono::{TimeZone, Utc};
use reqwest::Client;
use serde_json::Value;

use crate::cortex_auth::Auth;
use crate::parse::LogData;

const UAL_QUERY: &str = r#"config case_sensitive = false timeframe = 365d | dataset = forensics_user_access_logging |
        fields host_name, user, ip_address, role_name, role_guid, insert_date, last_access, access_count"#;

const MOUNTPOINTS_QUERY: &str = r###"config case_sensitive = false timeframe = 365d | dataset = forensics_registry |
        filter path contains "MountPoints2" and path contains "##" |
        fields host_name, path, key_last_modified, user"###;

/// A time the forensics tables give as a number: epoch seconds,
/// milliseconds or microseconds, or a Windows FILETIME; told apart by size.
pub fn time_of(v: Option<&Value>) -> Option<String> {
    let n: i64 = match v? {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64))?,
        Value::String(s) => s.trim().parse::<i64>().ok()?,
        _ => return None,
    };
    if n <= 0 {
        return None;
    }
    let ms = if n >= 100_000_000_000_000_000 {
        // FILETIME: 100 ns since 1601
        n / 10_000 - 11_644_473_600_000
    } else if n >= 100_000_000_000_000 {
        n / 1000 // microseconds
    } else if n >= 100_000_000_000 {
        n // milliseconds
    } else {
        n * 1000 // seconds
    };
    Utc.timestamp_millis_opt(ms).single().map(|d| d.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
}

fn text(r: &Value, k: &str) -> String {
    match r.get(k) {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// One UAL record: a row at the first access and one at the last, as
/// parse-windows writes them from a UAL database.
pub fn ual_rows(r: &Value) -> Vec<LogData> {
    let host = text(r, "host_name");
    let account = text(r, "user");
    let ip = crate::parse::strip_ipv4_mapped(&text(r, "ip_address"));
    if host.is_empty() || account.is_empty() {
        return Vec::new();
    }
    let role = {
        let name = text(r, "role_name");
        if name.is_empty() { text(r, "role_guid") } else { name }
    };
    let (user, domain) = crate::parse::split_account(&account);
    let count = text(r, "access_count");
    let detail = format!("UAL: {} ({}x)", role, if count.is_empty() { "0" } else { count.as_str() });
    let first = time_of(r.get("insert_date"));
    let last = time_of(r.get("last_access"));
    let mut times: Vec<String> = Vec::new();
    for t in [first, last].into_iter().flatten() {
        if !times.contains(&t) {
            times.push(t);
        }
    }
    times
        .into_iter()
        .map(|t| LogData {
            time_created: t,
            computer: host.clone(),
            event_type: "SUCCESSFUL_LOGON".to_string(),
            event_id: crate::parse_ual::role_to_event_id(&role).to_string(),
            subject_user_name: String::new(),
            subject_domain_name: String::new(),
            target_user_name: user.clone(),
            target_domain_name: domain.clone(),
            logon_type: crate::parse_ual::role_to_logon_type(&role).to_string(),
            workstation_name: String::new(),
            ip_address: ip.clone(),
            logon_id: String::new(),
            filename: "cortex_forensics_ual".to_string(),
            detail: detail.clone(),
        })
        .collect()
}

/// One registry record of a MountPoints2 share key (`…\MountPoints2\##SERVER#SHARE`):
/// the account of that hive mounted the share from this machine.
pub fn mountpoint_row(r: &Value) -> Option<LogData> {
    let host = text(r, "host_name");
    let path = text(r, "path");
    let key = path.rsplit(['\\', '/']).next().unwrap_or("");
    let (unc, server) = crate::parse_mountpoints::share_of(key)?;
    let time = time_of(r.get("key_last_modified"))?;
    if host.is_empty() {
        return None;
    }
    let (user, domain) = crate::parse::split_account(&text(r, "user"));
    Some(LogData {
        time_created: time,
        computer: server.clone(),
        event_type: "CONNECT".to_string(),
        event_id: "MountPoints2".to_string(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: user,
        target_domain_name: domain,
        logon_type: String::new(),
        workstation_name: host,
        ip_address: String::new(),
        logon_id: String::new(),
        filename: "cortex_forensics_registry".to_string(),
        detail: format!("MountPoints2: {}", unc),
    })
}

/// "YYYY-MM-DD HH:MM:SS[ -0000]" as the ISO text the rows carry, to compare.
fn bound(t: Option<&String>) -> Option<String> {
    let s = t?.trim();
    let base = s.get(..19)?;
    let d = chrono::NaiveDateTime::parse_from_str(base, "%Y-%m-%d %H:%M:%S").ok()?;
    Some(d.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
}

/// Read UAL and MountPoints2 and write their rows; returns how many. A
/// dataset the tenant does not have is said and gives none.
pub async fn parse_cortex_artifacts_data(
    client: &Client,
    base_url: &str,
    auth: &Auth,
    output: &String,
    debug: bool,
    start: Option<&String>,
    end: Option<&String>,
) -> Result<usize, Box<dyn Error>> {
    let base = base_url.trim_end_matches('/');
    let start_url = format!("{}/public_api/v1/xql/start_xql_query/", base);
    let results_url = format!("{}/public_api/v1/xql/get_query_results/", base);
    let stream_url = format!("{}/public_api/v1/xql/get_query_results_stream", base);
    let (from, to) = (bound(start), bound(end));
    let inside = |t: &str| from.as_deref().map_or(true, |f| t >= f) && to.as_deref().map_or(true, |x| t <= x);

    let mut rows: Vec<LogData> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut keep = |ld: LogData, rows: &mut Vec<LogData>| {
        if !inside(&ld.time_created) || !crate::filter::should_keep_record(&ld) {
            return;
        }
        if seen.insert(format!("{:?}", ld)) {
            rows.push(ld);
        }
    };

    // Cortex returns at most a million records to one query; these two
    // have no window to split, so a result that large is said, not taken
    // as complete
    let cut = |what: &str, n: usize| {
        if n >= 999_000 {
            crate::banner::print_warning(&format!(
                "{}: Cortex returned {} records, its limit for one query: the result is cut and rows are missing from the timeline",
                what, n
            ));
        }
    };
    match crate::parse_cortex::run_xql(client, &start_url, &results_url, &stream_url, auth, UAL_QUERY, debug).await {
        Ok(recs) => {
            cut("User Access Logging", recs.len());
            let before = rows.len();
            for r in &recs {
                for ld in ual_rows(r) {
                    keep(ld, &mut rows);
                }
            }
            crate::banner::print_phase_result(&format!("User Access Logging: {} records, {} rows", recs.len(), rows.len() - before));
        }
        Err(e) => crate::banner::print_warning(&format!("User Access Logging left out: {}", e)),
    }
    match crate::parse_cortex::run_xql(client, &start_url, &results_url, &stream_url, auth, MOUNTPOINTS_QUERY, debug).await {
        Ok(recs) => {
            cut("MountPoints2", recs.len());
            let before = rows.len();
            for r in &recs {
                if let Some(ld) = mountpoint_row(r) {
                    keep(ld, &mut rows);
                }
            }
            crate::banner::print_phase_result(&format!("MountPoints2: {} registry records, {} shares mounted", recs.len(), rows.len() - before));
        }
        Err(e) => crate::banner::print_warning(&format!("MountPoints2 left out: {}", e)),
    }
    rows.sort_by(|a, b| a.time_created.cmp(&b.time_created));
    crate::csv_out::write_timeline(&rows, Some(output))?;
    Ok(rows.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_time_is_read_whatever_its_unit() {
        let want = Some("2026-11-10T08:02:11.000000Z".to_string());
        assert_eq!(time_of(Some(&json!(1794297731))), want);
        assert_eq!(time_of(Some(&json!(1794297731000i64))), want);
        assert_eq!(time_of(Some(&json!(1794297731000000i64))), want);
        assert_eq!(time_of(Some(&json!("1794297731000"))), want);
        // FILETIME of the same instant
        assert_eq!(time_of(Some(&json!((1794297731i64 + 11_644_473_600) * 10_000_000))), want);
        assert_eq!(time_of(Some(&json!(0))), None);
        assert_eq!(time_of(None), None);
    }

    #[test]
    fn a_ual_record_is_two_rows_as_from_a_ual_database() {
        let r = json!({"host_name": "FS01", "user": "CORP\\ana", "ip_address": "10.0.0.5", "role_name": "File Server",
                       "insert_date": 1794297731000i64, "last_access": 1794384131000i64, "access_count": 12});
        let rows = ual_rows(&r);
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].computer.as_str(), rows[0].target_user_name.as_str(), rows[0].target_domain_name.as_str(), rows[0].ip_address.as_str()), ("FS01", "ana", "CORP", "10.0.0.5"));
        assert_eq!(rows[0].detail, "UAL: File Server (12x)");
        assert_eq!(rows[0].event_type, "SUCCESSFUL_LOGON");
        assert!(rows[0].time_created < rows[1].time_created);
        assert_eq!(rows[0].event_id, crate::parse_ual::role_to_event_id("File Server"));
        assert_eq!(rows[0].logon_type, crate::parse_ual::role_to_logon_type("File Server"));
        // the same instant twice is one row; no account, no row
        let same = json!({"host_name": "FS01", "user": "ana", "ip_address": "10.0.0.5", "role_name": "File Server", "insert_date": 1794297731000i64, "last_access": 1794297731000i64});
        assert_eq!(ual_rows(&same).len(), 1);
        assert!(ual_rows(&json!({"host_name": "FS01", "ip_address": "10.0.0.5", "insert_date": 1794297731000i64})).is_empty());
    }

    #[test]
    fn a_mounted_share_goes_from_the_machine_to_the_server() {
        let r = json!({"host_name": "WS07", "path": "S-1-5-21-1-2-3\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\##FS01#Finance$",
                       "key_last_modified": 1794297731000i64, "user": "CORP\\ana"});
        let ld = mountpoint_row(&r).unwrap();
        assert_eq!((ld.computer.as_str(), ld.workstation_name.as_str(), ld.target_user_name.as_str(), ld.target_domain_name.as_str()), ("FS01", "WS07", "ana", "CORP"));
        assert_eq!((ld.event_type.as_str(), ld.event_id.as_str(), ld.detail.as_str()), ("CONNECT", "MountPoints2", "MountPoints2: \\\\FS01\\Finance$"));
        // a server given as an address is still the destination: the
        // address column is the source's, and the hive does not hold it
        let ip = json!({"host_name": "WS07", "path": "x\\MountPoints2\\##10.0.0.9#c$", "key_last_modified": 1794297731000i64});
        let ld = mountpoint_row(&ip).unwrap();
        assert_eq!((ld.computer.as_str(), ld.workstation_name.as_str(), ld.ip_address.as_str()), ("10.0.0.9", "WS07", ""));
        // a volume GUID key, or a key without its time, is no share
        assert!(mountpoint_row(&json!({"host_name": "WS07", "path": "x\\MountPoints2\\{1234}", "key_last_modified": 1794297731000i64})).is_none());
        assert!(mountpoint_row(&json!({"host_name": "WS07", "path": "x\\MountPoints2\\##FS01#a"})).is_none());
    }

    #[test]
    fn the_window_bounds_compare_with_the_rows_times() {
        assert_eq!(bound(Some(&"2026-11-10 08:02:11 -0000".to_string())).as_deref(), Some("2026-11-10T08:02:11.000000Z"));
        assert_eq!(bound(Some(&"nonsense".to_string())), None);
        assert_eq!(bound(None), None);
    }
}
