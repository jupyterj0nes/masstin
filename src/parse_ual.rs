// =============================================================================
//   UAL (User Access Logging) parser
//   Reads ESE databases from C:\Windows\System32\LogFiles\Sum\
//   and converts them to masstin LogData events.
// =============================================================================

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use crate::parse::LogData;
use crate::parse_ese::{self, EseValue};

const UAL_SUM_PATH: &[&str] = &["Windows", "System32", "LogFiles", "Sum"];

/// Check if a directory contains UAL databases (the Sum folder)
pub fn find_ual_databases(dir: &str) -> Vec<PathBuf> {
    let path = Path::new(dir);
    let mut results = Vec::new();

    // Check if this IS the Sum directory
    if path.file_name().and_then(|n| n.to_str()).map(|n| n.eq_ignore_ascii_case("Sum")).unwrap_or(false) {
        collect_mdb_files(path, &mut results);
        return results;
    }

    // Check if it contains Windows/System32/LogFiles/Sum
    let mut sum_path = path.to_path_buf();
    for component in UAL_SUM_PATH {
        sum_path = sum_path.join(component);
    }
    if sum_path.is_dir() {
        collect_mdb_files(&sum_path, &mut results);
        return results;
    }

    // Also check common subdirectory patterns
    for sub in &["LogFiles/Sum", "Sum"] {
        let p = path.join(sub);
        if p.is_dir() {
            collect_mdb_files(&p, &mut results);
            return results;
        }
    }

    // Check if the directory itself contains .mdb files (user pointed directly at a folder with MDBs)
    collect_mdb_files(path, &mut results);
    if !results.is_empty() {
        return results;
    }

    // Recursive search: walk subdirectories looking for "Sum" folder or .mdb files
    find_sum_dirs_recursive(path, &mut results, 0);
    results
}

fn find_sum_dirs_recursive(dir: &Path, results: &mut Vec<PathBuf>, depth: usize) {
    if depth > 5 { return; }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.eq_ignore_ascii_case("Sum") {
                    collect_mdb_files(&path, results);
                } else {
                    find_sum_dirs_recursive(&path, results, depth + 1);
                }
            }
        }
    }
}

fn collect_mdb_files(dir: &Path, results: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("mdb")).unwrap_or(false) {
                results.push(path);
            }
        }
    }
}

/// Parse UAL databases and return LogData events.
pub fn parse_ual_databases(mdb_files: &[PathBuf], source_label: &str) -> Vec<LogData> {
    let mut events = Vec::new();

    // Load role mappings and server hostname from SystemIdentity.mdb
    let role_map = load_role_mappings(mdb_files);
    let server_hostname = load_server_hostname(mdb_files);

    let client_files: Vec<&PathBuf> = mdb_files.iter()
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            !name.eq_ignore_ascii_case("SystemIdentity.mdb")
        })
        .collect();

    for mdb_path in &client_files {
        let mdb_name = mdb_path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown.mdb");
        let path_str = mdb_path.to_string_lossy();

        // Try to read CLIENTS table
        let rows = match parse_ese::read_ese_table(&path_str, "CLIENTS") {
            Ok(r) => r,
            Err(e) => {
                crate::banner::print_info(&format!("  Warning: cannot read CLIENTS from {}: {}", mdb_name, e));
                continue;
            }
        };

        let mdb_full_path = mdb_path.to_string_lossy().to_string();
        for row in &rows {
            let new_events = ual_row_to_logdata_entries(row, &role_map, &server_hostname, &mdb_full_path);
            events.extend(new_events);
        }
    }

    events
}

/// Load server hostname from SystemIdentity.mdb SYSTEM_IDENTITY table
fn load_server_hostname(mdb_files: &[PathBuf]) -> String {
    let sys_identity = mdb_files.iter()
        .find(|p| p.file_name().and_then(|n| n.to_str())
            .map(|n| n.eq_ignore_ascii_case("SystemIdentity.mdb")).unwrap_or(false));

    let sys_path = match sys_identity {
        Some(p) => p,
        None => return String::new(),
    };

    let rows = match parse_ese::read_ese_table(&sys_path.to_string_lossy(), "SYSTEM_IDENTITY") {
        Ok(r) => r,
        Err(_) => return String::new(),
    };

    // Get hostname from last entry (most recent)
    for row in rows.iter().rev() {
        if let Some(name) = get_text(row, "SystemDNSHostName") {
            if !name.is_empty() {
                return name;
            }
        }
    }
    String::new()
}

/// Map UAL role name to a protocol/event_id for the masstin timeline
fn role_to_event_id(role_name: &str) -> &'static str {
    let lower = role_name.to_lowercase();
    if lower.contains("file server") { return "SMB"; }
    if lower.contains("remote access") { return "RDP"; }
    if lower.contains("web server") || lower.contains("ftp") { return "HTTP"; }
    if lower.contains("active directory") { return "LDAP"; }
    if lower.contains("dhcp") { return "DHCP"; }
    if lower.contains("dns") { return "DNS"; }
    if lower.contains("print") { return "PRINT"; }
    if lower.contains("certificate") { return "CERT"; }
    "UAL"
}

/// Load role GUID -> role name mappings from SystemIdentity.mdb
fn load_role_mappings(mdb_files: &[PathBuf]) -> HashMap<String, String> {
    let mut map = HashMap::new();

    let sys_identity = mdb_files.iter()
        .find(|p| p.file_name().and_then(|n| n.to_str())
            .map(|n| n.eq_ignore_ascii_case("SystemIdentity.mdb")).unwrap_or(false));

    let sys_path = match sys_identity {
        Some(p) => p,
        None => return map,
    };

    let rows = match parse_ese::read_ese_table(&sys_path.to_string_lossy(), "ROLE_IDS") {
        Ok(r) => r,
        Err(_) => return map,
    };

    for row in &rows {
        let guid = get_text(row, "RoleGuid");
        let name = get_text(row, "RoleName")
            .or_else(|| get_text(row, "ProductName"));

        if let (Some(g), Some(n)) = (guid, name) {
            map.insert(g.to_lowercase(), n);
        }
    }

    map
}

/// Convert a single UAL CLIENTS row to LogData events.
/// Generates TWO entries: one for InsertDate (first seen) and one for LastAccess (last seen).
fn ual_row_to_logdata_entries(
    row: &HashMap<String, EseValue>,
    role_map: &HashMap<String, String>,
    server_hostname: &str,
    mdb_path: &str,
) -> Vec<LogData> {
    let mut entries = Vec::new();

    let username = get_text(row, "AuthenticatedUserName").unwrap_or_default();
    if username.is_empty() {
        return entries;
    }

    let ip_address = get_text(row, "Address")
        .map(|s| parse_hex_ip(&s))
        .unwrap_or_default();

    let insert_date = get_text(row, "InsertDate")
        .map(|s| parse_filetime_string(&s))
        .unwrap_or_default();

    let last_access = get_text(row, "LastAccess")
        .map(|s| parse_filetime_string(&s))
        .unwrap_or_default();

    if insert_date.is_empty() && last_access.is_empty() {
        return entries;
    }

    let total_accesses = get_text(row, "TotalAccesses")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(0);

    let role_guid = get_text(row, "RoleGuid").unwrap_or_default();
    let role_name = role_map.get(&role_guid.to_lowercase())
        .cloned()
        .unwrap_or_else(|| if role_guid.is_empty() { String::new() } else { role_guid.clone() });

    let event_id = role_to_event_id(&role_name).to_string();

    let (domain, user) = if let Some(pos) = username.find('\\') {
        (username[..pos].to_string(), username[pos + 1..].to_string())
    } else {
        (String::new(), username.clone())
    };

    let detail = format!("UAL: {} ({}x)", role_name, total_accesses);
    let filename = mdb_path.to_string();

    // Entry 1: InsertDate (first access)
    if !insert_date.is_empty() {
        entries.push(LogData {
            time_created: insert_date,
            computer: server_hostname.to_string(),
            event_type: "SUCCESSFUL_LOGON".to_string(),
            event_id: event_id.clone(),
            subject_user_name: String::new(),
            subject_domain_name: String::new(),
            target_user_name: user.clone(),
            target_domain_name: domain.clone(),
            logon_type: String::new(),
            workstation_name: String::new(),
            ip_address: ip_address.clone(),
            logon_id: String::new(),
            filename: filename.clone(),
            detail: detail.clone(),
        });
    }

    // Entry 2: LastAccess (most recent access) — only if different from InsertDate
    if !last_access.is_empty() && last_access != entries.first().map(|e| e.time_created.as_str()).unwrap_or("") {
        entries.push(LogData {
            time_created: last_access,
            computer: server_hostname.to_string(),
            event_type: "SUCCESSFUL_LOGON".to_string(),
            event_id: event_id,
            subject_user_name: String::new(),
            subject_domain_name: String::new(),
            target_user_name: user,
            target_domain_name: domain,
            logon_type: String::new(),
            workstation_name: String::new(),
            ip_address,
            logon_id: String::new(),
            filename,
            detail,
        });
    }

    entries
}

/// Parse a hex IP string like "0A 0A 0C C8" or "00 00 ... 00 01" to readable IP
fn parse_hex_ip(s: &str) -> String {
    parse_ese::ip_from_hex_string(s)
}

/// Parse a FILETIME string (raw i64) to "YYYY-MM-DD HH:MM:SS"
fn parse_filetime_string(s: &str) -> String {
    if let Ok(ft) = s.trim().parse::<i64>() {
        let result = parse_ese::filetime_to_string(ft);
        if !result.is_empty() {
            return result;
        }
    }
    // If it's already a formatted date, return as-is
    s.to_string()
}

fn get_text(row: &HashMap<String, EseValue>, key: &str) -> Option<String> {
    for (k, v) in row {
        if k.eq_ignore_ascii_case(key) {
            return match v {
                EseValue::Text(s) if !s.is_empty() => Some(s.clone()),
                _ => None,
            };
        }
    }
    None
}
