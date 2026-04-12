// =============================================================================
//   MountPoints2 registry parser
//   Extracts lateral movement evidence from NTUSER.DAT registry hives.
//   Each ##SERVER#SHARE subkey under MountPoints2 indicates the user
//   connected to a remote share — with LastWriteTime as timestamp.
//
//   Uses notatin crate: offline registry parsing with transaction log
//   support and deleted key recovery for dirty/unclean hives.
// =============================================================================

use std::path::Path;
use notatin::parser_builder::ParserBuilder;
use crate::parse::LogData;

const MOUNTPOINTS2_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2";

/// Parse all NTUSER.DAT files in a directory and extract MountPoints2 entries.
/// Files should be named: username_NTUSER.DAT
pub fn parse_mountpoints(ntuser_dir: &Path, src_hostname: &str) -> Vec<LogData> {
    let mut events = Vec::new();

    // Collect all NTUSER.DAT files recursively (they may be in partition_N/ subdirs)
    let mut dat_files = Vec::new();
    collect_ntuser_files(ntuser_dir, &mut dat_files);

    for path in &dat_files {

        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let upper = filename.to_uppercase();
        if !upper.ends_with("_NTUSER.DAT") || upper.contains(".LOG") { continue; }

        let username = if let Some(pos) = upper.find("_NTUSER.DAT") {
            filename[..pos].to_string()
        } else {
            "unknown".to_string()
        };

        if crate::parse::is_debug_mode() {
            eprintln!("[DEBUG] MountPoints2: parsing {}'s NTUSER.DAT...", username);
        }
        match parse_single_ntuser(&path, &username, src_hostname) {
            Ok(new_events) => {
                if crate::parse::is_debug_mode() {
                    eprintln!("[DEBUG] MountPoints2: {} remote shares from {}", new_events.len(), username);
                }
                events.extend(new_events);
            }
            Err(e) => {
                if crate::parse::is_debug_mode() {
                    eprintln!("[DEBUG] MountPoints2: FAILED {}: {}", filename, e);
                }
            }
        }
    }

    events
}

/// Parse a single NTUSER.DAT and extract MountPoints2 remote share entries.
fn parse_single_ntuser(path: &Path, username: &str, src_hostname: &str) -> Result<Vec<LogData>, String> {
    let mut events = Vec::new();

    // Build parser with transaction log support and deleted key recovery
    let mut builder = ParserBuilder::from_path(path.to_path_buf());
    builder.recover_deleted(true);

    // Try to add transaction logs if they exist alongside the hive
    let base = path.to_string_lossy();
    let log1_path = format!("{}.LOG1", base);
    let log2_path = format!("{}.LOG2", base);

    if Path::new(&log1_path).exists() {
        builder.with_transaction_log(std::path::PathBuf::from(&log1_path));
    }
    if Path::new(&log2_path).exists() {
        builder.with_transaction_log(std::path::PathBuf::from(&log2_path));
    }

    let mut parser = builder.build()
        .map_err(|e| format!("Cannot build parser: {:?}", e))?;

    // Find MountPoints2 key
    let mut mp2_key = match parser.get_key(MOUNTPOINTS2_KEY, false) {
        Ok(Some(key)) => key,
        _ => {
            // Try with common root key prefixes
            let alt = format!("CMI-CreateHive{{2A7FB991-7BBE-4F9D-B91E-7CB51D4737F5}}\\{}", MOUNTPOINTS2_KEY);
            match parser.get_key(&alt, false) {
                Ok(Some(key)) => key,
                _ => return Ok(events), // MountPoints2 not found
            }
        }
    };

    let dat_path_str = path.to_string_lossy().to_string();

    // Read all subkeys of MountPoints2
    let subkeys = mp2_key.read_sub_keys(&mut parser);

    for mut subkey in subkeys {
        let key_name = subkey.key_name.clone();

        // Only process network shares (start with ##)
        if !key_name.starts_with("##") { continue; }

        // Parse ##SERVER#SHARE → \\SERVER\SHARE
        let unc_path = key_name.replace('#', "\\");
        let parts: Vec<&str> = unc_path.trim_start_matches('\\').splitn(2, '\\').collect();
        if parts.is_empty() { continue; }

        let server = parts[0].to_string();

        // Get timestamp (FILETIME u64 → ISO string)
        let timestamp = filetime_to_iso(subkey.detail.last_key_written_date_and_time());
        if timestamp.is_empty() { continue; }

        events.push(LogData {
            time_created: timestamp,
            computer: server.clone(),
            event_type: "CONNECT".to_string(),
            event_id: "MountPoints2".to_string(),
            subject_user_name: String::new(),
            subject_domain_name: String::new(),
            target_user_name: username.to_string(),
            target_domain_name: String::new(),
            logon_type: String::new(),
            workstation_name: src_hostname.to_string(),
            ip_address: extract_ip_if_present(&server),
            logon_id: String::new(),
            filename: dat_path_str.clone(),
            detail: format!("MountPoints2: {}", unc_path),
        });
    }

    Ok(events)
}

/// Convert Windows FILETIME (100ns intervals since 1601-01-01) to ISO 8601 string
fn filetime_to_iso(filetime: u64) -> String {
    if filetime == 0 { return String::new(); }
    const FILETIME_UNIX_DIFF: u64 = 11_644_473_600;
    const HUNDRED_NS_PER_SEC: u64 = 10_000_000;

    let secs_since_1601 = filetime / HUNDRED_NS_PER_SEC;
    if secs_since_1601 < FILETIME_UNIX_DIFF { return String::new(); }

    let unix_secs = secs_since_1601 - FILETIME_UNIX_DIFF;
    match chrono::DateTime::from_timestamp(unix_secs as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
        None => String::new(),
    }
}

/// Recursively collect all *_NTUSER.DAT files from a directory tree
fn collect_ntuser_files(dir: &Path, results: &mut Vec<std::path::PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_ntuser_files(&path, results);
        } else if path.is_file() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let upper = name.to_uppercase();
            if upper.ends_with("_NTUSER.DAT") && !upper.contains(".LOG") {
                results.push(path);
            }
        }
    }
}

/// If the server name looks like an IP address, return it
fn extract_ip_if_present(server: &str) -> String {
    if server.chars().all(|c| c.is_ascii_digit() || c == '.') && server.contains('.') {
        server.to_string()
    } else {
        String::new()
    }
}
