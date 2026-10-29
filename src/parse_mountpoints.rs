// =============================================================================
//   MountPoints2 registry parser
//   Extracts lateral movement evidence from NTUSER.DAT registry hives.
//   Each ##SERVER#SHARE subkey under MountPoints2 indicates the user
//   connected to a remote share — with LastWriteTime as timestamp.
//
//   The hive is read with nt_hive2 (the reader faramir uses): a dirty hive
//   gets its .LOG1/.LOG2 applied, every entry verified by its Marvin32 hashes.
//   Deleted ##SERVER#SHARE keys are recovered from the free cells of the
//   replayed hive with blockcarve::hive_cells (the walker faramir and caarea
//   share), so a connection the user removed from Explorer still shows up.
// =============================================================================

use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use nt_hive2::transactionlog::TransactionLog;
use nt_hive2::{CleanHive, ContainsHive, Hive, HiveParseMode, SubPath};

use crate::parse::LogData;

const MOUNTPOINTS2_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2";
const BASE_BLOCK_SIZE: usize = 4096;

type HiveFile = Hive<BufReader<File>, CleanHive>;

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
        if !upper.ends_with("_NTUSER.DAT") || upper.contains(".LOG") {
            continue;
        }

        let username = if let Some(pos) = upper.find("_NTUSER.DAT") {
            filename[..pos].to_string()
        } else {
            "unknown".to_string()
        };

        if crate::parse::is_debug_mode() {
            eprintln!("[DEBUG] MountPoints2: parsing {}'s NTUSER.DAT...", username);
        }
        match parse_single_ntuser(path, &username, src_hostname) {
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

/// Opens a hive and, when it is dirty, applies its `.LOG1` / `.LOG2`. A log that cannot be
/// read or applied leaves the hive in its on-disk state rather than failing.
fn open_hive(path: &Path) -> Result<HiveFile, String> {
    let label = path.display().to_string();
    let open = || -> Result<_, String> {
        let file = File::open(path).map_err(|e| format!("{label}: {e}"))?;
        match catch_unwind(AssertUnwindSafe(|| Hive::new(BufReader::new(file), HiveParseMode::NormalWithBaseBlock))) {
            Ok(Ok(h)) => Ok(h),
            Ok(Err(e)) => Err(format!("{label}: {e}")),
            Err(_) => Err(format!("{label}: the hive reader panicked")),
        }
    };
    let hive = open()?;
    if !is_dirty(path) {
        return Ok(hive.treat_hive_as_clean());
    }
    let logs: Vec<TransactionLog> = ["LOG1", "LOG2"]
        .iter()
        .filter_map(|ext| File::open(format!("{}.{}", path.display(), ext)).ok())
        .filter_map(|f| TransactionLog::try_from(f).ok())
        .collect();
    if logs.is_empty() {
        return Ok(hive.treat_hive_as_clean());
    }
    let replayed = catch_unwind(AssertUnwindSafe(move || -> Result<HiveFile, String> {
        // each added log nests the type, so the one- and two-log cases are spelled out
        let mut iter = logs.into_iter();
        let first = iter.next().expect("non-empty");
        let with_first = hive.with_transaction_log(first).map_err(|e| e.to_string())?;
        match iter.next() {
            Some(second) => Ok(with_first.with_transaction_log(second).map_err(|e| e.to_string())?.apply_logs()),
            None => Ok(with_first.apply_logs()),
        }
    }));
    match replayed {
        Ok(Ok(h)) => Ok(h),
        _ => {
            if crate::parse::is_debug_mode() {
                eprintln!("[DEBUG] MountPoints2: {label}: transaction logs not applied, using the on-disk state");
            }
            Ok(open()?.treat_hive_as_clean())
        }
    }
}

/// Primary and secondary sequence numbers differ: the latest changes may be in the logs.
fn is_dirty(path: &Path) -> bool {
    let mut header = [0u8; 12];
    File::open(path).and_then(|mut f| f.read_exact(&mut header)).is_ok() && header[4..8] != header[8..12]
}

/// Bytes of the (replayed) hive: base block followed by the hive bins.
fn hive_bytes(hive: &mut HiveFile) -> Option<Vec<u8>> {
    let mut buf = Cursor::new(Vec::new());
    hive.write_baseblock(&mut buf).ok()?;
    buf.seek(SeekFrom::Start(BASE_BLOCK_SIZE as u64)).ok()?;
    hive.seek(SeekFrom::Start(0)).ok()?;
    std::io::copy(hive, &mut buf).ok()?;
    Some(buf.into_inner())
}

/// `##SERVER#SHARE` -> (`\\SERVER\SHARE`, `SERVER`), for network share keys only.
fn share_of(key_name: &str) -> Option<(String, String)> {
    if !key_name.starts_with("##") {
        return None;
    }
    let unc_path = key_name.replace('#', "\\");
    let server = unc_path.trim_start_matches('\\').split('\\').next().unwrap_or("").to_string();
    if server.is_empty() {
        return None;
    }
    Some((unc_path, server))
}

fn event(timestamp: String, server: &str, unc_path: &str, username: &str, src_hostname: &str, file: &str, deleted: bool) -> LogData {
    LogData {
        time_created: timestamp,
        computer: server.to_string(),
        event_type: "CONNECT".to_string(),
        event_id: "MountPoints2".to_string(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: username.to_string(),
        target_domain_name: String::new(),
        logon_type: String::new(),
        workstation_name: src_hostname.to_string(),
        ip_address: extract_ip_if_present(server),
        logon_id: String::new(),
        filename: file.to_string(),
        detail: if deleted {
            format!("MountPoints2: {} (deleted key, recovered from a free hive cell)", unc_path)
        } else {
            format!("MountPoints2: {}", unc_path)
        },
    }
}

/// Parse a single NTUSER.DAT and extract MountPoints2 remote share entries, live and deleted.
fn parse_single_ntuser(path: &Path, username: &str, src_hostname: &str) -> Result<Vec<LogData>, String> {
    let mut events = Vec::new();
    let mut hive = open_hive(path)?;
    let dat_path_str = path.to_string_lossy().to_string();

    // Live keys
    let root = hive.root_key_node().map_err(|e| format!("Cannot read the root key: {e}"))?;
    if let Ok(Some(mp2_rc)) = root.subpath(MOUNTPOINTS2_KEY, &mut hive) {
        let mp2 = mp2_rc.borrow();
        let live: Vec<(String, String)> = match mp2.subkeys(&mut hive) {
            Ok(subkeys) => subkeys
                .iter()
                .map(|sub| {
                    let sub = sub.borrow();
                    (sub.name().to_string(), sub.timestamp().format("%Y-%m-%dT%H:%M:%S+00:00").to_string())
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        for (name, timestamp) in live {
            let Some((unc_path, server)) = share_of(&name) else { continue };
            events.push(event(timestamp, &server, &unc_path, username, src_hostname, &dat_path_str, false));
        }
    }

    // Deleted keys still in free cells of the replayed hive
    if let Some(scan) = hive_bytes(&mut hive).as_deref().and_then(blockcarve::hive_cells::scan) {
        for dk in &scan.deleted_keys {
            let parent = dk.path_tail().rsplit_once('\\').map(|(p, _)| p).unwrap_or("");
            if !parent.to_ascii_lowercase().ends_with("\\mountpoints2") && !parent.eq_ignore_ascii_case("MountPoints2") {
                continue;
            }
            let Some((unc_path, server)) = share_of(&dk.key.name) else { continue };
            let timestamp = filetime_to_iso(dk.key.timestamp_filetime);
            if timestamp.is_empty() {
                continue;
            }
            events.push(event(timestamp, &server, &unc_path, username, src_hostname, &dat_path_str, true));
        }
    }

    Ok(events)
}

/// Convert Windows FILETIME (100ns intervals since 1601-01-01) to ISO 8601 string
fn filetime_to_iso(filetime: u64) -> String {
    if filetime == 0 {
        return String::new();
    }
    const FILETIME_UNIX_DIFF: u64 = 11_644_473_600;
    const HUNDRED_NS_PER_SEC: u64 = 10_000_000;

    let secs_since_1601 = filetime / HUNDRED_NS_PER_SEC;
    if secs_since_1601 < FILETIME_UNIX_DIFF {
        return String::new();
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_names() {
        assert_eq!(share_of("##10.0.0.5#C$"), Some(("\\\\10.0.0.5\\C$".to_string(), "10.0.0.5".to_string())));
        assert_eq!(share_of("##FS01#Projects").unwrap().1, "FS01");
        assert!(share_of("{f5bd6a54-0000-0000-0000-100000000000}").is_none());
        assert_eq!(extract_ip_if_present("10.0.0.5"), "10.0.0.5");
        assert_eq!(extract_ip_if_present("FS01"), "");
    }

    /// Real hive from the lab: `MASSTIN_MP2_FIXTURE=<dir with user_NTUSER.DAT and its logs>`.
    /// Expects live and deleted share keys and prints what was found.
    #[test]
    fn real_hive_from_env() {
        let Ok(dir) = std::env::var("MASSTIN_MP2_FIXTURE") else { return };
        let events = parse_mountpoints(Path::new(&dir), "LAB");
        for e in &events {
            println!("{} | {} | {} | {}", e.time_created, e.computer, e.target_user_name, e.detail);
        }
        assert!(events.iter().any(|e| !e.detail.contains("deleted")), "live share keys");
        assert!(events.iter().any(|e| e.detail.contains("deleted")), "deleted share keys");
    }
}
