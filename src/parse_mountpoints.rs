// =============================================================================
//   MountPoints2 registry parser
//   Extracts lateral movement evidence from NTUSER.DAT registry hives.
//   Each ##SERVER#SHARE subkey under MountPoints2 indicates the user
//   connected to a remote share — with LastWriteTime as timestamp.
//
//   A dirty hive first gets its .LOG1/.LOG2 replayed in memory with
//   blockcarve::hive_logs (shared with faramir and caarea): new-format entries
//   verified by their Marvin32 hashes, old Windows 7/8 DIRT logs too. The
//   result is read with nt_hive2. Deleted ##SERVER#SHARE keys are recovered
//   from the free cells of the replayed hive with blockcarve::hive_cells, so
//   a connection the user removed from Explorer still shows up.
// =============================================================================

use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use nt_hive2::{CleanHive, Hive, HiveParseMode, SubPath};

use crate::parse::LogData;

const MOUNTPOINTS2_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2";

type HiveImage = Hive<Cursor<Vec<u8>>, CleanHive>;

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

/// Reads a hive and replays its `.LOG` / `.LOG1` / `.LOG2` when it is dirty. Returns the bytes
/// (base block and bins, marked clean once replayed) and the nt_hive2 view over them. A hive
/// whose logs are missing or unusable is read in its on-disk state.
fn open_hive(path: &Path) -> Result<(Vec<u8>, HiveImage), String> {
    let label = path.display().to_string();
    let raw = std::fs::read(path).map_err(|e| format!("{label}: {e}"))?;
    let replay = blockcarve::hive_logs::replay_beside(path, &raw);
    if crate::parse::is_debug_mode() && !replay.outcome.applied() && blockcarve::hive_logs::is_dirty(&raw) {
        eprintln!("[DEBUG] MountPoints2: {label}: transaction logs not applied ({:?}), using the on-disk state", replay.outcome);
    }
    let bytes = replay.data.into_owned();
    let reader = Cursor::new(bytes.clone());
    match catch_unwind(AssertUnwindSafe(|| Hive::new(reader, HiveParseMode::NormalWithBaseBlock))) {
        Ok(Ok(h)) => Ok((bytes, h.treat_hive_as_clean())),
        Ok(Err(e)) => Err(format!("{label}: {e}")),
        Err(_) => Err(format!("{label}: the hive reader panicked")),
    }
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
    let (bytes, mut hive) = open_hive(path)?;
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
    if let Some(scan) = blockcarve::hive_cells::scan(&bytes) {
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

    /// Same fixture: the hive bins replayed by blockcarve match the ones nt_hive2's own log
    /// applier produces from the same `.LOG1` / `.LOG2`.
    #[test]
    fn replay_matches_nt_hive2_on_real_hive() {
        use nt_hive2::transactionlog::TransactionLog;
        use nt_hive2::ContainsHive;
        use std::io::{Read, Seek, SeekFrom};

        let Ok(dir) = std::env::var("MASSTIN_MP2_FIXTURE") else { return };
        let mut files = Vec::new();
        collect_ntuser_files(Path::new(&dir), &mut files);
        let path = files.first().expect("an *_NTUSER.DAT in the fixture");
        let (ours, _) = open_hive(path).unwrap();

        let file = std::fs::File::open(path).unwrap();
        let hive = Hive::new(std::io::BufReader::new(file), HiveParseMode::NormalWithBaseBlock).unwrap();
        let log = |ext: &str| TransactionLog::try_from(std::fs::File::open(format!("{}.{ext}", path.display())).unwrap()).unwrap();
        let mut theirs = hive.with_transaction_log(log("LOG1")).unwrap().with_transaction_log(log("LOG2")).unwrap().apply_logs();
        let mut bins = Vec::new();
        theirs.seek(SeekFrom::Start(0)).unwrap();
        theirs.read_to_end(&mut bins).unwrap();

        let n = bins.len().min(ours.len() - 4096);
        assert!(n > 0);
        assert_eq!(&ours[4096..4096 + n], &bins[..n], "replayed hive bins differ");
        println!("{n} bytes of hive bins identical");
    }
}
