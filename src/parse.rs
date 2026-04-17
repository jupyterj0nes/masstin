use std::{path::PathBuf, fs::File};
use evtx::EvtxParser;
extern crate serde;
extern crate quick_xml;
use serde::{Serialize, Deserialize};
use quick_xml::de::from_str;
use std::{error::Error, collections::HashMap};
use polars::prelude::*;
use walkdir::WalkDir;
use std::path::Path;
use std::io::{self, Write};
use ::zip::read::ZipArchive;
use std::io::{Read, Cursor, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};

// Global atomic variable to store whether we are in debug mode
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_debug_mode(val: bool) {
    DEBUG_MODE.store(val, Ordering::SeqCst);
}

pub fn is_debug_mode() -> bool {
    DEBUG_MODE.load(Ordering::SeqCst)
}

/// "Massive mode" — set by the parse-massive action. Gates aggressive
/// fallbacks that can add noise or hit quirky EVTX files: currently
/// enables `parse_unknown` (dispatch by Provider.Name in the XML) for
/// EVTX whose filename does not match any known channel, so archived
/// or renamed logs like `Security-YYYY-MM-DD-HH-MM-SS.evtx` still get
/// parsed. Kept off in parse-windows / parse-image for predictability.
static MASSIVE_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_massive_mode(val: bool) {
    MASSIVE_MODE.store(val, Ordering::SeqCst);
}

pub fn is_massive_mode() -> bool {
    MASSIVE_MODE.load(Ordering::SeqCst)
}

/// Normalise IPv6 noise in the IpAddress field from Windows EVTX:
///   - `::ffff:192.168.10.32` → `192.168.10.32` (IPv4-mapped IPv6)
///   - `fe80::...` → `""` (link-local, useless for lateral movement)
/// Without this, each variant creates a separate node in the graph.
/// Infer logon_type for events that lack one natively.
/// Kerberos (4768/4769/4770/4771), NTLM (4776), share access (5140),
/// explicit creds (4648), and WinRM (6) are all network-based in a
/// lateral movement context → type 3.
fn infer_logon_type(event_id: &str, raw: &str) -> String {
    if !raw.is_empty() {
        return raw.to_string();
    }
    match event_id {
        "4768" | "4769" | "4770" | "4771" | "4776" | "5140" | "4648" | "6" => "3".to_string(),
        _ => String::new(),
    }
}

fn strip_ipv4_mapped(ip: &str) -> String {
    if let Some(v4) = ip.strip_prefix("::ffff:") {
        return v4.to_string();
    }
    let lower = ip.to_lowercase();
    if lower.starts_with("fe80:") {
        return String::new();
    }
    ip.to_string()
}

/// Translate Windows SubStatus hex codes to human-readable failure reasons
pub fn translate_substatus(code: &str) -> String {
    let desc = match code.to_lowercase().as_str() {
        "0xc000006a" => "Wrong password",
        "0xc0000064" => "User does not exist",
        "0xc0000072" => "Account disabled",
        "0xc0000234" => "Account locked out",
        "0xc0000070" => "Logon outside allowed hours",
        "0xc000006d" => "Bad username or auth info",
        "0xc0000071" => "Expired password",
        "0xc0000224" => "Password must change",
        "0xc0000193" => "Account expired",
        "0xc000015b" => "Logon type not granted",
        "0xc000006e" => "Unknown user or bad password",
        "0xc0000133" => "Clock skew too great",
        "0xc0000005" => "Access denied",
        _ => "",
    };
    if desc.is_empty() {
        code.to_string()
    } else {
        format!("{} ({})", desc, code)
    }
}

// Event IDs for various logs
// 5145 intentionally excluded: it fires on every file access inside an
// already-established SMB session (50+ events per connection) and adds no
// lateral-movement information beyond what 5140 already captures — the pivot
// (src→dst, user, share) is the same. Including it burns volume without
// adding edges to the graph.
const SECURITY_EVENT_IDS: &[&str] = &["4624","4625","4634","4647","4648","4768","4769","4770","4771","4776","4778","4779","5140"];
const SMBCLIENT_EVENT_IDS: &[&str] = &["31001"];
const SMBCLIENT_CONNECTIVITY_EVENT_IDS: &[&str] = &["30803","30804","30805","30806","30807","30808"];
const SMBSERVER_EVENT_IDS: &[&str] = &["1009","551"];
const RDPCLIENT_EVENT_IDS: &[&str] = &["1024","1102"];
const RDPCONNMANAGER_EVENT_IDS: &[&str] = &["1149"];
const RDPLOCALSESSION_EVENT_IDS: &[&str] = &["21","22","24","25"];
const RDPKORE_EVENT_IDS: &[&str] = &["131"];
const WINRM_EVENT_IDS: &[&str] = &["6"];
const WMI_EVENT_IDS: &[&str] = &["5858"];

pub mod parse {}

// Updated LogData struct with event_type, logon_id, and detail columns.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogData {
    pub time_created: String,
    pub computer: String,
    pub event_type: String,
    pub event_id: String,
    pub subject_user_name: String,
    pub subject_domain_name: String,
    pub target_user_name: String,
    pub target_domain_name: String,
    pub logon_type: String,
    pub workstation_name: String,
    pub ip_address: String,
    pub logon_id: String,
    pub filename: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
enum EvtxLocation {
    File(String), // Normal file in disk
    ZipEntry {
        zip_path: String,  // Path of the .zip file
        evtx_name: String, // Name of the EVTX inside the .zip
    },
}

// =============================================================================
//   Triage package detection (KAPE / Velociraptor / Cortex XDR)
// =============================================================================
//
// When the directory walker encounters a ZIP archive, we read its top-level
// entries and run pattern matching against three known triage tool layouts.
// Detected packages surface as `=> Triage found: ...` lines in phase 1 and
// drive the per-source grouping in the phase 2 breakdown.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TriageType {
    Kape,
    Velociraptor,
    CortexXdr,
}

impl TriageType {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            TriageType::Kape => "KAPE",
            TriageType::Velociraptor => "Velociraptor Offline Collector",
            TriageType::CortexXdr => "Cortex XDR Offline Collector",
        }
    }
    pub(crate) fn short_label(&self) -> &'static str {
        match self {
            TriageType::Kape => "KAPE",
            TriageType::Velociraptor => "Velociraptor",
            TriageType::CortexXdr => "Cortex XDR",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TriageInfo {
    pub kind: TriageType,
    pub zip_path: String,         // outer zip absolute path
    pub hostname: Option<String>, // extracted from filename when possible
    pub artifact_count: usize,    // EVTX or Linux-log entries inside
}

/// Check whether a zip filename (stem, no extension) follows the
/// Velociraptor offline collector naming convention:
///   `<LETTER>_<YYYYMMDD>-<HHMMSS>_<username>`           (e.g. F_20260406-182920_MANAN.SHAH)
///   `Extracted_<LETTER>_<YYYYMMDD>-<HHMMSS>_<username>` (re-zip of an extract)
///
/// The drive-letter prefix, 8-digit date, dash, 6-digit time and underscore
/// delimiters are unique enough that no other DFIR triage tool uses this
/// pattern. Used as a last-resort Velociraptor signature when the in-zip
/// JSON metadata markers are all missing (typical for re-zipped extracts).
fn is_velociraptor_filename(stem: &str) -> bool {
    let without_prefix = stem.strip_prefix("Extracted_").unwrap_or(stem);
    let bytes = without_prefix.as_bytes();
    // Minimum: "X_YYYYMMDD-HHMMSS_Z" → 19 chars
    if bytes.len() < 19 { return false; }
    if !bytes[0].is_ascii_alphabetic() { return false; }
    if bytes[1] != b'_' { return false; }
    // 8 digits (date)
    if !bytes[2..10].iter().all(|b| b.is_ascii_digit()) { return false; }
    if bytes[10] != b'-' { return false; }
    // 6 digits (time)
    if !bytes[11..17].iter().all(|b| b.is_ascii_digit()) { return false; }
    if bytes[17] != b'_' { return false; }
    // At least one more character for the username
    bytes.len() > 18
}

/// Check whether the zip path lives under a directory literally named
/// `Velociraptor` (case-insensitive). Velociraptor's offline collector
/// convention is to drop the output under a `Velociraptor/` subfolder.
/// Safe heuristic: no other DFIR tool uses this directory name.
fn is_velociraptor_path(zip_path: &str) -> bool {
    let normalized = zip_path.replace('\\', "/").to_lowercase();
    normalized.contains("/velociraptor/")
}

/// Detect what kind of triage package a ZIP is, based on its top-level entry
/// list AND its filename/path (Velociraptor re-zips can lose every JSON
/// metadata marker but still keep the distinctive `<LETTER>_<date>_<user>.zip`
/// filename convention under a `Velociraptor/` parent directory).
/// Returns None if the ZIP doesn't match any known triage layout.
pub(crate) fn detect_triage_type(zip_path: &str, entries: &[String]) -> Option<TriageType> {
    // 1. Cortex XDR Offline Collector — REQUIRE BOTH `output/manifest.json`
    //    AND `output/cortex-xdr-payload.log` together at the OUTER zip root.
    //
    //    The single-file marker (`cortex-xdr-payload.log` anywhere) is too
    //    loose: each Cortex XDR collection contains ~80 inner script_output.zip
    //    archives (one per artifact module), and EVERY one of them has
    //    `cortex-xdr-payload.log` at ITS root. If a user has an extracted
    //    Cortex XDR triage on disk, the directory walker hits each of those
    //    inner zips and would fire ~80 false-positive "Triage found" lines.
    //
    //    The combination `output/manifest.json` + `output/cortex-xdr-payload.log`
    //    only occurs at the outer offline_collector_output_*.zip top level.
    //    Inner script_output.zip files have neither (they have a
    //    different `manifest.json` at their own root, not under `output/`,
    //    and their cortex-xdr-payload.log is not under `output/` either).
    let has_outer_manifest = entries.iter().any(|n| {
        let lower = n.to_lowercase();
        lower == "output/manifest.json"
    });
    let has_outer_payload = entries.iter().any(|n| {
        let lower = n.to_lowercase();
        lower == "output/cortex-xdr-payload.log"
    });
    if has_outer_manifest && has_outer_payload {
        return Some(TriageType::CortexXdr);
    }

    // 2. Velociraptor Offline Collector — three matching paths.
    //    a) Root files combine
    //         client_info.json + (collection_context.json OR uploads.json)
    //    b) Encrypted variant: metadata.json + data.zip at root
    //    c) Re-zipped extract heuristic: any path containing `uploads/auto/`
    //       or `uploads/ntfs/`. These subdirectories are unique to
    //       Velociraptor (the offline collector stores files via the
    //       ntfs / auto accessors at those paths) and survive re-zipping
    //       even when the original root JSON metadata files end up under
    //       a subdirectory after extraction + re-zip.
    //
    //    The match patterns accept the marker at any level (root or under
    //    a subdirectory) so a user who extracted a Velociraptor zip and
    //    then re-zipped the resulting folder still gets correctly detected
    //    as Velociraptor instead of falling through to the KAPE fallback.
    let has_client_info = entries.iter().any(|n| n == "client_info.json" || n.ends_with("/client_info.json"));
    let has_collection_context = entries.iter().any(|n| n == "collection_context.json" || n.ends_with("/collection_context.json"));
    let has_uploads_json = entries.iter().any(|n| n == "uploads.json" || n.ends_with("/uploads.json"));
    if has_client_info && (has_collection_context || has_uploads_json) {
        return Some(TriageType::Velociraptor);
    }
    let has_metadata = entries.iter().any(|n| n == "metadata.json" || n.ends_with("/metadata.json"));
    let has_data_zip = entries.iter().any(|n| n == "data.zip" || n.ends_with("/data.zip"));
    if has_metadata && has_data_zip {
        return Some(TriageType::Velociraptor);
    }
    let has_vr_uploads = entries.iter().any(|n| {
        let normalized = n.replace('\\', "/");
        normalized.contains("uploads/auto/") || normalized.contains("uploads/ntfs/")
    });
    if has_vr_uploads {
        return Some(TriageType::Velociraptor);
    }
    //    d) Filename pattern heuristic — Velociraptor's offline collector
    //       produces archives with a very distinctive naming convention:
    //         <LETTER>_<YYYYMMDD>-<HHMMSS>_<username>.zip
    //         Extracted_<LETTER>_<YYYYMMDD>-<HHMMSS>_<username>.zip
    //       No other DFIR triage tool uses this pattern. We check the zip
    //       filename BEFORE falling through to KAPE so a re-zipped VR extract
    //       (which loses every JSON metadata marker and flattens the uploads/
    //       subtree, looking layout-wise like a KAPE triage to the fallback
    //       heuristic) still gets correctly classified as Velociraptor.
    //    e) Path heuristic — the zip lives under a directory literally named
    //       "Velociraptor" (the offline collector convention). Also unique.
    let zip_stem = std::path::Path::new(zip_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if is_velociraptor_filename(zip_stem) || is_velociraptor_path(zip_path) {
        return Some(TriageType::Velociraptor);
    }

    // 3. KAPE — direct markers first (the kape command-line file or run log)
    let has_kape_marker = entries.iter().any(|n| {
        let lower = n.to_lowercase();
        lower == "_kape.cli"
            || lower.ends_with("/_kape.cli")
            || (lower.ends_with("/kape.log") && lower.contains("/console/"))
    });
    if has_kape_marker {
        return Some(TriageType::Kape);
    }
    // KAPE fallback heuristic: many entries matching the typical layout
    //   <hostname>/C/Windows/System32/winevt/Logs/*.evtx
    let kape_layout_count = entries.iter().filter(|n| {
        let normalized = n.replace('\\', "/").to_lowercase();
        normalized.contains("/c/windows/system32/winevt/logs/")
            || normalized.starts_with("c/windows/system32/winevt/logs/")
    }).count();
    if kape_layout_count >= 5 {
        return Some(TriageType::Kape);
    }

    None
}

/// Best-effort hostname extraction from a triage zip filename.
pub(crate) fn extract_triage_hostname(zip_path: &str, kind: TriageType) -> Option<String> {
    let stem = std::path::Path::new(zip_path)
        .file_stem()
        .and_then(|s| s.to_str())?;
    match kind {
        TriageType::CortexXdr => {
            // offline_collector_output_<HOST>_<YYYY-MM-DD>_<HH-MM-SS>
            let prefix = "offline_collector_output_";
            if !stem.starts_with(prefix) { return None; }
            let rest = &stem[prefix.len()..];
            // Find the first '_' followed by a 4-digit year + '-' (date pattern)
            let bytes = rest.as_bytes();
            for (i, &b) in bytes.iter().enumerate() {
                if b == b'_' && i + 5 < bytes.len() {
                    let next4 = &bytes[i+1..i+5];
                    if next4.iter().all(|c| c.is_ascii_digit()) && bytes[i+5] == b'-' {
                        return Some(rest[..i].to_string());
                    }
                }
            }
            None
        }
        TriageType::Velociraptor => {
            // Collection-<HOST>-<TIMESTAMP> (timestamp starts with 4-digit year)
            let prefix = "Collection-";
            if !stem.starts_with(prefix) { return None; }
            let rest = &stem[prefix.len()..];
            let bytes = rest.as_bytes();
            for (i, &b) in bytes.iter().enumerate() {
                if b == b'-' && i + 1 < bytes.len() && bytes[i+1].is_ascii_digit() {
                    return Some(rest[..i].to_string());
                }
            }
            None
        }
        TriageType::Kape => {
            // KAPE has no enforced filename pattern. Common operator conventions:
            //   <hostname>_<YYYYMMDD>_<HHMMSS>.zip
            //   <hostname>_<timestamp>.zip
            // Only return a hostname when the stem clearly has a "<word>_<digits>"
            // shape so we don't misreport the zip basename as a hostname for
            // arbitrary names like "kape-output.zip".
            let mut parts = stem.splitn(2, '_');
            let head = parts.next()?;
            let tail = parts.next()?;
            // Tail must start with at least 4 digits to look like a date/time stamp
            let tail_starts_with_digits = tail.chars().take(4).all(|c| c.is_ascii_digit());
            if tail_starts_with_digits && !head.is_empty() {
                Some(head.to_string())
            } else {
                None
            }
        }
    }
}

/// Read the top-level entry names of a ZIP without recursion. Used by the
/// triage detector so it can scan the file listing once and decide the type.
pub(crate) fn read_zip_top_entries(zip_path: &Path) -> Option<Vec<String>> {
    let file = File::open(zip_path).ok()?;
    let mut archive = ZipArchive::new(file).ok()?;
    let mut names = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            names.push(entry.name().to_string());
        }
    }
    Some(names)
}

/// Source label helper for parse-linux. Linux artifacts come from one of:
///   - A forensic image extract dir (path contains "masstin_image_extract/")
///   - A triage extraction temp dir (mapped via `triage_dirs`)
///   - A regular folder on disk (loose auth.log, wtmp, etc.)
pub(crate) fn source_label_for_linux_path(
    path: &str,
    triage_dirs: &[(std::path::PathBuf, TriageInfo)],
) -> String {
    let normalized = path.replace('\\', "/");
    // 1. Triage extraction match
    for (dir, info) in triage_dirs {
        let dir_str = dir.to_string_lossy().replace('\\', "/");
        if !dir_str.is_empty() && normalized.starts_with(&dir_str) {
            let zip_name = std::path::Path::new(&info.zip_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&info.zip_path);
            let host_part = info.hostname.as_ref()
                .map(|h| format!("  [host: {}]", h))
                .unwrap_or_default();
            return format!("[TRIAGE: {}]  {}{}", info.kind.short_label(), zip_name, host_part);
        }
    }
    // 2. Forensic image extract
    if let Some(image) = extract_image_name_from_extract_path(path) {
        return format!("[IMAGE]  {}", image);
    }
    // 3. Loose folder
    let parent = std::path::Path::new(path)
        .parent()
        .and_then(|p| p.to_str())
        .map(|s| s.replace('\\', "/"))
        .unwrap_or_else(|| path.replace('\\', "/"));
    format!("[FOLDER]  {}", parent)
}

/// Result of the discovery walk: EVTX locations + any triage packages
/// detected at top-level zips along the way.
pub(crate) struct DiscoveryResult {
    pub evtx_files: Vec<EvtxLocation>,
    pub triages: Vec<TriageInfo>,
    pub archives_scanned: usize,        // total zips opened (bug #4)
    pub archives_with_evtx: usize,      // zips that contributed at least one evtx
}

/// Categories used to group artifacts in the phase-2 breakdown. The string
/// inside is the source label printed to the user (e.g. "[IMAGE]  HRServer.e01"
/// or "[TRIAGE: Cortex XDR]  offline_collector_...zip  [host: STFVEEAMPRXY01]").
pub(crate) fn source_label_for_evtx(
    loc: &EvtxLocation,
    triages: &std::collections::HashMap<String, TriageInfo>,
) -> String {
    match loc {
        EvtxLocation::File(path) => {
            // parse-image extracts EVTX into a temp dir whose path contains
            // the marker "masstin_image_extract/" — group by the image name.
            if let Some(image) = extract_image_name_from_extract_path(path) {
                return format!("[IMAGE]  {}", image);
            }
            // Loose EVTX: group by full parent-directory path.
            let parent = std::path::Path::new(path)
                .parent()
                .and_then(|p| p.to_str())
                .map(|s| s.replace('\\', "/"))
                .unwrap_or_else(|| path.replace('\\', "/"));
            format!("[FOLDER]  {}", parent)
        }
        EvtxLocation::ZipEntry { zip_path, .. } => {
            // zip_path is "outer.zip" or "outer.zip -> nested.zip"; we display
            // the OUTER zip and use it as triage map key.
            let outer = zip_path.split(" -> ").next().unwrap_or(zip_path);
            let path = std::path::Path::new(outer);
            let zip_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(outer);
            // Include the immediate parent directory in the displayed name so
            // two physical copies of the same triage zip living in different
            // folders (e.g. SFTP/.../host.zip vs To-Unit42/.../host.zip)
            // appear as DIFFERENT source groups instead of collapsing into
            // one bucket with duplicated entries inside.
            let parent_hint = path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .map(|s| format!("{}/", s))
                .unwrap_or_default();
            let display_name = format!("{}{}", parent_hint, zip_name);
            if let Some(info) = triages.get(outer) {
                let host_part = info.hostname.as_ref()
                    .map(|h| format!("  [host: {}]", h))
                    .unwrap_or_default();
                return format!("[TRIAGE: {}]  {}{}", info.kind.short_label(), display_name, host_part);
            }
            format!("[ARCHIVE]  {}", display_name)
        }
    }
}

/// Source label for non-EVTX artifacts whose origin is a regular filesystem
/// path (e.g. UAL .mdb files, MountPoints2 NTUSER.DAT hives). They never come
/// from inside a ZIP in the current code paths, so no triage handling is needed.
pub(crate) fn source_label_for_path(path: &str) -> String {
    if let Some(image) = extract_image_name_from_extract_path(path) {
        return format!("[IMAGE]  {}", image);
    }
    let parent = std::path::Path::new(path)
        .parent()
        .and_then(|p| p.to_str())
        .map(|s| s.replace('\\', "/"))
        .unwrap_or_else(|| path.replace('\\', "/"));
    format!("[FOLDER]  {}", parent)
}

fn extract_image_name_from_extract_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let marker = "masstin_image_extract/";
    let pos = normalized.find(marker)?;
    let after = &normalized[pos + marker.len()..];
    let dir_name = after.split('/').next()?;
    // Strip numeric prefix added for uniqueness ("0_HRServer.e01" -> "HRServer.e01")
    if let Some(underscore) = dir_name.find('_') {
        let prefix = &dir_name[..underscore];
        if !prefix.is_empty() && prefix.chars().all(|c| c.is_ascii_digit()) {
            return Some(dir_name[underscore + 1..].to_string());
        }
    }
    Some(dir_name.to_string())
}

/// Detect a VSS snapshot index in an extracted-EVTX path.
///
/// parse-image extracts EVTX files from forensic images into a temp directory
/// whose path contains the marker "masstin_image_extract/". Within that, live
/// partitions go to "partition_<N>/" and VSS snapshots go to
/// "partition_<N>_vss_<M>/". The latter is what we look for.
///
///   ".../masstin_image_extract/HRServer.e01/evtx_extracted/partition_0/Security.evtx"
///       → None (live)
///   ".../masstin_image_extract/HRServer.e01/evtx_extracted/partition_0_vss_0/Security.evtx"
///       → Some(0) (VSS snapshot 0)
///   ".../masstin_image_extract/HRServer.e01/evtx_extracted/partition_1_vss_2/Security.evtx"
///       → Some(2) (VSS snapshot 2)
pub(crate) fn detect_vss_index(path: &str) -> Option<u32> {
    let normalized = path.replace('\\', "/");
    let pos = normalized.find("_vss_")?;
    let after = &normalized[pos + "_vss_".len()..];
    let end = after.find('/').unwrap_or(after.len());
    after[..end].parse::<u32>().ok()
}

// ---------------------------------------------------------------------------------------
// SECURITY LOG PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_security_log(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            // If there's an error initializing, return empty
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event = match from_str(&data) {
                    Ok(event) => event,
                    Err(_) => {
                        continue;
                    },
                };
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        // Extend the map with ProcessName, Status, SubStatus, TargetLogonId keys.
                        let mut data_values: HashMap<String, String> = [
                            ("SubjectUserName".to_string(), String::from("")),
                            ("SubjectDomainName".to_string(), String::from("")),
                            ("TargetUserName".to_string(), String::from("")),
                            ("TargetDomainName".to_string(), String::from("")),
                            ("LogonType".to_string(), String::from("")),
                            ("WorkstationName".to_string(), String::from("")),
                            ("IpAddress".to_string(), String::from("")),
                            ("ProcessName".to_string(), String::from("")),
                            ("Status".to_string(), String::from("")),
                            ("SubStatus".to_string(), String::from("")),
                            ("TargetLogonId".to_string(), String::from("")),
                            ("ShareName".to_string(), String::from("")),
                            ("RelativeTargetName".to_string(), String::from("")),
                        ].iter().cloned().collect();

                        if let Some(event_data) = event.EventData {
                            for data in event_data.Datas {
                                if let Some(name) = data.Name {
                                    if let Some(data_value) = data_values.get_mut(&name) {
                                        *data_value = data.body.as_ref().unwrap_or(&"".to_string()).clone();
                                    }
                                }
                            }
                        }

                        // Classify event_type based on event ID
                        let status = data_values.get("Status").unwrap().as_str();
                        let event_type = match event_id.as_str() {
                            "4624" => "SUCCESSFUL_LOGON".to_string(),
                            "4625" => "FAILED_LOGON".to_string(),
                            "4634" => "LOGOFF".to_string(),
                            "4647" => "LOGOFF".to_string(),
                            "4648" => "SUCCESSFUL_LOGON".to_string(),
                            "4768" | "4769" | "4776" => {
                                if status == "0x0" { "SUCCESSFUL_LOGON".to_string() } else { "FAILED_LOGON".to_string() }
                            },
                            "4770" => "SUCCESSFUL_LOGON".to_string(),
                            "4771" => "FAILED_LOGON".to_string(),
                            "4778" => "SUCCESSFUL_LOGON".to_string(),
                            "4779" => "LOGOFF".to_string(),
                            "5140" => "SUCCESSFUL_LOGON".to_string(),
                            _ => "CONNECT".to_string(),
                        };

                        // Determine detail column
                        let share_name = data_values.get("ShareName").unwrap_or(&String::new()).to_string();
                        let detail = match event_id.as_str() {
                            "4624" | "4648" => data_values.get("ProcessName").unwrap_or(&String::new()).to_string(),
                            "4625" => translate_substatus(data_values.get("SubStatus").unwrap_or(&String::new())),
                            "5140" => share_name,
                            _ => String::from(""),
                        };

                        let logon_type = infer_logon_type(&event_id, data_values.get("LogonType").unwrap_or(&String::new()));
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap_or_default(),
                            computer: event.System.Computer.unwrap_or_default(),
                            event_type,
                            event_id,
                            subject_user_name: data_values.get("SubjectUserName").unwrap_or(&String::new()).to_string(),
                            subject_domain_name: data_values.get("SubjectDomainName").unwrap_or(&String::new()).to_string(),
                            target_user_name: data_values.get("TargetUserName").unwrap_or(&String::new()).to_string(),
                            target_domain_name: data_values.get("TargetDomainName").unwrap_or(&String::new()).to_string(),
                            logon_type,
                            workstation_name: data_values.get("WorkstationName").unwrap_or(&String::new()).to_string(),
                            ip_address: strip_ipv4_mapped(data_values.get("IpAddress").unwrap_or(&String::new())),
                            logon_id: data_values.get("TargetLogonId").unwrap_or(&String::new()).to_string(),
                            filename: file.to_string(),
                            detail,
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// SMB SERVER PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_smb_server(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event2 = match from_str(&data) { Ok(e) => e, Err(_) => continue };
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        let event_type = match event_id.as_str() {
                            "1009" => "SUCCESSFUL_LOGON".to_string(),
                            "551" => "FAILED_LOGON".to_string(),
                            _ => "CONNECT".to_string(),
                        };
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap_or_default(),
                            computer: event.System.Computer.unwrap_or_default(),
                            event_type,
                            event_id,
                            subject_user_name: event.System.Security.as_ref().and_then(|s| s.UserID.as_ref()).cloned().unwrap_or_default(),
                            subject_domain_name: String::from(""),
                            target_user_name: event.UserData.as_ref().unwrap().EventData.as_ref().unwrap().UserName.as_ref().unwrap_or(&String::from("")).to_owned(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("3"),
                            workstation_name: event.UserData.as_ref().unwrap().EventData.as_ref().unwrap().ClientName.as_ref().unwrap_or(&String::from("")).to_owned(),
                            ip_address: event.UserData.as_ref().unwrap().EventData.as_ref().unwrap().ClientName.as_ref().unwrap_or(&String::from("")).to_owned(),
                            logon_id: String::from(""),
                            filename: file.to_string(),
                            detail: String::from(""),
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// SMB CLIENT PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_smb_client(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event = match from_str(&data) { Ok(e) => e, Err(_) => continue };
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        let mut data_values: HashMap<String, String> = [
                            ("UserName".to_string(), String::from("")),
                            ("ServerName".to_string(), String::from("")),
                            ("ShareName".to_string(), String::from("")),
                        ].iter().cloned().collect();

                        if let Some(event_data) = event.EventData {
                            for data in event_data.Datas {
                                if let Some(name) = data.Name {
                                    if let Some(data_value) = data_values.get_mut(&name) {
                                        *data_value = data.body.as_ref().unwrap_or(&"".to_string()).clone();
                                    }
                                }
                            }
                        } else { continue; }

                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap_or_default(),
                            computer: data_values.get("ServerName").unwrap_or(&String::new()).to_string(),
                            event_type: "SUCCESSFUL_LOGON".to_string(),
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: data_values.get("UserName").unwrap_or(&String::new()).to_string(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("3"),
                            workstation_name: event.System.Computer.as_deref().unwrap_or("").to_owned(),
                            ip_address: event.System.Computer.as_deref().unwrap_or("").to_owned(),
                            logon_id: String::from(""),
                            filename: file.to_string(),
                            detail: data_values.get("ShareName").unwrap_or(&String::new()).to_string(),
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// SMB CLIENT CONNECTIVITY PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_smb_client_connectivity(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event = match from_str(&data) { Ok(e) => e, Err(_) => continue };
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        let mut data_values: HashMap<String, String> = [
                            ("UserName".to_string(), String::from("")),
                            ("ServerName".to_string(), String::from(""))
                        ].iter().cloned().collect();

                        let event_data = match event.EventData { Some(ed) => ed, None => continue };
                        for data in event_data.Datas {
                            if let Some(name) = data.Name {
                                if let Some(data_value) = data_values.get_mut(&name) {
                                    *data_value = data.body.as_ref().unwrap_or(&"".to_string()).clone();
                                }
                            }
                        }

                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap_or_default(),
                            computer: data_values.get("ServerName").unwrap_or(&String::new()).to_string(),
                            event_type: "CONNECT".to_string(),
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: data_values.get("UserName").unwrap_or(&String::new()).to_string(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("3"),
                            workstation_name: event.System.Computer.as_deref().unwrap_or("").to_owned(),
                            ip_address: event.System.Computer.as_deref().unwrap_or("").to_owned(),
                            logon_id: String::from(""),
                            filename: file.to_string(),
                            detail: String::from(""),
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// RDP CLIENT PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_rdp_client(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event = match from_str(&data) { Ok(e) => e, Err(_) => continue };
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        let mut data_values: HashMap<String, String> = [
                            ("Value".to_string(), String::from(""))
                        ].iter().cloned().collect();

                        let event_data = match event.EventData { Some(ed) => ed, None => continue };
                        for data in event_data.Datas {
                            if let Some(name) = data.Name {
                                if let Some(data_value) = data_values.get_mut(&name) {
                                    *data_value = data.body.as_ref().unwrap_or(&"".to_string()).clone();
                                }
                            }
                        }

                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap_or_default(),
                            computer: data_values.get("Value").unwrap_or(&String::new()).to_string(),
                            event_type: "CONNECT".to_string(),
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: event.System.Security.as_ref().and_then(|s| s.UserID.clone()).unwrap_or_default(),
                            target_domain_name: String::from(""),
                            logon_type: String::from("10"),
                            workstation_name: event.System.Computer.as_deref().unwrap_or("").to_owned(),
                            ip_address: event.System.Computer.as_deref().unwrap_or("").to_owned(),
                            logon_id: String::from(""),
                            filename: file.to_string(),
                            detail: String::from(""),
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// RDP CONNECTION MANAGER PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_rdp_connmanager(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    let mut log_data = Vec::new();

    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing RDP ConnManager {}", file);
    }
    let (mut parser, _) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((p, _)) => (p, ()),
        Err(_) => return log_data,
    };

    for record in parser.records() {
        let r = match record {
            Ok(r) => r,
            Err(_) => continue,
        };
        let xml = r.data.as_str();
        let event: Event2 = match from_str(&xml) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // 1) EventID presente y coincidente
        let event_id = match event.System.EventID {
            Some(ref id) if lateral_event_ids.contains(&id.as_str()) => id.clone(),
            _ => continue,
        };

        // 2) TimeCreated y Computer (salen siempre en System)
        let time_created = event
            .System
            .TimeCreated
            .SystemTime
            .unwrap_or_else(|| {
                if is_debug_mode() {
                    println!("[DEBUG] Missing TimeCreated in RDP ConnManager record, skipping");
                }
                return String::new();
            });
        if time_created.is_empty() {
            continue;
        }

        let computer = event.System.Computer.unwrap_or_else(|| {
            if is_debug_mode() {
                println!("[DEBUG] Missing Computer in RDP ConnManager record, skipping");
            }
            String::new()
        });
        if computer.is_empty() {
            continue;
        }

        // 3) UserData → EventData → UserName / ClientName
        let (target_user, client) = if let Some(ud) = event.UserData.as_ref() {
            if let Some(ed) = ud.EventData.as_ref() {
                let u = ed.UserName.clone().unwrap_or_default();
                let c = ed.ClientName.clone().unwrap_or_default();
                (u, c)
            } else {
                if is_debug_mode() {
                    println!("[DEBUG] Missing EventData in RDP ConnManager record, skipping");
                }
                continue;
            }
        } else {
            if is_debug_mode() {
                println!("[DEBUG] Missing UserData in RDP ConnManager record, skipping");
            }
            continue;
        };

        // Finalmente, construimos el LogData
        log_data.push(LogData {
            time_created,
            computer,
            event_type: "SUCCESSFUL_LOGON".to_string(),
            event_id,
            subject_user_name: String::new(),
            subject_domain_name: String::new(),
            target_user_name: target_user,
            target_domain_name: String::new(),
            logon_type: "10".into(),
            workstation_name: client.clone(),
            ip_address: client,
            logon_id: String::new(),
            filename: file.to_string(),
            detail: String::new(),
        });
    }

    log_data
}


// ---------------------------------------------------------------------------------------
// RDP LOCAL SESSION MANAGER PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_rdp_localsession(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event2 = match from_str(&data) { Ok(e) => e, Err(_) => continue };
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        let mut remotedomain = String::from("");
                        let mut remoteuser = event.UserData.as_ref().and_then(|ud| ud.EventXML.as_ref()).and_then(|xml| xml.User.as_ref()).cloned().unwrap_or_default();

                        if remoteuser.contains("\\") {
                            let parts: Vec<&str> = remoteuser.split("\\").collect();
                            remotedomain = parts[0].to_string();
                            remoteuser = parts[1].to_string();
                        }

                        let event_type = match event_id.as_str() {
                            "21" | "22" | "25" => "SUCCESSFUL_LOGON".to_string(),
                            "24" => "LOGOFF".to_string(),
                            _ => "CONNECT".to_string(),
                        };
                        // Try to extract SessionId for logon_id
                        let session_id = event.UserData.as_ref()
                            .and_then(|ud| ud.EventXML.as_ref())
                            .and_then(|xml| xml.Param1.as_ref())
                            .cloned()
                            .unwrap_or_default();
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap_or_default(),
                            computer: event.System.Computer.unwrap_or_default(),
                            event_type,
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: remoteuser,
                            target_domain_name: remotedomain,
                            logon_type: String::from("10"),
                            workstation_name: event.UserData.as_ref().and_then(|ud| ud.EventXML.as_ref()).and_then(|xml| xml.Address.as_ref()).cloned().unwrap_or_default(),
                            ip_address: event.UserData.as_ref().and_then(|ud| ud.EventXML.as_ref()).and_then(|xml| xml.Address.as_ref()).cloned().unwrap_or_default(),
                            logon_id: session_id,
                            filename: file.to_string(),
                            detail: String::from(""),
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// RDP KORE PARSER
// ---------------------------------------------------------------------------------------
pub fn parse_rdpkore(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event = match from_str(&data) { Ok(e) => e, Err(_) => continue };
                if let Some(event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        let mut data_values: HashMap<String, String> = [
                            ("ClientIP".to_string(), String::from(""))
                        ].iter().cloned().collect();

                        let event_data = match event.EventData { Some(ed) => ed, None => continue };
                        for data in event_data.Datas {
                            if let Some(name) = data.Name {
                                if let Some(data_value) = data_values.get_mut(&name) {
                                    *data_value = data.body.as_ref().unwrap_or(&"".to_string()).clone();
                                }
                            }
                        }
                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap_or_default(),
                            computer: event.System.Computer.unwrap_or_default(),
                            event_type: "CONNECT".to_string(),
                            event_id,
                            subject_user_name: String::from(""),
                            subject_domain_name: String::from(""),
                            target_user_name: String::from(""),
                            target_domain_name: String::from(""),
                            logon_type: String::from("10"),
                            workstation_name: data_values.get("ClientIP").unwrap_or(&String::new()).to_string(),
                            ip_address: data_values.get("ClientIP").unwrap_or(&String::new()).to_string(),
                            logon_id: String::from(""),
                            filename: file.to_string(),
                            detail: String::from(""),
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// WINRM PARSER (Microsoft-Windows-WinRM/Operational)
// Event ID 6: WinRM session init on source system — connection field has destination host
// ---------------------------------------------------------------------------------------
pub fn parse_winrm(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing WinRM {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                let event: Event = match from_str(&data) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                if let Some(ref event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        let mut connection = String::new();

                        if let Some(ref event_data) = event.EventData {
                            for data in &event_data.Datas {
                                if let Some(ref name) = data.Name {
                                    if name == "connection" {
                                        connection = data.body.as_ref().unwrap_or(&String::new()).clone();
                                    }
                                }
                            }
                        }

                        if connection.is_empty() {
                            continue;
                        }

                        // Parse destination from connection string
                        // Format: "hostname/wsman?PSVersion=..." or "http://ip:5985/wsman" or just "hostname/wsman"
                        let dst_host = extract_host_from_winrm_connection(&connection);

                        // Skip empty, localhost, and self-connections
                        if dst_host.is_empty() || dst_host.eq_ignore_ascii_case("localhost") || dst_host == "127.0.0.1" || dst_host == "::1" {
                            continue;
                        }
                        let src_host = event.System.Computer.as_deref().unwrap_or("");
                        let dst_short = dst_host.split('.').next().unwrap_or(&dst_host);
                        let src_short = src_host.split('.').next().unwrap_or(src_host);
                        if dst_short.eq_ignore_ascii_case(src_short) {
                            continue;
                        }

                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap_or_default(),
                            computer: event.System.Computer.unwrap_or_default(),
                            event_type: "CONNECT".to_string(),
                            event_id: event_id.clone(),
                            subject_user_name: String::new(),
                            subject_domain_name: String::new(),
                            target_user_name: String::new(),
                            target_domain_name: String::new(),
                            logon_type: String::new(),
                            workstation_name: dst_host.clone(),
                            ip_address: dst_host,
                            logon_id: String::new(),
                            filename: file.to_string(),
                            detail: format!("WinRM: {}", connection),
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

/// Extract hostname or IP from WinRM connection string.
/// Examples: "dc01/wsman?PSVersion=5.1", "http://192.168.1.10:5985/wsman", "server.domain.com/wsman"
fn extract_host_from_winrm_connection(connection: &str) -> String {
    let s = connection.trim();
    // Strip protocol prefix if present
    let s = s.strip_prefix("http://").or_else(|| s.strip_prefix("https://")).unwrap_or(s);
    // Take everything before the first '/'
    let host = s.split('/').next().unwrap_or("");
    // Strip port if present (e.g., "192.168.1.10:5985")
    let host = host.split(':').next().unwrap_or(host);
    host.to_string()
}

// ---------------------------------------------------------------------------------------
// WMI PARSER (Microsoft-Windows-WMI-Activity/Operational)
// Event ID 5858: WMI client failure — ClientMachine field identifies remote origin
// Only produces events when ClientMachine != Computer (i.e., remote WMI)
// ---------------------------------------------------------------------------------------
pub fn parse_wmi(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing WMI {}", file);
    }

    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    for record in parser.records() {
        match record {
            Ok(r) => {
                let data = r.data.as_str();
                // WMI uses UserData with Operation_ClientFailure, but serde can handle
                // it via the generic Event struct if we extract fields manually from XML
                let event: EventWMI = match from_str(&data) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                if let Some(ref event_id) = event.System.EventID {
                    if lateral_event_ids.contains(&event_id.as_str()) {
                        let (client_machine, user, operation) = match event.UserData {
                            Some(ref ud) => {
                                let cm = ud.client_machine().unwrap_or_default();
                                let u = ud.user().unwrap_or_default();
                                let op = ud.operation().unwrap_or_default();
                                (cm, u, op)
                            }
                            None => continue,
                        };

                        let computer = event.System.Computer.clone().unwrap_or_default();

                        // Only include remote WMI: ClientMachine must differ from Computer
                        // Compare short names to handle FQDN vs NetBIOS (e.g., "SRV01" vs "SRV01.domain.local")
                        let cm_short = client_machine.split('.').next().unwrap_or(&client_machine);
                        let comp_short = computer.split('.').next().unwrap_or(&computer);
                        if client_machine.is_empty() || cm_short.eq_ignore_ascii_case(comp_short) {
                            continue;
                        }

                        // Parse user: may be "DOMAIN\user" or just "user"
                        let (domain, username) = if let Some(pos) = user.find('\\') {
                            (user[..pos].to_string(), user[pos + 1..].to_string())
                        } else {
                            (String::new(), user.clone())
                        };

                        // Skip SYSTEM/LOCAL SERVICE noise
                        if username == "SYSTEM" || username == "LOCAL SERVICE" || username == "NETWORK SERVICE" {
                            continue;
                        }

                        log_data.push(LogData {
                            time_created: event.System.TimeCreated.SystemTime.unwrap_or_default(),
                            computer,
                            event_type: "CONNECT".to_string(),
                            event_id: event_id.clone(),
                            subject_user_name: String::new(),
                            subject_domain_name: String::new(),
                            target_user_name: username,
                            target_domain_name: domain,
                            logon_type: String::new(),
                            workstation_name: client_machine.clone(),
                            ip_address: client_machine,
                            logon_id: String::new(),
                            filename: file.to_string(),
                            detail: if operation.len() > 100 { format!("WMI: {}...", &operation[..100]) } else { format!("WMI: {}", operation) },
                        });
                    }
                }
            },
            Err(_) => (),
        }
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// UNKNOWN PARSER (AUTODETECT PROVIDER)
// ---------------------------------------------------------------------------------------
pub fn parse_unknown(file: &str) -> Vec<LogData> {
    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok((parser, log_data)) => (parser, log_data),
        Err(_) => {
            return vec![];
        }
    };

    let mut provider = String::from("");
    if let Some(Ok(r)) = parser.records().nth(1) {
        let data = r.data.as_str();
        if let Ok(event) = from_str::<Event>(&data) {
            provider = event.System.Provider.Name.unwrap_or_default();
        }
    }

    match provider.as_str() {
        "Microsoft-Windows-Security-Auditing" => {
            log_data = parse_security_log(file, SECURITY_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-SMBServer" => {
            log_data = parse_smb_server(file, SMBSERVER_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-SMBClient" => {
            log_data = parse_smb_client(file, SMBCLIENT_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-TerminalServices-ClientActiveXCore" => {
            log_data = parse_rdp_client(file, RDPCLIENT_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager" => {
            log_data = parse_rdp_connmanager(file, RDPCONNMANAGER_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-TerminalServices-LocalSessionManager" => {
            log_data = parse_rdp_localsession(file, RDPLOCALSESSION_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS" => {
            log_data = parse_rdpkore(file, RDPKORE_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-SmbClient%4Connectivity.evtx" => {
            log_data = parse_smb_client_connectivity(file, SMBCLIENT_CONNECTIVITY_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-WinRM" => {
            log_data = parse_winrm(file, WINRM_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-WMI-Activity" => {
            log_data = parse_wmi(file, WMI_EVENT_IDS.to_vec())
        },
        _ => (),
    }
    log_data
}

// ---------------------------------------------------------------------------------------
// PREPARE PARSE (DISK FILE OR ZIP FILE)
// ---------------------------------------------------------------------------------------
fn prep_parse(file: EvtxLocation) -> Result<(EvtxParser<Cursor<Vec<u8>>>, Vec<LogData>), Box<dyn Error>> {
    let log_data: Vec<LogData> = vec![];

    match file {
        EvtxLocation::File(path) => {
            if path.contains(" -> ") {
                let zip_parts: Vec<&str> = path.split(" -> ").collect();
                let evtx_name = zip_parts.last().unwrap().to_string(); // The last element is the EVTX file
                let zip_path = zip_parts[..zip_parts.len() - 1].join(" -> "); // All nested ZIP paths

                if is_debug_mode() {
                    println!("[INFO] Detected an EVTX file inside a nested ZIP: {}", evtx_name);
                    println!("[INFO] ZIP paths: {:?}", zip_parts);
                }

                // Call the correct function for the list of ZIPs
                if zip_parts.len() == 2 {
                    return open_evtx_from_zip(&zip_parts[0], &evtx_name);
                } else {
                    return open_evtx_from_nested_zip(zip_parts[..zip_parts.len() - 1].to_vec(), &evtx_name);
                }
            }

            // Normal file in disk
            if is_debug_mode() {
                println!("[DEBUG] Opening EVTX file in disk: {}", path);
            }
            let mut file = File::open(&path)?;
            let mut file_data = Vec::new();
            file.read_to_end(&mut file_data)?;

            let cursor = Cursor::new(file_data);
            let parser = EvtxParser::from_read_seek(cursor)?;
            Ok((parser, log_data))
        },
        EvtxLocation::ZipEntry { zip_path, evtx_name } => {
            let zip_parts: Vec<&str> = zip_path.split(" -> ").collect();
            if is_debug_mode() {
                println!("[INFO] Processing a file inside ZIP: {} -> {}", zip_path, evtx_name);
            }
            if zip_parts.len() == 1 {
                return open_evtx_from_zip(&zip_path, &evtx_name);
            } else {
                return open_evtx_from_nested_zip(zip_parts, &evtx_name);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// OPEN EVTX FROM ZIP
// ---------------------------------------------------------------------------------------
fn open_evtx_from_zip(zip_path: &str, evtx_name: &str) -> Result<(EvtxParser<Cursor<Vec<u8>>>, Vec<LogData>), Box<dyn Error>> {
    if is_debug_mode() {
        println!("[DEBUG] Opening ZIP: {}", zip_path);
    }

    let mut zip_file = File::open(zip_path).map_err(|e| {
        println!("[ERROR] Could not open ZIP {}: {}", zip_path, e);
        e
    })?;
    let mut archive = ZipArchive::new(zip_file).map_err(|e| {
        if is_debug_mode() { eprintln!("[DEBUG] Could not read ZIP {}: {}", zip_path, e); }
        e
    })?;

    let mut file_data = Vec::new();
    let mut found = false;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.name() == evtx_name {
            if is_debug_mode() {
                println!("[INFO] EVTX found inside the ZIP: {}", evtx_name);
            }
            file.read_to_end(&mut file_data)?;
            found = true;
            break;
        }
    }

    if !found {
        println!("[ERROR] EVTX file '{}' not found in ZIP '{}'", evtx_name, zip_path);
        return Err(format!("EVTX not found in ZIP: {}", evtx_name).into());
    }

    let cursor = Cursor::new(file_data);
    let parser = EvtxParser::from_read_seek(cursor)?;
    if is_debug_mode() {
        println!("[DEBUG] EVTX {} opened successfully from ZIP.", evtx_name);
    }

    Ok((parser, vec![]))
}

// ---------------------------------------------------------------------------------------
// OPEN EVTX FROM NESTED ZIP
// ---------------------------------------------------------------------------------------
fn open_evtx_from_nested_zip(zip_parts: Vec<&str>, evtx_name: &str) -> Result<(EvtxParser<Cursor<Vec<u8>>>, Vec<LogData>), Box<dyn Error>> {
    let mut current_zip_path = zip_parts[0].to_string();
    let mut nested_zip_data: Vec<u8> = vec![];

    for i in 1..zip_parts.len() {
        if is_debug_mode() {
            println!("[DEBUG] Opening nested ZIP: {} inside {}", zip_parts[i], current_zip_path);
        }

        let mut zip_file = File::open(&current_zip_path).map_err(|e| {
            println!("[ERROR] Could not open parent ZIP {}: {}", current_zip_path, e);
            e
        })?;
        let mut archive = ZipArchive::new(zip_file).map_err(|e| {
            println!("[ERROR] Could not read parent ZIP {}: {}", current_zip_path, e);
            e
        })?;

        let mut found = false;
        for j in 0..archive.len() {
            let mut file = archive.by_index(j)?;
            if file.name() == zip_parts[i] {
                if is_debug_mode() {
                    println!("[DEBUG] Nested ZIP found: {}", zip_parts[i]);
                }
                file.read_to_end(&mut nested_zip_data)?;
                found = true;
                break;
            }
        }

        if !found {
            println!("[ERROR] Nested ZIP {} not found inside {}", zip_parts[i], current_zip_path);
            return Err(format!("Nested ZIP not found: {}", zip_parts[i]).into());
        }
        current_zip_path = zip_parts[i].to_string();
    }

    let cursor = Cursor::new(nested_zip_data);
    let mut archive = ZipArchive::new(cursor).map_err(|e| {
        println!("[ERROR] Could not open final nested ZIP {}: {}", current_zip_path, e);
        e
    })?;

    let mut evtx_data = Vec::new();
    let mut found = false;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.name() == evtx_name {
            if is_debug_mode() {
                println!("[DEBUG] EVTX found inside nested ZIP: {}", evtx_name);
            }
            file.read_to_end(&mut evtx_data)?;
            found = true;
            break;
        }
    }

    if !found {
        println!("[ERROR] EVTX file '{}' not found in nested ZIP '{}'", evtx_name, current_zip_path);
        return Err(format!("EVTX not found in nested ZIP: {}", evtx_name).into());
    }

    let cursor = Cursor::new(evtx_data);
    let parser = EvtxParser::from_read_seek(cursor)?;
    if is_debug_mode() {
        println!("[DEBUG] EVTX {} opened successfully from nested ZIP.", evtx_name);
    }

    Ok((parser, vec![]))
}

// ---------------------------------------------------------------------------------------
// CREATE POLARS DATAFRAME AND WRITE/PRINT CSV
// ---------------------------------------------------------------------------------------
fn vector_to_polars(log_data: Vec<LogData>, output: Option<&String>) -> usize {
    // Deduplicate events (e.g., same event from live volume and VSS snapshot)
    // Key: (time_created, dst_computer, event_id, event_type, target_user_name, src_ip)
    // Prefer live volume events over VSS (shorter filename = no "vss_" in path)
    let log_data = {
        let mut seen = std::collections::HashSet::new();
        let mut deduped: Vec<LogData> = Vec::with_capacity(log_data.len());
        // Sort: live events first (shorter filenames), VSS after
        let mut sorted = log_data;
        sorted.sort_by(|a, b| a.filename.len().cmp(&b.filename.len()));
        for item in sorted {
            if !crate::filter::should_keep_record(&item) {
                continue;
            }
            let key = format!("{}|{}|{}|{}|{}|{}",
                item.time_created, item.computer, item.event_id,
                item.event_type, item.target_user_name, item.ip_address);
            if seen.insert(key) {
                deduped.push(item);
            }
        }
        deduped
    };

    let deduped_count = log_data.len();

    let time_created_vec: Vec<String> = log_data.iter().map(|x| x.time_created.to_string()).collect();
    let time_created = Series::new("time_created", time_created_vec);

    let computer_vec: Vec<String> = log_data.iter().map(|x| x.computer.to_string()).collect();
    let computer = Series::new("dst_computer", computer_vec);

    let event_type_vec: Vec<String> = log_data.iter().map(|x| x.event_type.to_string()).collect();
    let event_type = Series::new("event_type", event_type_vec);

    let event_id_vec: Vec<String> = log_data.iter().map(|x| x.event_id.to_string()).collect();
    let event_id = Series::new("event_id", event_id_vec);

    let logon_type_vec: Vec<String> = log_data.iter().map(|x| x.logon_type.to_string()).collect();
    let logon_type = Series::new("logon_type", logon_type_vec);

    let target_user_name_vec: Vec<String> = log_data.iter().map(|x| x.target_user_name.to_string()).collect();
    let target_user_name = Series::new("target_user_name", target_user_name_vec);

    let target_domain_name_vec: Vec<String> = log_data.iter().map(|x| x.target_domain_name.to_string()).collect();
    let target_domain_name = Series::new("target_domain_name", target_domain_name_vec);

    let workstation_name_vec: Vec<String> = log_data.iter().map(|x| x.workstation_name.to_string()).collect();
    let workstation_name = Series::new("src_computer", workstation_name_vec);

    let ip_address_vec: Vec<String> = log_data.iter().map(|x| x.ip_address.to_string()).collect();
    let ip_address = Series::new("src_ip", ip_address_vec);

    let subject_user_name_vec: Vec<String> = log_data.iter().map(|x| x.subject_user_name.to_string()).collect();
    let subject_user_name = Series::new("subject_user_name", subject_user_name_vec);

    let subject_domain_name_vec: Vec<String> = log_data.iter().map(|x| x.subject_domain_name.to_string()).collect();
    let subject_domain_name = Series::new("subject_domain_name", subject_domain_name_vec);

    let logon_id_vec: Vec<String> = log_data.iter().map(|x| x.logon_id.to_string()).collect();
    let logon_id = Series::new("logon_id", logon_id_vec);

    let detail_vec: Vec<String> = log_data.iter().map(|x| x.detail.to_string()).collect();
    let detail = Series::new("detail", detail_vec);

    let filename_vec: Vec<String> = log_data.iter().map(|x| x.filename.to_string()).collect();
    let filename = Series::new("log_filename", filename_vec);

    let df = DataFrame::new(vec![
        time_created,
        computer,
        event_type,
        event_id,
        logon_type,
        target_user_name,
        target_domain_name,
        workstation_name,
        ip_address,
        subject_user_name,
        subject_domain_name,
        logon_id,
        detail,
        filename
    ]);
    let df = df.unwrap().sort(["time_created"], false);

    match output {
        Some(output_path) => {
            let mut output_file = match File::create(output_path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[ERROR] Cannot create output file {}: {}", output_path, e);
                    return 0;
                }
            };
            CsvWriter::new(&mut output_file)
                .has_header(true)
                .finish(&mut df.unwrap())
                .unwrap();
        },
        None => {
            CsvWriter::new(io::stdout())
                .has_header(true)
                .finish(&mut df.unwrap())
                .unwrap();
        },
    }

    deduped_count
}

// ---------------------------------------------------------------------------------------
// SEARCH FOR EVTX FILES IN DIRECTORIES (AND ZIP)
// ---------------------------------------------------------------------------------------
fn find_evtx_files(directories: &[String]) -> DiscoveryResult {
    let mut result = DiscoveryResult {
        evtx_files: Vec::new(),
        triages: Vec::new(),
        archives_scanned: 0,
        archives_with_evtx: 0,
    };

    for directory in directories {
        let path = Path::new(directory);
        if is_debug_mode() {
            println!("[DEBUG] Exploring directory: {}", directory);
        }

        for entry in WalkDir::new(path) {
            if let Ok(entry) = entry {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                match path.extension().and_then(|e| e.to_str()) {
                    Some("evtx") => {
                        if let Some(path_str) = path.to_str() {
                            result.evtx_files.push(EvtxLocation::File(path_str.to_string()));
                        }
                    }
                    Some("zip") => {
                        if is_debug_mode() {
                            println!("[DEBUG] ZIP detected: {}", path.display());
                        }
                        result.archives_scanned += 1;
                        let zip_path_str = path.to_string_lossy().to_string();

                        // Detect triage type from the top-level entry list
                        // AND the zip path/filename (the filename + path
                        // heuristics catch re-zipped Velociraptor extracts
                        // that lost their JSON metadata markers).
                        let triage_kind = read_zip_top_entries(path)
                            .and_then(|entries| detect_triage_type(&zip_path_str, &entries));

                        // Walk the ZIP recursively for EVTX files
                        let found = list_evtx_in_zip(path, None).unwrap_or_default();
                        let count_in_this_zip = found.len();
                        if count_in_this_zip > 0 {
                            result.archives_with_evtx += 1;
                        }

                        // If we detected a triage layout, record it
                        if let Some(kind) = triage_kind {
                            let hostname = extract_triage_hostname(&zip_path_str, kind);
                            result.triages.push(TriageInfo {
                                kind,
                                zip_path: zip_path_str,
                                hostname,
                                artifact_count: count_in_this_zip,
                            });
                        }

                        result.evtx_files.extend(found);
                    }
                    _ => {}
                }
            }
        }
    }

    if is_debug_mode() {
        println!("[DEBUG] Total EVTX files found: {}", result.evtx_files.len());
        println!("[DEBUG] Triages detected: {}", result.triages.len());
    }

    result
}

// -----------------------------------------------------------------------------
// LIST EVTX FILES INSIDE A ZIP
// -----------------------------------------------------------------------------
fn list_evtx_in_zip(zip_path: &Path, parent_chain: Option<String>) -> Option<Vec<EvtxLocation>> {
    let mut evtx_files = Vec::<EvtxLocation>::new();

    // Abrimos el ZIP raíz
    let file = File::open(zip_path).map_err(|e| {
        if is_debug_mode() { eprintln!("[DEBUG] Could not open ZIP {:?}: {}", zip_path, e); }
    }).ok()?;
    let mut archive = ZipArchive::new(file).map_err(|e| {
        if is_debug_mode() { eprintln!("[DEBUG] Could not read ZIP {:?}: {}", zip_path, e); }
    }).ok()?;

    // Ruta acumulada:  zip1 -> zip2 -> ... -> actual.zip
    let this_chain = match &parent_chain {
        Some(c) => format!("{} -> {}", c, zip_path.to_string_lossy()),
        None     => zip_path.to_string_lossy().to_string(),
    };

    // Recorremos todas las entradas
    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(f)  => f,
            Err(e) => {
                if is_debug_mode() { eprintln!("[DEBUG] Reading file {} in {:?}: {}", i, zip_path, e); }
                continue;
            }
        };

        let name = entry.name().to_owned();

        if name.ends_with(".evtx") {
            // Encontrado un EVTX
            if is_debug_mode() {
                println!("[INFO] EVTX found: {} inside {}", name, zip_path.display());
            }
            evtx_files.push(EvtxLocation::ZipEntry {
                zip_path: this_chain.clone(),
                evtx_name: name,
            });
        } else if name.ends_with(".zip") {
            // ZIP anidado → lo leemos en memoria y llamamos recursivamente
            let mut nested_data = Vec::with_capacity(entry.size() as usize);
            if entry.read_to_end(&mut nested_data).is_err() {
                println!("[ERROR] Could not read nested ZIP {}", name);
                continue;
            }
            let mut nested_archive = match ZipArchive::new(Cursor::new(nested_data)) {
                Ok(a)  => a,
                Err(e) => {
                    if is_debug_mode() { eprintln!("[DEBUG] Opening nested ZIP {}: {}", name, e); }
                    continue;
                }
            };

            // Creamos un Cursor temporal para pasarlo a la función recursiva
            let tmp_path = zip_path.with_file_name(name.clone());
            // El Cursor anterior ya tiene los datos, sólo necesitamos una ruta “ficticia”
            // para llevar la cuenta de la jerarquía.
            if let Some(mut deeper) =
                recurse_zip(&mut nested_archive, &this_chain, &name)
            {
                evtx_files.append(&mut deeper);
            }
        }
    }

    if evtx_files.is_empty() {
        None
    } else {
        Some(evtx_files)
    }
}

// -----------------------------------------------------------------------------
// Helper recursivo para ZIPs anidados ilimitadamente
// -----------------------------------------------------------------------------
fn recurse_zip<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    parent_chain: &str,
    current_zip_name: &str,
) -> Option<Vec<EvtxLocation>> {
    let mut evtx_files = Vec::<EvtxLocation>::new();

    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(f)  => f,
            Err(_) => continue,
        };
        let name = entry.name().to_owned();

        if name.ends_with(".evtx") {
            evtx_files.push(EvtxLocation::ZipEntry {
                zip_path: format!("{} -> {}", parent_chain, current_zip_name),
                evtx_name: name,
            });
        } else if name.ends_with(".zip") {
            // ZIP dentro de ZIP dentro de ZIP…​
            let mut nested_data = Vec::with_capacity(entry.size() as usize);
            if entry.read_to_end(&mut nested_data).is_err() {
                continue;
            }
            if let Ok(mut deeper_archive) = ZipArchive::new(Cursor::new(nested_data)) {
                if let Some(mut deeper) = recurse_zip(
                    &mut deeper_archive,
                    &format!("{} -> {}", parent_chain, current_zip_name),
                    &name,
                ) {
                    evtx_files.append(&mut deeper);
                }
            }
        }
    }

    if evtx_files.is_empty() {
        None
    } else {
        Some(evtx_files)
    }
}


// ---------------------------------------------------------------------------------------
// GENERIC PARSE FUNCTION FOR A GIVEN EvtxLocation
// ---------------------------------------------------------------------------------------
pub fn parselog(file: EvtxLocation) -> Vec<LogData> {
    let file_origin = match &file {
        EvtxLocation::File(path) => path.clone(),
        EvtxLocation::ZipEntry { zip_path, evtx_name } => format!("{} -> {}", zip_path, evtx_name),
    };

    // Extract only the filename without paths
    let file_name = match &file {
        EvtxLocation::File(path) => Path::new(path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("")
            .to_string(),
        EvtxLocation::ZipEntry { evtx_name, .. } => {
            Path::new(evtx_name)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("")
                .to_string()
        }
    };

    // Check existence only for disk files, not for ZIP entries
    if let EvtxLocation::File(ref path) = file {
        if File::open(PathBuf::from(path)).is_err() {
            if is_debug_mode() {
                println!("[ERROR] Could not access file: {}", path);
            }
            return Vec::new();
        }
    }

    // Decide parsing based on known filenames
    let parsed_data = match file_name.as_str() {
        "Security.evtx" => parse_security_log(&file_origin, SECURITY_EVENT_IDS.to_vec()),
        "Microsoft-Windows-SMBServer%4Security.evtx" => parse_smb_server(&file_origin, SMBSERVER_EVENT_IDS.to_vec()),
        "Microsoft-Windows-SmbClient%4Security.evtx" => parse_smb_client(&file_origin, SMBCLIENT_EVENT_IDS.to_vec()),
        "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx" => {
            parse_rdp_client(&file_origin, RDPCLIENT_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx" => {
            parse_rdp_connmanager(&file_origin, RDPCONNMANAGER_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx" => {
            parse_rdp_localsession(&file_origin, RDPLOCALSESSION_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx" => {
            parse_rdpkore(&file_origin, RDPKORE_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-SmbClient%4Connectivity.evtx" => {
            parse_smb_client_connectivity(&file_origin, SMBCLIENT_CONNECTIVITY_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-WinRM%4Operational.evtx" => {
            parse_winrm(&file_origin, WINRM_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-WMI-Activity%4Operational.evtx" => {
            parse_wmi(&file_origin, WMI_EVENT_IDS.to_vec())
        },
        _ => {
            // Unknown filename (e.g. archived EVTX like Security-YYYY-MM-DD-HH-MM-SS.evtx
            // that Windows drops into winevt\Logs\Archive\ when "Archive the log when
            // full" is enabled, or operator-renamed files). Only fall back to Provider.Name
            // dispatch in parse-massive — the cautious action stays predictable.
            if is_massive_mode() {
                parse_unknown(&file_origin)
            } else {
                Vec::new()
            }
        }
    };

    if parsed_data.is_empty() {
        if is_debug_mode() {
            println!("[WARNING] No events found in {}", file_origin);
        }
    }

    parsed_data
}

// ---------------------------------------------------------------------------------------
// MAIN FUNCTION TO PARSE EVENTS
// ---------------------------------------------------------------------------------------
pub fn parse_events(files: &Vec<String>, directories: &Vec<String>, output: Option<&String>) {
    parse_events_ex(files, directories, output, &[], &[]);
}

/// Parse events with optional extra LogData entries from external sources.
///
/// `extra_task_events`: events synthesised from remote Scheduled Tasks XML
///   (parsed by parse_image_windows when it walks a forensic image).
/// `extra_mountpoint_events`: events synthesised from MountPoints2 registry
///   entries (parsed from NTUSER.DAT hives extracted by parse_image_windows).
///
/// Both vectors are added to the final timeline AND counted in the discovery
/// summary inside the [1/3] phase, with their own labelled lines next to the
/// EVTX count, so the analyst sees one coherent block instead of having
/// counters leak out before the phase header.
pub fn parse_events_ex(
    files: &Vec<String>,
    directories: &Vec<String>,
    output: Option<&String>,
    extra_task_events: &[LogData],
    extra_mountpoint_events: &[LogData],
) {
    let start_time = std::time::Instant::now();

    if is_debug_mode() {
        println!("[INFO] Starting event processing...");
    }

    let mut log_data: Vec<LogData> = vec![];
    let mut vec_filenames: Vec<EvtxLocation> = vec![];

    // Detect drive root paths and suggest parse-image-windows for VSS
    // parse-windows passes "X:\" (normalized), parse-image-windows passes "X:" (no trailing \)
    for dir in directories {
        let d = dir.replace('/', "\\");
        let is_drive_with_backslash = d.len() == 3
            && d.as_bytes()[0].is_ascii_alphabetic()
            && d.as_bytes()[1] == b':'
            && d.as_bytes()[2] == b'\\';
        if is_drive_with_backslash {
            let letter = &d[..2];
            crate::banner::print_info(&format!(
                "Drive {} detected — scanning as filesystem (EVTX + UAL only).", letter
            ));
            crate::banner::print_info(&format!(
                "Tip: use '-a parse-image-windows -d {}' to also recover events from VSS shadow copies.", letter
            ));
        }
    }

    // Phase 1: Search for artifacts
    crate::banner::print_search_start();

    if is_debug_mode() {
        println!("[INFO] Adding individual EVTX files...");
    }
    vec_filenames.extend(files.iter().map(|s| EvtxLocation::File(s.to_string())));

    if is_debug_mode() {
        println!("[INFO] Searching for EVTX files in provided directories...");
    }
    let dir_count = directories.len();
    let file_count = files.len();
    let discovery = find_evtx_files(directories);
    let archives_scanned = discovery.archives_scanned;
    let archives_with_evtx = discovery.archives_with_evtx;
    let triages = discovery.triages;
    vec_filenames.extend(discovery.evtx_files);

    // Build the triage lookup map keyed by outer-zip path. Phase 2 grouping
    // uses this to label EVTX rows with [TRIAGE: <type>] instead of [ARCHIVE].
    let triage_map: std::collections::HashMap<String, TriageInfo> = triages
        .iter()
        .map(|t| (t.zip_path.clone(), t.clone()))
        .collect();

    // Print "Triage found" lines BEFORE the EVTX count summary so the analyst
    // sees the high-value detections at the top of phase 1. We pass the FULL
    // zip path (not just filename) because real cases often have duplicate
    // copies of the same host's triage in different folders and the analyst
    // needs to see they're physically different files.
    for t in &triages {
        crate::banner::print_triage_found(
            t.kind.label(),
            t.hostname.as_deref(),
            &t.zip_path,
            t.artifact_count,
        );
    }

    // Count ZIPs vs direct files for the summary
    let zip_entries_inside_archives = vec_filenames
        .iter()
        .filter(|f| matches!(f, EvtxLocation::ZipEntry { .. }))
        .count();
    let total_evtx = vec_filenames.len();

    // Detect UAL databases early so we can include them in the artifact count
    let mut all_ual_files: Vec<std::path::PathBuf> = Vec::new();
    for dir in directories {
        all_ual_files.extend(crate::parse_ual::find_ual_databases(dir));
    }
    for f in files {
        if f.to_lowercase().ends_with(".mdb") && std::path::Path::new(f).exists() {
            all_ual_files.push(std::path::PathBuf::from(f));
        }
    }
    all_ual_files.sort();
    all_ual_files.dedup();

    crate::banner::print_search_results_v2(
        total_evtx,
        zip_entries_inside_archives,
        archives_scanned,
        archives_with_evtx,
        dir_count,
        file_count,
        "EVTX artifacts",
    );
    if !all_ual_files.is_empty() {
        crate::banner::print_search_result_line(all_ual_files.len(), "UAL databases");
    }
    // Both extras (scheduled tasks + MountPoints2) get printed here inside
    // phase 1, with their own labels, so the analyst sees the full discovery
    // summary in one block instead of having counters leak out before [1/3].
    if !extra_mountpoint_events.is_empty() {
        crate::banner::print_search_result_line(extra_mountpoint_events.len(), "MountPoints2 remote share events");
    }
    if !extra_task_events.is_empty() {
        crate::banner::print_search_result_line(extra_task_events.len(), "remote Scheduled Task events");
    }

    if is_debug_mode() {
        println!("[INFO] Total EVTX files to process: {}", vec_filenames.len());
    }

    // Phase 2: Process artifacts
    crate::banner::print_processing_start();
    let pb = crate::banner::create_progress_bar(vec_filenames.len() as u64);
    let mut skipped_no_events: usize = 0;
    let mut parsed_files: usize = 0;
    // (source_label, evtx_short_name, vss_index, count)
    //   vss_index = None for live artifacts, Some(N) for VSS snapshot N
    // The phase-2 breakdown sorts each source's items live-first then by
    // VSS index, and renders VSS entries with a "[VSS]" / "[VSS-N]" suffix
    // so the analyst can see at a glance which events came from a snapshot.
    let mut artifact_details: Vec<(String, String, Option<u32>, usize)> = Vec::new();

    for evtxfile in &vec_filenames {
        let short_name = match &evtxfile {
            EvtxLocation::File(path) => std::path::Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(path)
                .to_string(),
            EvtxLocation::ZipEntry { evtx_name, .. } => std::path::Path::new(evtx_name)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(evtx_name)
                .to_string(),
        };
        let progress_name = match &evtxfile {
            EvtxLocation::File(path) => path.clone(),
            EvtxLocation::ZipEntry { evtx_name, .. } => evtx_name.clone(),
        };
        crate::banner::progress_set_message(&pb, &progress_name);

        let parsed_logs = parselog(evtxfile.clone());
        let count = parsed_logs.len();
        if count == 0 {
            skipped_no_events += 1;
        } else {
            parsed_files += 1;
            let source = source_label_for_evtx(evtxfile, &triage_map);
            // Detect VSS index from the underlying path (only applies to
            // EvtxLocation::File paths that came from parse-image's temp
            // extract dir; EvtxLocation::ZipEntry never has VSS).
            let vss_idx = match evtxfile {
                EvtxLocation::File(path) => detect_vss_index(path),
                EvtxLocation::ZipEntry { .. } => None,
            };
            artifact_details.push((source, short_name.clone(), vss_idx, count));
            if is_debug_mode() {
                println!("[INFO] {} events from {}", count, short_name);
            }
        }
        log_data.extend(parsed_logs);
        pb.inc(1);
    }

    pb.finish_and_clear();

    // Parse UAL databases (detected earlier during artifact search)
    if !all_ual_files.is_empty() {
        let source_dir = directories.first().map(|s| s.as_str()).unwrap_or("UAL");
        let (ual_events, mdb_details) = crate::parse_ual::parse_ual_databases(&all_ual_files, source_dir);
        if !ual_events.is_empty() {
            for (mdb_name, count) in &mdb_details {
                let src = source_label_for_path(mdb_name);
                let short = std::path::Path::new(mdb_name)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(mdb_name)
                    .to_string();
                // UAL databases live in the same per-partition temp dir as
                // EVTX files, so the VSS detection applies here too.
                let vss_idx = detect_vss_index(mdb_name);
                artifact_details.push((src, short, vss_idx, *count));
            }
            log_data.extend(ual_events);
        }
    }

    crate::banner::print_artifact_detail_grouped(&artifact_details);

    if is_debug_mode() {
        println!("[INFO] Parsing finished. Total events collected: {}", log_data.len());
    }

    // Add both extras streams (Scheduled Tasks + MountPoints2) to the final
    // timeline. They come from parse_image_windows's registry / XML parsing
    // and are counted as "parsed_files" so the summary line reflects them.
    let extra_task_count = extra_task_events.len();
    if extra_task_count > 0 {
        log_data.extend_from_slice(extra_task_events);
        parsed_files += extra_task_count;
    }
    let extra_mp_count = extra_mountpoint_events.len();
    if extra_mp_count > 0 {
        log_data.extend_from_slice(extra_mountpoint_events);
        parsed_files += extra_mp_count;
    }

    // Phase 3: Generate output
    crate::banner::print_output_start();
    let total_before_dedup = log_data.len();
    let total_after_dedup = vector_to_polars(log_data, output);
    let deduped = total_before_dedup - total_after_dedup;
    if deduped > 0 {
        crate::banner::print_info(&format!("{} duplicate events removed (live + VSS overlap)", deduped));
    }

    crate::banner::print_summary(total_after_dedup, parsed_files, skipped_no_events, output.map(|s| s.as_str()), start_time);
}

// ---------------------------------------------------------------------------------------
// STRUCTS TO MAP EVTX XML
// ---------------------------------------------------------------------------------------
#[derive(Debug, Deserialize, PartialEq)]
struct Event {
    System: System,
    EventData: Option<EventData>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Event2 {
    System: System,
    UserData: Option<UserData>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct System {
    TimeCreated: TimeCreated,
    Provider: Provider,
    EventID: Option<String>,
    Computer: Option<String>,
    Security: Option<Security>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct TimeCreated {
    SystemTime: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Provider {
    Name: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct EventData {
    #[serde(rename = "Data", default)]
    Datas: Vec<Data>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Data {
    Name: Option<String>,
    #[serde(rename = "$value")]
    pub body: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct UserData {
    EventData: Option<EventDataSMBServer>,
    EventXML: Option<EventXML>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Security {
    UserID: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct EventDataSMBServer {
    ClientName: Option<String>,
    UserName: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct EventXML {
    Param1: Option<String>,
    Param2: Option<String>,
    Param3: Option<String>,
    User: Option<String>,
    Address: Option<String>,
}

// WMI event structs — UserData contains Operation_ClientFailure (5858) or Operation_TemporaryEssStarted (5860)
#[derive(Debug, Deserialize, PartialEq)]
struct EventWMI {
    System: System,
    UserData: Option<WMIUserData>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct WMIUserData {
    Operation_ClientFailure: Option<WMIClientFailure>,
}

impl WMIUserData {
    fn client_machine(&self) -> Option<String> {
        self.Operation_ClientFailure.as_ref().and_then(|f| f.ClientMachine.clone())
    }
    fn user(&self) -> Option<String> {
        self.Operation_ClientFailure.as_ref().and_then(|f| f.User.clone())
    }
    fn operation(&self) -> Option<String> {
        self.Operation_ClientFailure.as_ref().and_then(|f| f.Operation.clone())
    }
}

#[derive(Debug, Deserialize, PartialEq)]
struct WMIClientFailure {
    ClientMachine: Option<String>,
    User: Option<String>,
    Operation: Option<String>,
}
