use std::{path::PathBuf, fs::File};
use evtx::EvtxParser;
extern crate serde;
extern crate quick_xml;
use serde::{Serialize, Deserialize};

/// Deserialise one event record with whitespace-only text trimmed, as the
/// quick-xml 0.20 deserializer did: a Param element holding only a line
/// break and spaces is an empty value, not a run of spaces.
fn from_str<'a, T: serde::Deserialize<'a>>(s: &'a str) -> Result<T, quick_xml::DeError> {
    let mut reader = quick_xml::NsReader::from_str(s);
    reader.config_mut().trim_text(true);
    let mut de = quick_xml::de::Deserializer::borrowing(reader);
    serde::Deserialize::deserialize(&mut de)
}
use std::{error::Error, collections::HashMap};
use walkdir::WalkDir;
use std::path::Path;
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

/// Normalise IPv6 noise in the IpAddress field from Windows EVTX:
///   - `::ffff:192.168.10.32` → `192.168.10.32` (IPv4-mapped IPv6)
///   - `fe80::...` → `""` (link-local, useless for lateral movement)
/// Without this, each variant creates a separate node in the graph.
/// Infer logon_type for events that lack one natively.
/// Kerberos (4768/4769/4770/4771), NTLM (4776), share access (5140),
/// explicit creds (4648), and WinRM (6) are all network-based in a
/// lateral movement context → type 3. 4778 / 4779 (session reconnected /
/// disconnected) are Terminal Services sessions → type 10, like the
/// LocalSessionManager 21-25 events they go with.
pub(crate) fn infer_logon_type(event_id: &str, raw: &str) -> String {
    if !raw.is_empty() {
        return raw.to_string();
    }
    match event_id {
        "4768" | "4769" | "4770" | "4771" | "4776" | "5140" | "4648" | "6" => "3".to_string(),
        "4778" | "4779" => "10".to_string(),
        _ => String::new(),
    }
}

/// Split a UNC-style server reference as the SMB channels write it
/// (`\\192.0.2.31`, `\192.0.2.31\C$`, `\\srv01\ADMIN$`) into the
/// server and the share path. Returns (server, share); share is empty when
/// the value names the server alone.
pub(crate) fn split_unc(v: &str) -> (String, String) {
    let t = v.trim().trim_start_matches(|c| c == '\\' || c == '/');
    match t.find(|c| c == '\\' || c == '/') {
        Some(i) => (t[..i].to_string(), t[i + 1..].trim_matches(|c| c == '\\' || c == '/').to_string()),
        None => (t.to_string(), String::new()),
    }
}

/// Decode the hex dump of a Windows SOCKADDR_STORAGE as the SMB channels
/// write it (`ClientAddress`, `RemoteAddress`, `Address`): family in the
/// first two bytes (little-endian, 2 = AF_INET, 23 = AF_INET6), the port,
/// then the address. Returns the IP as text, or None when the dump is not
/// an address (unset, zero, or another family).
pub(crate) fn sockaddr_hex_ip(hex: &str) -> Option<String> {
    let h = hex.trim();
    if h.len() < 16 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let b: Vec<u8> = (0..h.len() / 2).filter_map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()).collect();
    let family = u16::from_le_bytes([b[0], b[1]]);
    match family {
        2 if b.len() >= 8 => {
            let ip = std::net::Ipv4Addr::new(b[4], b[5], b[6], b[7]);
            if ip.is_unspecified() { None } else { Some(ip.to_string()) }
        }
        23 if b.len() >= 24 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[8..24]);
            let ip = std::net::Ipv6Addr::from(o);
            if ip.is_unspecified() { None } else { Some(strip_ipv4_mapped(&ip.to_string())) }
        }
        _ => None,
    }
}

/// `DOMAIN\user` or `user@domain` into (user, domain).
pub(crate) fn split_account(v: &str) -> (String, String) {
    let v = v.trim();
    if let Some(i) = v.find('\\') {
        return (v[i + 1..].to_string(), v[..i].to_string());
    }
    if let Some(i) = v.find('@') {
        return (v[..i].to_string(), v[i + 1..].to_string());
    }
    (v.to_string(), String::new())
}

/// Source columns for a host name recorded by a client-side channel: the
/// name goes to src_computer, an address to src_ip, never both.
pub(crate) fn source_columns(host: &str) -> (String, String) {
    let h = host.trim().to_string();
    if h.parse::<std::net::IpAddr>().is_ok() { (String::new(), h) } else { (h, String::new()) }
}

pub(crate) fn strip_ipv4_mapped(ip: &str) -> String {
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
        "0xc0000070" => "Workstation restriction",
        "0xc000006f" => "Logon outside allowed hours",
        "0xc000006d" => "Bad username or auth info",
        "0xc0000071" => "Expired password",
        "0xc0000224" => "Password must change",
        "0xc0000193" => "Account expired",
        "0xc000015b" => "Logon type not granted",
        "0xc000006e" => "Account restriction",
        "0xc0000133" => "Clock skew too great",
        "0xc0000022" => "Access denied",
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
// Sysmon Operational. Only Event ID 3 (network connection) is lateral-movement
// relevant; process/pipe/file/registry events are tool-attribution territory,
// out of masstin's scope.
const SYSMON_EVENT_IDS: &[&str] = &["3"];
// Admin / lateral-movement service ports. Sysmon logs EVERY connection, so the
// parser keeps only connections whose SERVICE port is one of these — same port
// set parse-cortex uses with --admin-ports — to control volume.
const SYSMON_LM_PORTS: &[&str] = &["22", "135", "139", "445", "1433", "3306", "3389", "5900", "5985", "5986"];

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
    /// UAC — Unix-like Artifacts Collector (https://github.com/tclahr/uac).
    /// Linux / macOS / *BSD / Solaris / ESXi triage. Output is a tar.gz by
    /// default (zip with `-f zip`) named `uac-<host>-<os>-<YYYYMMDDhhmmss>`.
    Uac,
}

impl TriageType {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            TriageType::Kape => "KAPE",
            TriageType::Velociraptor => "Velociraptor Offline Collector",
            TriageType::CortexXdr => "Cortex XDR Offline Collector",
            TriageType::Uac => "UAC (Unix-like Artifacts Collector)",
        }
    }
    pub(crate) fn short_label(&self) -> &'static str {
        match self {
            TriageType::Kape => "KAPE",
            TriageType::Velociraptor => "Velociraptor",
            TriageType::CortexXdr => "Cortex XDR",
            TriageType::Uac => "UAC",
        }
    }
}

/// Archive stem without the compression AND container extensions:
/// `host.zip` → `host`, `uac-x-linux-2026.tar.gz` → `uac-x-linux-2026`,
/// `dump.tgz` → `dump`. `Path::file_stem` alone would leave the `.tar` in.
pub(crate) fn archive_stem(archive_path: &str) -> Option<String> {
    let name = std::path::Path::new(archive_path).file_name()?.to_str()?;
    let lower = name.to_lowercase();
    let cut = if lower.ends_with(".tar.gz") {
        name.len() - 7
    } else if lower.ends_with(".tgz") || lower.ends_with(".tar") || lower.ends_with(".zip") {
        name.len() - 4
    } else {
        match name.rfind('.') {
            Some(i) if i > 0 => i,
            _ => name.len(),
        }
    };
    Some(name[..cut].to_string())
}

/// UAC output naming convention: `uac-<hostname>-<os>-<YYYYMMDDhhmmss>`.
/// `<os>` is one of the UAC platform names (linux, macos, freebsd, ...),
/// the trailing stamp is exactly 14 digits. The hostname itself may contain
/// dashes, so we anchor on the tail: `-<alpha>-<14 digits>`.
fn is_uac_filename(stem: &str) -> bool {
    if !stem.starts_with("uac-") { return false; }
    let parts: Vec<&str> = stem.split('-').collect();
    if parts.len() < 4 { return false; }
    let stamp = parts[parts.len() - 1];
    let os = parts[parts.len() - 2];
    stamp.len() == 14
        && stamp.bytes().all(|b| b.is_ascii_digit())
        && !os.is_empty()
        && os.bytes().all(|b| b.is_ascii_alphabetic())
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
    // 0. UAC (Unix-like Artifacts Collector). Every UAC archive carries the
    //    run log `uac.log` at its root, the collected files under `[root]/`
    //    and the live-response output under `live_response/`. Require the
    //    run log PLUS one of the two layout directories so an unrelated
    //    archive that merely contains a file called uac.log is not
    //    misclassified. GNU tar may prefix entries with `./`.
    let has_uac_log = entries.iter().any(|n| {
        let t = n.replace('\\', "/");
        let t = t.trim_start_matches("./");
        t == "uac.log" || t.ends_with("/uac.log")
    });
    let has_uac_layout = entries.iter().any(|n| {
        let t = n.replace('\\', "/");
        let t = t.trim_start_matches("./");
        t.starts_with("[root]/") || t.contains("/[root]/")
            || t.starts_with("live_response/") || t.contains("/live_response/")
    });
    if has_uac_log && has_uac_layout {
        return Some(TriageType::Uac);
    }
    //    Filename fallback: `uac-<host>-<os>-<YYYYMMDDhhmmss>` is UAC's
    //    enforced output name; no other collector uses it.
    if archive_stem(zip_path).map(|s| is_uac_filename(&s)).unwrap_or(false) {
        return Some(TriageType::Uac);
    }

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
    let stem_owned = archive_stem(zip_path)?;
    let stem = stem_owned.as_str();
    match kind {
        TriageType::Uac => {
            // uac-<hostname>-<os>-<YYYYMMDDhhmmss>; hostname may contain
            // dashes, so drop the fixed prefix and the two trailing fields.
            if !is_uac_filename(stem) { return None; }
            let parts: Vec<&str> = stem.split('-').collect();
            let host = parts[1..parts.len() - 2].join("-");
            // UAC writes "unknown" when it was run against a mounted
            // image (`-m /mnt/sysroot`); leave it to the log-content
            // heuristics (/etc/hostname, syslog header) in that case.
            if host.is_empty() || host.eq_ignore_ascii_case("unknown") {
                None
            } else {
                Some(host)
            }
        }
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
// ONE MAPPING PER EVENT FAMILY, WHATEVER CARRIED THE EVENT
//
// A Windows event reaches masstin as EVTX XML (parse-windows, parse-image,
// parse-massive) or as a Winlogbeat JSON document (parser-elastic). Both are
// reduced to a `WinRec` (event id, time, computer, the System UserID SID and
// the event's fields by name) and turned into a row by the same `map_*`
// function, so the two readers cannot drift apart again: they did, and the
// Winlogbeat reader read 4778/4779 and 4776 with the 4624 field names (no
// account, no origin) and wrote 4648, 31001 and 1024 with the edge reversed.
// ---------------------------------------------------------------------------------------

/// A Windows event reduced to what the lateral-movement mapping reads.
#[derive(Debug, Default, Clone)]
pub(crate) struct WinRec {
    pub event_id: String,
    pub time: String,
    pub computer: String,
    /// System/Security/@UserID (Winlogbeat: `winlog.user.identifier`)
    pub user_sid: String,
    /// EventData `<Data Name=..>` values and the UserData leaves, by name.
    /// A key is present only when the event carried that element.
    pub fields: HashMap<String, String>,
    /// The event had an EventData block (some families require one).
    pub has_event_data: bool,
}

impl WinRec {
    fn f(&self, k: &str) -> String {
        self.fields.get(k).cloned().unwrap_or_default()
    }
    fn has(&self, k: &str) -> bool {
        self.fields.contains_key(k)
    }
}

fn put(fields: &mut HashMap<String, String>, k: &str, v: &Option<String>) {
    if let Some(v) = v {
        fields.insert(k.to_string(), v.clone());
    }
}

fn rec_from_event(event: &Event) -> Option<WinRec> {
    let mut fields = HashMap::new();
    let has_event_data = event.EventData.is_some();
    if let Some(ed) = event.EventData.as_ref() {
        for d in &ed.Datas {
            if let Some(name) = d.Name.as_ref() {
                fields.insert(name.clone(), d.body.clone().unwrap_or_default());
            }
        }
    }
    Some(WinRec {
        event_id: event.System.EventID.clone()?,
        time: event.System.TimeCreated.SystemTime.clone().unwrap_or_default(),
        computer: event.System.Computer.clone().unwrap_or_default(),
        user_sid: event.System.Security.as_ref().and_then(|s| s.UserID.clone()).unwrap_or_default(),
        fields,
        has_event_data,
    })
}

fn rec_from_event2(event: &Event2) -> Option<WinRec> {
    let mut fields = HashMap::new();
    if let Some(ud) = event.UserData.as_ref() {
        if let Some(ed) = ud.EventData.as_ref() {
            put(&mut fields, "UserName", &ed.UserName);
            put(&mut fields, "ClientName", &ed.ClientName);
            put(&mut fields, "ClientAddress", &ed.ClientAddress);
            put(&mut fields, "Status", &ed.Status);
        }
        if let Some(x) = ud.EventXML.as_ref() {
            put(&mut fields, "Param1", &x.Param1);
            put(&mut fields, "Param2", &x.Param2);
            put(&mut fields, "Param3", &x.Param3);
            put(&mut fields, "User", &x.User);
            put(&mut fields, "Address", &x.Address);
            put(&mut fields, "SessionID", &x.SessionID);
        }
    }
    Some(WinRec {
        event_id: event.System.EventID.clone()?,
        time: event.System.TimeCreated.SystemTime.clone().unwrap_or_default(),
        computer: event.System.Computer.clone().unwrap_or_default(),
        user_sid: event.System.Security.as_ref().and_then(|s| s.UserID.clone()).unwrap_or_default(),
        fields,
        has_event_data: false,
    })
}

/// Iterate the records of one EVTX file whose id is in `ids`, as WinRecs
/// built by `build`, and map each with `map`.
fn evtx_rows(
    file: &str,
    ids: &[&str],
    build: fn(&str) -> Option<WinRec>,
    map: fn(&WinRec, &str) -> Option<LogData>,
) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {}", file);
    }
    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok(p) => p,
        Err(_) => return vec![],
    };
    for record in parser.records() {
        let r = match record { Ok(r) => r, Err(_) => continue };
        let rec = match build(r.data.as_str()) { Some(x) => x, None => continue };
        if !ids.contains(&rec.event_id.as_str()) {
            continue;
        }
        if let Some(row) = map(&rec, file) {
            log_data.push(row);
        }
    }
    log_data
}

fn build_event(xml: &str) -> Option<WinRec> {
    rec_from_event(&from_str::<Event>(xml).ok()?)
}
fn build_event2(xml: &str) -> Option<WinRec> {
    rec_from_event2(&from_str::<Event2>(xml).ok()?)
}
fn build_wmi(xml: &str) -> Option<WinRec> {
    let event: EventWMI = from_str(xml).ok()?;
    let mut fields = HashMap::new();
    if let Some(ud) = event.UserData.as_ref() {
        put(&mut fields, "ClientMachine", &ud.client_machine());
        put(&mut fields, "User", &ud.user());
        put(&mut fields, "Operation", &ud.operation());
    }
    Some(WinRec {
        event_id: event.System.EventID.clone()?,
        time: event.System.TimeCreated.SystemTime.clone().unwrap_or_default(),
        computer: event.System.Computer.clone().unwrap_or_default(),
        user_sid: String::new(),
        fields,
        has_event_data: false,
    })
}

type MapFn = fn(&WinRec, &str) -> Option<LogData>;

/// The mapping for an event of `channel` (the EVTX channel name, as
/// Winlogbeat writes it in `winlog.channel`), or None when masstin does not
/// read that event. Event ids are only unique within a channel (1102 is an
/// RDP client event and also "audit log cleared" in Security; 6 and 3 exist
/// in many channels), so the channel decides the family.
pub(crate) fn mapper_for_channel(channel: &str, event_id: &str) -> Option<MapFn> {
    let c = channel.to_ascii_lowercase();
    let table: [(&str, &[&str], MapFn); 11] = [
        ("security", SECURITY_EVENT_IDS, map_security),
        ("microsoft-windows-smbserver/", SMBSERVER_EVENT_IDS, map_smb_server),
        ("microsoft-windows-smbclient/security", SMBCLIENT_EVENT_IDS, map_smb_client),
        ("microsoft-windows-smbclient/connectivity", SMBCLIENT_CONNECTIVITY_EVENT_IDS, map_smb_client_connectivity),
        ("microsoft-windows-terminalservices-rdpclient/", RDPCLIENT_EVENT_IDS, map_rdp_client),
        ("microsoft-windows-terminalservices-remoteconnectionmanager/", RDPCONNMANAGER_EVENT_IDS, map_rdp_connmanager),
        ("microsoft-windows-terminalservices-localsessionmanager/", RDPLOCALSESSION_EVENT_IDS, map_rdp_localsession),
        ("microsoft-windows-remotedesktopservices-rdpcorets/", RDPKORE_EVENT_IDS, map_rdpkore),
        ("microsoft-windows-winrm/", WINRM_EVENT_IDS, map_winrm),
        ("microsoft-windows-wmi-activity/", WMI_EVENT_IDS, map_wmi),
        ("microsoft-windows-sysmon/", SYSMON_EVENT_IDS, map_sysmon),
    ];
    table.iter()
        .find(|(prefix, ids, _)| {
            (if *prefix == "security" { c == "security" } else { c.starts_with(prefix) }) && ids.contains(&event_id)
        })
        .map(|(_, _, f)| *f)
}

/// For records that do not say their channel (old exports): the event ids
/// that belong to one family only. 1102, 6 and 3 are left out: without the
/// channel they are as likely to be something else.
pub(crate) fn mapper_for_id(event_id: &str) -> Option<MapFn> {
    let table: [(&[&str], MapFn); 8] = [
        (SECURITY_EVENT_IDS, map_security),
        (SMBCLIENT_EVENT_IDS, map_smb_client),
        (SMBCLIENT_CONNECTIVITY_EVENT_IDS, map_smb_client_connectivity),
        (SMBSERVER_EVENT_IDS, map_smb_server),
        (&["1024"], map_rdp_client),
        (RDPCONNMANAGER_EVENT_IDS, map_rdp_connmanager),
        (RDPLOCALSESSION_EVENT_IDS, map_rdp_localsession),
        (WMI_EVENT_IDS, map_wmi),
    ];
    table.iter().find(|(ids, _)| ids.contains(&event_id)).map(|(_, f)| *f)
}

// ---------------------------------------------------------------------------------------
// SECURITY
// ---------------------------------------------------------------------------------------
pub fn parse_security_log(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    evtx_rows(file, &lateral_event_ids, build_event, map_security)
}

pub(crate) fn map_security(rec: &WinRec, file: &str) -> Option<LogData> {
    let event_id = rec.event_id.clone();
    let v = |k: &str| rec.f(k);
    let status = v("Status");
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
    let detail = match event_id.as_str() {
        "4624" | "4648" => v("ProcessName"),
        "4625" => translate_substatus(&v("SubStatus")),
        "5140" => v("ShareName"),
        _ => String::new(),
    };
    let logon_type = infer_logon_type(&event_id, &v("LogonType"));
    let computer = rec.computer.clone();
    // Field names differ per event (checked against the Windows provider
    // manifests):
    //  * 4648 is logged on the SOURCE host; the host it authenticated to is
    //    TargetServerName. Reading Computer as destination reversed the edge.
    //  * 4776: Workstation.  4778/4779: AccountName, AccountDomain,
    //    ClientName, ClientAddress, LogonID.
    //  * 5140: the user is the subject.
    let (dst, tgt_user, tgt_dom, wks, ip, lid) = match event_id.as_str() {
        "4648" => {
            let target = v("TargetServerName");
            let t = target.trim();
            if !t.is_empty() && t != "-" && !t.eq_ignore_ascii_case("localhost") && t != "127.0.0.1" {
                (t.to_string(), v("TargetUserName"), v("TargetDomainName"), computer.clone(), String::new(), v("TargetLogonId"))
            } else {
                (computer.clone(), v("TargetUserName"), v("TargetDomainName"), v("WorkstationName"), v("IpAddress"), v("TargetLogonId"))
            }
        }
        "4776" => (computer.clone(), v("TargetUserName"), String::new(), v("Workstation"), String::new(), String::new()),
        "4778" | "4779" => (computer.clone(), v("AccountName"), v("AccountDomain"), v("ClientName"), v("ClientAddress"), v("LogonID")),
        "5140" => (computer.clone(), v("SubjectUserName"), v("SubjectDomainName"), v("WorkstationName"), v("IpAddress"), v("SubjectLogonId")),
        _ => (computer.clone(), v("TargetUserName"), v("TargetDomainName"), v("WorkstationName"), v("IpAddress"), v("TargetLogonId")),
    };
    Some(LogData {
        time_created: rec.time.clone(),
        computer: dst,
        event_type,
        event_id,
        subject_user_name: v("SubjectUserName"),
        subject_domain_name: v("SubjectDomainName"),
        target_user_name: tgt_user,
        target_domain_name: tgt_dom,
        logon_type,
        workstation_name: wks,
        ip_address: strip_ipv4_mapped(&ip),
        logon_id: lid,
        filename: file.to_string(),
        detail,
    })
}

// ---------------------------------------------------------------------------------------
// SMB SERVER (551 / 1009, written on the server)
// ---------------------------------------------------------------------------------------
pub fn parse_smb_server(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    evtx_rows(file, &lateral_event_ids, build_event2, map_smb_server)
}

pub(crate) fn map_smb_server(rec: &WinRec, file: &str) -> Option<LogData> {
    let event_type = match rec.event_id.as_str() {
        // 1009: "The server denied anonymous access to the client" (Error).
        // 551: session auth failure.
        "1009" | "551" => "FAILED_LOGON".to_string(),
        _ => "CONNECT".to_string(),
    };
    // Newer 551/1009 templates carry no UserName and no
    // <UserData><EventData>: every field is optional.
    let (user, domain) = split_account(&rec.f("UserName"));
    // ClientName is written as a UNC reference (`\\192.0.2.76`); the raw
    // value was landing in src_computer with its backslashes and the address
    // was never recognised. ClientAddress (a SOCKADDR hex dump) is the
    // fallback when the name is empty.
    let mut client = strip_ipv4_mapped(&split_unc(&rec.f("ClientName")).0);
    if client.is_empty() {
        client = sockaddr_hex_ip(&rec.f("ClientAddress")).unwrap_or_default();
    }
    let (workstation_name, ip_address) = source_columns(&client);
    let status = rec.f("Status");
    let detail = if status.is_empty() { String::new() } else { format!("Status {}", status) };
    Some(LogData {
        time_created: rec.time.clone(),
        computer: rec.computer.clone(),
        event_type,
        event_id: rec.event_id.clone(),
        subject_user_name: rec.user_sid.clone(),
        subject_domain_name: String::new(),
        target_user_name: user,
        target_domain_name: domain,
        logon_type: String::from("3"),
        workstation_name,
        ip_address,
        logon_id: String::new(),
        filename: file.to_string(),
        detail,
    })
}

// ---------------------------------------------------------------------------------------
// SMB CLIENT (31001, written on the client)
// ---------------------------------------------------------------------------------------
pub fn parse_smb_client(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    evtx_rows(file, &lateral_event_ids, build_event, map_smb_client)
}

pub(crate) fn map_smb_client(rec: &WinRec, file: &str) -> Option<LogData> {
    if !rec.has_event_data {
        return None;
    }
    let (server, share_in_name) = split_unc(&rec.f("ServerName"));
    let share = {
        let s = split_unc(&rec.f("ShareName")).1;
        if s.is_empty() { share_in_name } else { s }
    };
    let (user, domain) = split_account(&rec.f("UserName"));
    // written on the CLIENT: the local Computer is the source (a name, not
    // an address), the server the destination
    let (workstation_name, ip_address) = source_columns(&rec.computer);
    Some(LogData {
        time_created: rec.time.clone(),
        computer: strip_ipv4_mapped(&server),
        // 31001 (level Error): the client failed to authenticate to the server.
        event_type: "FAILED_LOGON".to_string(),
        event_id: rec.event_id.clone(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: user,
        target_domain_name: domain,
        logon_type: String::from("3"),
        workstation_name,
        ip_address,
        logon_id: String::new(),
        filename: file.to_string(),
        detail: share,
    })
}

// ---------------------------------------------------------------------------------------
// SMB CLIENT CONNECTIVITY (30803-30808, written on the client)
// ---------------------------------------------------------------------------------------
pub fn parse_smb_client_connectivity(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    evtx_rows(file, &lateral_event_ids, build_event, map_smb_client_connectivity)
}

pub(crate) fn map_smb_client_connectivity(rec: &WinRec, file: &str) -> Option<LogData> {
    if !rec.has_event_data {
        return None;
    }
    // ServerName is a UNC reference (`\192.0.2.31`, and `\192.0.2.31\C$` on
    // 30807, the share lost); the SOCKADDR dumps are the fallback when it is
    // empty
    let (mut server, share) = split_unc(&rec.f("ServerName"));
    if server.is_empty() {
        server = ["RemoteAddress", "Address"].iter()
            .map(|k| rec.f(k))
            .find_map(|v| sockaddr_hex_ip(&v))
            .unwrap_or_default();
    }
    if server.is_empty() {
        return None;
    }
    let (user, domain) = split_account(&rec.f("UserName"));
    // written on the CLIENT: the local Computer is the source, a name,
    // never an address
    let (workstation_name, ip_address) = source_columns(&rec.computer);
    Some(LogData {
        time_created: rec.time.clone(),
        computer: strip_ipv4_mapped(&server),
        event_type: "CONNECT".to_string(),
        event_id: rec.event_id.clone(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: user,
        target_domain_name: domain,
        logon_type: String::from("3"),
        workstation_name,
        ip_address,
        logon_id: String::new(),
        filename: file.to_string(),
        detail: share,
    })
}

// ---------------------------------------------------------------------------------------
// RDP CLIENT (1024 / 1102, written on the client)
// ---------------------------------------------------------------------------------------
pub fn parse_rdp_client(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    evtx_rows(file, &lateral_event_ids, build_event, map_rdp_client)
}

pub(crate) fn map_rdp_client(rec: &WinRec, file: &str) -> Option<LogData> {
    if !rec.has_event_data {
        return None;
    }
    Some(LogData {
        time_created: rec.time.clone(),
        computer: rec.f("Value"),
        event_type: "CONNECT".to_string(),
        event_id: rec.event_id.clone(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: rec.user_sid.clone(),
        target_domain_name: String::new(),
        logon_type: String::from("10"),
        workstation_name: rec.computer.clone(),
        ip_address: rec.computer.clone(),
        logon_id: String::new(),
        filename: file.to_string(),
        detail: String::new(),
    })
}

// ---------------------------------------------------------------------------------------
// RDP CONNECTION MANAGER (1149, written on the server)
// ---------------------------------------------------------------------------------------
pub fn parse_rdp_connmanager(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    evtx_rows(file, &lateral_event_ids, build_event2, map_rdp_connmanager)
}

pub(crate) fn map_rdp_connmanager(rec: &WinRec, file: &str) -> Option<LogData> {
    if rec.time.is_empty() || rec.computer.is_empty() {
        return None;
    }
    // 1149 ("Remote Desktop Services: User authentication succeeded")
    // stores its data as UserData/EventXML with Param1 = user, Param2 =
    // domain, Param3 = source network address. UserData/EventData (the
    // legacy SMB shape) is kept as a fallback for any producer that writes it.
    let (target_user, target_domain, client) = if rec.has("Param1") || rec.has("Param3") {
        (rec.f("Param1"), rec.f("Param2"), rec.f("Param3"))
    } else if rec.has("UserName") || rec.has("ClientName") {
        (rec.f("UserName"), String::new(), rec.f("ClientName"))
    } else {
        if is_debug_mode() {
            println!("[DEBUG] RDP ConnManager record without EventXML/EventData, skipping");
        }
        return None;
    };
    let client = strip_ipv4_mapped(&client);
    let is_ip = client.parse::<std::net::IpAddr>().is_ok();
    Some(LogData {
        time_created: rec.time.clone(),
        computer: rec.computer.clone(),
        event_type: "SUCCESSFUL_LOGON".to_string(),
        event_id: rec.event_id.clone(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: target_user,
        target_domain_name: target_domain,
        logon_type: "10".into(),
        workstation_name: if is_ip { String::new() } else { client.clone() },
        ip_address: if is_ip { client } else { String::new() },
        logon_id: String::new(),
        filename: file.to_string(),
        detail: String::new(),
    })
}

// ---------------------------------------------------------------------------------------
// RDP LOCAL SESSION MANAGER (21 / 22 / 24 / 25, written on the server)
// ---------------------------------------------------------------------------------------
pub fn parse_rdp_localsession(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    evtx_rows(file, &lateral_event_ids, build_event2, map_rdp_localsession)
}

pub(crate) fn map_rdp_localsession(rec: &WinRec, file: &str) -> Option<LogData> {
    let mut remotedomain = String::new();
    let mut remoteuser = rec.f("User");
    if remoteuser.contains('\\') {
        let parts: Vec<&str> = remoteuser.split('\\').collect();
        remotedomain = parts[0].to_string();
        remoteuser = parts[1].to_string();
    }
    let event_type = match rec.event_id.as_str() {
        "21" | "22" | "25" => "SUCCESSFUL_LOGON".to_string(),
        "24" => "LOGOFF".to_string(),
        _ => "CONNECT".to_string(),
    };
    // Events 21/22/24/25 carry the session as <SessionID> (Param1 does not
    // exist in these templates).
    let session_id = if rec.has("SessionID") { rec.f("SessionID") } else { rec.f("Param1") };
    let address = rec.f("Address");
    Some(LogData {
        time_created: rec.time.clone(),
        computer: rec.computer.clone(),
        event_type,
        event_id: rec.event_id.clone(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: remoteuser,
        target_domain_name: remotedomain,
        logon_type: String::from("10"),
        workstation_name: address.clone(),
        ip_address: address,
        logon_id: session_id,
        filename: file.to_string(),
        detail: String::new(),
    })
}

// ---------------------------------------------------------------------------------------
// RDPCORETS (131, written on the server)
// ---------------------------------------------------------------------------------------
pub fn parse_rdpkore(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    evtx_rows(file, &lateral_event_ids, build_event, map_rdpkore)
}

pub(crate) fn map_rdpkore(rec: &WinRec, file: &str) -> Option<LogData> {
    if !rec.has_event_data {
        return None;
    }
    let client = rec.f("ClientIP");
    Some(LogData {
        time_created: rec.time.clone(),
        computer: rec.computer.clone(),
        event_type: "CONNECT".to_string(),
        event_id: rec.event_id.clone(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: String::new(),
        target_domain_name: String::new(),
        logon_type: String::from("10"),
        workstation_name: client.clone(),
        ip_address: client,
        logon_id: String::new(),
        filename: file.to_string(),
        detail: String::new(),
    })
}

// ---------------------------------------------------------------------------------------
// WINRM (6: WSMan session opened, written on the client)
// ---------------------------------------------------------------------------------------
pub fn parse_winrm(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    evtx_rows(file, &lateral_event_ids, build_event, map_winrm)
}

pub(crate) fn map_winrm(rec: &WinRec, file: &str) -> Option<LogData> {
    let connection = rec.f("connection");
    if connection.is_empty() {
        return None;
    }
    // Format: "hostname/wsman?PSVersion=..." or "http://ip:5985/wsman"
    let dst_host = extract_host_from_winrm_connection(&connection);
    // Skip empty, localhost, and self-connections
    if dst_host.is_empty() || dst_host.eq_ignore_ascii_case("localhost") || dst_host == "127.0.0.1" || dst_host == "::1" {
        return None;
    }
    let src_host = rec.computer.as_str();
    let dst_short = dst_host.split('.').next().unwrap_or(&dst_host);
    let src_short = src_host.split('.').next().unwrap_or(src_host);
    if dst_short.eq_ignore_ascii_case(src_short) {
        return None;
    }
    // Event 6 is written on the CLIENT that opened the WSMan session: the
    // local Computer is the source, the host in the connection string the
    // destination.
    let src_owned = src_host.to_string();
    let src_is_ip = src_owned.parse::<std::net::IpAddr>().is_ok();
    Some(LogData {
        time_created: rec.time.clone(),
        computer: dst_host,
        event_type: "CONNECT".to_string(),
        event_id: rec.event_id.clone(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: String::new(),
        target_domain_name: String::new(),
        logon_type: String::new(),
        workstation_name: if src_is_ip { String::new() } else { src_owned.clone() },
        ip_address: if src_is_ip { src_owned } else { String::new() },
        logon_id: String::new(),
        filename: file.to_string(),
        detail: format!("WinRM: {}", connection),
    })
}

/// Extract hostname or IP from WinRM connection string.
/// Examples: "dc01/wsman?PSVersion=5.1", "http://192.168.1.10:5985/wsman", "server.domain.com/wsman"
fn extract_host_from_winrm_connection(connection: &str) -> String {
    let s = connection.trim();
    // Strip protocol prefix if present
    let s = s.strip_prefix("http://").or_else(|| s.strip_prefix("https://")).unwrap_or(s);
    // Take everything before the first '/'
    let host = s.split('/').next().unwrap_or("");
    // [IPv6]:port
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("").to_string();
    }
    // Strip port if present (e.g., "192.168.1.10:5985"); a bare IPv6 has
    // several colons and no port.
    if host.matches(':').count() == 1 {
        return host.split(':').next().unwrap_or(host).to_string();
    }
    host.to_string()
}

// ---------------------------------------------------------------------------------------
// WMI-ACTIVITY (5858: WMI client failure, written on the server)
// ---------------------------------------------------------------------------------------
pub fn parse_wmi(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    evtx_rows(file, &lateral_event_ids, build_wmi, map_wmi)
}

/// One WMI-Activity record (XML) to a row.
pub(crate) fn wmi_row(xml: &str, file: &str, lateral_event_ids: &[&str]) -> Option<LogData> {
    let rec = build_wmi(xml)?;
    if !lateral_event_ids.contains(&rec.event_id.as_str()) {
        return None;
    }
    map_wmi(&rec, file)
}

/// 5858 is written on the SERVER whose WMI service refused an operation,
/// with the client in `ClientMachine`. Local clients (the machine itself, by
/// short name) and service accounts are not lateral movement and give None.
pub(crate) fn map_wmi(rec: &WinRec, file: &str) -> Option<LogData> {
    let client_machine = rec.f("ClientMachine");
    let user = rec.f("User");
    let operation = rec.f("Operation");
    let computer = rec.computer.clone();
    // Only remote WMI: ClientMachine must differ from Computer, compared by
    // short name (FQDN vs NetBIOS)
    let cm_short = client_machine.split('.').next().unwrap_or(&client_machine);
    let comp_short = computer.split('.').next().unwrap_or(&computer);
    if client_machine.is_empty() || cm_short.eq_ignore_ascii_case(comp_short) {
        return None;
    }
    let (username, domain) = split_account(&user);
    if username == "SYSTEM" || username == "LOCAL SERVICE" || username == "NETWORK SERVICE" {
        return None;
    }
    let (workstation_name, ip_address) = source_columns(&client_machine);
    Some(LogData {
        time_created: rec.time.clone(),
        computer,
        event_type: "CONNECT".to_string(),
        event_id: rec.event_id.clone(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: username,
        target_domain_name: domain,
        logon_type: String::new(),
        workstation_name,
        ip_address,
        logon_id: String::new(),
        filename: file.to_string(),
        detail: if operation.chars().count() > 100 {
            format!("WMI: {}...", operation.chars().take(100).collect::<String>())
        } else {
            format!("WMI: {}", operation)
        },
    })
}

// ---------------------------------------------------------------------------------------
// SYSMON (Microsoft-Windows-Sysmon/Operational)
// Event ID 3: network connection detected. The host where Sysmon runs is the
// LOCAL endpoint (Source*); the peer is Destination*. `Initiated` says whether
// the local process opened the connection (outbound) or accepted it (inbound):
//   Initiated=true  -> local -> remote, service port = DestinationPort
//   Initiated=false -> remote -> local, service port = SourcePort
// Only connections on a lateral-movement service port are kept, mapped to a
// CONNECT edge origin -> destination, with the process + protocol in `detail`.
// ---------------------------------------------------------------------------------------
pub fn parse_sysmon(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    evtx_rows(file, &lateral_event_ids, build_event, map_sysmon)
}

pub(crate) fn map_sysmon(rec: &WinRec, file: &str) -> Option<LogData> {
    if !rec.has_event_data {
        return None;
    }
    let computer = rec.computer.clone();
    let v = |k: &str| rec.f(k);
    let initiated = v("Initiated").eq_ignore_ascii_case("true");

    // (origin hostname, origin ip, dest hostname, dest ip, service port)
    let (origin_host, origin_ip, dest_host, dest_ip, port) = if initiated {
        (computer.clone(), v("SourceIp"), v("DestinationHostname"), v("DestinationIp"), v("DestinationPort"))
    } else {
        (v("DestinationHostname"), v("DestinationIp"), computer.clone(), v("SourceIp"), v("SourcePort"))
    };

    if !SYSMON_LM_PORTS.contains(&port.as_str()) {
        return None;
    }

    let dest_ip = strip_ipv4_mapped(&dest_ip);
    let origin_ip = strip_ipv4_mapped(&origin_ip);
    let dst_computer = if !dest_host.is_empty() && dest_host != "-" { dest_host } else { dest_ip };
    if dst_computer.is_empty() {
        return None;
    }
    // origin: a hostname when we have one, otherwise the bare IP
    let origin_is_ip = origin_host.is_empty() || origin_host == "-";
    let (src_computer, src_ip) = if origin_is_ip { (String::new(), origin_ip) } else { (origin_host, origin_ip) };

    // drop loopback / empty / self-connections (volume + noise control)
    let is_local = |s: &str| {
        s.is_empty() || s == "-" || s == "127.0.0.1" || s == "::1" || s == "0.0.0.0" || s.eq_ignore_ascii_case("localhost")
    };
    if is_local(&src_ip) && is_local(&src_computer) {
        return None;
    }
    if (!src_computer.is_empty() && src_computer.eq_ignore_ascii_case(&dst_computer))
        || (!src_ip.is_empty() && src_ip == dst_computer)
    {
        return None;
    }

    let (domain, user) = match v("User").split_once('\\') {
        Some((d, u)) => (d.to_string(), u.to_string()),
        None => (String::new(), v("User")),
    };
    let logon_type = match port.as_str() {
        "3389" | "5900" => "10",
        "22" => "SSH",
        _ => "3",
    }.to_string();
    let proto = v("Protocol");
    let image = v("Image");

    Some(LogData {
        time_created: rec.time.clone(),
        computer: dst_computer,
        event_type: "CONNECT".to_string(),
        event_id: rec.event_id.clone(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: user,
        target_domain_name: domain,
        logon_type,
        workstation_name: src_computer,
        ip_address: src_ip,
        logon_id: String::new(),
        filename: file.to_string(),
        detail: format!("Sysmon3 {} {} :{}", proto, image, port),
    })
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
            // the Security (31001) and Connectivity (30803-30808) channels
            // share this provider; their event ids do not overlap
            log_data = parse_smb_client(file, SMBCLIENT_EVENT_IDS.to_vec());
            log_data.extend(parse_smb_client_connectivity(file, SMBCLIENT_CONNECTIVITY_EVENT_IDS.to_vec()));
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
        "Microsoft-Windows-WinRM" => {
            log_data = parse_winrm(file, WINRM_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-WMI-Activity" => {
            log_data = parse_wmi(file, WMI_EVENT_IDS.to_vec())
        },
        "Microsoft-Windows-Sysmon" => {
            log_data = parse_sysmon(file, SYSMON_EVENT_IDS.to_vec())
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
/// UTC instant of any time_created string masstin writes, for sorting.
fn time_sort_key(raw: &str) -> Option<chrono::NaiveDateTime> {
    use chrono::{DateTime, NaiveDateTime, Utc};
    let t = raw.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(t) {
        return Some(dt.with_timezone(&Utc).naive_utc());
    }
    let t2 = t.replacen(' ', "T", 1);
    if let Ok(dt) = DateTime::parse_from_rfc3339(&t2) {
        return Some(dt.with_timezone(&Utc).naive_utc());
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(n) = NaiveDateTime::parse_from_str(&t2, f) {
            return Some(n);
        }
    }
    crate::timefmt::parse_fallback(t)
}

/// 4634 / 4647 (logoff) name no origin: the logon they close does. That is
/// the 4624 with the same TargetLogonId on the same machine, the latest one
/// at or before the logoff (a logon id can be reused after a reboot). Its
/// origin, and its logon type when the logoff has none (4647), are copied.
/// A logoff whose logon is not in the evidence names no origin, and a
/// masstin row needs one: it is not written. Returns the rows, how many
/// logoffs were given an origin and how many were dropped.
pub(crate) fn pair_logoffs(rows: Vec<LogData>) -> (Vec<LogData>, usize, usize) {
    let blank = |v: &str| { let t = v.trim(); t.is_empty() || t == "-" };
    let key = |r: &LogData| (r.computer.to_ascii_lowercase(), r.logon_id.to_ascii_lowercase());
    let mut logons: HashMap<(String, String), Vec<(Option<chrono::NaiveDateTime>, String, String, String)>> = HashMap::new();
    for r in &rows {
        if r.event_id == "4624" && !blank(&r.logon_id) {
            logons.entry(key(r)).or_default().push((
                time_sort_key(&r.time_created),
                r.workstation_name.clone(),
                r.ip_address.clone(),
                r.logon_type.clone(),
            ));
        }
    }
    for v in logons.values_mut() {
        v.sort_by(|a, b| a.0.cmp(&b.0));
    }
    let (mut filled, mut dropped) = (0usize, 0usize);
    let mut out = Vec::with_capacity(rows.len());
    for mut r in rows {
        let is_logoff = r.event_id == "4634" || r.event_id == "4647";
        if !is_logoff || !blank(&r.workstation_name) || !blank(&r.ip_address) {
            out.push(r);
            continue;
        }
        let t = time_sort_key(&r.time_created);
        let found = logons.get(&key(&r)).and_then(|v| {
            match t {
                // the latest logon at or before the logoff
                Some(t) => v.iter().rev().find(|l| l.0.map_or(true, |lt| lt <= t)),
                None => v.last(),
            }
        });
        match found {
            Some((_, wks, ip, lt)) => {
                r.workstation_name = wks.clone();
                r.ip_address = ip.clone();
                if r.logon_type.is_empty() {
                    r.logon_type = lt.clone();
                }
                filled += 1;
                out.push(r);
            }
            None => dropped += 1,
        }
    }
    (out, filled, dropped)
}

/// The summary line for `pair_logoffs`.
pub(crate) fn report_logoff_pairing(filled: usize, dropped: usize) {
    if filled + dropped > 0 {
        crate::banner::print_info(&format!(
            "  Logoffs (4634/4647): {} given the origin of the logon they close (same logon ID), {} not written (their logon is not in the evidence)",
            filled, dropped
        ));
    }
}

fn write_rows(log_data: Vec<LogData>, output: Option<&String>) -> usize {
    // before the noise filter: a logoff without its origin would be dropped
    // by --ignore-local before it could be given one
    let (log_data, filled, dropped) = pair_logoffs(log_data);
    report_logoff_pairing(filled, dropped);
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
            // logon_id and detail are part of the identity: Windows writes
            // two 4624 in the same microsecond for a split-token admin
            // logon (different TargetLogonId), and several 5140 for
            // different shares at once. VSS copies of a live event are
            // still collapsed because every field matches.
            let key = format!("{}|{}|{}|{}|{}|{}|{}|{}",
                item.time_created, item.computer, item.event_id,
                item.event_type, item.target_user_name, item.ip_address,
                item.logon_id, item.detail);
            if seen.insert(key) {
                deduped.push(item);
            }
        }
        deduped
    };

    let deduped_count = log_data.len();

    // Sort on the actual instant, not the text: EVTX writes
    // `...T..:..:...ffffffZ`, MountPoints2 `...+00:00`, UAL
    // `YYYY-MM-DD HH:MM:SS` — as strings a space sorts before `T`, so a UAL
    // row at 10:00 landed before an EVTX row at 08:00 the same day. The
    // text itself is written unchanged. Unparseable times sort last.
    let mut log_data = log_data;
    log_data.sort_by_cached_key(|x| (time_sort_key(&x.time_created), x.time_created.clone()));

    if let Err(e) = crate::csv_out::write_timeline(&log_data, output) {
        match output {
            Some(p) => eprintln!("[ERROR] Cannot write output file {}: {}", p, e),
            None => eprintln!("[ERROR] Cannot write output: {}", e),
        }
        return 0;
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
        "Microsoft-Windows-Sysmon%4Operational.evtx" => {
            parse_sysmon(&file_origin, SYSMON_EVENT_IDS.to_vec())
        },
        _ => {
            // Unknown filename (archived EVTX such as Security-YYYY-MM-DD-HH-MM-SS.evtx
            // that Windows drops into winevt\Logs\Archive\ when "Archive the log when
            // full" is enabled, operator-renamed files, or EVTX extracted from
            // third-party tooling). Fall back to Provider.Name dispatch so these
            // still get parsed. Users who want strict canonical-only matching can
            // simply point -d at the canonical Logs directory.
            parse_unknown(&file_origin)
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
    let total_after_dedup = write_rows(log_data, output);
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
    #[serde(rename = "@SystemTime")]
    SystemTime: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Provider {
    #[serde(rename = "@Name")]
    Name: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct EventData {
    #[serde(rename = "Data", default)]
    Datas: Vec<Data>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Data {
    #[serde(rename = "@Name")]
    Name: Option<String>,
    #[serde(rename = "$text")]
    pub body: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct UserData {
    EventData: Option<EventDataSMBServer>,
    EventXML: Option<EventXML>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Security {
    #[serde(rename = "@UserID")]
    UserID: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct EventDataSMBServer {
    ClientName: Option<String>,
    UserName: Option<String>,
    ClientAddress: Option<String>,
    Status: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct EventXML {
    Param1: Option<String>,
    Param2: Option<String>,
    Param3: Option<String>,
    User: Option<String>,
    Address: Option<String>,
    SessionID: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logoffs_take_the_origin_of_their_logon() {
        let row = |t: &str, eid: &str, et: &str, wks: &str, ip: &str, lt: &str, lid: &str| LogData {
            time_created: t.into(), computer: "SRV01.corp".into(), event_type: et.into(), event_id: eid.into(),
            subject_user_name: String::new(), subject_domain_name: String::new(),
            target_user_name: "alice".into(), target_domain_name: "CORP".into(), logon_type: lt.into(),
            workstation_name: wks.into(), ip_address: ip.into(), logon_id: lid.into(),
            filename: "Security.evtx".into(), detail: String::new(),
        };
        let rows = vec![
            row("2026-01-01T08:00:00Z", "4624", "SUCCESSFUL_LOGON", "WS01", "10.0.0.5", "3", "0x1a2b"),
            // the same logon id reused after a reboot, from another machine
            row("2026-01-02T08:00:00Z", "4624", "SUCCESSFUL_LOGON", "WS02", "10.0.0.6", "10", "0x1a2b"),
            row("2026-01-01T09:00:00Z", "4634", "LOGOFF", "", "", "3", "0x1a2b"),
            row("2026-01-02T09:00:00Z", "4647", "LOGOFF", "", "", "", "0x1A2B"),
            // its logon is not in the evidence
            row("2026-01-03T09:00:00Z", "4634", "LOGOFF", "", "", "3", "0xdead"),
        ];
        let (out, filled, dropped) = pair_logoffs(rows);
        assert_eq!((filled, dropped, out.len()), (2, 1, 4));
        let off: Vec<&LogData> = out.iter().filter(|r| r.event_type == "LOGOFF").collect();
        assert_eq!((off[0].workstation_name.as_str(), off[0].ip_address.as_str()), ("WS01", "10.0.0.5"));
        assert_eq!((off[1].workstation_name.as_str(), off[1].logon_type.as_str()), ("WS02", "10"));
    }

    #[test]
    fn unc_server_and_share() {
        assert_eq!(split_unc(r"\\192.0.2.76"), ("192.0.2.76".to_string(), String::new()));
        assert_eq!(split_unc(r"\192.0.2.31\C$"), ("192.0.2.31".to_string(), "C$".to_string()));
        assert_eq!(split_unc(r"\\srv01\ADMIN$\"), ("srv01".to_string(), "ADMIN$".to_string()));
        assert_eq!(split_unc("srv01"), ("srv01".to_string(), String::new()));
        assert_eq!(split_unc(""), (String::new(), String::new()));
    }

    #[test]
    fn sockaddr_dumps() {
        // AF_INET, port 0x7DB3, 127.0.0.1 (as SMBServer 551 writes ClientAddress)
        assert_eq!(sockaddr_hex_ip("02007DB37F0000010000000000000000"), Some("127.0.0.1".to_string()));
        // AF_INET, port 445, 192.168.1.43 (SmbClient 30803 RemoteAddress)
        assert_eq!(sockaddr_hex_ip("020001BDC0A8012B0000000000000000"), Some("192.168.1.43".to_string()));
        // unset
        assert_eq!(sockaddr_hex_ip("00000000000000000000000000000000"), None);
        assert_eq!(sockaddr_hex_ip(""), None);
        // AF_INET6, port 445, ::1
        assert_eq!(sockaddr_hex_ip(&format!("170001BD00000000{}01", "00".repeat(15))), Some("::1".to_string()));
    }

    #[test]
    fn accounts_split() {
        assert_eq!(split_account(r"NT AUTHORITY\ANONYMOUS LOGON"), ("ANONYMOUS LOGON".to_string(), "NT AUTHORITY".to_string()));
        assert_eq!(split_account("alice@corp.example"), ("alice".to_string(), "corp.example".to_string()));
        assert_eq!(split_account("bob"), ("bob".to_string(), String::new()));
    }

    /// A 5858 as Windows writes it (fields from a real record, names
    /// replaced), with the client on another machine.
    const WMI_5858: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WMI-Activity' Guid='{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}'/><EventID>5858</EventID><Version>0</Version><Level>2</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2026-10-07T14:28:11.1517614Z'/><EventRecordID>128870</EventRecordID><Correlation/><Execution ProcessID='4304' ThreadID='4728'/><Channel>Microsoft-Windows-WMI-Activity/Operational</Channel><Computer>SRV01.corp.example</Computer><Security UserID='S-1-5-18'/></System><UserData><Operation_ClientFailure xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'><Id>{0736B5DE-549D-0007-CE8C-51079D54DD01}</Id><ClientMachine>WS-ADMIN01</ClientMachine><User>CORP\alice</User><ClientProcessId>13300</ClientProcessId><Component>Unknown</Component><Operation>Start IWbemServices::ExecQuery - root\cimv2 : select * from Win32_Process</Operation><ResultCode>0x80041010</ResultCode><PossibleCause>Unknown</PossibleCause></Operation_ClientFailure></UserData></Event>"#;

    #[test]
    fn wmi_5858_remote_client_is_a_connect_row() {
        let row = wmi_row(WMI_5858, "f.evtx", &["5858"]).expect("remote 5858 gives a row");
        assert_eq!(row.event_type, "CONNECT");
        assert_eq!(row.computer, "SRV01.corp.example");
        assert_eq!(row.workstation_name, "WS-ADMIN01");
        assert_eq!(row.ip_address, "");
        assert_eq!(row.target_user_name, "alice");
        assert_eq!(row.target_domain_name, "CORP");
        assert_eq!(row.time_created, "2026-10-07T14:28:11.1517614Z");
        assert!(row.detail.starts_with("WMI: Start IWbemServices::ExecQuery"));
    }

    #[test]
    fn wmi_5858_local_client_is_dropped() {
        let local = WMI_5858.replace("<ClientMachine>WS-ADMIN01</ClientMachine>", "<ClientMachine>SRV01</ClientMachine>");
        assert!(wmi_row(&local, "f.evtx", &["5858"]).is_none());
        let svc = WMI_5858.replace(r"CORP\alice", r"NT AUTHORITY\SYSTEM");
        assert!(wmi_row(&svc, "f.evtx", &["5858"]).is_none());
    }
}
