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

/// `10.0.0.5:51234` → `10.0.0.5`, `[2001:db8::1]:3389` → `2001:db8::1`,
/// `srv01:3389` → `srv01`. A value without a port, or a bare IPv6, is
/// returned as it is. RdpCoreTS 131 writes the client as address:port.
pub(crate) fn strip_port(v: &str) -> String {
    let t = v.trim();
    if let Some(rest) = t.strip_prefix('[') {
        if let Some(i) = rest.find(']') {
            return rest[..i].to_string();
        }
    }
    if let Some((host, port)) = t.rsplit_once(':') {
        if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && !host.contains(':') {
            return host.to_string();
        }
    }
    t.to_string()
}

/// Text of the first `<tag>` element of an event's XML (`<EventID>4624`,
/// `<Channel>Security`), without deserialising the record: enough to pick
/// its family. Empty when the element is missing or self-closing.
fn xml_tag_text(xml: &str, tag: &str) -> String {
    let open = format!("<{}", tag);
    let mut from = 0;
    while let Some(i) = xml[from..].find(&open) {
        let start = from + i + open.len();
        match xml[start..].chars().next() {
            Some('>') | Some(' ') | Some('\t') | Some('\n') | Some('\r') => {}
            _ => { from = start; continue; }
        }
        let gt = match xml[start..].find('>') { Some(g) => start + g, None => return String::new() };
        if xml[..gt].ends_with('/') {
            return String::new();
        }
        return xml[gt + 1..].split("</").next().unwrap_or("").trim().to_string();
    }
    String::new()
}

/// The channels a provider writes the events masstin reads to, for a
/// record that carries no `<Channel>` (old exports). Ids do not overlap
/// between the two SMB client channels.
fn channels_for_provider(provider: &str) -> &'static [&'static str] {
    match provider {
        "Microsoft-Windows-Security-Auditing" => &["Security"],
        "Microsoft-Windows-SMBServer" => &["Microsoft-Windows-SMBServer/Security"],
        "Microsoft-Windows-SMBClient" => &["Microsoft-Windows-SmbClient/Security", "Microsoft-Windows-SmbClient/Connectivity"],
        "Microsoft-Windows-TerminalServices-ClientActiveXCore" => &["Microsoft-Windows-TerminalServices-RDPClient/Operational"],
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager" => &["Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"],
        "Microsoft-Windows-TerminalServices-LocalSessionManager" => &["Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"],
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS" => &["Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"],
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV" => &["Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational"],
        "Microsoft-Windows-WinRM" => &["Microsoft-Windows-WinRM/Operational"],
        "Microsoft-Windows-WMI-Activity" => &["Microsoft-Windows-WMI-Activity/Operational"],
        "Microsoft-Windows-Sysmon" => &["Microsoft-Windows-Sysmon/Operational"],
        "OpenSSH" => &["OpenSSH/Operational"],
        _ => &[],
    }
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
// 5145 (Detailed File Share) fires on every object access inside an SMB
// session, 50+ per connection, and is a subcategory of its own: a domain
// can audit it without 5140 (File Share), and then it is the only trace of
// the share connection. It is read and collapsed to one row per
// (destination, logon ID, origin, share) per file, see `collapse_5145`.
const SECURITY_EVENT_IDS: &[&str] = &["4624","4625","4634","4647","4648","4768","4769","4770","4771","4776","4778","4779","5140","5145"];
const SMBCLIENT_EVENT_IDS: &[&str] = &["31001"];
const SMBCLIENT_CONNECTIVITY_EVENT_IDS: &[&str] = &["30803","30804","30805","30806","30807","30808"];
const SMBSERVER_EVENT_IDS: &[&str] = &["1009","551"];
const RDPCLIENT_EVENT_IDS: &[&str] = &["1024","1102"];
const RDPCONNMANAGER_EVENT_IDS: &[&str] = &["1149"];
const RDPLOCALSESSION_EVENT_IDS: &[&str] = &["21","22","24","25"];
// RdpCoreTS (and RdpCoreCDV on Windows 10/11 hosts): 131 is the accepted
// TCP connection, 140 the NLA failure ("failed because the user name or
// password is not correct") with the client address.
const RDPKORE_EVENT_IDS: &[&str] = &["131","140"];
const WINRM_EVENT_IDS: &[&str] = &["6"];
const WMI_EVENT_IDS: &[&str] = &["5858"];
// OpenSSH/Operational: Windows' sshd writes the OpenSSH text ("Accepted
// password for alice from 10.0.0.5 port 51234 ssh2") as `payload` of event
// 4 (information) and 3 (error); parse-linux's regexes read it.
const OPENSSH_EVENT_IDS: &[&str] = &["3","4"];
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
    /// System/Execution/@ProcessID (Winlogbeat: `winlog.process.pid`): the
    /// process that wrote the event. OpenSSH's sshd runs one process per
    /// connection, so it ties the lines of one connection together.
    pub pid: String,
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
        pid: event.System.Execution.as_ref().and_then(|e| e.ProcessID.clone()).unwrap_or_default(),
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
        pid: event.System.Execution.as_ref().and_then(|e| e.ProcessID.clone()).unwrap_or_default(),
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
        pid: String::new(),
        fields,
        has_event_data: false,
    })
}

type MapFn = fn(&WinRec, &str) -> Option<LogData>;
type BuildFn = fn(&str) -> Option<WinRec>;

/// The reader (XML shape) and the mapping for an event of `channel` (the
/// EVTX channel name, as Winlogbeat writes it in `winlog.channel`), or None
/// when masstin does not read that event. Event ids are only unique within
/// a channel (1102 is an RDP client event and also "audit log cleared" in
/// Security; 6, 4 and 3 exist in many channels), so the channel decides the
/// family.
pub(crate) fn family_for_channel(channel: &str, event_id: &str) -> Option<(BuildFn, MapFn)> {
    let c = channel.to_ascii_lowercase();
    let table: [(&str, &[&str], BuildFn, MapFn); 13] = [
        ("security", SECURITY_EVENT_IDS, build_event, map_security),
        ("microsoft-windows-smbserver/", SMBSERVER_EVENT_IDS, build_event2, map_smb_server),
        ("microsoft-windows-smbclient/security", SMBCLIENT_EVENT_IDS, build_event, map_smb_client),
        ("microsoft-windows-smbclient/connectivity", SMBCLIENT_CONNECTIVITY_EVENT_IDS, build_event, map_smb_client_connectivity),
        ("microsoft-windows-terminalservices-rdpclient/", RDPCLIENT_EVENT_IDS, build_event, map_rdp_client),
        ("microsoft-windows-terminalservices-remoteconnectionmanager/", RDPCONNMANAGER_EVENT_IDS, build_event2, map_rdp_connmanager),
        ("microsoft-windows-terminalservices-localsessionmanager/", RDPLOCALSESSION_EVENT_IDS, build_event2, map_rdp_localsession),
        ("microsoft-windows-remotedesktopservices-rdpcorets/", RDPKORE_EVENT_IDS, build_event, map_rdpkore),
        ("microsoft-windows-remotedesktopservices-rdpcorecdv/", RDPKORE_EVENT_IDS, build_event, map_rdpkore),
        ("microsoft-windows-winrm/", WINRM_EVENT_IDS, build_event, map_winrm),
        ("microsoft-windows-wmi-activity/", WMI_EVENT_IDS, build_wmi, map_wmi),
        ("microsoft-windows-sysmon/", SYSMON_EVENT_IDS, build_event, map_sysmon),
        ("openssh/", OPENSSH_EVENT_IDS, build_event, map_openssh),
    ];
    table.iter()
        .find(|(prefix, ids, _, _)| {
            (if *prefix == "security" { c == "security" } else { c.starts_with(prefix) }) && ids.contains(&event_id)
        })
        .map(|(_, _, b, m)| (*b, *m))
}

/// The mapping alone, for readers that build the record themselves
/// (Winlogbeat documents).
pub(crate) fn mapper_for_channel(channel: &str, event_id: &str) -> Option<MapFn> {
    family_for_channel(channel, event_id).map(|(_, m)| m)
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
    collapse_5145(evtx_rows(file, &lateral_event_ids, build_event, map_security))
}

/// The share of a 5140 / 5145 detail: `\\*\ADMIN$` of
/// `\\*\ADMIN$\System32\cmd.exe` (the share reference is always
/// `\\<server>\<share>`, three separators in).
fn share_of_detail(detail: &str) -> &str {
    let mut seps = 0;
    for (i, c) in detail.char_indices() {
        if c == '\\' || c == '/' {
            seps += 1;
            if seps == 4 {
                return &detail[..i];
            }
        }
    }
    detail
}

/// 5145 is written once per object accessed inside an SMB session; the
/// lateral-movement fact is the session on the share. Keep the first 5145
/// per (destination, logon ID, origin, share) of one file, drop the rest.
pub(crate) fn collapse_5145(rows: Vec<LogData>) -> Vec<LogData> {
    let mut seen: std::collections::HashSet<(String, String, String, String, String)> = std::collections::HashSet::new();
    rows.into_iter()
        .filter(|r| {
            if r.event_id != "5145" {
                return true;
            }
            seen.insert((
                r.computer.to_ascii_lowercase(),
                r.logon_id.to_ascii_lowercase(),
                r.ip_address.clone(),
                r.workstation_name.to_ascii_lowercase(),
                share_of_detail(&r.detail).to_ascii_lowercase(),
            ))
        })
        .collect()
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
        "5140" | "5145" => "SUCCESSFUL_LOGON".to_string(),
        _ => "CONNECT".to_string(),
    };
    let detail = match event_id.as_str() {
        "4624" | "4648" => v("ProcessName"),
        "4625" => translate_substatus(&v("SubStatus")),
        "5140" => v("ShareName"),
        // the object as a path on the share: `\\*\ADMIN$\System32\cmd.exe`
        "5145" => {
            let share = v("ShareName");
            let target = v("RelativeTargetName");
            if target.is_empty() || target == "-" { share } else { format!("{}\\{}", share.trim_end_matches('\\'), target) }
        }
        // the service the ticket was issued for: the real destination of
        // the move (the row's destination is the KDC)
        "4769" | "4770" => v("ServiceName"),
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
        "5140" | "5145" => (computer.clone(), v("SubjectUserName"), v("SubjectDomainName"), v("WorkstationName"), v("IpAddress"), v("SubjectLogonId")),
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
    // written on the CLIENT: the local Computer is the source, a name
    let (workstation_name, ip_address) = source_columns(&rec.computer);
    Some(LogData {
        time_created: rec.time.clone(),
        computer: strip_port(&rec.f("Value")),
        event_type: "CONNECT".to_string(),
        event_id: rec.event_id.clone(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: rec.user_sid.clone(),
        target_domain_name: String::new(),
        logon_type: String::from("10"),
        workstation_name,
        ip_address,
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
    // Address is the client's address, or "LOCAL" for a console session
    let (workstation_name, ip_address) = source_columns(&strip_ipv4_mapped(&rec.f("Address")));
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
        workstation_name,
        ip_address,
        logon_id: session_id,
        filename: file.to_string(),
        detail: String::new(),
    })
}

// ---------------------------------------------------------------------------------------
// RDPCORETS / RDPCORECDV (131 / 140, written on the server)
// ---------------------------------------------------------------------------------------
pub fn parse_rdpkore(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    evtx_rows(file, &lateral_event_ids, build_event, map_rdpkore)
}

/// 131: "The server accepted a new TCP connection from client
/// <ClientIP>", written as address:port. 140: "A connection from the
/// client computer with an IP address of <IPString> failed because the
/// user name or password is not correct": the NLA failure, often the only
/// trace of an RDP brute force when 4625 carries no address.
pub(crate) fn map_rdpkore(rec: &WinRec, file: &str) -> Option<LogData> {
    if !rec.has_event_data {
        return None;
    }
    let (event_type, client) = match rec.event_id.as_str() {
        "140" => ("FAILED_LOGON", rec.f("IPString")),
        _ => ("CONNECT", rec.f("ClientIP")),
    };
    let client = strip_ipv4_mapped(&strip_port(&client));
    if client.is_empty() {
        return None;
    }
    let (workstation_name, ip_address) = source_columns(&client);
    Some(LogData {
        time_created: rec.time.clone(),
        computer: rec.computer.clone(),
        event_type: event_type.to_string(),
        event_id: rec.event_id.clone(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: String::new(),
        target_domain_name: String::new(),
        logon_type: String::from("10"),
        workstation_name,
        ip_address,
        logon_id: String::new(),
        filename: file.to_string(),
        detail: if rec.event_id == "140" { "NLA: user name or password not correct".to_string() } else { String::new() },
    })
}

// ---------------------------------------------------------------------------------------
// OPENSSH/OPERATIONAL (3 / 4, written on the server: Windows' sshd)
// ---------------------------------------------------------------------------------------
pub fn parse_openssh(file: &str, lateral_event_ids: Vec<&str>) -> Vec<LogData> {
    pair_openssh(evtx_rows(file, &lateral_event_ids, build_event, map_openssh))
}

/// The `payload` of an OpenSSH event is the OpenSSH log text, read with
/// the parse-linux regexes: `Accepted <method> for <user> from <src>`,
/// `Failed ...`, `Invalid user ...`, policy denials, session ends and
/// pre-authentication touches. The destination is the machine that wrote
/// the event, the logon id its sshd process (one per connection).
pub(crate) fn map_openssh(rec: &WinRec, file: &str) -> Option<LogData> {
    use crate::parse_linux::{preauth_touch, INVALID_USER_RE, SSH_DISCONNECT_RE, SSH_FAIL_RE, SSH_NOTALLOWED_RE, SSH_OK_RE};
    if !rec.has_event_data {
        return None;
    }
    let msg = rec.f("payload");
    let msg = msg.trim();
    let (event_type, user, src, detail) = if let Some(c) = SSH_FAIL_RE.captures(msg) {
        // "Failed none" is the client asking which methods are allowed
        if &c[1] == "none" {
            return None;
        }
        let invalid = if c.get(2).is_some() { " invalid-user" } else { "" };
        ("FAILED_LOGON", c[3].to_string(), c[4].to_string(), format!("ssh/{}{}", &c[1], invalid))
    } else if let Some(c) = SSH_OK_RE.captures(msg) {
        ("SUCCESSFUL_LOGON", c[2].to_string(), c[3].to_string(), format!("ssh/{}", &c[1]))
    } else if let Some(c) = SSH_NOTALLOWED_RE.captures(msg) {
        ("FAILED_LOGON", c[1].to_string(), c[2].to_string(), "ssh/not-allowed".to_string())
    } else if let Some(c) = INVALID_USER_RE.captures(msg) {
        // resolved per connection by `pair_openssh`
        ("FAILED_LOGON", c[1].trim().to_string(), c[2].to_string(), "ssh/invalid-user".to_string())
    } else if let Some(c) = SSH_DISCONNECT_RE.captures(msg).filter(|_| !msg.contains("[preauth]")) {
        ("LOGOFF", c[1].to_string(), c[2].to_string(), "ssh/disconnected".to_string())
    } else if let Some((src, kind)) = preauth_touch(msg) {
        ("CONNECT", String::new(), src, format!("ssh/{}", kind))
    } else if let Some(c) = OPENSSH_BARE_DISCONNECT_RE.captures(msg) {
        // Windows' sshd ends an authenticated session with the bare
        // "Received disconnect from <src> port <n>:11: ..." and
        // "Disconnected from <src> port <n>" (no user, no [preauth]):
        // `pair_openssh` turns it into the LOGOFF of the Accepted with the
        // same process, else into a pre-authentication close
        ("CONNECT", String::new(), c[1].to_string(), "ssh/preauth-closed".to_string())
    } else if let Some(c) = OPENSSH_BANNER_RE.captures(msg) {
        ("CONNECT", String::new(), c[1].to_string(), "ssh/preauth-bad-proto".to_string())
    } else {
        return None;
    };
    let src = strip_ipv4_mapped(&src);
    if src.is_empty() {
        return None;
    }
    let (workstation_name, ip_address) = source_columns(&src);
    Some(LogData {
        time_created: rec.time.clone(),
        computer: rec.computer.clone(),
        event_type: event_type.to_string(),
        event_id: rec.event_id.clone(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: user,
        target_domain_name: String::new(),
        logon_type: String::from("SSH"),
        workstation_name,
        ip_address,
        logon_id: rec.pid.clone(),
        filename: file.to_string(),
        detail,
    })
}

/// Windows' sshd session ends, without user or `[preauth]` tag (seen on
/// Server 2019, OpenSSH for Windows 8.x): captures the source.
static OPENSSH_BARE_DISCONNECT_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
    regex::Regex::new(r"^(?:Received disconnect from|Disconnected from)\s+(\S+)\s+port\s+\d+").unwrap()
});
/// "banner exchange: Connection from <src> port <n>: invalid format": a
/// client that sent no SSH banner (OpenSSH 8.5+ wording).
static OPENSSH_BANNER_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
    regex::Regex::new(r"banner exchange: Connection from (\S+) port \d+: invalid format").unwrap()
});

/// Per sshd process (one per connection):
///  * as `parse_linux::invalid_users_as_failures`, a connection that named
///    an account that does not exist is one failed logon. When it also
///    logged `Failed <method> for invalid user`, that row is the failure
///    and the announcement is dropped; when it logged no outcome, the
///    first announcement (the `Invalid user` line, else a pre-auth close
///    naming the invalid user) is the failure and the connection's other
///    pre-auth rows go with it;
///  * a close logged by a process that had an `Accepted` is the end of
///    that session: one LOGOFF with the session's account (Windows' sshd
///    writes "Disconnected from <src> port <n>" without the user), the
///    other close lines of the process dropped.
/// Rows without a process id are taken one by one.
pub(crate) fn pair_openssh(rows: Vec<LogData>) -> Vec<LogData> {
    use std::collections::{HashMap, HashSet};
    let key = |r: &LogData| (r.computer.to_ascii_lowercase(), r.logon_id.clone());
    let announced = |r: &LogData| r.detail == "ssh/invalid-user" || r.detail.starts_with("ssh/preauth-closed invalid-user=");
    let outcome = |r: &LogData| (r.event_type == "FAILED_LOGON" || r.event_type == "SUCCESSFUL_LOGON") && r.detail != "ssh/invalid-user";
    let is_close = |r: &LogData| r.event_type == "CONNECT" && r.detail.starts_with("ssh/preauth-closed");
    let mut has_outcome: HashSet<(String, String)> = HashSet::new();
    // the account of the Accepted per process, and the index of the last
    // close line of that process (the session's end)
    let mut accepted: HashMap<(String, String), String> = HashMap::new();
    let mut last_close: HashMap<(String, String), usize> = HashMap::new();
    for (i, r) in rows.iter().enumerate() {
        if r.logon_id.is_empty() {
            continue;
        }
        if outcome(r) {
            has_outcome.insert(key(r));
        }
        if r.event_type == "SUCCESSFUL_LOGON" {
            accepted.entry(key(r)).or_insert_with(|| r.target_user_name.clone());
        }
        if is_close(r) {
            last_close.insert(key(r), i);
        }
    }
    let rows: Vec<LogData> = rows
        .into_iter()
        .enumerate()
        .filter_map(|(i, mut r)| {
            if r.logon_id.is_empty() || !is_close(&r) {
                return Some(r);
            }
            let user = match accepted.get(&key(&r)) {
                Some(u) => u.clone(),
                None => return Some(r),
            };
            if last_close.get(&key(&r)) != Some(&i) {
                return None;
            }
            r.event_type = "LOGOFF".to_string();
            r.target_user_name = user;
            r.detail = "ssh/disconnected".to_string();
            Some(r)
        })
        .collect();
    let mut first: HashMap<(String, String), usize> = HashMap::new();
    for (i, r) in rows.iter().enumerate() {
        if announced(r) && !r.logon_id.is_empty() && !has_outcome.contains(&key(r)) {
            first.entry(key(r)).or_insert(i);
        }
    }
    let converted: HashSet<(String, String)> = first.keys().cloned().collect();
    let keep_idx: HashSet<usize> = first.values().copied().collect();
    let mut out = Vec::with_capacity(rows.len());
    for (i, mut r) in rows.into_iter().enumerate() {
        let is_announcement = announced(&r);
        if keep_idx.contains(&i) || (is_announcement && r.logon_id.is_empty()) {
            if r.event_type == "CONNECT" {
                r.target_user_name = r.detail.split("invalid-user=").nth(1).unwrap_or("").to_string();
            }
            r.event_type = "FAILED_LOGON".to_string();
            r.detail = "ssh/invalid-user".to_string();
            out.push(r);
        } else if r.detail == "ssh/invalid-user" {
            // the connection logged its own Failed line, or a later repeat
        } else if r.event_type == "CONNECT" && converted.contains(&key(&r)) {
            // the same connection, now a failed logon
        } else {
            out.push(r);
        }
    }
    out
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
// UNKNOWN FILE NAME: EVERY RECORD BY ITS CHANNEL
// ---------------------------------------------------------------------------------------
/// An EVTX whose name says nothing (an archived `Security-2024-...evtx`,
/// a renamed copy, a carved file, a collector's `ForwardedEvents.evtx` with
/// the Security of many hosts next to other channels): each record is
/// routed by its own `<Channel>` (by provider when it has none), so a file
/// with one record, or with several families, is read whole. The file used
/// to be routed by the provider of its second record only.
pub fn parse_unknown(file: &str) -> Vec<LogData> {
    if is_debug_mode() {
        println!("[DEBUG] MASSTIN: Parsing {} by channel", file);
    }
    let (mut parser, mut log_data) = match prep_parse(EvtxLocation::File(file.to_string())) {
        Ok(p) => p,
        Err(_) => return vec![],
    };
    for record in parser.records() {
        let r = match record { Ok(r) => r, Err(_) => continue };
        let xml = r.data.as_str();
        let event_id = xml_tag_text(xml, "EventID");
        if event_id.is_empty() {
            continue;
        }
        let channel = xml_tag_text(xml, "Channel");
        let family = if channel.is_empty() {
            let provider = from_str::<Event>(xml).ok().and_then(|e| e.System.Provider.Name).unwrap_or_default();
            channels_for_provider(&provider).iter().find_map(|c| family_for_channel(c, &event_id))
        } else {
            family_for_channel(&channel, &event_id)
        };
        let (build, map) = match family { Some(f) => f, None => continue };
        if let Some(rec) = build(xml) {
            if let Some(row) = map(&rec, file) {
                log_data.push(row);
            }
        }
    }
    pair_openssh(collapse_5145(log_data))
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
            // logon_id, the origin name and detail are part of the
            // identity: Windows writes two 4624 in the same microsecond for
            // a split-token admin logon (different TargetLogonId), and
            // several 5140 for different shares at once. VSS copies of a
            // live event are still collapsed because every field matches.
            let key = format!("{}|{}|{}|{}|{}|{}|{}|{}|{}",
                item.time_created, item.computer, item.event_id,
                item.event_type, item.target_user_name, item.ip_address,
                item.workstation_name, item.logon_id, item.detail);
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
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx"
        | "Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV%4Operational.evtx" => {
            parse_rdpkore(&file_origin, RDPKORE_EVENT_IDS.to_vec())
        },
        "OpenSSH%4Operational.evtx" => {
            parse_openssh(&file_origin, OPENSSH_EVENT_IDS.to_vec())
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
    Execution: Option<Execution>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Execution {
    #[serde(rename = "@ProcessID")]
    ProcessID: Option<String>,
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

    #[test]
    fn ports_are_dropped_from_client_addresses() {
        assert_eq!(strip_port("194.61.24.102:39550"), "194.61.24.102");
        assert_eq!(strip_port("[2001:db8::1]:3389"), "2001:db8::1");
        assert_eq!(strip_port("fe80::1"), "fe80::1");
        assert_eq!(strip_port("srv01:3389"), "srv01");
        assert_eq!(strip_port("10.0.0.5"), "10.0.0.5");
        assert_eq!(strip_port(""), "");
    }

    #[test]
    fn tag_text_picks_the_family_fields_without_deserialising() {
        let xml = "<Event><System><Provider Name='X'/><EventID Qualifiers='0'>4624</EventID><Channel>Security</Channel><Correlation/></System></Event>";
        assert_eq!(xml_tag_text(xml, "EventID"), "4624");
        assert_eq!(xml_tag_text(xml, "Channel"), "Security");
        assert_eq!(xml_tag_text(xml, "Correlation"), "");
        assert_eq!(xml_tag_text("<EventIDx>1</EventIDx>", "EventID"), "");
        assert_eq!(xml_tag_text("<a>1</a>", "EventID"), "");
    }

    /// A record as a Windows OpenSSH server writes it (fields from a real
    /// record of the public EVTX-to-MITRE set, names replaced).
    fn openssh_xml(pid: u32, payload: &str) -> String {
        format!("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='OpenSSH' Guid='{{C4B57D35-0636-4BC3-A262-370F249F9802}}'/><EventID>4</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000000</Keywords><TimeCreated SystemTime='2021-05-21T20:43:22.562971Z'/><EventRecordID>24</EventRecordID><Correlation/><Execution ProcessID='{}' ThreadID='4344'/><Channel>OpenSSH/Operational</Channel><Computer>fs01.corp.example</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='process'>sshd</Data><Data Name='payload'>{}</Data></EventData></Event>", pid, payload)
    }

    #[test]
    fn openssh_payloads_are_ssh_rows_on_the_windows_host() {
        let (build, map) = family_for_channel("OpenSSH/Operational", "4").expect("OpenSSH is a family");
        let row = |pid: u32, payload: &str| map(&build(&openssh_xml(pid, payload)).unwrap(), "f.evtx");
        let ok = row(4332, "Accepted password for admmig from 10.23.23.9 port 56605 ssh2").unwrap();
        assert_eq!((ok.event_type.as_str(), ok.computer.as_str(), ok.target_user_name.as_str(), ok.ip_address.as_str(), ok.logon_type.as_str(), ok.logon_id.as_str(), ok.detail.as_str()),
                   ("SUCCESSFUL_LOGON", "fs01.corp.example", "admmig", "10.23.23.9", "SSH", "4332", "ssh/password"));
        let failed = row(4332, "Failed password for admmig from 10.23.23.9 port 56605 ssh2").unwrap();
        assert_eq!((failed.event_type.as_str(), failed.workstation_name.as_str()), ("FAILED_LOGON", ""));
        assert!(row(4332, "Failed none for admmig from 10.23.23.9 port 56605 ssh2").is_none());
        let pre = row(988, "Connection closed by authenticating user admmig 10.23.23.9 port 56589 [preauth]").unwrap();
        assert_eq!((pre.event_type.as_str(), pre.target_user_name.as_str(), pre.detail.as_str()), ("CONNECT", "", "ssh/preauth-closed user=admmig"));
        let off = row(4332, "Disconnected from user admmig 10.23.23.9 port 56605").unwrap();
        assert_eq!(off.event_type, "LOGOFF");
        assert!(row(4332, "Server listening on :: port 22.").is_none());
        // the same file name routes through parselog, the channel through parse_unknown
        assert!(family_for_channel("Security", "4").is_none());
    }

    #[test]
    fn openssh_invalid_user_connections_are_one_failed_logon() {
        let (build, map) = family_for_channel("OpenSSH/Operational", "4").unwrap();
        let row = |pid: u32, payload: &str| map(&build(&openssh_xml(pid, payload)).unwrap(), "f.evtx").unwrap();
        let rows = vec![
            // a key-only exchange: no Failed line ever comes
            row(100, "Invalid user admin from 10.23.23.9 port 1000"),
            row(100, "Connection closed by invalid user admin 10.23.23.9 port 1000 [preauth]"),
            // a password guess: the Failed line is the failure
            row(200, "Invalid user test from 10.23.23.9 port 1001"),
            row(200, "Failed password for invalid user test from 10.23.23.9 port 1001 ssh2"),
        ];
        let out = pair_openssh(rows);
        assert_eq!(out.len(), 2);
        assert_eq!((out[0].event_type.as_str(), out[0].target_user_name.as_str(), out[0].detail.as_str(), out[0].logon_id.as_str()),
                   ("FAILED_LOGON", "admin", "ssh/invalid-user", "100"));
        assert_eq!((out[1].target_user_name.as_str(), out[1].detail.as_str()), ("test", "ssh/password invalid-user"));
    }

    /// Lines as Windows Server 2019's sshd writes them (one process per
    /// connection, from a RangeForge lab): the session end carries no user.
    #[test]
    fn openssh_windows_session_ends_take_the_account_of_their_accepted() {
        let (build, map) = family_for_channel("OpenSSH/Operational", "4").unwrap();
        let row = |pid: u32, payload: &str| map(&build(&openssh_xml(pid, payload)).unwrap(), "f.evtx").unwrap();
        let rows = vec![
            row(4604, "Accepted publickey for Administrator from 35.235.248.226 port 46625 ssh2: ED25519 SHA256:abc"),
            row(4604, "Received disconnect from 35.235.248.226 port 46625:11: disconnected by user"),
            row(4604, "Disconnected from 35.235.248.226 port 46625"),
            // an IAP health probe: a close with no Accepted stays a touch
            row(2220, "Connection closed by 35.235.248.224 port 39001 [preauth]"),
            row(2224, "banner exchange: Connection from 35.235.247.32 port 35445: invalid format"),
        ];
        let out = pair_openssh(rows);
        let v: Vec<(&str, &str, &str, &str)> = out.iter().map(|r| (r.event_type.as_str(), r.target_user_name.as_str(), r.detail.as_str(), r.logon_id.as_str())).collect();
        assert_eq!(v, vec![
            ("SUCCESSFUL_LOGON", "Administrator", "ssh/publickey", "4604"),
            ("LOGOFF", "Administrator", "ssh/disconnected", "4604"),
            ("CONNECT", "", "ssh/preauth-closed", "2220"),
            ("CONNECT", "", "ssh/preauth-bad-proto", "2224"),
        ]);
        assert_eq!(out[1].ip_address, "35.235.248.226");
    }

    #[test]
    fn rdpcore_131_and_140_name_the_client_address() {
        let xml = |id: &str, name: &str, value: &str| format!("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS'/><EventID>{}</EventID><TimeCreated SystemTime='2020-09-19T03:20:25.469636Z'/><Channel>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</Channel><Computer>DC01.corp.example</Computer></System><EventData><Data Name='{}'>{}</Data></EventData></Event>", id, name, value);
        let (build, map) = family_for_channel("Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational", "131").expect("CDV is routed like TS");
        let r = map(&build(&xml("131", "ClientIP", "194.61.24.102:39550")).unwrap(), "f.evtx").unwrap();
        assert_eq!((r.event_type.as_str(), r.ip_address.as_str(), r.workstation_name.as_str(), r.logon_type.as_str()), ("CONNECT", "194.61.24.102", "", "10"));
        let (build, map) = family_for_channel("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "140").unwrap();
        let r = map(&build(&xml("140", "IPString", "194.61.24.102")).unwrap(), "f.evtx").unwrap();
        assert_eq!((r.event_type.as_str(), r.ip_address.as_str(), r.computer.as_str()), ("FAILED_LOGON", "194.61.24.102", "DC01.corp.example"));
    }

    #[test]
    fn detailed_share_access_is_one_row_per_session_on_a_share() {
        let row = |t: &str, lid: &str, ip: &str, detail: &str| LogData {
            time_created: t.into(), computer: "FS01".into(), event_type: "SUCCESSFUL_LOGON".into(), event_id: "5145".into(),
            subject_user_name: "alice".into(), subject_domain_name: "CORP".into(),
            target_user_name: "alice".into(), target_domain_name: "CORP".into(), logon_type: "3".into(),
            workstation_name: String::new(), ip_address: ip.into(), logon_id: lid.into(),
            filename: "Security.evtx".into(), detail: detail.into(),
        };
        let rows = vec![
            row("2026-01-01T08:00:00Z", "0x1", "10.0.0.5", r"\\*\ADMIN$\System32\cmd.exe"),
            row("2026-01-01T08:00:01Z", "0x1", "10.0.0.5", r"\\*\ADMIN$\System32\svc.exe"),
            row("2026-01-01T08:00:02Z", "0x1", "10.0.0.5", r"\\*\IPC$\svcctl"),
            row("2026-01-01T09:00:00Z", "0x2", "10.0.0.5", r"\\*\ADMIN$\System32\cmd.exe"),
        ];
        let out = collapse_5145(rows);
        let details: Vec<&str> = out.iter().map(|r| r.detail.as_str()).collect();
        assert_eq!(details, vec![r"\\*\ADMIN$\System32\cmd.exe", r"\\*\IPC$\svcctl", r"\\*\ADMIN$\System32\cmd.exe"]);
        assert_eq!(share_of_detail(r"\\*\ADMIN$\System32\cmd.exe"), r"\\*\ADMIN$");
        assert_eq!(share_of_detail(r"\\*\IPC$"), r"\\*\IPC$");
    }
}
