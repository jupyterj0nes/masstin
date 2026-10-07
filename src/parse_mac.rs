// -----------------------------------------------------------------------------
//  macOS parser for masstin
//
//  What it reads
//  -------------
//  Two carriers of the same events, through one classifier:
//
//    * A `.logarchive` bundle — the binary Unified Log, as produced by
//      `sudo log collect` or exported from Console.app, and collected by
//      every macOS triage tool. masstin reads the tracev3 / dsc / uuidtext /
//      timesync files directly with the `macos-unifiedlogs` crate (pure
//      Rust, no Apple APIs), so a bundle acquired from a Mac can be parsed
//      on Windows or Linux just as well.
//
//    * A `log show` JSON export — `log show --style ndjson` (one JSON object
//      per line) or `log show --style json` (a single array). This is the
//      dependency-free path for an analyst who exported the log on the Mac
//      and carries the triage off as text, and it needs no uuidtext / dsc
//      catalogues to resolve the message.
//
//  What it extracts
//  ----------------
//  Only lateral movement, like every other masstin parser: remote logons to
//  this Mac, not console logins or local privilege changes. The two confirmed
//  macOS remote-access vectors are covered:
//
//    * sshd / sshd-session — SSH logons (success, failure, policy denial,
//      pre-authentication contact, disconnect). The message wording is the
//      same OpenSSH text masstin already parses on Linux, so the Linux
//      regexes are reused verbatim.
//
//    * screensharingd / ScreensharingAgent — Screen Sharing and Apple Remote
//      Desktop (ARD) screen-control sessions, which both authenticate through
//      screensharingd and log
//        "Authentication: SUCCEEDED :: User Name: <u> :: Viewer Address: <ip>"
//        "Authentication: FAILED    :: User Name: <u> :: Viewer Address: <ip>"
//
//  The destination of every row is this Mac; the source is the client that
//  connected (an address for SSH and Screen Sharing). The CSV stays the
//  14-column lateral-movement timeline — no new columns, no host-local rows.
//
//  Not yet covered (roadmap, see docs/parsing.md): smbd share connections
//  (the Unified Log message format is not documented reliably enough to parse
//  without guessing), `/var/log/system.log` / ASL text, and the utmpx / wtmpx
//  binary login databases.
// -----------------------------------------------------------------------------

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use walkdir::WalkDir;

use macos_unifiedlogs::cache::MemoryStringCache;
use macos_unifiedlogs::filesystem::LogarchiveProvider;
use macos_unifiedlogs::iterator::UnifiedLogIterator;
use macos_unifiedlogs::parser::{build_log, collect_timesync};
use macos_unifiedlogs::traits::{FileProvider, SourceFile};
use macos_unifiedlogs::unified_log::{LogData as UlData, UnifiedLogData};

use crate::parse::LogData;
use crate::parse_linux::{
    preauth_touch, SSH_DISCONNECT_RE, SSH_FAIL_RE, SSH_NOTALLOWED_RE, SSH_OK_RE,
};

// ───────────────────────────── screensharingd ────────────────────────────────
// "Authentication: SUCCEEDED :: User Name: deanwinchester :: Viewer Address: 192.168.1.1 :: Type: DH"
// "Authentication: FAILED :: User Name: geertl :: Viewer Address: 10.0.0.9 :: Type: DH"
// The user name is captured non-greedily so a value with spaces (a macOS
// full name) does not swallow the " :: Viewer Address:" separator.
static SCREENSHARE_OK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Authentication:\s*SUCCEEDED\s*::\s*User Name:\s*(.*?)\s*::\s*Viewer Address:\s*(\S+)").unwrap()
});
static SCREENSHARE_FAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"Authentication:\s*FAILED\s*::\s*User Name:\s*(.*?)\s*::\s*Viewer Address:\s*(\S+)").unwrap()
});
// The ":: Type: <kind>" tail names the authentication method (DH, VNC, …).
static SCREENSHARE_TYPE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"::\s*Type:\s*(\S+)").unwrap());

/// Route a source token to the right column: an address goes to `src_ip`,
/// anything else (a hostname) to `src_computer`. Returns
/// `(src_computer, src_ip)`.
fn src_columns(token: &str) -> (String, String) {
    let t = token.trim_end_matches(|c: char| c == ',' || c == ':' || c == '.');
    if t.parse::<std::net::IpAddr>().is_ok() {
        (String::new(), t.to_string())
    } else {
        (t.to_string(), String::new())
    }
}

/// One classified lateral-movement fact, before it is placed on the Mac
/// being analysed as the destination.
struct Classified {
    event_type: &'static str,
    event_id: &'static str,
    user: String,
    src: String,
    logon_type: &'static str,
    detail: String,
}

/// The basename of a process path (`/usr/sbin/sshd` -> `sshd`), lower-cased.
fn proc_base(process: &str) -> String {
    process
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(process)
        .trim()
        .to_ascii_lowercase()
}

/// True when this process is one masstin reads on macOS. Keeping the filter
/// here (not only in the classifier) lets the binary reader discard the vast
/// majority of records before resolving their message strings.
fn is_relevant_process(process: &str) -> bool {
    let b = proc_base(process);
    b.starts_with("sshd") || b == "screensharingd" || b == "screensharingagent"
}

/// The heart of the parser: turn one `(process, message)` pair into a
/// lateral-movement fact, or `None` when the line is not one. The same
/// function serves the binary logarchive and the JSON export.
fn classify(process: &str, message: &str) -> Option<Classified> {
    let b = proc_base(process);

    if b.starts_with("sshd") {
        // Order matters: a failed login must be tested before the success
        // form, and both before the pre-auth touches.
        if let Some(c) = SSH_FAIL_RE.captures(message) {
            let method = &c[1];
            let user = c.get(3).map_or("", |m| m.as_str());
            let invalid = c.get(2).is_some();
            return Some(Classified {
                event_type: "FAILED_LOGON",
                event_id: "MAC-SSHD-FAIL",
                user: user.to_string(),
                src: c[4].to_string(),
                logon_type: "SSH",
                detail: format!(
                    "ssh failed {}{}",
                    method,
                    if invalid { " (invalid user)" } else { "" }
                ),
            });
        }
        if let Some(c) = SSH_OK_RE.captures(message) {
            return Some(Classified {
                event_type: "SUCCESSFUL_LOGON",
                event_id: "MAC-SSHD-OK",
                user: c[2].to_string(),
                src: c[3].to_string(),
                logon_type: "SSH",
                detail: format!("ssh accepted {}", &c[1]),
            });
        }
        if let Some(c) = SSH_NOTALLOWED_RE.captures(message) {
            return Some(Classified {
                event_type: "FAILED_LOGON",
                event_id: "MAC-SSHD-DENY",
                user: c[1].to_string(),
                src: c[2].to_string(),
                logon_type: "SSH",
                detail: "ssh user not allowed by policy".to_string(),
            });
        }
        if let Some(c) = SSH_DISCONNECT_RE.captures(message) {
            return Some(Classified {
                event_type: "LOGOFF",
                event_id: "MAC-SSHD-LOGOFF",
                user: c[1].to_string(),
                src: c[2].to_string(),
                logon_type: "SSH",
                detail: "ssh session ended".to_string(),
            });
        }
        if let Some((src, kind)) = preauth_touch(message) {
            return Some(Classified {
                event_type: "CONNECT",
                event_id: "MAC-SSHD-PREAUTH",
                user: String::new(),
                src,
                logon_type: "SSH",
                detail: format!("ssh {}", kind),
            });
        }
        return None;
    }

    if b == "screensharingd" || b == "screensharingagent" {
        let kind = SCREENSHARE_TYPE_RE
            .captures(message)
            .map(|c| c[1].to_string());
        if let Some(c) = SCREENSHARE_OK_RE.captures(message) {
            return Some(Classified {
                event_type: "SUCCESSFUL_LOGON",
                event_id: "MAC-SCREENSHARE-OK",
                user: c[1].trim().to_string(),
                src: c[2].to_string(),
                logon_type: "ScreenSharing",
                detail: match kind {
                    Some(k) => format!("screen sharing authenticated type={}", k),
                    None => "screen sharing authenticated".to_string(),
                },
            });
        }
        if let Some(c) = SCREENSHARE_FAIL_RE.captures(message) {
            return Some(Classified {
                event_type: "FAILED_LOGON",
                event_id: "MAC-SCREENSHARE-FAIL",
                user: c[1].trim().to_string(),
                src: c[2].to_string(),
                logon_type: "ScreenSharing",
                detail: match kind {
                    Some(k) => format!("screen sharing authentication failed type={}", k),
                    None => "screen sharing authentication failed".to_string(),
                },
            });
        }
        return None;
    }

    None
}

/// Build a timeline row from a classified fact. The Mac being analysed
/// (`dst`) is always the destination; the classified source is split into
/// its address / hostname column.
fn row(ts_iso: String, dst: &str, file: &str, c: Classified) -> LogData {
    let (src_computer, src_ip) = src_columns(&c.src);
    LogData {
        time_created: ts_iso,
        computer: dst.to_string(),
        event_type: c.event_type.to_string(),
        event_id: c.event_id.to_string(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: c.user,
        target_domain_name: String::new(),
        logon_type: c.logon_type.to_string(),
        workstation_name: src_computer,
        ip_address: src_ip,
        logon_id: String::new(),
        filename: file.to_string(),
        detail: c.detail,
    }
}

// ──────────────────────────── timestamp helpers ──────────────────────────────

/// A Unified Log `LogData.time` is nanoseconds since the Unix epoch. Render
/// it as the ISO form masstin writes everywhere (`…Z`, microsecond
/// precision), which every downstream reader already accepts.
fn ul_time_iso(nanos: f64) -> String {
    let n = nanos as i64;
    Utc.timestamp_nanos(n)
        .to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// Parse the `timestamp` field of a `log show` JSON export
/// ("2021-04-27 10:03:30.981638-0700", also RFC 3339) into masstin ISO UTC.
/// Falls back to the raw value, which `crate::timefmt` may still resolve.
fn json_time_iso(raw: &str) -> String {
    let t = raw.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(t) {
        return dt
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Micros, true);
    }
    for f in [
        "%Y-%m-%d %H:%M:%S%.f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%.f%z",
    ] {
        if let Ok(dt) = DateTime::parse_from_str(t, f) {
            return dt
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Micros, true);
        }
    }
    t.to_string()
}

// ──────────────────────────── host identification ────────────────────────────

/// The name of the Mac whose logs these are. There is no clean per-record
/// hostname in the Unified Log, so the bundle / file name is used, stripped
/// of the `.logarchive` suffix. A `log collect` archive is conventionally
/// named after the host.
fn host_from_path(p: &Path) -> String {
    let name = p
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown-mac");
    name.strip_suffix(".logarchive")
        .unwrap_or(name)
        .trim_end_matches(".json")
        .trim_end_matches(".ndjson")
        .to_string()
}

// ──────────────────────────── logarchive reader ──────────────────────────────

/// A directory is a logarchive if it holds at least one `*.tracev3` file and
/// a `timesync` directory — true for a `.logarchive` bundle whatever its
/// name.
fn is_logarchive_dir(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let mut has_tracev3 = false;
    let mut has_timesync = false;
    for e in WalkDir::new(dir).max_depth(2).into_iter().filter_map(Result::ok) {
        let p = e.path();
        if p.is_dir() && p.file_name().and_then(|s| s.to_str()) == Some("timesync") {
            has_timesync = true;
        }
        if p.extension().and_then(|s| s.to_str()) == Some("tracev3") {
            has_tracev3 = true;
        }
        if has_tracev3 && has_timesync {
            return true;
        }
    }
    false
}

/// Filter one batch of resolved Unified Log records down to lateral-movement
/// rows, appending them to `out`.
fn harvest(records: &[UlData], dst: &str, file: &str, out: &mut Vec<LogData>) {
    for r in records {
        if !is_relevant_process(&r.process) {
            continue;
        }
        if let Some(c) = classify(&r.process, &r.message) {
            out.push(row(ul_time_iso(r.time), dst, file, c));
        }
    }
}

/// Parse one `.logarchive` bundle. Mirrors the two-pass oversize handling of
/// the crate's own example: records whose large strings live in a different,
/// already-rolled tracev3 file are set aside and retried once every oversize
/// entry has been seen, so nothing is dropped.
fn parse_logarchive(dir: &Path, out: &mut Vec<LogData>) {
    let dst = host_from_path(dir);
    let provider = LogarchiveProvider::new(dir);
    let timesync = match collect_timesync(&provider) {
        Ok(t) => t,
        Err(e) => {
            crate::banner::print_info(&format!(
                "macOS: could not read timesync in {}: {:?}",
                dir.display(),
                e
            ));
            HashMap::new()
        }
    };
    let cache = MemoryStringCache::default();

    let mut oversize: Vec<_> = Vec::new();
    let mut missing: Vec<UnifiedLogData> = Vec::new();

    for mut source in provider.tracev3_files() {
        let path = source.source_path().to_string();
        if Path::new(&path)
            .file_name()
            .and_then(|f| f.to_str())
            .is_some_and(|f| f.starts_with("._"))
        {
            continue;
        }
        let mut buf = Vec::new();
        if source.reader().read_to_end(&mut buf).is_err() {
            continue;
        }
        let iter = UnifiedLogIterator {
            data: buf,
            header: Vec::new(),
            evidence: path.clone(),
        };
        for mut chunk in iter {
            chunk.oversize.append(&mut oversize);
            let (results, missing_logs) = build_log(&chunk, &provider, &cache, &timesync, true);
            harvest(&results, &dst, &path, out);
            oversize = chunk.oversize;
            missing.push(missing_logs);
        }
    }

    // Second pass: entries that referenced an Oversize string we had not yet
    // seen. Retry with every oversize entry available and keep whatever
    // resolves (exclude_missing = false).
    for mut leftover in std::mem::take(&mut missing) {
        leftover.oversize.clone_from(&oversize);
        let (results, _) = build_log(&leftover, &provider, &cache, &timesync, false);
        harvest(&results, &dst, &leftover.evidence.clone(), out);
    }
}

// ──────────────────────────── JSON export reader ─────────────────────────────

/// Pull `(process, message, timestamp)` out of one `log show` JSON object.
/// `log show` names them `processImagePath` (or `process`), `eventMessage`
/// and `timestamp`.
fn classify_json_value(v: &serde_json::Value, dst: &str, file: &str) -> Option<LogData> {
    let process = v
        .get("processImagePath")
        .or_else(|| v.get("process"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    if !is_relevant_process(process) {
        return None;
    }
    let message = v.get("eventMessage").and_then(|x| x.as_str()).unwrap_or("");
    let c = classify(process, message)?;
    let ts = v
        .get("timestamp")
        .and_then(|x| x.as_str())
        .map(json_time_iso)
        .unwrap_or_default();
    Some(row(ts, dst, file, c))
}

/// Parse a `log show` export: `--style ndjson` (one object per line) or
/// `--style json` (a single array). Both are detected from the content.
fn parse_json_export(path: &Path, out: &mut Vec<LogData>) {
    let dst = host_from_path(path);
    let file = path.display().to_string();
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            crate::banner::print_info(&format!("macOS: cannot read {}: {}", file, e));
            return;
        }
    };
    let trimmed = text.trim_start();
    if trimmed.starts_with('[') {
        // `--style json`: a single array.
        if let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(&text)
        {
            for v in &items {
                if let Some(r) = classify_json_value(v, &dst, &file) {
                    out.push(r);
                }
            }
        }
    } else {
        // `--style ndjson`: one object per line.
        for line in text.lines() {
            let line = line.trim().trim_end_matches(',');
            if line.is_empty() || line == "[" || line == "]" {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(r) = classify_json_value(&v, &dst, &file) {
                    out.push(r);
                }
            }
        }
    }
}

/// True when a file looks like a `log show` JSON / NDJSON export.
fn looks_like_json_export(path: &Path) -> bool {
    match path.extension().and_then(|s| s.to_str()) {
        Some("json") | Some("ndjson") | Some("jsonl") => true,
        _ => false,
    }
}

// ──────────────────────────── entry point ────────────────────────────────────

pub fn parse_mac(files: &[String], dirs: &[String], output: Option<&String>) {
    let start = std::time::Instant::now();
    crate::banner::print_search_start();

    let mut rows: Vec<LogData> = Vec::new();
    let mut sources = 0usize;

    // Explicit -f files: a .logarchive given by path, or a JSON export.
    for f in files {
        let p = PathBuf::from(f);
        if p.is_dir() && is_logarchive_dir(&p) {
            crate::banner::print_info(&format!("macOS logarchive: {}", p.display()));
            parse_logarchive(&p, &mut rows);
            sources += 1;
        } else if looks_like_json_export(&p) {
            crate::banner::print_info(&format!("macOS log show export: {}", p.display()));
            parse_json_export(&p, &mut rows);
            sources += 1;
        } else {
            crate::banner::print_info(&format!(
                "macOS: {} is neither a .logarchive nor a JSON export — skipped",
                p.display()
            ));
        }
    }

    // -d directories: a .logarchive itself, or a tree that contains
    // .logarchive bundles and / or JSON exports (e.g. an unpacked triage).
    for d in dirs {
        let root = PathBuf::from(d);
        if is_logarchive_dir(&root) {
            crate::banner::print_info(&format!("macOS logarchive: {}", root.display()));
            parse_logarchive(&root, &mut rows);
            sources += 1;
            continue;
        }
        for e in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
            let p = e.path();
            if p.is_dir()
                && p.extension().and_then(|s| s.to_str()) == Some("logarchive")
                && is_logarchive_dir(p)
            {
                crate::banner::print_info(&format!("macOS logarchive: {}", p.display()));
                parse_logarchive(p, &mut rows);
                sources += 1;
            } else if p.is_file() && looks_like_json_export(p) {
                crate::banner::print_info(&format!("macOS log show export: {}", p.display()));
                parse_json_export(p, &mut rows);
                sources += 1;
            }
        }
    }

    // Deterministic order: by timestamp string, then host, then source.
    rows.sort_by(|a, b| {
        a.time_created
            .cmp(&b.time_created)
            .then(a.computer.cmp(&b.computer))
            .then(a.filename.cmp(&b.filename))
    });

    if rows.is_empty() {
        crate::banner::print_info(
            "macOS: no SSH or Screen Sharing lateral movement found in the sources provided",
        );
    }
    if let Err(e) = crate::csv_out::write_timeline(&rows, output) {
        eprintln!("Error writing macOS timeline: {}", e);
        return;
    }
    crate::banner::print_info(&format!(
        "macOS: {} row(s) from {} source(s) in {:.1}s",
        rows.len(),
        sources,
        start.elapsed().as_secs_f32()
    ));
}

// ───────────────────────────────── tests ─────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_success_and_failure() {
        let ok = classify(
            "/usr/sbin/sshd",
            "Accepted publickey for alice from 10.0.0.5 port 50022 ssh2: ED25519 SHA256:abc",
        )
        .unwrap();
        assert_eq!(ok.event_type, "SUCCESSFUL_LOGON");
        assert_eq!(ok.user, "alice");
        assert_eq!(ok.src, "10.0.0.5");
        assert_eq!(ok.logon_type, "SSH");

        let fail = classify(
            "sshd",
            "Failed password for invalid user root from 203.0.113.7 port 40510 ssh2",
        )
        .unwrap();
        assert_eq!(fail.event_type, "FAILED_LOGON");
        assert_eq!(fail.user, "root");
        assert_eq!(fail.src, "203.0.113.7");
        assert!(fail.detail.contains("invalid user"));

        // sshd-session (OpenSSH 9.8+) is the same text.
        assert!(classify(
            "sshd-session",
            "Accepted keyboard-interactive/pam for bob from 10.1.2.3 port 5022 ssh2"
        )
        .is_some());
    }

    #[test]
    fn ssh_disconnect_and_preauth() {
        let off = classify("sshd", "Disconnected from user alice 10.0.0.5 port 51234").unwrap();
        assert_eq!(off.event_type, "LOGOFF");
        assert_eq!(off.user, "alice");

        let pre = classify(
            "sshd",
            "Did not receive identification string from 198.51.100.4 port 55000",
        )
        .unwrap();
        assert_eq!(pre.event_type, "CONNECT");
        assert_eq!(pre.src, "198.51.100.4");
    }

    #[test]
    fn screensharing_success_and_failure() {
        let ok = classify(
            "screensharingd",
            "Authentication: SUCCEEDED :: User Name: deanwinchester :: Viewer Address: 192.168.1.10 :: Type: DH",
        )
        .unwrap();
        assert_eq!(ok.event_type, "SUCCESSFUL_LOGON");
        assert_eq!(ok.user, "deanwinchester");
        assert_eq!(ok.src, "192.168.1.10");
        assert_eq!(ok.logon_type, "ScreenSharing");
        assert!(ok.detail.contains("type=DH"));

        let fail = classify(
            "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd",
            "Authentication: FAILED :: User Name: geertl :: Viewer Address: 10.0.0.9 :: Type: DH",
        )
        .unwrap();
        assert_eq!(fail.event_type, "FAILED_LOGON");
        assert_eq!(fail.user, "geertl");
        assert_eq!(fail.src, "10.0.0.9");
    }

    #[test]
    fn irrelevant_processes_and_messages_are_dropped() {
        assert!(classify("loginwindow", "USER_PROCESS").is_none());
        assert!(classify("sudo", "alice : TTY=ttys000 ; PWD=/ ; USER=root ; COMMAND=/bin/ls").is_none());
        assert!(classify("sshd", "Server listening on 0.0.0.0 port 22.").is_none());
        assert!(!is_relevant_process("kernel"));
        assert!(is_relevant_process("/usr/sbin/sshd"));
        assert!(is_relevant_process("screensharingd"));
    }

    #[test]
    fn source_is_split_into_the_right_column() {
        assert_eq!(src_columns("10.0.0.5"), (String::new(), "10.0.0.5".to_string()));
        assert_eq!(
            src_columns("mac-air.local"),
            ("mac-air.local".to_string(), String::new())
        );
    }

    #[test]
    fn json_timestamp_becomes_iso_utc() {
        assert_eq!(
            json_time_iso("2021-04-27 10:03:30.981638-0700"),
            "2021-04-27T17:03:30.981638Z"
        );
        assert_eq!(
            json_time_iso("2024-05-01T09:05:00Z"),
            "2024-05-01T09:05:00.000000Z"
        );
    }

    #[test]
    fn host_name_strips_the_logarchive_suffix() {
        assert_eq!(
            host_from_path(Path::new("/eco/MACBOOK-01.logarchive")),
            "MACBOOK-01"
        );
    }
}
