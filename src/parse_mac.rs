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
use std::io::{BufRead, BufReader, Read};
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

// ────────────────────────── sshd on macOS, pre-auth ──────────────────────────
// Seen on real Sonoma 14.8 and Sequoia 15.7 bundles (OpenSSH 9.9,
// sshd-session): a connection that closes before authenticating is logged
// without the `[preauth]` tag Linux writes, as a bare
//   "Connection closed by 127.0.0.1 port 49181"
// (a closed session is "Disconnected from user ..." / "Connection closed by
// user ..."), and a client that sends no SSH banner as
//   "banner exchange: Connection from 127.0.0.1 port 49188: invalid format"
// (the wording that replaced "Bad protocol version identification").
static MAC_PREAUTH_CLOSED_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^Connection closed by ([0-9A-Fa-f][0-9A-Fa-f:.]*) port \d+\s*$").unwrap());
static MAC_PREAUTH_BANNER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"banner exchange: Connection from (\S+) port \d+: invalid format").unwrap());

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

// Sonoma 14.8 and Sequoia 15.7 no longer write the "Authentication: ..."
// line (the format string is gone from screensharingd). An ARD / VNC logon
// leaves separate lines, same process, same instant:
//   "*outUID= 502"                       the account's uid (successes only)
//   "authResult = 0" / "authResult = 1"  the outcome
//   "new viewer connection: 10.0.0.9"    the client's address (seen on
//                                        Sequoia failures; "Connection
//                                        accepted :: Viewer Address: %s" is
//                                        the other form in the binary)
// They are paired per process within a few seconds (`pair_screenshare`).
// A row needs an origin: an outcome without a viewer address is counted
// and dropped, a viewer address without an outcome is a CONNECT.
static SS_VIEWER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:new viewer connection:|Connection accepted :: Viewer Address:)\s*(\S+)").unwrap()
});
static SS_AUTH_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^authResult = (\d+)").unwrap());
static SS_UID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\*outUID= (\d+)").unwrap());

/// One screensharingd line of the modern, split kind.
#[derive(Debug, Clone, PartialEq)]
enum SsKind {
    Viewer(String),
    Auth(u32),
    Uid(u64),
}

#[derive(Debug, Clone)]
struct SsEvt {
    /// microseconds since the epoch
    t_us: i64,
    pid: u64,
    kind: SsKind,
}

fn screenshare_event(process: &str, message: &str) -> Option<SsKind> {
    let b = proc_base(process);
    if b != "screensharingd" {
        return None;
    }
    let m = message.trim();
    if let Some(c) = SS_VIEWER_RE.captures(m) {
        return Some(SsKind::Viewer(c[1].trim_end_matches(|ch: char| ch == ',' || ch == '.').to_string()));
    }
    if let Some(c) = SS_AUTH_RE.captures(m) {
        return c[1].parse().ok().map(SsKind::Auth);
    }
    if let Some(c) = SS_UID_RE.captures(m) {
        return c[1].parse().ok().map(SsKind::Uid);
    }
    None
}

fn us_iso(t_us: i64) -> String {
    Utc.timestamp_nanos(t_us.saturating_mul(1000))
        .to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// Pair the split screensharingd lines into rows. Per process: a viewer
/// address and an outcome within `WINDOW` of each other make a login row
/// (SUCCESSFUL_LOGON with `uid:<n>` when the uid was logged just before,
/// FAILED_LOGON otherwise); a viewer address with no outcome is a CONNECT;
/// an outcome with no address is counted in `no_origin` and dropped.
/// Returns the rows and the number of outcomes dropped for lack of origin.
fn pair_screenshare(mut evts: Vec<SsEvt>, dst: &str, file: &str) -> (Vec<LogData>, usize) {
    const WINDOW: i64 = 5_000_000;
    const UID_WINDOW: i64 = 2_000_000;
    evts.sort_by_key(|e| e.t_us);
    let mut rows = Vec::new();
    let mut no_origin = 0usize;
    // per pid: pending viewer (ip, t), pending outcome (result, t), last uid (n, t)
    let mut viewer: HashMap<u64, (String, i64)> = HashMap::new();
    let mut auth: HashMap<u64, (u32, i64)> = HashMap::new();
    let mut uid: HashMap<u64, (u64, i64)> = HashMap::new();
    // per pid: the address of the connection last turned into a row, so the
    // accept path logging it again a moment later is not a second row
    let mut recent: HashMap<u64, (String, i64)> = HashMap::new();
    let emit = |rows: &mut Vec<LogData>, ip: &str, t: i64, res: Option<u32>, who: Option<u64>| {
        let (event_type, event_id, detail) = match res {
            Some(0) => ("SUCCESSFUL_LOGON", "MAC-SCREENSHARE-OK", "screen sharing authenticated (authResult 0)".to_string()),
            Some(r) => ("FAILED_LOGON", "MAC-SCREENSHARE-FAIL", format!("screen sharing authentication failed (authResult {})", r)),
            None => ("CONNECT", "MAC-SCREENSHARE-CONNECT", "screen sharing viewer connected, outcome not logged".to_string()),
        };
        rows.push(row(
            us_iso(t),
            dst,
            file,
            Classified {
                event_type,
                event_id,
                user: who.map(|u| format!("uid:{}", u)).unwrap_or_default(),
                src: ip.to_string(),
                logon_type: "ScreenSharing",
                detail,
            },
        ));
    };
    let flush_viewer = |rows: &mut Vec<LogData>, v: Option<(String, i64)>| {
        if let Some((ip, t)) = v {
            emit(rows, &ip, t, None, None);
        }
    };
    for e in evts {
        match e.kind {
            SsKind::Uid(n) => {
                uid.insert(e.pid, (n, e.t_us));
            }
            SsKind::Auth(res) => {
                let who = uid.get(&e.pid).filter(|(_, t)| (e.t_us - t).abs() <= UID_WINDOW).map(|(n, _)| *n);
                match viewer.get(&e.pid) {
                    Some((ip, t)) if (e.t_us - t).abs() <= WINDOW => {
                        let (ip, t) = (ip.clone(), *t);
                        viewer.remove(&e.pid);
                        emit(&mut rows, &ip, t.min(e.t_us), Some(res), if res == 0 { who } else { None });
                        recent.insert(e.pid, (ip, e.t_us));
                    }
                    other => {
                        if other.is_some() {
                            // an older viewer that never got an outcome
                            let v = viewer.remove(&e.pid);
                            flush_viewer(&mut rows, v);
                        }
                        if let Some((_, t)) = auth.get(&e.pid) {
                            if (e.t_us - t).abs() > WINDOW {
                                no_origin += 1;
                            }
                        }
                        auth.insert(e.pid, (res, e.t_us));
                    }
                }
            }
            SsKind::Viewer(ip) => {
                if let Some((rip, rt)) = recent.get(&e.pid) {
                    if *rip == ip && (e.t_us - rt).abs() <= WINDOW {
                        continue;
                    }
                }
                if let Some((res, t)) = auth.get(&e.pid).copied() {
                    if (e.t_us - t).abs() <= WINDOW {
                        auth.remove(&e.pid);
                        let who = uid.get(&e.pid).filter(|(_, tu)| (t - tu).abs() <= UID_WINDOW).map(|(n, _)| *n);
                        emit(&mut rows, &ip, t.min(e.t_us), Some(res), if res == 0 { who } else { None });
                        recent.insert(e.pid, (ip, e.t_us));
                        continue;
                    }
                }
                match viewer.get(&e.pid) {
                    Some((vip, t)) if *vip == ip && (e.t_us - t).abs() <= WINDOW => {
                        // the accept path logs the address again: same connection
                    }
                    _ => {
                        let v = viewer.remove(&e.pid);
                        flush_viewer(&mut rows, v);
                        viewer.insert(e.pid, (ip, e.t_us));
                    }
                }
            }
        }
    }
    for (_, v) in viewer.drain() {
        flush_viewer(&mut rows, Some(v));
    }
    no_origin += auth.len();
    (rows, no_origin)
}

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
        if let Some(c) = MAC_PREAUTH_CLOSED_RE.captures(message.trim()) {
            return Some(Classified {
                event_type: "CONNECT",
                event_id: "MAC-SSHD-PREAUTH",
                user: String::new(),
                src: c[1].to_string(),
                logon_type: "SSH",
                detail: "ssh preauth-closed".to_string(),
            });
        }
        if let Some(c) = MAC_PREAUTH_BANNER_RE.captures(message) {
            return Some(Classified {
                event_type: "CONNECT",
                event_id: "MAC-SSHD-PREAUTH",
                user: String::new(),
                src: c[1].to_string(),
                logon_type: "SSH",
                detail: "ssh preauth-bad-proto".to_string(),
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
/// precision), which every downstream reader already accepts. Truncated to
/// the microsecond the way `log show` prints it, so a bundle and its
/// export carry the same instant (up to the float the crate hands over).
fn ul_time_iso(nanos: f64) -> String {
    us_iso(ul_micros(nanos))
}

/// Microseconds since the epoch, truncated as `log show` truncates.
fn ul_micros(nanos: f64) -> i64 {
    (nanos / 1000.0).floor() as i64
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

/// What a logarchive pass saw, for `--debug`: how many records were
/// scanned, how many came from sshd / screensharingd, how many became rows.
#[derive(Default)]
struct Tally {
    scanned: usize,
    sshd: usize,
    screenshare: usize,
    rows: usize,
    /// sshd / screensharingd messages that classified as nothing (first
    /// 40 of each, printed with --debug so an empty timeline can be
    /// explained)
    unclassified: Vec<String>,
    /// modern screensharingd lines, paired at the end (see `pair_screenshare`)
    ss: Vec<SsEvt>,
    /// screensharingd outcomes dropped for lack of a viewer address
    ss_no_origin: usize,
}

/// Filter one batch of resolved Unified Log records down to lateral-movement
/// rows, appending them to `out`.
fn harvest(records: &[UlData], dst: &str, file: &str, out: &mut Vec<LogData>, tally: &mut Tally) {
    tally.scanned += records.len();
    for r in records {
        if !is_relevant_process(&r.process) {
            continue;
        }
        if proc_base(&r.process).starts_with("sshd") {
            tally.sshd += 1;
        } else {
            tally.screenshare += 1;
        }
        match classify(&r.process, &r.message) {
            Some(c) => {
                tally.rows += 1;
                out.push(row(ul_time_iso(r.time), dst, file, c));
            }
            None => {
                if let Some(kind) = screenshare_event(&r.process, &r.message) {
                    tally.ss.push(SsEvt { t_us: ul_micros(r.time), pid: r.pid, kind });
                    continue;
                }
                // up to 40 per process, so a busy sshd does not hide what
                // screensharingd wrote
                let is_ssh = proc_base(&r.process).starts_with("sshd");
                let same: usize = tally.unclassified.iter().filter(|m| m.contains(if is_ssh { " sshd" } else { " screensharing" })).count();
                if same < 40 {
                    tally.unclassified.push(format!("{} {} [{:?} {:?}]: {}", ul_time_iso(r.time), proc_base(&r.process), r.event_type, r.log_type, r.message.trim()));
                }
            }
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
    let mut tally = Tally::default();
    let mut files = 0usize;

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
        files += 1;
        let iter = UnifiedLogIterator {
            data: buf,
            header: Vec::new(),
            evidence: path.clone(),
        };
        for mut chunk in iter {
            chunk.oversize.append(&mut oversize);
            let (results, missing_logs) = build_log(&chunk, &provider, &cache, &timesync, true);
            harvest(&results, &dst, &path, out, &mut tally);
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
        harvest(&results, &dst, &leftover.evidence.clone(), out, &mut tally);
    }
    let (ss_rows, dropped) = pair_screenshare(std::mem::take(&mut tally.ss), &dst, &dir.display().to_string());
    tally.rows += ss_rows.len();
    tally.ss_no_origin = dropped;
    out.extend(ss_rows);
    if crate::parse::is_debug_mode() {
        eprintln!(
            "[DEBUG] logarchive {}: {} tracev3 file(s), {} record(s) scanned, {} from sshd, {} from screensharingd, {} lateral-movement row(s)",
            dir.display(),
            files,
            tally.scanned,
            tally.sshd,
            tally.screenshare,
            tally.rows
        );
        if tally.ss_no_origin > 0 {
            eprintln!(
                "[DEBUG]   {} screensharingd outcome(s) (authResult) without a viewer address: no origin, no row",
                tally.ss_no_origin
            );
        }
        for m in &tally.unclassified {
            eprintln!("[DEBUG]   not a logon: {}", m);
        }
    }
}

// ──────────────────────────── JSON export reader ─────────────────────────────

/// Pull `(process, message, timestamp)` out of one `log show` JSON object.
/// `log show` names them `processImagePath` (or `process`), `eventMessage`
/// and `timestamp`. A modern screensharingd line goes to `ss` for pairing.
fn classify_json_value(v: &serde_json::Value, dst: &str, file: &str, ss: &mut Vec<SsEvt>) -> Option<LogData> {
    let process = v
        .get("processImagePath")
        .or_else(|| v.get("process"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    if !is_relevant_process(process) {
        return None;
    }
    let message = v.get("eventMessage").and_then(|x| x.as_str()).unwrap_or("");
    let ts = v
        .get("timestamp")
        .and_then(|x| x.as_str())
        .map(json_time_iso)
        .unwrap_or_default();
    match classify(process, message) {
        Some(c) => Some(row(ts, dst, file, c)),
        None => {
            if let Some(kind) = screenshare_event(process, message) {
                if let Ok(t) = DateTime::parse_from_rfc3339(&ts) {
                    let pid = v.get("processID").and_then(|x| x.as_u64()).unwrap_or(0);
                    ss.push(SsEvt { t_us: t.timestamp_micros(), pid, kind });
                }
            }
            None
        }
    }
}

/// Parse a `log show` export: `--style ndjson` (one object per line) or
/// `--style json` (a single array). Both are detected from the first
/// non-blank byte. An NDJSON export is read line by line: a `log show` of a
/// few weeks is several GB and must not be held in memory whole.
fn parse_json_export(path: &Path, out: &mut Vec<LogData>) {
    let dst = host_from_path(path);
    let file = path.display().to_string();
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            crate::banner::print_info(&format!("macOS: cannot read {}: {}", file, e));
            return;
        }
    };
    let mut reader = BufReader::new(f);
    let mut ss: Vec<SsEvt> = Vec::new();
    let first = match reader.fill_buf() {
        Ok(b) => b.iter().copied().find(|c| !c.is_ascii_whitespace()),
        Err(_) => None,
    };
    if first == Some(b'[') {
        // `--style json`: a single array; has to be read whole.
        let mut text = String::new();
        if reader.read_to_string(&mut text).is_err() {
            return;
        }
        if let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(&text) {
            for v in &items {
                if let Some(r) = classify_json_value(v, &dst, &file, &mut ss) {
                    out.push(r);
                }
            }
        }
        out.extend(pair_screenshare(ss, &dst, &file).0);
        return;
    }
    // `--style ndjson`: one object per line, streamed.
    for line in reader.lines().map_while(Result::ok) {
        let line = line.trim().trim_end_matches(',');
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(r) = classify_json_value(&v, &dst, &file, &mut ss) {
                out.push(r);
            }
        }
    }
    out.extend(pair_screenshare(ss, &dst, &file).0);
}

/// True when a file looks like a `log show` JSON / NDJSON export: a JSON
/// extension and, in its first 64 KB, the `eventMessage` key `log show`
/// writes on every record. A Velociraptor result file or any other JSON
/// lying in a triage tree is left alone.
fn looks_like_json_export(path: &Path) -> bool {
    match path.extension().and_then(|s| s.to_str()) {
        Some("json") | Some("ndjson") | Some("jsonl") => {}
        _ => return false,
    }
    let mut head = vec![0u8; 65_536];
    let n = match std::fs::File::open(path).and_then(|mut f| f.read(&mut head)) {
        Ok(n) => n,
        Err(_) => return false,
    };
    String::from_utf8_lossy(&head[..n]).contains("\"eventMessage\"")
}

// ──────────────────────────── entry point ────────────────────────────────────

pub fn parse_mac(files: &[String], dirs: &[String], output: Option<&String>) {
    let start = std::time::Instant::now();
    crate::banner::print_search_start();
    // the discovery walk and the parse are one pass here: a .logarchive is
    // read as it is found
    crate::banner::print_processing_start();

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

    // --ignore-local / --exclude-* apply here as on every other parser
    rows.retain(|r| crate::filter::should_keep_record(r));

    crate::banner::print_output_start();
    if rows.is_empty() {
        crate::banner::print_info(
            "macOS: no SSH or Screen Sharing lateral movement found in the sources provided",
        );
    }
    if let Err(e) = crate::csv_out::write_timeline(&rows, output) {
        eprintln!("Error writing macOS timeline: {}", e);
        return;
    }
    crate::banner::print_summary(rows.len(), sources, 0, output.map(|s| s.as_str()), start);
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

    /// Lines as Sonoma 14.8 and Sequoia 15.7 (OpenSSH 9.9, sshd-session)
    /// wrote them on the GitHub macOS runners, read back from the
    /// collected .logarchive.
    #[test]
    fn macos_preauth_shapes_from_real_bundles() {
        let c = classify("/usr/libexec/sshd-session", "Connection closed by 127.0.0.1 port 49181").unwrap();
        assert_eq!((c.event_type, c.src.as_str(), c.detail.as_str()), ("CONNECT", "127.0.0.1", "ssh preauth-closed"));
        let c = classify("sshd-session", "banner exchange: Connection from 127.0.0.1 port 49188: invalid format").unwrap();
        assert_eq!((c.event_type, c.src.as_str(), c.detail.as_str()), ("CONNECT", "127.0.0.1", "ssh preauth-bad-proto"));
        // a closed session is not a pre-auth touch
        assert!(classify("sshd-session", "Connection closed by user runner 127.0.0.1 port 49184").is_none());
        assert!(classify("sshd-session", "Received disconnect from 127.0.0.1 port 49184:11: disconnected by user").is_none());
        // the "Invalid user" announcement precedes the Failed line that counts
        assert!(classify("sshd-session", "Invalid user nosuchuser from 127.0.0.1 port 49186").is_none());
        let c = classify("sshd-session", "Failed password for invalid user nosuchuser from 127.0.0.1 port 49186 ssh2").unwrap();
        assert_eq!((c.event_type, c.user.as_str()), ("FAILED_LOGON", "nosuchuser"));
    }

    /// The split lines Sequoia 15.7 wrote for two refused ARD attempts and
    /// one accepted one (GitHub runner, 2026-10-08), and what Sonoma 14.8
    /// wrote for the same: outcomes without any viewer address.
    #[test]
    fn modern_screensharing_lines_are_paired_by_process() {
        let us = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().timestamp_micros();
        let ev = |t: &str, pid: u64, m: &str| SsEvt { t_us: us(t), pid, kind: screenshare_event("screensharingd", m).unwrap() };
        // Sequoia: an outcome and the address in the same instant; then the
        // address logged twice (accept path, then bad-auth path) around
        // the outcome; then a success with uid and no address
        let evts = vec![
            ev("2026-10-08T09:26:13.426000Z", 5880, "authResult = 1"),
            ev("2026-10-08T09:26:13.426000Z", 5880, "new viewer connection: 127.0.0.1"),
            ev("2026-10-08T09:26:23.419000Z", 5880, "new viewer connection: 127.0.0.1"),
            ev("2026-10-08T09:26:23.622000Z", 5880, "authResult = 1"),
            ev("2026-10-08T09:26:23.622000Z", 5880, "new viewer connection: 127.0.0.1"),
            ev("2026-10-08T09:24:46.977000Z", 4885, "*outUID= 502"),
            ev("2026-10-08T09:24:46.977000Z", 4885, "authResult = 0"),
        ];
        let (rows, dropped) = pair_screenshare(evts, "MAC-CI", "f");
        assert_eq!(dropped, 1, "the success without a viewer address is dropped");
        assert_eq!(rows.len(), 2, "{:?}", rows.iter().map(|r| (&r.time_created, &r.event_type)).collect::<Vec<_>>());
        for r in &rows {
            assert_eq!(r.event_type, "FAILED_LOGON");
            assert_eq!(r.event_id, "MAC-SCREENSHARE-FAIL");
            assert_eq!(r.ip_address, "127.0.0.1");
            assert_eq!(r.logon_type, "ScreenSharing");
            assert_eq!(r.target_user_name, "");
        }
        assert_eq!(rows[0].time_created, "2026-10-08T09:26:13.426000Z");
        assert_eq!(rows[1].time_created, "2026-10-08T09:26:23.419000Z");
        // a success with the address logged becomes a login with the uid
        let evts = vec![
            ev("2026-10-08T09:16:13.423000Z", 2819, "*outUID= 502"),
            ev("2026-10-08T09:16:13.423000Z", 2819, "authResult = 0"),
            ev("2026-10-08T09:16:13.500000Z", 2819, "Connection accepted :: Viewer Address: 10.0.0.9"),
        ];
        let (rows, dropped) = pair_screenshare(evts, "MAC-CI", "f");
        assert_eq!((rows.len(), dropped), (1, 0));
        assert_eq!((rows[0].event_type.as_str(), rows[0].target_user_name.as_str(), rows[0].ip_address.as_str()), ("SUCCESSFUL_LOGON", "uid:502", "10.0.0.9"));
        // an address with no outcome in the window is a CONNECT
        let evts = vec![ev("2026-10-08T09:30:00.000000Z", 7, "new viewer connection: 10.0.0.9")];
        let (rows, dropped) = pair_screenshare(evts, "MAC-CI", "f");
        assert_eq!((rows.len(), dropped), (1, 0));
        assert_eq!((rows[0].event_type.as_str(), rows[0].event_id.as_str()), ("CONNECT", "MAC-SCREENSHARE-CONNECT"));
        // Sonoma: outcomes only
        let evts = vec![
            ev("2026-10-08T09:24:43.476000Z", 3085, "*outUID= 502"),
            ev("2026-10-08T09:24:43.476000Z", 3085, "authResult = 0"),
            ev("2026-10-08T09:25:36.463000Z", 4248, "authResult = 1"),
            ev("2026-10-08T09:25:45.752000Z", 4248, "authResult = 1"),
        ];
        let (rows, dropped) = pair_screenshare(evts, "MAC-CI", "f");
        assert_eq!((rows.len(), dropped), (0, 3));
        assert!(screenshare_event("sshd", "authResult = 1").is_none());
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
