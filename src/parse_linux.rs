// -----------------------------------------------------------------------------
//  Linux parser for Masstin
//  * Binary: utmp / wtmp / btmp / lastlog                          (lateral + failed)
//  * Text  : secure*, messages*, audit.log* (incl. *.gz)           (SSH success / fail)
//  Produces a DataFrame identical (column-wise) to Windows output.
// -----------------------------------------------------------------------------
use flate2::read::GzDecoder;
use once_cell::sync::Lazy;
use polars::prelude::*;
use regex::Regex;
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    mem,
    os::raw::{c_char, c_int, c_short},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;
use ::zip::ZipArchive;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc, Datelike};
use crate::parse::is_debug_mode; // global flag set by --debug

// ────────────────────────── utmp constants ───────────────────────────────────
const EMPTY: c_short = 0;
const RUN_LVL: c_short = 1;
const BOOT_TIME: c_short = 2;
const NEW_TIME: c_short = 3;
const OLD_TIME: c_short = 4;
const INIT_PROCESS: c_short = 5;
const LOGIN_PROCESS: c_short = 6;
const USER_PROCESS: c_short = 7;
const DEAD_PROCESS: c_short = 8;
const ACCOUNTING: c_short = 9;

// ────────────────────────── utmp struct (on-disk) ────────────────────────────
#[repr(C)]
#[derive(Clone, Copy)]
struct TimeVal32 {
    tv_sec: i32,
    tv_usec: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct UtmpEntry {
    ut_type: c_short,
    ut_pid: c_int,
    ut_line: [c_char; 32],
    ut_id: [c_char; 4],
    ut_user: [c_char; 32],
    ut_host: [c_char; 256],
    ut_exit: [u8; 4],
    ut_session: c_int,
    ut_tv: TimeVal32,
    ut_addr_v6: [u32; 4],
    _reserved: [u8; 20],
}

// ────────────────────────── helper regexes ───────────────────────────────────
static IPV4_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d{1,3}(\.\d{1,3}){3}$").unwrap());
static IPV6_COLON: Lazy<Regex> = Lazy::new(|| Regex::new(r":").unwrap());

// sshd auth outcome lines. Captures: 1 = method, 2 = user, 3 = source.
//   "Accepted publickey for jboss from 10.1.2.3 port 5022 ssh2: RSA SHA256:..."
//   "Accepted keyboard-interactive/pam for bob from 10.1.2.3 port 5022 ssh2"
// Any method is accepted (password, publickey, keyboard-interactive/pam,
// gssapi-with-mic, hostbased): the old `password|publickey` list silently
// dropped Kerberos and PAM-challenge logins.
pub(crate) static SSH_OK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"Accepted (\S+) for (\S+) from (\S+)"#).unwrap()
});
// Captures: 1 = method, 2 = "invalid user" marker (optional), 3 = user,
// 4 = source. The marker matters: "Failed password for invalid user bob
// from ..." did not match the previous `for (\S+) from` form at all, so
// every guess against a non-existent account was lost.
pub(crate) static SSH_FAIL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"Failed (\S+) for (?:(invalid user) )?(\S+) from (\S+)"#).unwrap());
// Policy denial after successful authentication — still a failed logon
// from the network's point of view, and the source is usually a hostname.
static SSH_NOTALLOWED_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"User (\S+) from (\S+) not allowed because"#).unwrap());
static PAM_FAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"pam_unix\(sshd:[^\)]*\).*rhost=(\S+)\s+user=(\S+)"#).unwrap()
});
static XINETD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"START: ssh .* from=::ffff:(\S+)"#).unwrap());
// Matches auditd SSH/PAM auth events on Debian/Ubuntu/RHEL:
//   - USER_AUTH  : pam_unix / pam_sss authentication attempt
//   - USER_LOGIN : sshd login (Ubuntu 22 + SSSD primary signal — no acct= field)
//   - USER_ACCT  : account validation
//   - USER_START : session_open (hostname=? for sudo, but carries addr= on SSH)
// We anchor on `addr=<ip>` (more reliable than hostname=, which is often `?`)
// and pick up res=success/failed. Username is extracted separately from the
// several possible fields: acct="...", id=<uid>, AUID="...", UID="...".
static AUDIT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"type=(USER_AUTH|USER_LOGIN|USER_ACCT|USER_START).*?addr=([\d\.:a-fA-F]+).*?res=(\w+)"#,
    )
    .unwrap()
});

// Username extractors — tried in order. First match wins.
static AUDIT_USER_ACCT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"acct="([^"]+)""#).unwrap()
});
static AUDIT_USER_AUID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"AUID="([^"?]+)""#).unwrap()
});
static AUDIT_USER_UID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\bUID="([^"?]+)""#).unwrap()
});

// Regex for RFC3164 syslog header: "Mar 16 08:25:22 hostname"
static RFC3164_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([A-Z][a-z]{2})\s+([\d ]\d)\s+(\d{2}:\d{2}:\d{2})\s+(\S+)").unwrap()
});

// ────────────────────────── utils ────────────────────────────────────────────
fn c_chars(b: &[c_char]) -> String {
    let v: Vec<u8> = b.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&v).trim().to_owned()
}
fn looks_like_ip(s: &str) -> bool {
    IPV4_RE.is_match(s) || IPV6_COLON.is_match(s)
}

/// Parse RFC3164 syslog timestamp (no year) into RFC3339.
/// Uses the file's modification year as a heuristic, falling back to current year.
fn parse_rfc3164_naive(month: &str, day: &str, time: &str, file_year: i32) -> Option<NaiveDateTime> {
    let date_str = format!("{} {} {} {}", file_year, month, day.trim(), time);
    NaiveDateTime::parse_from_str(&date_str, "%Y %b %d %H:%M:%S").ok()
}

/// RFC3164 timestamps carry no year. `file_year` is the best guess for the
/// file as a whole; `rotation` (from a logrotate `-YYYYMMDD` suffix) is
/// the day the file was closed, so any entry dated AFTER it must belong to
/// the previous year — a `secure-20260104` holds late-December 2025 lines
/// followed by early-January 2026 ones.
fn parse_rfc3164_timestamp(
    month: &str,
    day: &str,
    time: &str,
    file_year: i32,
    rotation: Option<NaiveDate>,
    tz: &crate::linux_tz::LocalTz,
) -> Option<String> {
    let mut dt = parse_rfc3164_naive(month, day, time, file_year)?;
    if let Some(rot) = rotation {
        if dt.date() > rot {
            dt = parse_rfc3164_naive(month, day, time, file_year - 1)?;
        }
    }
    // The line is host wall-clock time; make it absolute like every other
    // Linux source (wtmp, audit, journald are epoch-based).
    let utc = tz.to_utc(&dt);
    Some(DateTime::<Utc>::from_utc(utc, Utc).to_rfc3339())
}

/// logrotate `dateext` suffix → the date the file was rotated. Tolerates
/// the trailing `.gz`: `secure-20260830.gz` → 2026-08-30.
fn rotation_date_from_name(fname: &str) -> Option<NaiveDate> {
    let base = fname.strip_suffix(".gz").unwrap_or(fname);
    let idx = base.rfind('-')?;
    let stamp = &base[idx + 1..];
    if stamp.len() != 8 || !stamp.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    NaiveDate::from_ymd_opt(
        stamp[..4].parse().ok()?,
        stamp[4..6].parse().ok()?,
        stamp[6..].parse().ok()?,
    )
}

// Regex to find a year in dpkg.log format: "2010-04-19 12:00:17"
static YEAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(20\d{2})-\d{2}-\d{2}\s+\d{2}:\d{2}").unwrap()
});

/// Infer the year of logs by looking at sibling files in the same directory.
/// Priority: dpkg.log (has full dates) > wtmp (binary with epoch) > file mtime > current year.
fn get_file_year(path: &Path) -> i32 {
    let dir = path.parent().unwrap_or(Path::new("."));

    // 1) dpkg.log — always has "YYYY-MM-DD HH:MM:SS" format
    let dpkg_candidates = ["dpkg.log", "dpkg.log.1"];
    for name in &dpkg_candidates {
        let dpkg_path = dir.join(name);
        if dpkg_path.exists() {
            if let Ok(file) = File::open(&dpkg_path) {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten().take(5) {
                    if let Some(cap) = YEAR_RE.captures(&line) {
                        if let Ok(year) = cap[1].parse::<i32>() {
                            crate::banner::print_info(&format!(
                                "Year inferred: {} (from dpkg.log)", year
                            ));
                            return year;
                        }
                    }
                }
            }
        }
    }

    // 2) wtmp — binary with epoch timestamps, read first valid entry
    let wtmp_path = dir.join("wtmp");
    if wtmp_path.exists() {
        if let Ok(metadata) = fs::metadata(&wtmp_path) {
            if metadata.len() > 0 {
                // Parse first utmp entry to get the year from its epoch
                let entries = parse_utmp_file(&wtmp_path, "", false);
                if let Some(first) = entries.first() {
                    if let Ok(dt) = DateTime::parse_from_rfc3339(&first.ts_rfc3339) {
                        let year = dt.year();
                        crate::banner::print_info(&format!(
                            "Year inferred: {} (from wtmp)", year
                        ));
                        return year;
                    }
                }
            }
        }
    }

    // 3) File modification time
    if let Ok(metadata) = fs::metadata(path) {
        if let Ok(modified) = metadata.modified() {
            let dt: DateTime<Utc> = modified.into();
            let year = dt.year();
            crate::banner::print_info(&format!(
                "Year inferred: {} (from file modification date)", year
            ));
            return year;
        }
    }

    // 4) Current year
    let year = Utc::now().year();
    crate::banner::print_info(&format!(
        "Year inferred: {} (current year - no date source found)", year
    ));
    year
}

// ────────────────────────── raw event holder ─────────────────────────────────
#[derive(Clone)]
pub(crate) struct RawEvt {
    pub(crate) ts_rfc3339: String,
    pub(crate) user: String,
    pub(crate) remote: String, // ip OR host (we’ll split later)
    pub(crate) tty_or_proc: String,
    pub(crate) evt: String,
    pub(crate) filename: String,
    pub(crate) dst_host: String,
}

// ────────────────────────── hostname discovery ───────────────────────────────
fn extract_hostname_txt(file: &Path) -> Option<String> {
    let try_open = File::open(file).ok()?;
    let mut rdr = BufReader::new(try_open);
    let mut line = String::new();
    while rdr.read_line(&mut line).ok()? > 0 {
        if let Some(cap) = line.find("Set hostname to <") {
            // dmesg output
            if let Some(end) = line[cap..].find('>') {
                return Some(line[cap + 18..cap + end].trim().to_string());
            }
        }
        if line.starts_with("127.0.0.1") || line.starts_with("::1") {
            // /etc/hosts loopback line may carry the real hostname, but on
            // most distros it is just "localhost localhost.localdomain
            // localhost4 ..." — skip those aliases and keep looking.
            let real = line
                .split_whitespace()
                .skip(1)
                .find(|t| !t.to_lowercase().starts_with("localhost"));
            if let Some(h) = real {
                return Some(h.to_string());
            }
        }
        line.clear();
    }
    None
}

fn discover_hostname(root: &Path) -> String {
    // 1) /etc/hostname — most reliable on modern Linux
    for entry in WalkDir::new(root).max_depth(4).into_iter().filter_map(Result::ok) {
        let path = entry.path().to_owned();
        if path.file_name() == Some(OsStr::new("hostname"))
            && path.parent().map(|p| p.ends_with("etc")).unwrap_or(false)
        {
            if let Ok(content) = fs::read_to_string(&path) {
                let h = content.trim().to_string();
                if !h.is_empty() {
                    crate::banner::print_info(&format!(
                        "Hostname identified: {} (from /etc/hostname)", h
                    ));
                    return h;
                }
            }
        }
    }

    // 1a) RHEL/CentOS 6 keep the name in /etc/sysconfig/network (HOSTNAME=)
    //     and have no /etc/hostname at all.
    for entry in WalkDir::new(root).max_depth(4).into_iter().filter_map(Result::ok) {
        let path = entry.path().to_owned();
        if path.file_name() != Some(OsStr::new("network")) { continue; }
        if !path.parent().map(|p| p.ends_with("sysconfig")).unwrap_or(false) { continue; }
        if let Ok(content) = fs::read_to_string(&path) {
            for line in content.lines() {
                if let Some(v) = line.trim().strip_prefix("HOSTNAME=") {
                    let h = v.trim().trim_matches('"').to_string();
                    if !h.is_empty() && !h.to_lowercase().starts_with("localhost") {
                        crate::banner::print_info(&format!(
                            "Hostname identified: {} (from /etc/sysconfig/network)", h
                        ));
                        return h;
                    }
                }
            }
        }
    }

    // 1b) UAC run log: `uac.log` at the extract root carries a
    //     "Hostname: <name>" line. UAC writes "unknown" when it was pointed
    //     at a mounted image instead of a live system, so only a real value
    //     counts; otherwise fall through to the log-content heuristics.
    for entry in WalkDir::new(root).max_depth(2).into_iter().filter_map(Result::ok) {
        let path = entry.path().to_owned();
        if path.file_name() != Some(OsStr::new("uac.log")) { continue; }
        if let Ok(content) = fs::read_to_string(&path) {
            for line in content.lines().take(40) {
                if let Some(rest) = line.trim().strip_prefix("Hostname:") {
                    let h = rest.trim();
                    if !h.is_empty() && !h.eq_ignore_ascii_case("unknown") {
                        crate::banner::print_info(&format!(
                            "Hostname identified: {} (from uac.log)", h
                        ));
                        return h.to_string();
                    }
                }
            }
        }
    }

    // 2) dmesg
    for entry in WalkDir::new(root).max_depth(3).into_iter().filter_map(Result::ok) {
        let path = entry.path().to_owned();
        if path.file_name() == Some(OsStr::new("dmesg")) {
            if let Some(h) = extract_hostname_txt(&path) {
                crate::banner::print_info(&format!(
                    "Hostname identified: {} (from dmesg)", h
                ));
                return h;
            }
        }
        // /etc/hosts
        if path.file_name() == Some(OsStr::new("hosts")) && path.parent().map(|p| p.ends_with("etc")).unwrap_or(false)
        {
            if let Some(h) = extract_hostname_txt(&path) {
                crate::banner::print_info(&format!(
                    "Hostname identified: {} (from /etc/hosts)", h
                ));
                return h;
            }
        }
    }

    // 3) Extract hostname from the first RFC3164 syslog line in any log file
    for entry in WalkDir::new(root).max_depth(4).into_iter().filter_map(Result::ok) {
        let path = entry.path().to_owned();
        if !path.is_file() { continue; }
        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
        if is_linux_artifact(&fname) {
            if let Ok(file) = File::open(&path) {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten().take(20) {
                    if let Some(cap) = RFC3164_RE.captures(&line) {
                        let hostname = cap[4].to_string();
                        if !hostname.is_empty() && hostname != "-" {
                            crate::banner::print_info(&format!(
                                "Hostname identified: {} (from syslog header)", hostname
                            ));
                            return hostname;
                        }
                    }
                }
            }
        }
    }

    // 4) fallback to folder name
    root.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
}

// ────────────────────────── utmp family parser ───────────────────────────────
fn parse_utmp_file(path: &Path, dst_host: &str, filter_ip: bool) -> Vec<RawEvt> {
    let mut res = Vec::new();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[ERROR] cannot open {}: {}", path.display(), e);
            return res;
        }
    };
    // Rotated wtmp/btmp are routinely gzipped by logrotate
    // (`btmp-20260901.gz`); the fixed-size record layout is identical once
    // inflated, so just swap the reader.
    let is_gz = path.extension().map(|e| e == "gz").unwrap_or(false);
    let mut rdr: Box<dyn Read> = if is_gz {
        Box::new(GzDecoder::new(BufReader::new(file)))
    } else {
        Box::new(BufReader::new(file))
    };
    let mut buf = vec![0u8; mem::size_of::<UtmpEntry>()];
    let fname = path.display().to_string();
    let base_lower = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    let is_btmp = is_rotated_name(&base_lower, "btmp");
    while rdr.read_exact(&mut buf).is_ok() {
        let rec: &UtmpEntry = unsafe { &*(buf.as_ptr() as *const UtmpEntry) };
        // Only session records matter: USER_PROCESS (login), DEAD_PROCESS
        // (logout) and, in btmp, LOGIN_PROCESS (failed attempt). Boot,
        // runlevel and init records name the kernel or "~" in ut_host and
        // would otherwise pass the "has a source" filter below.
        if !(rec.ut_type == USER_PROCESS || rec.ut_type == DEAD_PROCESS || (is_btmp && rec.ut_type == LOGIN_PROCESS)) {
            continue;
        }
        let ts = NaiveDateTime::from_timestamp(rec.ut_tv.tv_sec as i64, 0);
        let when = DateTime::<Utc>::from_utc(ts, Utc).to_rfc3339();

        let user = c_chars(&rec.ut_user);
        let host = c_chars(&rec.ut_host);
        let mut evt = match rec.ut_type {
            USER_PROCESS => "LOGIN",
            DEAD_PROCESS => "LOGOUT",
            BOOT_TIME => "BOOT_TIME",
            _ => "OTHER",
        }
        .to_string();

        if is_btmp {
            evt = "FAILED_LOGIN".into();
        }

        // Keep every record that names a remote source, IP or hostname —
        // with `UseDNS yes` sshd writes the resolved name into ut_host, and
        // on such estates an IP-only filter throws away >99% of wtmp. Only
        // console / tty sessions (empty ut_host) are dropped.
        if filter_ip && host.is_empty() && !evt.eq("FAILED_LOGIN") {
            continue;
        }

        res.push(RawEvt {
            ts_rfc3339: when,
            user,
            remote: host,
            tty_or_proc: c_chars(&rec.ut_line),
            evt,
            filename: fname.clone(),
            dst_host: dst_host.into(),
        });
    }
    res
}

// ────────────────────────── lastlog ──────────────────────────────────────────
// /var/log/lastlog: one fixed 292-byte slot per uid (glibc: i32 ll_time,
// char ll_line[32], char ll_host[256]), indexed by uid. It records the LAST
// login of every account that ever logged in — including accounts whose
// activity predates every surviving wtmp / secure rotation — so it is often
// the only trace of a dormant account's origin host. The uid → name map
// comes from the collected /etc/passwd; unknown uids (directory users) are
// reported as `uid:<n>`.
const LASTLOG_RECORD: usize = 292;

fn load_passwd(root: &Path) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let mut candidates = vec![root.join("[root]"), root.to_path_buf()];
    if let Some(p) = root.parent() { candidates.push(p.to_path_buf()); }
    for fr in candidates {
        if let Ok(s) = fs::read_to_string(fr.join("etc/passwd")) {
            for l in s.lines() {
                let mut it = l.split(':');
                if let (Some(name), Some(_), Some(uid)) = (it.next(), it.next(), it.next()) {
                    if let Ok(u) = uid.parse::<u32>() { map.insert(u, name.to_string()); }
                }
            }
            if !map.is_empty() { break; }
        }
    }
    map
}

fn parse_lastlog(path: &Path, dst_host: &str, passwd: &HashMap<u32, String>) -> Vec<RawEvt> {
    let mut out = Vec::new();
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[ERROR] cannot open {}: {}", path.display(), e);
            return out;
        }
    };
    if data.len() % LASTLOG_RECORD != 0 {
        if is_debug_mode() {
            println!("    lastlog {}: size {} is not a multiple of {} — unknown layout, skipped",
                     path.display(), data.len(), LASTLOG_RECORD);
        }
        return out;
    }
    let fname = path.display().to_string();
    for (uid, rec) in data.chunks_exact(LASTLOG_RECORD).enumerate() {
        let secs = i32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]) as i64;
        if secs == 0 { continue; }
        let line = String::from_utf8_lossy(rec[4..36].split(|&b| b == 0).next().unwrap_or(&[])).trim().to_string();
        let host = String::from_utf8_lossy(rec[36..292].split(|&b| b == 0).next().unwrap_or(&[])).trim().to_string();
        // Console logins carry no host; nothing to plot on the graph.
        if host.is_empty() { continue; }
        let when = match NaiveDateTime::from_timestamp_opt(secs, 0) {
            Some(n) => DateTime::<Utc>::from_utc(n, Utc).to_rfc3339(),
            None => continue,
        };
        let user = passwd.get(&(uid as u32)).cloned().unwrap_or_else(|| format!("uid:{}", uid));
        out.push(RawEvt {
            ts_rfc3339: when,
            user,
            remote: host,
            tty_or_proc: line,
            evt: "LASTLOG".into(),
            filename: fname.clone(),
            dst_host: dst_host.into(),
        });
    }
    out
}

// ────────────────────────── text log helpers ─────────────────────────────────
fn open_plain_or_gzip(path: &Path) -> Box<dyn BufRead> {
    if path
        .extension()
        .map(|e| e == "gz")
        .unwrap_or(false)
    {
        let f = File::open(path).unwrap();
        Box::new(BufReader::new(GzDecoder::new(f)))
    } else {
        Box::new(BufReader::new(File::open(path).unwrap()))
    }
}

fn parse_timestamp_syslog(fragment: &str, default_year: i32) -> Option<String> {
    // RFC3164 "Sep  6 21:39:20"
    if let Ok(ts) = chrono::NaiveDateTime::parse_from_str(
        &format!("{} {}", default_year, fragment),
        "%Y %b %e %H:%M:%S",
    ) {
        return Some(DateTime::<Utc>::from_utc(ts, Utc).to_rfc3339());
    }
    None
}
fn parse_secure_or_messages(
    path: &Path,
    dst_host: &str,
    filter_ip: bool,
    year_hint: Option<i32>,
    tz: &crate::linux_tz::LocalTz,
) -> Vec<RawEvt> {
    let mut out = Vec::new();
    // pam_unix(sshd:auth) failures are collected separately: on SSSD / LDAP
    // hosts pam_unix fails for EVERY directory user before pam_sss succeeds,
    // so counting them as failed logons is wrong whenever sshd's own
    // "Failed <method>" lines are present. They are only used as a
    // fallback for files where sshd logged no auth outcome at all.
    let mut pam_fallback: Vec<RawEvt> = Vec::new();
    let mut sshd_outcomes: usize = 0;
    let fname = path.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase();
    let is_secure = fname.starts_with("secure") || fname.starts_with("auth.log");
    // A logrotate `-YYYYMMDD` suffix beats every other year heuristic: the
    // per-directory hint comes from the CURRENT wtmp/dpkg.log and would
    // stamp a 2024 `secure-20240616` with the 2026 of its siblings.
    let rotation = rotation_date_from_name(&fname);
    let file_year = match rotation {
        Some(rot) => {
            if is_debug_mode() {
                println!("    year {} for {} (from logrotate suffix)", rot.year(), fname);
            }
            rot.year()
        }
        None => year_hint.unwrap_or_else(|| get_file_year(path)),
    };

    if is_debug_mode() {
        println!("    reading {} (year hint: {}) ...", path.display(), file_year);
    }

    for line in open_plain_or_gzip(path).lines().flatten() {
        let (when, msg) =
        // ——— RFC3164 legacy syslog: "Mar 16 08:25:22 hostname msg..." ———
        // Used by: /var/log/secure (RHEL/CentOS), /var/log/auth.log (Debian/Ubuntu),
        //          /var/log/messages (all distros)
        if let Some(cap) = RFC3164_RE.captures(&line) {
            let month = &cap[1];
            let day = &cap[2];
            let time = &cap[3];
            // Message starts after "hostname " (4th capture + space + rest)
            let header_end = cap.get(0).unwrap().end();
            let msg = if header_end < line.len() { &line[header_end..] } else { "" };
            if let Some(ts) = parse_rfc3164_timestamp(month, day, time, file_year, rotation, tz) {
                (ts, msg.to_string())
            } else {
                continue;
            }
        }
        // ——— RFC5424 structured syslog: "<PRI>VERSION TIMESTAMP ..." ———
        // Used by: systemd journal export, rsyslog with structured format
        else if line.starts_with('<') {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 7 {
                continue;
            }
            if let Ok(dt) = DateTime::parse_from_rfc3339(parts[1]) {
                let ts = dt.with_timezone(&Utc).to_rfc3339();
                let msg = line[line.find(" - - ").unwrap_or(0)..].to_string();
                (ts, msg)
            } else {
                continue;
            }
        } else {
            continue;
        };

        // Apply SSH/PAM regexes to the message part
        // 1) xinetd "START: ssh" → SSH_CONNECT
        if let Some(cap) = XINETD_RE.captures(&msg) {
            let ip = cap[1].to_string();
            if !filter_ip || looks_like_ip(&ip) {
                out.push(RawEvt {
                    ts_rfc3339:  when.clone(),
                    user:        "".into(),
                    remote:      ip,
                    tty_or_proc: "xinetd".into(),
                    evt:         "SSH_CONNECT".into(),
                    filename:    path.display().to_string(),
                    dst_host:    dst_host.into(),
                });
            }
            continue;
        }

        // 2) SSH success: "Accepted <method> for <user> from <src> ..."
        if let Some(cap) = SSH_OK_RE.captures(&msg) {
            let method = cap[1].to_string();
            let user = cap[2].to_string();
            let src  = cap[3].to_string();
            sshd_outcomes += 1;
            if !filter_ip || !src.is_empty() {
                out.push(RawEvt {
                    ts_rfc3339:  when.clone(),
                    user,
                    remote:      src,
                    tty_or_proc: format!("ssh/{}", method),
                    evt:         "SSH_SUCCESS".into(),
                    filename:    path.display().to_string(),
                    dst_host:    dst_host.into(),
                });
            }
            continue;
        }

        // 3) SSH failure: "Failed <method> for [invalid user] <user> from <src>"
        if let Some(cap) = SSH_FAIL_RE.captures(&msg) {
            let method = cap[1].to_string();
            let invalid = cap.get(2).is_some();
            let user = cap[3].to_string();
            let src  = cap[4].to_string();
            sshd_outcomes += 1;
            // "Failed none" is the client asking which methods are allowed,
            // not an authentication attempt; the real attempt follows as
            // "Failed password/publickey ..." and would be double-counted.
            if method == "none" { continue; }
            if !filter_ip || !src.is_empty() {
                out.push(RawEvt {
                    ts_rfc3339:  when.clone(),
                    user,
                    remote:      src,
                    tty_or_proc: if invalid { format!("ssh/{} invalid-user", method) } else { format!("ssh/{}", method) },
                    evt:         "SSH_FAILED".into(),
                    filename:    path.display().to_string(),
                    dst_host:    dst_host.into(),
                });
            }
            continue;
        }

        // 3b) Policy denial: "User bob from host not allowed because ..."
        //     (AllowGroups / AllowUsers / DenyUsers). Authenticated but
        //     refused — a failed logon with a usually-hostname source.
        if let Some(cap) = SSH_NOTALLOWED_RE.captures(&msg) {
            let user = cap[1].to_string();
            let src  = cap[2].to_string();
            sshd_outcomes += 1;
            out.push(RawEvt {
                ts_rfc3339:  when.clone(),
                user,
                remote:      src,
                tty_or_proc: "ssh/not-allowed".into(),
                evt:         "SSH_FAILED".into(),
                filename:    path.display().to_string(),
                dst_host:    dst_host.into(),
            });
            continue;
        }

        // 4) PAM failure: "pam_unix(sshd:...) rhost=SRC user=USER" — kept
        //    only as a fallback, see `pam_fallback` above.
        if is_secure {
            if let Some(cap) = PAM_FAIL_RE.captures(&msg) {
                let src  = cap[1].to_string();
                let user = cap[2].to_string();
                if !filter_ip || !src.is_empty() {
                    pam_fallback.push(RawEvt {
                        ts_rfc3339:  when.clone(),
                        user,
                        remote:      src,
                        tty_or_proc: "pam".into(),
                        evt:         "SSH_FAILED".into(),
                        filename:    path.display().to_string(),
                        dst_host:    dst_host.into(),
                    });
                }
            }
        }
    }

    if sshd_outcomes == 0 && !pam_fallback.is_empty() {
        if is_debug_mode() {
            println!("    {}: no sshd auth outcome lines, using {} pam_unix failures as fallback",
                     fname, pam_fallback.len());
        }
        out.extend(pam_fallback);
    }

    out
}

// audit.log* ------------------------------------------------------------------
fn parse_audit(path: &Path, dst_host: &str, filter_ip: bool) -> Vec<RawEvt> {
    let mut out = Vec::new();
    for line in open_plain_or_gzip(path).lines().flatten() {
        let cap = match AUDIT_RE.captures(&line) {
            Some(c) => c,
            None => continue,
        };

        // Reject sudo/cron session_open lines where addr is literally "?".
        // The outer regex already requires an addr digit/hex, but USER_START
        // with hostname=? addr=? would otherwise be caught by nothing; our
        // [\d\.:a-fA-F]+ class excludes `?` so that's fine.
        let evt_type = &cap[1];
        let ip = cap[2].to_string();
        let res = &cap[3];

        if filter_ip && !looks_like_ip(&ip) {
            continue;
        }

        // Extract timestamp from msg=audit(<epoch>.<ms>:<serial>)
        let ts = match line.find("msg=audit(") {
            Some(idx_start) => {
                let rest = &line[idx_start + 10..];
                match rest.find(':') {
                    Some(idx_colon) => {
                        match rest[..idx_colon].parse::<f64>() {
                            Ok(frac) => {
                                let secs = frac.trunc() as i64;
                                DateTime::<Utc>::from_utc(
                                    NaiveDateTime::from_timestamp(secs, 0), Utc,
                                ).to_rfc3339()
                            }
                            Err(_) => continue,
                        }
                    }
                    None => continue,
                }
            }
            None => continue,
        };

        // Username: try acct="..." first (USER_AUTH/USER_START), then AUID="..."
        // (USER_LOGIN on Ubuntu 22 + SSSD), then UID="..." as last resort.
        let user = AUDIT_USER_ACCT_RE
            .captures(&line)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
            .or_else(|| AUDIT_USER_AUID_RE
                .captures(&line)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string())))
            .or_else(|| AUDIT_USER_UID_RE
                .captures(&line)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string())))
            .unwrap_or_default();

        // USER_LOGIN = SSH login itself; USER_AUTH/USER_ACCT/USER_START = PAM
        // stages. Only USER_LOGIN and USER_AUTH are the lateral-movement
        // signal; USER_START is session_open which fires once per session and
        // would double-count. Keep USER_LOGIN + USER_AUTH, drop the rest.
        if evt_type != "USER_LOGIN" && evt_type != "USER_AUTH" {
            continue;
        }

        let evt = if res == "success" { "SSH_SUCCESS" } else { "SSH_FAILED" };

        out.push(RawEvt {
            ts_rfc3339: ts,
            user,
            remote: ip,
            tty_or_proc: "audit".into(),
            evt: evt.into(),
            filename: path.display().to_string(),
            dst_host: dst_host.into(),
        });
    }
    out
}

// ────────────────────────── DataFrame builder ────────────────────────────────
/// Write a masstin CSV containing only the canonical header.
/// Used when no Linux events match, so downstream merge steps in parse-image /
/// parse-massive find a valid (empty) file instead of erroring with ENOENT.
fn write_empty_csv(output: Option<&String>) {
    let header = "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename\n";
    if let Some(path) = output {
        let _ = std::fs::write(path, header);
    }
}

fn build_dataframe(rows: &[RawEvt], output: Option<&String>) {
    if rows.is_empty() {
        eprintln!("[WARN] nothing matched lateral-movement filter");
        write_empty_csv(output);
        return;
    }

    // Apply noise filter (--ignore-local / --exclude-*). We build a minimal
    // LogData view of each RawEvt just for the filter check — RawEvt's
    // `remote` field can be either an IP or a hostname, so we route it to
    // both src_ip and workstation_name for the classifier.
    let filtered: Vec<RawEvt> = rows
        .iter()
        .filter(|r| {
            let (src_ip, src_computer) = if r.remote.parse::<std::net::IpAddr>().is_ok() {
                (r.remote.clone(), String::new())
            } else {
                (String::new(), r.remote.clone())
            };
            let ld = crate::parse::LogData {
                time_created: r.ts_rfc3339.clone(),
                computer: r.dst_host.clone(),
                event_type: String::new(),
                event_id: String::new(),
                subject_user_name: String::new(),
                subject_domain_name: String::new(),
                target_user_name: r.user.clone(),
                target_domain_name: String::new(),
                logon_type: String::new(),
                workstation_name: src_computer,
                ip_address: src_ip,
                logon_id: String::new(),
                filename: r.filename.clone(),
                detail: String::new(),
            };
            crate::filter::should_keep_record(&ld)
        })
        .cloned()
        .collect();
    if filtered.is_empty() {
        eprintln!("[WARN] all rows filtered by --ignore-local / --exclude-* flags");
        write_empty_csv(output);
        return;
    }
    // Same event seen through two channels of the SAME kind is one event:
    // on RHEL 7+ rsyslog's imjournal copies every sshd line from journald
    // into /var/log/secure, so a login parsed from both would appear twice.
    // Channels of different kinds (sshd log vs auditd vs wtmp) are kept —
    // they corroborate each other and carry different detail. Key: second-
    // resolution timestamp (journald has µs, syslog has seconds), host,
    // event, user, source, channel class. Preference within a class:
    // rsyslog text over journal (the file the analyst can open).
    let channel_class = |t: &str| -> &'static str {
        if t.starts_with("ssh") || t.starts_with("journal-ssh") { "ssh" }
        else if t == "audit" { "audit" }
        else if t == "pam" { "pam" }
        else { "other" }
    };
    let rank = |t: &str| -> u8 { if t.starts_with("journal-ssh") { 1 } else { 0 } };
    let mut ordered: Vec<&RawEvt> = filtered.iter().collect();
    ordered.sort_by_key(|r| rank(&r.tty_or_proc));
    // A key is claimed by the first FILE that produced it; rows for the same
    // key from OTHER files are the cross-channel copies and go. Rows from
    // the claiming file itself are all kept: automation (Ansible, batch
    // scp) legitimately opens several sessions per second from the same
    // account and source, and those are distinct logins, not duplicates.
    let mut owner: HashMap<(String, String, String, String, String, &'static str), String> = HashMap::new();
    let mut deduped: Vec<RawEvt> = Vec::with_capacity(filtered.len());
    for r in ordered {
        let ts_sec = r.ts_rfc3339.get(..19).unwrap_or(&r.ts_rfc3339).to_string();
        let key = (ts_sec, r.dst_host.clone(), r.evt.clone(), r.user.clone(), r.remote.clone(), channel_class(&r.tty_or_proc));
        let claimant = owner.entry(key).or_insert_with(|| r.filename.clone());
        if *claimant == r.filename { deduped.push(r.clone()); }
    }
    let removed = filtered.len() - deduped.len();
    if removed > 0 {
        crate::banner::print_info(&format!("{} duplicate events removed (journald + rsyslog overlap)", removed));
    }
    let rows = &deduped[..];

    let col = |f: fn(&RawEvt) -> String| rows.iter().map(f).collect::<Vec<_>>();

    let df = DataFrame::new(vec![
        Series::new("time_created", col(|r| r.ts_rfc3339.clone())),
        Series::new("dst_computer", col(|r| r.dst_host.clone())),
        Series::new("event_type", col(|r| {
            match r.evt.as_str() {
                "SSH_SUCCESS" | "LOGIN" | "LASTLOG" => "SUCCESSFUL_LOGON".to_string(),
                "SSH_FAILED" | "FAILED_LOGIN" => "FAILED_LOGON".to_string(),
                "SSH_CONNECT" => "CONNECT".to_string(),
                "LOGOUT" => "LOGOFF".to_string(),
                _ => "CONNECT".to_string(),
            }
        })),
        Series::new("event_id", col(|r| r.evt.clone())),
        Series::new("logon_type", vec![""; rows.len()]),
        Series::new("target_user_name", col(|r| r.user.clone())),
        Series::new("target_domain_name", vec![""; rows.len()]),
        Series::new(
            "src_computer",
            col(|r| if looks_like_ip(&r.remote) { "".into() } else { r.remote.clone() }),
        ),
        Series::new(
            "src_ip",
            col(|r| if looks_like_ip(&r.remote) { r.remote.clone() } else { "".into() }),
        ),
        Series::new("subject_user_name", vec![""; rows.len()]),
        Series::new("subject_domain_name", vec![""; rows.len()]),
        Series::new("logon_id", vec![""; rows.len()]),
        Series::new("detail", col(|r| r.tty_or_proc.clone())),
        Series::new("log_filename", col(|r| r.filename.clone())),
    ])
    .unwrap()
    .sort(["time_created"], false)
    .unwrap();

    match output {
        Some(p) => {
            CsvWriter::new(&mut File::create(p).unwrap())
                .has_header(true)
                .finish(&mut df.clone())
                .unwrap();
            // Output path shown in summary
        }
        None => {
            CsvWriter::new(std::io::stdout())
                .has_header(true)
                .finish(&mut df.clone())
                .unwrap();
        }
    }
}

// ────────────────────────── main entry point ─────────────────────────────────
/// Check if a filename is a Linux forensic artifact we care about
fn is_linux_artifact(fname: &str) -> bool {
    let lower = fname.to_lowercase();
    matches!(lower.as_str(), "utmp" | "lastlog" | "auth.log")
        || is_rotated_name(&lower, "wtmp")
        || is_rotated_name(&lower, "btmp")
        || lower.starts_with("secure")
        || lower.starts_with("messages")
        || lower.starts_with("audit.log")
        || lower.starts_with("auth.log")
        || lower.ends_with(".journal")
        || lower.ends_with(".journal~")
}

/// `base` itself or a logrotate variant of it: `wtmp`, `wtmp.1`,
/// `wtmp-20231119`, `btmp-20260901.gz`. Deliberately NOT a bare prefix
/// match so `wtmpx` (Solaris, different record layout) stays out.
fn is_rotated_name(lower: &str, base: &str) -> bool {
    lower == base
        || lower.starts_with(&format!("{}-", base))
        || lower.starts_with(&format!("{}.", base))
}

/// Files that are not auth logs but that hostname / year inference relies
/// on (`discover_hostname`, `get_file_year`). Pulled out of tar archives
/// next to the artifacts so a selective extract keeps those heuristics
/// working.
fn is_context_file(lower: &str) -> bool {
    matches!(lower, "hostname" | "hosts" | "dmesg" | "dpkg.log" | "dpkg.log.1" | "uac.log" | "os-release")
}

fn is_tar_archive(lower: &str) -> bool {
    lower.ends_with(".tar.gz") || lower.ends_with(".tgz") || lower.ends_with(".tar")
}

/// One tar archive (outer or nested) met while walking an archive tree.
/// `display_path` is what the analyst sees as the source
/// (`outer.tar.gz -> inner/uac-host-linux-2026.tar.gz` for nested ones);
/// `archive_name` is the bare file name used for filename heuristics.
pub(crate) struct TarExtract {
    pub extract_dir: PathBuf,
    pub display_path: String,
    pub archive_name: String,
    pub entries: Vec<String>,
    pub matched: usize,
}

/// Stream a `.tar` / `.tar.gz` / `.tgz` and unpack ONLY what parse-linux
/// can use: auth-log artifacts, the hostname / year context files, and
/// nested archives (which are recursed into and then deleted). Triage
/// collectors such as UAC ship multi-GB tarballs whose bulk is bodyfiles,
/// hashed executables and live-response output — extracting all of that
/// to temp would cost minutes and gigabytes for nothing.
///
/// Every entry name is recorded so the caller can run triage detection on
/// the listing exactly as it does for zips.
fn extract_tar_recursive(tar_path: &Path, dest_base: &Path, display_path: &str, out: &mut Vec<TarExtract>) {
    let archive_name = tar_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("archive")
        .to_string();
    let lower = archive_name.to_lowercase();
    let file = match File::open(tar_path) {
        Ok(f) => f,
        Err(e) => {
            if is_debug_mode() {
                eprintln!("[ERROR] Could not open tar {:?}: {}", tar_path, e);
            }
            return;
        }
    };
    let reader: Box<dyn Read> = if lower.ends_with(".tar") {
        Box::new(BufReader::new(file))
    } else {
        Box::new(GzDecoder::new(BufReader::new(file)))
    };
    let mut archive = tar::Archive::new(reader);

    let stem = crate::parse::archive_stem(&archive_name).unwrap_or_else(|| "extracted".to_string());
    let extract_dir = dest_base.join(stem);
    let _ = fs::create_dir_all(&extract_dir);

    let mut entries: Vec<String> = Vec::new();
    let mut matched: usize = 0;
    let mut nested: Vec<(PathBuf, String)> = Vec::new();

    let iter = match archive.entries() {
        Ok(it) => it,
        Err(e) => {
            if is_debug_mode() {
                eprintln!("[ERROR] Could not read tar {:?}: {}", tar_path, e);
            }
            return;
        }
    };
    for entry in iter {
        // A read error mid-stream (truncated upload, corrupt gzip member)
        // leaves the decoder in an undefined position: stop here and keep
        // whatever was already unpacked instead of spinning on garbage.
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                // Loud on purpose: a truncated collection (interrupted SFTP
                // upload, 2 GB tooling limits) silently loses whatever tar
                // put last — for UAC that is most of /var/log.
                crate::banner::print_warning(&format!(
                    "{}: archive ended early after {} entries ({}). \
                     The collection is probably TRUNCATED — everything tar wrote \
                     after that point is missing; re-transfer or re-collect it.",
                    archive_name, entries.len(), e
                ));
                break;
            }
        };
        let rel: PathBuf = match entry.path() {
            Ok(p) => p.into_owned(),
            Err(_) => continue,
        };
        let name = rel.to_string_lossy().replace('\\', "/");
        entries.push(name.clone());
        let etype = entry.header().entry_type();
        // /etc/localtime is a symlink into zoneinfo on every systemd distro;
        // Windows cannot materialise the link, so record its target in a
        // sidecar that linux_tz::discover_timezone knows to read.
        if etype.is_symlink() {
            if name.ends_with("etc/localtime") {
                if let Ok(Some(target)) = entry.link_name() {
                    let side = extract_dir.join(format!("{}.masstin-link", rel.to_string_lossy()));
                    if let Some(parent) = side.parent() { let _ = fs::create_dir_all(parent); }
                    let _ = fs::write(&side, target.to_string_lossy().as_bytes());
                }
            }
            continue;
        }
        if !etype.is_file() { continue; }

        let fname_lower = rel
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        // Context the hostname / timezone / lastlog heuristics need, matched
        // on the path tail so `[root]/etc/passwd` is taken but not a stray
        // `passwd` elsewhere.
        let ctx_path = [
            "etc/sysconfig/network",                    // RHEL 6 HOSTNAME=
            "etc/sysconfig/clock",                      // RHEL 6 ZONE=
            "etc/timezone",                             // Debian zone name
            "etc/localtime",                            // TZif (RHEL 6 / mounted images)
            "etc/passwd",                               // uid → name for lastlog
            "live_response/system/timedatectl_status.txt",
        ].iter().any(|s| name.ends_with(s));
        let wanted = is_linux_artifact(&fname_lower) || is_context_file(&fname_lower) || ctx_path;
        // Nested archives are recursed into — EXCEPT those UAC copied off
        // the victim filesystem under `[root]/` (application dumps, vendor
        // tarballs, backups). Those are evidence, not containers of it.
        let from_victim_fs = rel.components().any(|c| c.as_os_str() == "[root]");
        let is_nested = !from_victim_fs
            && (is_tar_archive(&fname_lower) || fname_lower.ends_with(".zip"));
        if !wanted && !is_nested { continue; }

        // unpack_in() refuses paths that escape `extract_dir` (`..`,
        // absolute) and creates the parent directories itself.
        match entry.unpack_in(&extract_dir) {
            Ok(true) => {}
            _ => continue,
        }
        if wanted { matched += 1; }
        if is_nested { nested.push((extract_dir.join(&rel), name)); }
    }

    out.push(TarExtract {
        extract_dir: extract_dir.clone(),
        display_path: display_path.to_string(),
        archive_name,
        entries,
        matched,
    });

    for (nested_path, nested_name) in nested {
        let display = format!("{} -> {}", display_path, nested_name);
        let nested_lower = nested_name.to_lowercase();
        if nested_lower.ends_with(".zip") {
            let zip_entries = crate::parse::read_zip_top_entries(&nested_path).unwrap_or_default();
            let dirs = extract_zips_recursive(&nested_path, &extract_dir, out);
            if let Some(dir) = dirs.last() {
                out.push(TarExtract {
                    extract_dir: dir.clone(),
                    display_path: display,
                    archive_name: nested_path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string(),
                    entries: zip_entries,
                    matched: 0,
                });
            }
        } else {
            extract_tar_recursive(&nested_path, &extract_dir, &display, out);
        }
        // The intermediate archive has served its purpose; free the disk.
        let _ = fs::remove_file(&nested_path);
    }
}

/// Recursively extract ZIPs (including password-protected with common forensic passwords)
/// and return paths to extracted directories
fn extract_zips_recursive(zip_path: &Path, dest_base: &Path, tar_out: &mut Vec<TarExtract>) -> Vec<PathBuf> {
    let mut extracted_dirs: Vec<PathBuf> = Vec::new();
    let passwords: &[&[u8]] = &[b"", b"cyberdefenders.org", b"infected", b"malware", b"password"];

    // The archive is re-opened from disk for every password probe instead
    // of being slurped into memory: evidence zips routinely run into the
    // gigabytes (a zip wrapping two UAC tarballs is ~3 GB) and the old
    // read_to_end() doubled the process footprint for nothing.
    let open = |p: &Path| -> Option<ZipArchive<File>> {
        let f = File::open(p).ok()?;
        ZipArchive::new(f).ok()
    };
    let mut archive = match open(zip_path) {
        Some(a) => a,
        None => {
            if is_debug_mode() {
                eprintln!("[ERROR] Could not open ZIP {:?}", zip_path);
            }
            return extracted_dirs;
        }
    };

    let zip_name = zip_path.file_stem().and_then(|s| s.to_str()).unwrap_or("extracted");
    let extract_dir = dest_base.join(zip_name);
    let _ = fs::create_dir_all(&extract_dir);

    // Try each password — test with the first actual file (not directory)
    let entry_count = archive.len();
    let test_idx = (0..entry_count)
        .find(|&i| archive.by_index_raw(i).map(|e| !e.is_dir()).unwrap_or(false))
        .unwrap_or(0);
    let mut working_pwd: Option<&[u8]> = None;
    for pwd in passwords {
        let mut pa = match open(zip_path) {
            Some(a) => a,
            None => break,
        };
        let ok = if pwd.is_empty() {
            if let Ok(mut e) = pa.by_index(test_idx) {
                let mut buf = [0u8; 4];
                e.read(&mut buf).is_ok()
            } else { false }
        } else {
            if let Ok(Ok(mut e)) = pa.by_index_decrypt(test_idx, pwd) {
                let mut buf = [0u8; 4];
                e.read(&mut buf).is_ok()
            } else { false }
        };
        if ok {
            working_pwd = Some(pwd);
            if !pwd.is_empty() {
                crate::banner::print_info(&format!(
                    "ZIP is password-protected, unlocked with known forensic password"
                ));
            }
            break;
        }
    }

    for i in 0..entry_count {
        let mut zip_entry = match working_pwd {
            Some(pwd) if !pwd.is_empty() => {
                match archive.by_index_decrypt(i, pwd) {
                    Ok(Ok(e)) => e,
                    _ => continue,
                }
            },
            _ => {
                match archive.by_index(i) {
                    Ok(e) => e,
                    Err(_) => continue,
                }
            }
        };

        let entry_name = zip_entry.name().to_string();
        if zip_entry.is_dir() {
            let dir_path = extract_dir.join(&entry_name);
            let _ = fs::create_dir_all(&dir_path);
            continue;
        }

        let out_path = extract_dir.join(&entry_name);
        if let Some(parent) = out_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        // Extract file — streamed, so a multi-GB tarball inside the zip
        // never has to fit in memory.
        let mut out_file = match File::create(&out_path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if std::io::copy(&mut zip_entry, &mut out_file).is_err() {
            continue;
        }
        drop(out_file);

        // Nested archives: zip → recurse here; tar/tgz → stream it with
        // the selective extractor and drop the intermediate file after.
        let lower = out_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        if lower.ends_with(".zip") {
            let nested = extract_zips_recursive(&out_path, &extract_dir, tar_out);
            extracted_dirs.extend(nested);
        } else if is_tar_archive(&lower) {
            let display = format!("{} -> {}", zip_path.display(), entry_name);
            extract_tar_recursive(&out_path, &extract_dir, &display, tar_out);
            let _ = fs::remove_file(&out_path);
        }
    }

    extracted_dirs.push(extract_dir);
    extracted_dirs
}

/// Fold every tar archive met during extraction (outer, nested, or nested
/// inside a zip) into the discovery state: triage detection on its entry
/// listing, source labelling, filename rewriting and the dir list to walk.
fn register_tar_extracts(
    tars: Vec<TarExtract>,
    archives_scanned: &mut usize,
    triage_dirs: &mut Vec<(PathBuf, crate::parse::TriageInfo)>,
    triages: &mut Vec<crate::parse::TriageInfo>,
    all_dirs: &mut Vec<PathBuf>,
    archive_dirs: &mut Vec<(PathBuf, String)>,
) {
    for t in tars {
        *archives_scanned += 1;
        if is_debug_mode() {
            println!(
                "[DEBUG] archive extracted: {} ({} entries, {} usable)",
                t.display_path, t.entries.len(), t.matched
            );
        }
        // display_path ends with the archive's own file name even when
        // nested ("outer.tar.gz -> dir/inner.tar.gz"), which is all the
        // filename / path heuristics need.
        if let Some(kind) = crate::parse::detect_triage_type(&t.display_path, &t.entries) {
            let hostname = crate::parse::extract_triage_hostname(&t.display_path, kind);
            let info = crate::parse::TriageInfo {
                kind,
                zip_path: t.display_path.clone(),
                hostname,
                artifact_count: t.matched,
            };
            triage_dirs.push((t.extract_dir.clone(), info.clone()));
            triages.push(info);
        }
        archive_dirs.push((t.extract_dir.clone(), t.archive_name.clone()));
        all_dirs.push(t.extract_dir);
    }
}

pub fn parse_linux(files: &[String], dirs: &[String], output: Option<&String>) {
    parse_linux_inner(files, dirs, output, false);
}

/// Quiet mode: skip phase headers and summary (used when integrated into parse-image mixed pipeline)
pub fn parse_linux_quiet(files: &[String], dirs: &[String], output: Option<&String>) {
    parse_linux_inner(files, dirs, output, true);
}

fn parse_linux_inner(files: &[String], dirs: &[String], output: Option<&String>, quiet: bool) {
    let start_time = std::time::Instant::now();

    // Phase 1: Search for artifacts (with ZIP support)
    if !quiet { crate::banner::print_search_start(); }

    let mut targets: Vec<PathBuf> = files.iter().map(PathBuf::from).collect();
    let mut archives_scanned: usize = 0;

    // Create temp dir for ZIP extraction
    let temp_dir = std::env::temp_dir().join("masstin_linux_extract");
    let _ = fs::create_dir_all(&temp_dir);

    // Collect additional dirs from ZIP extraction
    let mut all_dirs: Vec<PathBuf> = dirs.iter().map(PathBuf::from).collect();

    // Triage tracking: maps each extraction directory to the TriageInfo of
    // the source ZIP, so the per-source breakdown can label artifacts as
    // "[TRIAGE: <type>]" instead of "[FOLDER]" pointing to a temp path.
    let mut triage_dirs: Vec<(PathBuf, crate::parse::TriageInfo)> = Vec::new();
    let mut triages: Vec<crate::parse::TriageInfo> = Vec::new();

    // Maps each archive extraction dir to the archive file it came from, so
    // the CSV `log_filename` column can show `<archive>:<path inside>`
    // instead of a masstin temp path that is gone once the run finishes.
    let mut archive_dirs: Vec<(PathBuf, String)> = Vec::new();

    // First pass: find archives (zip / tar / tar.gz / tgz), detect triage,
    // extract them. Tar archives are what Unix collectors such as UAC
    // produce; they are streamed selectively (see extract_tar_recursive)
    // and may nest (UAC wrapped in a zip, tar.gz wrapped in a tar.gz).
    for root in dirs {
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            let p = entry.into_path();
            if !p.is_file() { continue; }
            let lower = p.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
            if lower.ends_with(".zip") {
                if is_debug_mode() {
                    println!("[DEBUG] ZIP detected: {}", p.display());
                }
                archives_scanned += 1;
                let zip_path_str = p.to_string_lossy().to_string();

                // Detect triage type from top-level entries AND zip path
                // BEFORE extraction. The filename + path heuristics catch
                // re-zipped Velociraptor extracts whose JSON metadata
                // markers are missing (happens when users extract a VR
                // collection and re-zip only the C/ subtree).
                let triage_kind = crate::parse::read_zip_top_entries(&p)
                    .and_then(|entries| crate::parse::detect_triage_type(&zip_path_str, &entries));

                let mut tar_out: Vec<TarExtract> = Vec::new();
                let extracted = extract_zips_recursive(&p, &temp_dir, &mut tar_out);

                // extract_zips_recursive lists nested-zip dirs first and
                // the outer zip's own dir LAST; that last one is the root
                // of this zip's extraction.
                if let Some(kind) = triage_kind {
                    let hostname = crate::parse::extract_triage_hostname(&zip_path_str, kind);
                    let info = crate::parse::TriageInfo {
                        kind,
                        zip_path: zip_path_str.clone(),
                        hostname,
                        artifact_count: 0,
                    };
                    if let Some(outer_dir) = extracted.last() {
                        triage_dirs.push((outer_dir.clone(), info.clone()));
                    }
                    triages.push(info);
                }
                if let Some(outer_dir) = extracted.last() {
                    archive_dirs.push((outer_dir.clone(), lower.clone()));
                }

                all_dirs.extend(extracted);
                register_tar_extracts(
                    tar_out, &mut archives_scanned, &mut triage_dirs,
                    &mut triages, &mut all_dirs, &mut archive_dirs,
                );
            } else if is_tar_archive(&lower) {
                if is_debug_mode() {
                    println!("[DEBUG] TAR detected: {}", p.display());
                }
                let mut tar_out: Vec<TarExtract> = Vec::new();
                extract_tar_recursive(&p, &temp_dir, &p.to_string_lossy(), &mut tar_out);
                register_tar_extracts(
                    tar_out, &mut archives_scanned, &mut triage_dirs,
                    &mut triages, &mut all_dirs, &mut archive_dirs,
                );
            }
        }
    }
    // Nested triages live INSIDE their wrapper's extract dir: match the
    // most specific (longest) dir first when labelling sources.
    triage_dirs.sort_by(|a, b| b.0.as_os_str().len().cmp(&a.0.as_os_str().len()));

    // Print triage detections right after the discovery walk, before the
    // overall count summary. Same formatting helper as parse-windows — we
    // pass the full zip path so the analyst can tell two physically
    // distinct copies of the same host's triage apart.
    if !quiet {
        for t in &triages {
            crate::banner::print_triage_found(
                t.kind.label(),
                t.hostname.as_deref(),
                &t.zip_path,
                t.artifact_count,
            );
        }
    }
    if is_debug_mode() {
        println!("[DEBUG] {} archive(s) opened during discovery", archives_scanned);
    }

    // Second pass: find Linux artifacts in all dirs (original + extracted)
    for root in &all_dirs {
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            let p = entry.into_path();
            if !p.is_file() { continue; }
            let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if is_linux_artifact(fname) {
                targets.push(p);
            }
        }
    }

    if targets.is_empty() {
        eprintln!("[WARN] no candidate logs found");
        // Cleanup temp dir
        let _ = fs::remove_dir_all(&temp_dir);
        return;
    }
    targets.sort();
    targets.dedup();

    if !quiet {
        // Artifacts that came out of an archive live under our temp dir.
        let inside_archives = targets.iter().filter(|p| p.starts_with(&temp_dir)).count();
        crate::banner::print_search_results_labeled(targets.len(), inside_archives, dirs.len(), files.len(), "Linux log artifacts");
    }

    if is_debug_mode() {
        println!("[DEBUG] {} candidate files", targets.len());
    }

    // 2) hostname cache
    let mut root2host: HashMap<PathBuf, String> = HashMap::new();
    // Per-root local timezone (syslog lines are wall-clock) and uid map
    // (lastlog). Resolved once per root, like the hostname.
    let mut root2tz: HashMap<PathBuf, crate::linux_tz::LocalTz> = HashMap::new();
    let mut root2passwd: HashMap<PathBuf, HashMap<u32, String>> = HashMap::new();

    // Phase 2: Process artifacts
    if !quiet { crate::banner::print_processing_start(); }
    let pb = crate::banner::create_progress_bar(targets.len() as u64);

    let mut collected = Vec::<RawEvt>::new();
    let mut parsed_count: usize = 0;
    let mut skipped: usize = 0;
    // (source_label, artifact_short_name, vss_index, count) — same structure
    // as parse-windows so banner::print_artifact_detail_grouped can render it.
    // Linux logs never come from VSS snapshots, so vss_index is always None.
    let mut artifact_details: Vec<(String, String, Option<u32>, usize)> = Vec::new();
    let mut year_cache: HashMap<PathBuf, i32> = HashMap::new();

    for path in &targets {
        let path_str = path.to_string_lossy().to_string();
        crate::banner::progress_set_message(&pb, &path_str);

        // Find the root dir the hostname heuristics should scan. UAC lays
        // the collected filesystem out under `[root]/` with uac.log as its
        // sibling, so the dir holding `[root]` is the natural root: /etc/
        // hostname, /etc/hosts and /var/log/* all hang from it, and
        // /var/run/utmp (which has no `log` ancestor) resolves too.
        // Otherwise: walk upwards until a "log" folder and take its parent.
        let root = match path.components().position(|c| c.as_os_str() == "[root]") {
            Some(idx) => path.components().take(idx).collect::<PathBuf>(),
            None => {
                let mut cur = path.parent().unwrap_or(Path::new("/"));
                while cur.parent().is_some() && cur.file_name() != Some(OsStr::new("log")) {
                    cur = cur.parent().unwrap();
                }
                cur.parent().unwrap_or(cur).to_path_buf()
            }
        };
        let mut dst_host = root2host
            .entry(root.clone())
            .or_insert_with(|| discover_hostname(&root))
            .clone();

        // Fallback: if hostname is still unknown/generic, extract from the log's RFC3164 header
        if dst_host == "unknown" || dst_host == "C:" || dst_host.len() <= 2 {
            if let Ok(file) = File::open(path) {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten().take(20) {
                    if let Some(cap) = RFC3164_RE.captures(&line) {
                        let h = cap[4].to_string();
                        if !h.is_empty() && h != "-" {
                            crate::banner::print_info(&format!(
                                "Hostname identified: {} (from syslog header)", h
                            ));
                            dst_host = h;
                            root2host.insert(root.clone(), dst_host.clone());
                            break;
                        }
                    }
                }
            }
        }

        if is_debug_mode() {
            println!(
                "[DEBUG] scanning  {}\n        candidate root  {}",
                path.display(),
                root.display()
            );
        }

        let fname = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Get cached year for this directory (only infer + print once)
        let dir_key = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        let cached_year = if year_cache.contains_key(&dir_key) {
            Some(*year_cache.get(&dir_key).unwrap())
        } else {
            let y = get_file_year(path);
            year_cache.insert(dir_key, y);
            Some(y)
        };

        if !root2tz.contains_key(&root) {
            let (tz, source) = crate::linux_tz::discover_timezone(&root);
            if tz.is_utc() && source.starts_with("not found") {
                crate::banner::print_warning(&format!(
                    "Timezone for {}: {}", dst_host, source
                ));
            } else {
                crate::banner::print_info(&format!("Timezone identified: {}", source));
            }
            root2tz.insert(root.clone(), tz);
        }
        let tz = root2tz.get(&root).unwrap();

        let mut parsed: Vec<RawEvt> = Vec::new();
        if fname == "lastlog" {
            let passwd = root2passwd
                .entry(root.clone())
                .or_insert_with(|| load_passwd(&root));
            parsed = parse_lastlog(path, &dst_host, passwd);
        } else if fname == "utmp"
            || is_rotated_name(&fname, "wtmp") || is_rotated_name(&fname, "btmp")
        {
            parsed = parse_utmp_file(path, &dst_host, true);
        } else if fname.starts_with("secure") || fname.starts_with("auth.log") {
            parsed = parse_secure_or_messages(path, &dst_host, true, cached_year, tz);
        } else if fname.starts_with("messages") {
            parsed = parse_secure_or_messages(path, &dst_host, true, cached_year, tz);
        } else if fname.starts_with("audit.log") {
            parsed = parse_audit(path, &dst_host, true);
        } else if fname.ends_with(".journal") || fname.ends_with(".journal~") {
            parsed = crate::parse_journal::parse_journal_file(path, &dst_host);
        }

        let count = parsed.len();
        if count == 0 {
            skipped += 1;
        } else {
            parsed_count += 1;
            let source = crate::parse::source_label_for_linux_path(&path_str, &triage_dirs);
            let short = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&path_str)
                .to_string();
            // Linux logs never come from VSS; always None.
            artifact_details.push((source, short, None, count));
        }
        collected.extend(parsed);

        if is_debug_mode() {
            println!(
                "        {:<8} events {:>5}",
                fname.split('.').next().unwrap_or("log"),
                count,
            );
        }

        pb.inc(1);
    }

    pb.finish_and_clear();
    crate::banner::print_artifact_detail_grouped(&artifact_details);

    if is_debug_mode() {
        println!(
            "[DEBUG] SUMMARY  total {:>6}",
            collected.len()
        );
    }

    // Rewrite temp-extract paths in log_filename to `<archive>:<path inside>`
    // so the CSV points at evidence the analyst actually holds. Longest
    // prefix wins: nested archives extract inside their wrapper's dir.
    if !archive_dirs.is_empty() {
        archive_dirs.sort_by(|a, b| b.0.as_os_str().len().cmp(&a.0.as_os_str().len()));
        let prefixes: Vec<(String, String)> = archive_dirs
            .iter()
            .map(|(d, n)| (d.to_string_lossy().replace('\\', "/"), n.clone()))
            .collect();
        for evt in collected.iter_mut() {
            let norm = evt.filename.replace('\\', "/");
            if let Some((prefix, name)) = prefixes.iter().find(|(pfx, _)| norm.starts_with(pfx.as_str())) {
                let inside = norm[prefix.len()..].trim_start_matches('/');
                evt.filename = format!("{}:{}", name, inside);
            }
        }
    }

    // Phase 3: Generate output
    if !quiet { crate::banner::print_output_start(); }
    let total_events = collected.len();
    build_dataframe(&collected, output);

    if !quiet {
        crate::banner::print_summary(total_events, parsed_count, skipped, output.map(|s| s.as_str()), start_time);
    }

    // Cleanup temp extraction dir
    let _ = fs::remove_dir_all(&temp_dir);
}
