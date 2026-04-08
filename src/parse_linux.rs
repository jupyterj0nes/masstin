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
    io::{BufRead, BufReader, Read, Cursor},
    mem,
    os::raw::{c_char, c_int, c_short},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;
use ::zip::ZipArchive;
use chrono::{DateTime, NaiveDateTime, Utc, Datelike};
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

static SSH_OK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"Accepted (?:password|publickey) for (\S+) from (\S+)"#).unwrap()
});
static SSH_FAIL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"Failed password for (\S+) from (\S+)"#).unwrap());
static PAM_FAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"pam_unix\(sshd:[^\)]*\).*rhost=(\S+)\s+user=(\S+)"#).unwrap()
});
static XINETD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"START: ssh .* from=::ffff:(\S+)"#).unwrap());
static AUDIT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"type=(USER_AUTH|USER_START).*acct="([^"]+)".*hostname=([\d\.]+).*res=(\w+)"#,
    )
    .unwrap()
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
fn parse_rfc3164_timestamp(month: &str, day: &str, time: &str, file_year: i32) -> Option<String> {
    let date_str = format!("{} {} {} {}", file_year, month, day.trim(), time);
    if let Ok(dt) = NaiveDateTime::parse_from_str(&date_str, "%Y %b %d %H:%M:%S") {
        return Some(DateTime::<Utc>::from_utc(dt, Utc).to_rfc3339());
    }
    None
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
struct RawEvt {
    ts_rfc3339: String,
    user: String,
    remote: String, // ip OR host (we’ll split later)
    tty_or_proc: String,
    evt: String,
    filename: String,
    dst_host: String,
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
            // /etc/hosts first non-comment line may contain hostname
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 1 {
                return Some(parts[1].to_string());
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
    let mut rdr = match File::open(path) {
        Ok(f) => BufReader::new(f),
        Err(e) => {
            eprintln!("[ERROR] cannot open {}: {}", path.display(), e);
            return res;
        }
    };
    let mut buf = vec![0u8; mem::size_of::<UtmpEntry>()];
    let fname = path.display().to_string();
    while rdr.read_exact(&mut buf).is_ok() {
        let rec: &UtmpEntry = unsafe { &*(buf.as_ptr() as *const UtmpEntry) };
        if rec.ut_type == ACCOUNTING {
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

        if path.file_name() == Some(OsStr::new("btmp")) {
            evt = "FAILED_LOGIN".into();
        }

        if filter_ip && !looks_like_ip(&host) && !evt.eq("FAILED_LOGIN") {
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
fn parse_secure_or_messages(path: &Path, dst_host: &str, filter_ip: bool, year_hint: Option<i32>) -> Vec<RawEvt> {
    let mut out = Vec::new();
    let fname = path.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase();
    let is_secure = fname.starts_with("secure") || fname.starts_with("auth.log");
    let file_year = year_hint.unwrap_or_else(|| get_file_year(path));

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
            if let Some(ts) = parse_rfc3164_timestamp(month, day, time, file_year) {
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

        // 2) SSH success: "Accepted password for user from IP"
        if let Some(cap) = SSH_OK_RE.captures(&msg) {
            let user = cap[1].to_string();
            let ip   = cap[2].to_string();
            if !filter_ip || looks_like_ip(&ip) {
                out.push(RawEvt {
                    ts_rfc3339:  when.clone(),
                    user,
                    remote:      ip,
                    tty_or_proc: "ssh".into(),
                    evt:         "SSH_SUCCESS".into(),
                    filename:    path.display().to_string(),
                    dst_host:    dst_host.into(),
                });
            }
            continue;
        }

        // 3) SSH failure: "Failed password for user from IP"
        if let Some(cap) = SSH_FAIL_RE.captures(&msg) {
            let user = cap[1].to_string();
            let ip   = cap[2].to_string();
            if !filter_ip || looks_like_ip(&ip) {
                out.push(RawEvt {
                    ts_rfc3339:  when.clone(),
                    user,
                    remote:      ip,
                    tty_or_proc: "ssh".into(),
                    evt:         "SSH_FAILED".into(),
                    filename:    path.display().to_string(),
                    dst_host:    dst_host.into(),
                });
            }
            continue;
        }

        // 4) PAM failure: "pam_unix(sshd:...) rhost=IP user=USER"
        if is_secure {
            if let Some(cap) = PAM_FAIL_RE.captures(&msg) {
                let ip   = cap[1].to_string();
                let user = cap[2].to_string();
                if !filter_ip || looks_like_ip(&ip) {
                    out.push(RawEvt {
                        ts_rfc3339:  when.clone(),
                        user,
                        remote:      ip,
                        tty_or_proc: "pam".into(),
                        evt:         "SSH_FAILED".into(),
                        filename:    path.display().to_string(),
                        dst_host:    dst_host.into(),
                    });
                }
            }
        }
    }

    out
}

// audit.log* ------------------------------------------------------------------
fn parse_audit(path: &Path, dst_host: &str, filter_ip: bool) -> Vec<RawEvt> {
    let mut out = Vec::new();
    for line in open_plain_or_gzip(path).lines().flatten() {
        if let Some(cap) = AUDIT_RE.captures(&line) {
            // extract epoch.seconds.micro -> first field inside msg=audit(...)
            if let Some(idx_start) = line.find("msg=audit(") {
                if let Some(idx_colon) = line[idx_start + 10..].find(':') {
                    let ts_str = &line[idx_start + 10..idx_start + 10 + idx_colon];
                    if let Ok(frac) = ts_str.parse::<f64>() {
                        let secs = frac.trunc() as i64;
                        let ts =
                            DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(secs, 0), Utc)
                                .to_rfc3339();
                        let user = cap[2].to_string();
                        let ip = cap[3].to_string();
                        let res = &cap[4];
                        let evt = if res == "success" {
                            "SSH_SUCCESS"
                        } else {
                            "SSH_FAILED"
                        };
                        if filter_ip && !looks_like_ip(&ip) {
                            continue;
                        }
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
                }
            }
        }
    }
    out
}

// ────────────────────────── DataFrame builder ────────────────────────────────
fn build_dataframe(rows: &[RawEvt], output: Option<&String>) {
    if rows.is_empty() {
        eprintln!("[WARN] nothing matched lateral-movement filter");
        return;
    }
    let col = |f: fn(&RawEvt) -> String| rows.iter().map(f).collect::<Vec<_>>();

    let df = DataFrame::new(vec![
        Series::new("time_created", col(|r| r.ts_rfc3339.clone())),
        Series::new("dst_computer", col(|r| r.dst_host.clone())),
        Series::new("event_id", col(|r| r.evt.clone())),
        Series::new("subject_user_name", vec![""; rows.len()]),
        Series::new("subject_domain_name", vec![""; rows.len()]),
        Series::new("target_user_name", col(|r| r.user.clone())),
        Series::new("target_domain_name", vec![""; rows.len()]),
        Series::new("logon_type", vec![""; rows.len()]),
        Series::new(
            "src_computer",
            col(|r| if looks_like_ip(&r.remote) { "".into() } else { r.remote.clone() }),
        ),
        Series::new(
            "src_ip",
            col(|r| if looks_like_ip(&r.remote) { r.remote.clone() } else { "".into() }),
        ),
        Series::new("process", col(|r| r.tty_or_proc.clone())),
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
    matches!(lower.as_str(), "utmp" | "wtmp" | "btmp" | "lastlog" | "auth.log")
        || lower.starts_with("secure")
        || lower.starts_with("messages")
        || lower.starts_with("audit.log")
        || lower.starts_with("auth.log")
}

/// Recursively extract ZIPs (including password-protected with common forensic passwords)
/// and return paths to extracted directories
fn extract_zips_recursive(zip_path: &Path, dest_base: &Path) -> Vec<PathBuf> {
    let mut extracted_dirs: Vec<PathBuf> = Vec::new();
    let passwords: &[&[u8]] = &[b"", b"cyberdefenders.org", b"infected", b"malware", b"password"];

    let file = match File::open(zip_path) {
        Ok(f) => f,
        Err(e) => {
            if is_debug_mode() {
                eprintln!("[ERROR] Could not open ZIP {:?}: {}", zip_path, e);
            }
            return extracted_dirs;
        }
    };

    let mut archive = match ZipArchive::new(file) {
        Ok(a) => a,
        Err(e) => {
            if is_debug_mode() {
                eprintln!("[ERROR] Could not read ZIP {:?}: {}", zip_path, e);
            }
            return extracted_dirs;
        }
    };

    let zip_name = zip_path.file_stem().and_then(|s| s.to_str()).unwrap_or("extracted");
    let extract_dir = dest_base.join(zip_name);
    let _ = fs::create_dir_all(&extract_dir);

    // Read the entire ZIP into memory to avoid borrow issues with passwords
    let mut zip_bytes = Vec::new();
    {
        let mut f = match File::open(zip_path) {
            Ok(f) => f,
            Err(_) => return extracted_dirs,
        };
        if f.read_to_end(&mut zip_bytes).is_err() {
            return extracted_dirs;
        }
    }

    // Try each password — test with the first actual file (not directory)
    let mut working_pwd: Option<&[u8]> = None;
    {
        let cursor = Cursor::new(&zip_bytes);
        if let Ok(test_archive) = ZipArchive::new(cursor) {
            // Find first non-directory entry
            let test_idx = (0..test_archive.len()).find(|&i| {
                let cursor2 = Cursor::new(&zip_bytes);
                if let Ok(mut a) = ZipArchive::new(cursor2) {
                    if let Ok(e) = a.by_index_raw(i) {
                        return !e.is_dir();
                    }
                }
                false
            }).unwrap_or(0);

            for pwd in passwords {
                let cursor = Cursor::new(&zip_bytes);
                if let Ok(mut pa) = ZipArchive::new(cursor) {
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
            }
        }
    }

    let cursor = Cursor::new(&zip_bytes);
    let mut archive = match ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return extracted_dirs,
    };

    for i in 0..archive.len() {
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

        // Extract file
        let mut buf = Vec::new();
        if zip_entry.read_to_end(&mut buf).is_err() {
            continue;
        }
        if fs::write(&out_path, &buf).is_err() {
            continue;
        }

        // If it's a nested ZIP, recurse
        let ext = out_path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        if ext == "zip" {
            let nested = extract_zips_recursive(&out_path, &extract_dir);
            extracted_dirs.extend(nested);
        }
    }

    extracted_dirs.push(extract_dir);
    extracted_dirs
}

pub fn parse_linux(files: &[String], dirs: &[String], output: Option<&String>) {
    let start_time = std::time::Instant::now();

    // Phase 1: Search for artifacts (with ZIP support)
    crate::banner::print_search_start();

    let mut targets: Vec<PathBuf> = files.iter().map(PathBuf::from).collect();
    let mut zip_count: usize = 0;

    // Create temp dir for ZIP extraction
    let temp_dir = std::env::temp_dir().join("masstin_linux_extract");
    let _ = fs::create_dir_all(&temp_dir);

    // Collect additional dirs from ZIP extraction
    let mut all_dirs: Vec<PathBuf> = dirs.iter().map(PathBuf::from).collect();

    // First pass: find ZIPs and extract them
    for root in dirs {
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            let p = entry.into_path();
            if !p.is_file() { continue; }
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
            if ext == "zip" {
                if is_debug_mode() {
                    println!("[DEBUG] ZIP detected: {}", p.display());
                }
                zip_count += 1;
                let extracted = extract_zips_recursive(&p, &temp_dir);
                all_dirs.extend(extracted);
            }
        }
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

    crate::banner::print_search_results_labeled(targets.len(), zip_count, dirs.len(), files.len(), "Linux log artifacts");

    if is_debug_mode() {
        println!("[DEBUG] {} candidate files", targets.len());
    }

    // 2) hostname cache
    let mut root2host: HashMap<PathBuf, String> = HashMap::new();

    // Phase 2: Process artifacts
    crate::banner::print_processing_start();
    let pb = crate::banner::create_progress_bar(targets.len() as u64);

    let mut collected = Vec::<RawEvt>::new();
    let mut parsed_count: usize = 0;
    let mut skipped: usize = 0;
    let mut artifact_details: Vec<(String, usize)> = Vec::new();
    let mut year_cache: HashMap<PathBuf, i32> = HashMap::new();

    for path in &targets {
        let path_str = path.to_string_lossy().to_string();
        crate::banner::progress_set_message(&pb, &path_str);

        // find root dir (upwards until "log" folder)
        let mut cur = path.parent().unwrap_or(Path::new("/"));
        while cur.parent().is_some() && cur.file_name() != Some(OsStr::new("log")) {
            cur = cur.parent().unwrap();
        }
        let root = cur.parent().unwrap_or(cur).to_path_buf();
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

        let mut parsed: Vec<RawEvt> = Vec::new();
        if ["utmp", "wtmp", "btmp", "lastlog"].contains(&fname.as_str()) {
            parsed = parse_utmp_file(path, &dst_host, true);
        } else if fname.starts_with("secure") || fname.starts_with("auth.log") {
            parsed = parse_secure_or_messages(path, &dst_host, true, cached_year);
        } else if fname.starts_with("messages") {
            parsed = parse_secure_or_messages(path, &dst_host, true, cached_year);
        } else if fname.starts_with("audit.log") {
            parsed = parse_audit(path, &dst_host, true);
        }

        let count = parsed.len();
        if count == 0 {
            skipped += 1;
        } else {
            parsed_count += 1;
            artifact_details.push((path_str, count));
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
    crate::banner::print_artifact_detail(&artifact_details);

    if is_debug_mode() {
        println!(
            "[DEBUG] SUMMARY  total {:>6}",
            collected.len()
        );
    }

    // Phase 3: Generate output
    crate::banner::print_output_start();
    let total_events = collected.len();
    build_dataframe(&collected, output);

    crate::banner::print_summary(total_events, parsed_count, skipped, output.map(|s| s.as_str()), start_time);

    // Cleanup temp extraction dir
    let _ = fs::remove_dir_all(&temp_dir);
}
