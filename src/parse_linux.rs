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

// ────────────────────────── utils ────────────────────────────────────────────
fn c_chars(b: &[c_char]) -> String {
    let v: Vec<u8> = b.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&v).trim().to_owned()
}
fn looks_like_ip(s: &str) -> bool {
    IPV4_RE.is_match(s) || IPV6_COLON.is_match(s)
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
    // 1) dmesg
    for entry in WalkDir::new(root).max_depth(3) {
        let path = entry.unwrap().path().to_owned();
        if path.file_name() == Some(OsStr::new("dmesg")) {
            if let Some(h) = extract_hostname_txt(&path) {
                if is_debug_mode() {
                    println!("        hostname from dmesg @ {}  →  {}", path.display(), h);
                }
                return h;
            }
        }
        // /etc/hosts
        if path.file_name() == Some(OsStr::new("hosts")) && path.parent().map(|p| p.ends_with("etc")).unwrap_or(false)
        {
            if let Some(h) = extract_hostname_txt(&path) {
                if is_debug_mode() {
                    println!("        hostname from /etc/hosts @ {}  →  {}", path.display(), h);
                }
                return h;
            }
        }
    }
    // 2) fallback to folder name
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
fn parse_secure_or_messages(path: &Path, dst_host: &str, filter_ip: bool) -> Vec<RawEvt> {
    let mut out = Vec::new();
    let fname = path.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase();
    let is_secure = fname.starts_with("secure");

    if is_debug_mode() {
        println!("    reading {} …", path.display());
    }

    for line in open_plain_or_gzip(path).lines().flatten() {
        // ——— Legacy syslog (RFC3164) ALWAYS SKIP ———
        if line.len() > 15 && line.chars().take(3).all(|c| c.is_ascii_alphabetic()) {
            let rest = &line[16..];
            if is_secure && is_debug_mode() && (
                   SSH_OK_RE.is_match(rest)
                || SSH_FAIL_RE.is_match(rest)
                || PAM_FAIL_RE.is_match(rest)
                || XINETD_RE.is_match(rest)
            ) {
                println!("    [DEBUG] secure skip no-year login-line: {}", line);
            }
            continue;
        }

        // ——— Structured syslog/journal (RFC5424) ———
        if line.starts_with('<') {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 7 {
                continue;
            }
            if let Ok(dt) = DateTime::parse_from_rfc3339(parts[1]) {
                let when = dt.with_timezone(&Utc).to_rfc3339();
                // slice out the " - -  ..." + message
                let msg = &line[line.find(" - - ").unwrap_or(0)..];

                // 1) xinetd “START: ssh” → SSH_CONNECT
                if let Some(cap) = XINETD_RE.captures(msg) {
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

                // 2) SSH success
                if let Some(cap) = SSH_OK_RE.captures(msg) {
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

                // 3) SSH failure
                if let Some(cap) = SSH_FAIL_RE.captures(msg) {
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
            println!("[INFO] CSV written to {}", p);
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
pub fn parse_linux(files: &[String], dirs: &[String], output: Option<&String>) {
    // 1) Build initial target list from explicit files and recursive dir walk
    let mut targets: Vec<PathBuf> = files.iter().map(PathBuf::from).collect();
    for root in dirs {
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            let p = entry.into_path();
            if !p.is_file() {
                continue;
            }
            let fname = p
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            if matches!(
                fname.as_str(),
                "utmp" | "wtmp" | "btmp" | "lastlog"
            ) || fname.starts_with("secure")
                || fname.starts_with("messages")
                || fname.starts_with("audit.log")
            {
                targets.push(p);
            }
        }
    }
    if targets.is_empty() {
        eprintln!("[WARN] no candidate logs found");
        return;
    }
    targets.sort();
    targets.dedup();
    if is_debug_mode() {
        println!("[DEBUG] {} candidate files", targets.len());
    }

    // 2) hostname cache
    let mut root2host: HashMap<PathBuf, String> = HashMap::new();

    // 3) Parse each file
    let mut collected = Vec::<RawEvt>::new();
    let mut stats_total = 0;
    let mut stats_kept = 0;
    for path in targets {
        // find root dir (upwards until "log" folder)
        let mut cur = path.parent().unwrap_or(Path::new("/"));
        while cur.parent().is_some() && cur.file_name() != Some(OsStr::new("log")) {
            cur = cur.parent().unwrap();
        }
        let root = cur.parent().unwrap_or(cur).to_path_buf();
        let dst_host = root2host
            .entry(root.clone())
            .or_insert_with(|| discover_hostname(&root))
            .clone();

        if is_debug_mode() {
            println!(
                "[DEBUG] scanning  {}\n        candidate root  {}",
                path.display(),
                root.display()
            );
        }

        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let fname = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        let mut parsed: Vec<RawEvt> = Vec::new();
        if ["utmp", "wtmp", "btmp", "lastlog"].contains(&fname.as_str()) {
            parsed = parse_utmp_file(&path, &dst_host, true);
        } else if fname.starts_with("secure") {
            parsed = parse_secure_or_messages(&path, &dst_host, true);
        } else if fname.starts_with("messages") {
            parsed = parse_secure_or_messages(&path, &dst_host, true);
        } else if fname.starts_with("audit.log") {
            parsed = parse_audit(&path, &dst_host, true);
        }

        stats_total += parsed.len();
        collected.extend(parsed.clone());
        stats_kept += parsed.len();

        if is_debug_mode() {
            let kept = parsed.len();
            println!(
                "        {:<8} total {:>5} kept {:>5}",
                fname.split('.').next().unwrap_or("log"),
                kept,
                kept
            );
        }
    }
    if is_debug_mode() {
        println!(
            "[DEBUG] SUMMARY  total {:>6}  kept {:>6}",
            stats_total, stats_kept
        );
    }

    build_dataframe(&collected, output);
}
