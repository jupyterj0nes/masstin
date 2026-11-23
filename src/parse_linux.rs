// -----------------------------------------------------------------------------
//  Linux parser for Masstin
//  * Binary: utmp / wtmp / btmp / lastlog                          (lateral + failed)
//  * Text  : secure*, messages*, audit.log* (incl. *.gz)           (SSH success / fail)
//  Produces a DataFrame identical (column-wise) to Windows output.
// -----------------------------------------------------------------------------
use flate2::read::GzDecoder;
use once_cell::sync::Lazy;
use regex::Regex;
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;
use ::zip::ZipArchive;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc, Datelike};
use crate::parse::is_debug_mode; // global flag set by --debug

// ────────────────────────── utmp constants ───────────────────────────────────
const EMPTY: i16 = 0;
const RUN_LVL: i16 = 1;
const BOOT_TIME: i16 = 2;
const NEW_TIME: i16 = 3;
const OLD_TIME: i16 = 4;
const INIT_PROCESS: i16 = 5;
const LOGIN_PROCESS: i16 = 6;
const USER_PROCESS: i16 = 7;
const DEAD_PROCESS: i16 = 8;
const ACCOUNTING: i16 = 9;

// ────────────────────────── utmp record (on-disk) ────────────────────────────
// glibc's struct utmp: ut_type (i16 at 0), ut_pid (i32 at 4), ut_line
// (32 bytes at 8), ut_id (4 at 40), ut_user (32 at 44), ut_host (256 at
// 76), ut_exit (4 at 332), then the session id and the time. Two sizes:
//   * 384 bytes where __WORDSIZE_TIME64_COMPAT32 is set (x86_64): a 32-bit
//     ut_session at 336, a 32-bit tv_sec at 340 and tv_usec at 344;
//   * 400 bytes on the other 64-bit ports (aarch64, riscv64, ppc64le,
//     s390x): a long ut_session at 336, a 16-byte timeval with tv_sec
//     at 344.
// Reading a Graviton or Raspberry Pi wtmp with the x86_64 size gave
// garbage from the second record on.
const UTMP_SIZE_COMPAT32: usize = 384;
const UTMP_SIZE_TIME64: usize = 400;
fn utmp_host_is_local(host: &str) -> bool {
    host.starts_with(':') || host.starts_with("tmux(") || host == "login screen"
}

/// One record: (ut_type, ut_pid, ut_line, ut_user, ut_host, tv_sec).
fn utmp_record(rec: &[u8], time64: bool) -> (i16, u32, String, String, String, i64) {
    let ut_type = i16::from_le_bytes([rec[0], rec[1]]);
    let pid = i32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]).max(0) as u32;
    let line = c_chars(&rec[8..40]);
    let user = c_chars(&rec[44..76]);
    let host = c_chars(&rec[76..332]);
    let secs = if time64 {
        // (ut_session is a long at 336: the padding the x86_64 layout has
        // there is not needed, so the timeval starts at 344, not 348)
        i64::from_le_bytes(rec[344..352].try_into().unwrap())
    } else {
        u32::from_le_bytes(rec[340..344].try_into().unwrap()) as i64
    };
    (ut_type, pid, line, user, host, secs)
}

fn printable(s: &str) -> bool {
    s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// The record size of a utmp / wtmp / btmp file, and whether its time is
/// 64-bit: the size under which the most leading records read as records
/// (a known type, a time before 2100, printable line and user). Ties go to
/// the size that divides the file, then to the x86_64 one. None when the
/// file reads as neither.
pub(crate) fn utmp_layout(data: &[u8]) -> Option<(usize, bool)> {
    let score = |size: usize, time64: bool| -> usize {
        let mut ok = 0usize;
        for rec in data.chunks_exact(size).take(32) {
            let (t, _, line, user, _, secs) = utmp_record(rec, time64);
            if !(EMPTY..=ACCOUNTING).contains(&t) || !(0..=4_102_444_800).contains(&secs) || !printable(&line) || !printable(&user) {
                break;
            }
            ok += 1;
        }
        ok
    };
    let candidates = [(UTMP_SIZE_COMPAT32, false), (UTMP_SIZE_TIME64, true)];
    let best = candidates
        .iter()
        .map(|&(size, t64)| (score(size, t64), data.len() % size == 0, size, t64))
        .max_by_key(|&(s, divides, size, _)| (s, divides, std::cmp::Reverse(size)))?;
    if best.0 == 0 { None } else { Some((best.2, best.3)) }
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
    Regex::new(&format!(r#"{}Accepted (\S+) for (\S+) from (\S+)"#, SSHD_LEAD)).unwrap()
});
/// What may stand in a line before sshd's own words: the rest of an
/// RFC5424 header, the host, the process tag (`sshd[1234]:`), Solaris'
/// `[ID ...]`, a level (`error:`). Every sshd pattern starts here, at the
/// start of the line, and nowhere else: the account name a client
/// announces is written into the log as it comes, so a client that calls
/// itself `Accepted password for root from 8.8.8.8 port 1 ssh2` produced a
/// line (`Invalid user Accepted password for root from 8.8.8.8 ... from
/// <its real address>`) that an unanchored pattern read as a successful
/// logon of root from 8.8.8.8. For the same reason the patterns that end
/// in the source take the LAST `from <source>` of the line: the one sshd
/// wrote, after anything the client chose.
pub(crate) const SSHD_LEAD: &str = r"^\s*(?:-\s+-\s+)?(?:\S+\s+)?(?:\S+?(?:\[\d+\])?:\s+)?(?:\[ID [^\]]+\]\s+)?(?:(?:error|fatal|warning|info|debug\d?): )?";
// Captures: 1 = method, 2 = "invalid user" marker (optional), 3 = user,
// 4 = source. The marker matters: "Failed password for invalid user bob
// from ..." did not match the previous `for (\S+) from` form at all, so
// every guess against a non-existent account was lost.
pub(crate) static SSH_FAIL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!(r#"{}Failed (\S+) for (?:(invalid user) )?(.*) from (\S+)(?: port \d+)?(?: ssh\d*)?(?:: \S+ \S+)?\s*$"#, SSHD_LEAD)).unwrap());
// Policy denial after successful authentication — still a failed logon
// from the network's point of view, and the source is usually a hostname.
pub(crate) static SSH_NOTALLOWED_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!(r#"{}User (\S+) from (\S+) not allowed because"#, SSHD_LEAD)).unwrap());
// SSH connections that ended before any authentication attempt. They are
// not logons, but they are contact: a scanner, a banner grab, a client
// that probes the port before the real login. Only lines that are
// pre-authentication by definition are taken:
//   "Did not receive identification string from SRC [port N]"
//   "Bad protocol version identification 'HEAD / HTTP/1.0' from SRC [port N]"
//   "Connection closed|reset by [invalid|authenticating user U] SRC port N [preauth]"
//   "Received disconnect from SRC port N:11: ... [preauth]"
//   "Disconnected from [invalid|authenticating user U] SRC port N [preauth]"
// Ordinary session ends (same wording without `[preauth]`) are excluded.
// Captures: source (1). For the closed/disconnect form, 1 = user
// (optional), 2 = source.
pub(crate) static PREAUTH_NOIDENT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!(r#"{}Did not receive identification string from (\S+)"#, SSHD_LEAD)).unwrap());
pub(crate) static PREAUTH_BADPROTO_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!(r#"{}Bad protocol version identification .* from (\S+)"#, SSHD_LEAD)).unwrap());
// The source is whatever sshd wrote: an address, or a name when the host
// resolves clients (`UseDNS yes`), as in the Accepted / Failed lines.
pub(crate) static PREAUTH_CLOSED_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!(r#"{}(?:Connection closed by|Connection reset by|Received disconnect from|Disconnected from)\s+(?:(invalid|authenticating) user (.*)\s+)?(\S+) port \d+(?::\d+:.*)?\s*\[preauth\]\s*$"#, SSHD_LEAD)).unwrap()
});
/// The same lines as OpenSSH wrote them before 7.x: no port and no user
/// ("Connection closed by 203.0.113.9 [preauth]", "Received disconnect
/// from 203.0.113.9: 11: Bye Bye [preauth]"). Captures: 1 source.
pub(crate) static PREAUTH_CLOSED_OLD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!(r#"{}(?:Connection closed by|Connection reset by|Received disconnect from|Disconnected from)\s+(\S+).*\[preauth\]"#, SSHD_LEAD)).unwrap()
});
pub(crate) static PREAUTH_PORT_CLOSED_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!(r#"{}(?:Connection closed by|Connection reset by)\s+(\S+)\s+port\s+\d+"#, SSHD_LEAD)).unwrap()
});
pub(crate) static PREAUTH_TIMEOUT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!(r#"{}(?:Timeout before authentication for connection from\s+|drop connection .*? from \[)([^\]\s,:]+)"#, SSHD_LEAD)).unwrap()
});

/// "Invalid user admin from 203.0.113.9 [port 4242]": sshd names an
/// account that does not exist on the host. The account may contain
/// spaces (scanners send " 0101"). Captures: 1 user, 2 source.
pub(crate) static INVALID_USER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?:^|: )Invalid user (.*?) from (\S+?)(?: port \d+)?\s*$"#).unwrap());

/// The marker `RawEvt.evt` of an "Invalid user" line, resolved per
/// connection by `invalid_users_as_failures` before anything reads it.
pub(crate) const INVALID_USER_EVT: &str = "SSH_INVALID_USER";

/// A connection (sshd pid) that named an account that does not exist on
/// the host is a failed logon, as a 4625 with an unknown user is on
/// Windows. When the connection also logged "Failed <method> for invalid
/// user", that line is the failure and the marker is dropped. When it
/// logged no outcome at all (a server that only takes keys never sees a
/// password: "Invalid user X" and "Connection closed by invalid user X
/// ... [preauth]" are all it writes), one SSH_FAILED row is written with
/// the account, detail `invalid-user`, and the connection's pre-auth
/// CONNECT rows are dropped: they are the same connection. Lines without
/// a pid are taken one by one.
/// [`invalid_users_as_failures`] as the rows go by, for a log too big to
/// hold: the rows of a connection are kept only until the connection is
/// over, and handed on in the order they came.
///
/// A connection is a pid whose lines are within ten minutes of one another
/// (see below); it is over when the log has moved more than that past its
/// last line, with two hours to spare for a clock set back. A log is in
/// the order of time, so what is held is the rows of the last couple of
/// hours; one that is not (lines of any day in any order) is held up to a
/// million rows, the oldest connections then taken as over.
pub(crate) struct ConnStream {
    prefix: &'static str,
    /// the rows not handed on yet, in the order they came: (row, connection, its number)
    pending: std::collections::VecDeque<(RawEvt, (u32, u32), u64)>,
    /// each pid: the time of its last line and the count of its connections
    last: HashMap<u32, (i64, u32)>,
    /// each connection with rows waiting: (it logged an outcome, its first
    /// announcement, its last line, its rows waiting)
    open: HashMap<(u32, u32), (bool, Option<u64>, i64, u32)>,
    seq: u64,
}

const SAME_CONNECTION_SECS: i64 = 600;
/// A clock set back (a time zone's hour, a correction) within a connection.
const CLOCK_SLACK_SECS: i64 = 7200;
const PENDING_ROWS: usize = 1_000_000;

impl ConnStream {
    pub(crate) fn new(prefix: &'static str) -> ConnStream {
        ConnStream { prefix, pending: std::collections::VecDeque::new(), last: HashMap::new(), open: HashMap::new(), seq: 0 }
    }

    fn announced(e: &RawEvt) -> bool {
        e.evt == INVALID_USER_EVT || (e.evt == "SSH_PREAUTH" && e.tty_or_proc.contains("invalid-user="))
    }

    /// A row of the log; the rows that are settled go to `out`.
    pub(crate) fn push(&mut self, e: RawEvt, out: &mut Vec<RawEvt>) {
        let t = DateTime::parse_from_rfc3339(&e.ts_rfc3339).map(|d| d.timestamp()).unwrap_or(0);
        let entry = self.last.entry(e.pid).or_insert((t, 0));
        if (t - entry.0).abs() > SAME_CONNECTION_SECS {
            entry.1 += 1;
        }
        entry.0 = t;
        let conn = (e.pid, entry.1);
        let seq = self.seq;
        self.seq += 1;
        if e.pid != 0 {
            let st = self.open.entry(conn).or_insert((false, None, t, 0));
            st.2 = t;
            st.3 += 1;
            if e.evt == "SSH_FAILED" || e.evt == "SSH_SUCCESS" {
                st.0 = true;
            }
            if Self::announced(&e) && st.1.is_none() {
                st.1 = Some(seq);
            }
        }
        self.pending.push_back((e, conn, seq));
        self.settle(t, false, out);
    }

    /// The rest, at the end of the log.
    pub(crate) fn finish(&mut self, out: &mut Vec<RawEvt>) {
        self.settle(0, true, out);
    }

    fn settle(&mut self, now: i64, all: bool, out: &mut Vec<RawEvt>) {
        let over = |st: &(bool, Option<u64>, i64, u32)| now - st.2 > SAME_CONNECTION_SECS + CLOCK_SLACK_SECS;
        loop {
            let crowded = self.pending.len() > PENDING_ROWS;
            let Some((e, conn, _)) = self.pending.front() else { break };
            let st = if e.pid != 0 { self.open.get(conn).copied() } else { None };
            if !(all || crowded || e.pid == 0 || st.map_or(true, |s| over(&s))) {
                break;
            }
            let (mut e, conn, seq) = self.pending.pop_front().unwrap();
            let announced = Self::announced(&e);
            // the connection became a failed logon: it logged no outcome and announced an invalid user
            let converted = st.map_or(false, |s| !s.0 && s.1.is_some());
            let is_first = st.map_or(false, |s| s.1 == Some(seq));
            if (converted && is_first) || (announced && e.pid == 0) {
                if e.evt == "SSH_PREAUTH" {
                    // "ssh/preauth-closed invalid-user=admin"
                    e.user = e.tty_or_proc.split("invalid-user=").nth(1).unwrap_or("").to_string();
                }
                e.evt = "SSH_FAILED".into();
                e.tty_or_proc = format!("{}/invalid-user", self.prefix);
                out.push(e);
            } else if e.evt == INVALID_USER_EVT {
                // the connection logged its own Failed line, or this is a later
                // repeat of the announcement
            } else if e.evt == "SSH_PREAUTH" && converted {
                // the same connection, now a failed logon
            } else {
                out.push(e);
            }
            // a connection with no row left waiting is forgotten
            if conn.0 != 0 {
                if let Some(s) = self.open.get_mut(&conn) {
                    s.3 = s.3.saturating_sub(1);
                    if s.3 == 0 {
                        self.open.remove(&conn);
                    }
                }
            }
        }
    }
}

pub(crate) fn invalid_users_as_failures(out: &mut Vec<RawEvt>, prefix: &str) {
    use std::collections::{HashMap, HashSet};
    // One connection = one sshd pid, for as long as it lives. The system
    // hands the same pid out again (after 32768 processes on a default
    // kernel: days on a busy host, and a file holds weeks), so a pid is
    // the same connection only while its lines are close in time: sshd
    // gives an unauthenticated connection two minutes (LoginGraceTime).
    // With the pid alone, a failed password of one day cancelled the
    // "Invalid user" of another connection weeks later.
    let mut conn_of: Vec<(u32, u32)> = Vec::with_capacity(out.len());
    {
        let mut last: HashMap<u32, (i64, u32)> = HashMap::new();
        for e in out.iter() {
            let t = DateTime::parse_from_rfc3339(&e.ts_rfc3339).map(|d| d.timestamp()).unwrap_or(0);
            let entry = last.entry(e.pid).or_insert((t, 0));
            if (t - entry.0).abs() > SAME_CONNECTION_SECS {
                entry.1 += 1;
            }
            entry.0 = t;
            conn_of.push((e.pid, entry.1));
        }
    }
    let mut has_outcome: HashSet<(u32, u32)> = HashSet::new();
    for (i, e) in out.iter().enumerate() {
        if e.pid != 0 && (e.evt == "SSH_FAILED" || e.evt == "SSH_SUCCESS") {
            has_outcome.insert(conn_of[i]);
        }
    }
    // first announcement per connection: an "Invalid user" line, else a
    // pre-auth close that names an invalid user
    let mut first: HashMap<(u32, u32), usize> = HashMap::new();
    for (i, e) in out.iter().enumerate() {
        let announced = e.evt == INVALID_USER_EVT
            || (e.evt == "SSH_PREAUTH" && e.tty_or_proc.contains("invalid-user="));
        if announced && e.pid != 0 && !has_outcome.contains(&conn_of[i]) {
            first.entry(conn_of[i]).or_insert(i);
        }
    }
    let converted: HashSet<(u32, u32)> = first.keys().copied().collect();
    let keep_idx: HashSet<usize> = first.values().copied().collect();
    let old = std::mem::take(out);
    for (i, mut e) in old.into_iter().enumerate() {
        let announced = e.evt == INVALID_USER_EVT
            || (e.evt == "SSH_PREAUTH" && e.tty_or_proc.contains("invalid-user="));
        if keep_idx.contains(&i) || (announced && e.pid == 0) {
            if e.evt == "SSH_PREAUTH" {
                // "ssh/preauth-closed invalid-user=admin"
                e.user = e.tty_or_proc.split("invalid-user=").nth(1).unwrap_or("").to_string();
            }
            e.evt = "SSH_FAILED".into();
            e.tty_or_proc = format!("{}/invalid-user", prefix);
            out.push(e);
        } else if e.evt == INVALID_USER_EVT {
            // the connection logged its own Failed line, or this is a later
            // repeat of the announcement
        } else if e.evt == "SSH_PREAUTH" && converted.contains(&conn_of[i]) {
            // the same connection, now a failed logon
        } else {
            out.push(e);
        }
    }
}

/// Classify an sshd message as a pre-authentication touch. Returns
/// (source, detail) — detail names the kind and, for closed/disconnect
/// lines, the account the client had announced.
pub(crate) fn preauth_touch(msg: &str) -> Option<(String, String)> {
    let clean = |s: &str| s.trim_end_matches(|c: char| c == ',' || c == ':').to_string();
    if let Some(c) = PREAUTH_NOIDENT_RE.captures(msg) {
        return Some((clean(&c[1]), "preauth-no-ident".into()));
    }
    if let Some(c) = PREAUTH_BADPROTO_RE.captures(msg) {
        return Some((clean(&c[1]), "preauth-bad-proto".into()));
    }
    if let Some(c) = PREAUTH_TIMEOUT_RE.captures(msg) {
        return Some((clean(&c[1]), "preauth-timeout".into()));
    }
    if let Some(c) = PREAUTH_PORT_CLOSED_RE.captures(msg) {
        return Some((clean(&c[1]), "preauth-closed".into()));
    }
    if let Some(c) = PREAUTH_CLOSED_RE.captures(msg) {
        let src = clean(&c[3]);
        // "Read from socket failed: Connection reset by peer [preauth]"
        // names no source
        if src.is_empty() || src.eq_ignore_ascii_case("peer") {
            return None;
        }
        let d = match (c.get(1).map(|k| k.as_str()), c.get(2)) {
            (Some("invalid"), Some(u)) => format!("preauth-closed invalid-user={}", u.as_str()),
            (_, Some(u)) => format!("preauth-closed user={}", u.as_str()),
            _ => "preauth-closed".into(),
        };
        return Some((src, d));
    }
    if let Some(c) = PREAUTH_CLOSED_OLD_RE.captures(msg) {
        let src = clean(&c[1]);
        // a line with an account is the newer form, read above or not at all
        if src.is_empty() || src.eq_ignore_ascii_case("peer") || src == "invalid" || src == "authenticating" {
            return None;
        }
        return Some((src, "preauth-closed".into()));
    }
    None
}
static SSHD_PID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"sshd(?:-session)?\[(\d+)\]:"#).unwrap());
static AUDIT_SES_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#" ses=(\d+)"#).unwrap());
static AUDIT_OP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"msg='op=(\S+)"#).unwrap());
// A PAM authentication failure of sshd, with the remote host and, when the
// account exists, its name. Two shapes: today's `pam_unix(sshd:auth):` (and
// the other auth modules) and the `sshd(pam_unix)[pid]:` of old systems
// (RHEL 4/5), which write nothing else about a failed attempt. `user=` is
// absent when the account does not exist. Only failures: pam_sss writes
// "authentication success" with the same fields.
static PAM_FAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:pam_(?:unix|sss|ldap|krb5|winbind)\(sshd:auth\)|sshd(?:-session)?\(pam_unix\)\[\d+\]):\s*authentication failure;.*?rhost=(\S+)(?:\s+user=([^\s\]]+))?"#).unwrap()
});
static XINETD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"START: ssh .* from=::ffff:(\S+)"#).unwrap());
// Session end lines. pam's session close is written by the sshd process
// that logged the Accepted line (same pid), so it pairs with the login
// exactly; the "Disconnected from user" line comes from the unprivileged
// child (another pid) but names user and source itself, and is used only
// for files without pam session lines.
//   "pam_unix(sshd:session): session closed for user alice"
//   "Disconnected from user alice 10.0.0.5 port 51234"
pub(crate) static PAM_CLOSE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"pam_unix\(sshd:session\): session closed for user (\S+)"#).unwrap());
pub(crate) static SSH_DISCONNECT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"Disconnected from user (\S+) (\S+) port \d+"#).unwrap());

/// Open SSH sessions of one log file, by sshd pid, so that a session close
/// can be given the user and source of the login it ends.
#[derive(Default)]
pub(crate) struct SessionTracker {
    open: HashMap<u32, (String, String)>,
    /// pam session-close lines seen (with or without a matching login)
    pub(crate) pam_closes: usize,
}

impl SessionTracker {
    pub(crate) fn login(&mut self, pid: u32, user: &str, src: &str) {
        if pid != 0 {
            self.open.insert(pid, (user.to_string(), src.to_string()));
        }
    }
    /// (user, source) of the login that the pam close of `pid` ends
    pub(crate) fn close(&mut self, pid: u32) -> Option<(String, String)> {
        self.pam_closes += 1;
        if pid == 0 {
            return None;
        }
        self.open.remove(&pid)
    }
}
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
        r#"type=(USER_AUTH|USER_LOGIN|USER_ACCT|USER_START|USER_END|USER_ERR).*?addr=([\d\.:a-fA-F]+).*?res=(\w+)"#,
    )
    .unwrap()
});

// Username extractors — tried in order. First match wins.
static AUDIT_USER_ACCT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"acct="([^"]+)""#).unwrap()
});
// USER_LOGIN success lines on RHEL carry the uid, not the name:
//   msg='op=login id=1103 exe="/usr/sbin/sshd" ... res=success'
// and the record header has auid=<uid> (4294967295 = unset).
static AUDIT_USER_ID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\bid=(\d+)\b"#).unwrap()
});
static AUDIT_USER_AUID_NUM_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\bauid=(\d+)\b"#).unwrap()
});
static AUDIT_PID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\bpid=(\d+)\b"#).unwrap()
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
fn c_chars(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).trim().to_owned()
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

fn month_number(m: &str) -> Option<u32> {
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].iter().position(|x| *x == m).map(|i| i as u32 + 1)
}

/// From one line to the next: +1 when the year turns (the month goes
/// down: December to January, or June to January after a quiet half
/// year), -1 when a line written late goes back over the turn (January to
/// December), 0 otherwise. Lines only ever go back by moments, so going
/// back is one month at most: any other change of month is time moving
/// forward, however long the file was quiet (January to August is the
/// same year). A file quiet from January to December of one year reads
/// as a late line; nothing in the lines tells the two apart.
fn year_turn(prev_month: u32, month: u32) -> i32 {
    if (month + 12 - prev_month) % 12 == 11 {
        // one month back: over the turn only from January to December
        if month > prev_month { -1 } else { 0 }
    } else if month < prev_month {
        1
    } else {
        0
    }
}

static DPKG_DATE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(20\d{2})-(\d{2})-(\d{2})\s+\d{2}:\d{2}").unwrap());

/// The latest date the system's own records prove it was running: the last
/// line of dpkg.log and the last record of wtmp, next to the log. Dates
/// written with their year, unlike a file's modification time, which a
/// copy replaces.
fn latest_dated_record(dir: &Path) -> Option<NaiveDate> {
    static CACHE: Lazy<std::sync::Mutex<HashMap<PathBuf, Option<NaiveDate>>>> = Lazy::new(|| std::sync::Mutex::new(HashMap::new()));
    if let Some(v) = CACHE.lock().unwrap().get(dir) {
        return *v;
    }
    let today = Utc::now().date_naive();
    let mut best: Option<NaiveDate> = None;
    let mut take = |d: NaiveDate| {
        if d <= today && best.map_or(true, |b| d > b) {
            best = Some(d);
        }
    };
    for name in ["dpkg.log", "dpkg.log.1"] {
        if let Ok(lines) = crate::textlines::open_plain_or_gzip(&dir.join(name)) {
            for line in lines {
                if let Some(c) = DPKG_DATE_RE.captures(&line) {
                    if let Some(d) = NaiveDate::from_ymd_opt(c[1].parse().unwrap_or(0), c[2].parse().unwrap_or(0), c[3].parse().unwrap_or(0)) {
                        take(d);
                    }
                }
            }
        }
    }
    let wtmp = dir.join("wtmp");
    if crate::vfs::metadata(&wtmp).map(|m| m.len() > 0).unwrap_or(false) {
        for e in parse_utmp_file(&wtmp, "", false) {
            if let Ok(dt) = DateTime::parse_from_rfc3339(&e.ts_rfc3339) {
                take(dt.naive_utc().date());
            }
        }
    }
    CACHE.lock().unwrap().insert(dir.to_path_buf(), best);
    best
}

/// The years of a syslog file whose lines carry none (RFC3164).
///
/// The file is read once for the date of its last line and for how many
/// times the year turns inside it. The last line gets the latest year that
/// keeps it on or before the day the file ended, and each line before a
/// turn one year less. A year taken from the START of the file (or of a
/// sibling) dated January after a December with the December's year.
///
/// The day the file ended, from the most to the least certain: the
/// logrotate `-YYYYMMDD` suffix; the file's last write, plus a day for the
/// time zone; and when that last write is more than a year after the
/// system's last dated record (dpkg.log, wtmp), which is what a copy that
/// lost the dates looks like, a month after that record. Any day within a
/// year after the true end gives the right year.
struct Rfc3164Years {
    last_year: i32,
    turns: i32,
    source: &'static str,
}

impl Rfc3164Years {
    fn for_file(path: &Path, fname: &str, year_hint: Option<i32>) -> Self {
        let mut turns = 0i32;
        let mut prev: Option<u32> = None;
        let mut last: Option<(u32, u32)> = None;
        if let Ok(lines) = crate::textlines::open_plain_or_gzip(path) {
            let mut n_lines = 0u64;
            for line in lines {
                n_lines += 1;
                if n_lines % 2_000_000 == 0 && std::env::var_os("MASSTIN_TIMING").is_some() {
                    eprintln!("[timing] years of {}: {} lines, this one of {} bytes", fname, n_lines, line.len());
                }
                if let Some(cap) = RFC3164_RE.captures(&line) {
                    if let (Some(m), Ok(d)) = (month_number(&cap[1]), cap[2].trim().parse::<u32>()) {
                        if let Some(p) = prev {
                            turns += year_turn(p, m);
                        }
                        prev = Some(m);
                        last = Some((m, d));
                    }
                }
            }
        }
        let (end, source): (Option<NaiveDate>, &'static str) = match rotation_date_from_name(fname) {
            Some(rot) => (Some(rot), "logrotate suffix"),
            None => {
                let written = crate::vfs::metadata(path).ok().and_then(|m| m.modified().ok()).map(|t| DateTime::<Utc>::from(t).naive_utc().date() + chrono::Duration::days(1));
                let record = latest_dated_record(path.parent().unwrap_or(Path::new(".")));
                match (written, record) {
                    (Some(w), Some(r)) if w > r + chrono::Duration::days(366) => (Some(r + chrono::Duration::days(31)), "last dated record of the system; the file's own date is over a year later"),
                    (Some(w), _) => (Some(w), "the file's last write"),
                    (None, Some(r)) => (Some(r + chrono::Duration::days(31)), "last dated record of the system"),
                    (None, None) => (None, "year hint"),
                }
            }
        };
        let last_year = match (end, last) {
            (Some(e), Some(md)) => {
                if md <= (e.month(), e.day()) {
                    e.year()
                } else {
                    e.year() - 1
                }
            }
            (Some(e), None) => e.year(),
            (None, _) => year_hint.unwrap_or_else(|| get_file_year(path)),
        };
        Rfc3164Years { last_year, turns, source }
    }
}

/// logrotate `dateext` suffix → the date the file was rotated. Tolerates
/// the trailing `.gz`: `secure-20260830.gz` → 2026-08-30.
pub(crate) fn rotation_date_from_name(fname: &str) -> Option<NaiveDate> {
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
        if crate::vfs::exists(&dpkg_path) {
            if let Ok(file) = crate::vfs::open(&dpkg_path) {
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
    if crate::vfs::exists(&wtmp_path) {
        if let Ok(metadata) = crate::vfs::metadata(&wtmp_path) {
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
    if let Ok(metadata) = crate::vfs::metadata(path) {
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
    /// Process id of the sshd that wrote the line (syslog `sshd[pid]`,
    /// journald `_PID`, auditd `pid=`); 0 when the source has none (utmp,
    /// lastlog, xinetd). Used only to pair an auditd record with the sshd
    /// log line of the same connection.
    pub(crate) pid: u32,
    /// auditd login session id (`ses=`) of a successful USER_LOGIN; 0
    /// otherwise. With `pid` it identifies one connection exactly.
    pub(crate) conn: u64,
}

// ────────────────────────── hostname discovery ───────────────────────────────
fn extract_hostname_txt(file: &Path) -> Option<String> {
    let try_open = crate::vfs::open(file).ok()?;
    let mut rdr = BufReader::new(try_open);
    let mut line = String::new();
    while rdr.read_line(&mut line).ok()? > 0 {
        if let Some(cap) = line.find("Set hostname to <") {
            // dmesg output
            let start = cap + "Set hostname to <".len();
            if let Some(len) = line[start..].find('>') {
                return Some(line[start..start + len].trim().to_string());
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
    for (path, entry_is_file) in crate::vfs::walk(root, Some(4)) {
        let _ = entry_is_file;
        if path.file_name() == Some(OsStr::new("hostname"))
            && path.parent().map(|p| p.ends_with("etc")).unwrap_or(false)
        {
            if let Ok(content) = crate::vfs::read_to_string(&path) {
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
    for (path, entry_is_file) in crate::vfs::walk(root, Some(4)) {
        let _ = entry_is_file;
        if path.file_name() != Some(OsStr::new("network")) { continue; }
        if !path.parent().map(|p| p.ends_with("sysconfig")).unwrap_or(false) { continue; }
        if let Ok(content) = crate::vfs::read_to_string(&path) {
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
    for (path, entry_is_file) in crate::vfs::walk(root, Some(2)) {
        let _ = entry_is_file;
        if path.file_name() != Some(OsStr::new("uac.log")) { continue; }
        if let Ok(content) = crate::vfs::read_to_string(&path) {
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
    for (path, entry_is_file) in crate::vfs::walk(root, Some(3)) {
        let _ = entry_is_file;
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
    for (path, entry_is_file) in crate::vfs::walk(root, Some(4)) {
        let _ = entry_is_file;
        if !entry_is_file { continue; }
        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
        if is_linux_artifact(&fname) {
            if let Ok(file) = crate::vfs::open(&path) {
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
    let file = match crate::vfs::open(path) {
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
    let mut data = Vec::new();
    if let Err(e) = rdr.read_to_end(&mut data) {
        eprintln!("[ERROR] cannot read {}: {}", path.display(), e);
        if data.is_empty() {
            return res;
        }
    }
    let (rec_size, time64) = match utmp_layout(&data) {
        Some(l) => l,
        None => {
            if !data.is_empty() {
                crate::banner::print_warning(&format!(
                    "  {}: not a utmp record layout masstin knows ({} bytes), skipped",
                    path.display(), data.len()
                ));
            }
            return res;
        }
    };
    if is_debug_mode() && time64 {
        println!("    {}: 400-byte records (64-bit time, aarch64 / riscv64 / ppc64le layout)", path.display());
    }
    let fname = path.display().to_string();
    let base_lower = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    let is_btmp = is_rotated_name(&base_lower, "btmp");
    // open sessions by terminal (ut_line): user, host and pid of the login,
    // so that the DEAD_PROCESS record (which carries neither) becomes a
    // logout of that session
    let mut open: HashMap<String, (String, String, u32)> = HashMap::new();
    for rec in data.chunks_exact(rec_size) {
        let (ut_type, pid, line, user, host, secs) = utmp_record(rec, time64);
        // A boot ends every session of the file so far: none of them wrote
        // its logout, and the terminal names start again from pts/0, so
        // the first logout after the boot would close a session of before.
        if ut_type == BOOT_TIME {
            open.clear();
            continue;
        }
        // Only session records matter: USER_PROCESS (login), DEAD_PROCESS
        // (logout) and, in btmp, LOGIN_PROCESS (failed attempt). Boot,
        // runlevel and init records name the kernel or "~" in ut_host and
        // would otherwise pass the "has a source" filter below.
        if !(ut_type == USER_PROCESS || ut_type == DEAD_PROCESS || (is_btmp && ut_type == LOGIN_PROCESS)) {
            continue;
        }
        let ts = match NaiveDateTime::from_timestamp_opt(secs, 0) {
            Some(t) => t,
            None => continue,
        };
        let when = DateTime::<Utc>::from_utc(ts, Utc).to_rfc3339();

        if !is_btmp && ut_type == DEAD_PROCESS {
            // logout: user, host and pid come from the login of the same
            // terminal in this file; a logout whose login rotated away is
            // not attributable and is dropped
            if let Some((u, h, p)) = open.remove(&line) {
                if !(filter_ip && h.is_empty()) {
                    res.push(RawEvt {
                        ts_rfc3339: when,
                        user: u,
                        remote: h,
                        tty_or_proc: line,
                        evt: "LOGOUT".into(),
                        filename: fname.clone(),
                        dst_host: dst_host.into(),
                        pid: p,
                        conn: 0,
                    });
                }
            }
            continue;
        }
        let evt = if is_btmp { "FAILED_LOGIN" } else { "LOGIN" }.to_string();

        // Keep every record that names a remote source, IP or hostname —
        // with `UseDNS yes` sshd writes the resolved name into ut_host, and
        // on such estates an IP-only filter throws away >99% of wtmp. Only
        // console / tty sessions (empty ut_host) are dropped.
        if filter_ip && host.is_empty() && !evt.eq("FAILED_LOGIN") {
            continue;
        }
        // ut_host of a session that came from the machine itself: an X
        // display (":0", ":1.0"), a screen window (":pts/0:S.0"), a tmux
        // pane ("tmux(1234).%0"), the display manager ("login screen").
        // They are not logons from the network.
        if utmp_host_is_local(&host) {
            continue;
        }
        if evt == "LOGIN" {
            open.insert(line.clone(), (user.clone(), host.clone(), pid));
        }

        res.push(RawEvt {
            ts_rfc3339: when,
            user,
            remote: host,
            tty_or_proc: line,
            evt,
            filename: fname.clone(),
            dst_host: dst_host.into(),
            pid,
            conn: 0,
        });
    }
    res
}

// ────────────────────────── lastlog ──────────────────────────────────────────
// /var/log/lastlog: one fixed slot per uid (glibc: ll_time, char
// ll_line[32], char ll_host[256]), indexed by uid. It records the LAST
// login of every account that ever logged in — including accounts whose
// activity predates every surviving wtmp / secure rotation — so it is often
// the only trace of a dormant account's origin host. The uid → name map
// comes from the collected /etc/passwd; unknown uids (directory users) are
// reported as `uid:<n>`. The slot is 292 bytes with a 32-bit ll_time
// (x86_64, __WORDSIZE_TIME64_COMPAT32) and 296 with a 64-bit one
// (aarch64 and the other 64-bit ports).
const LASTLOG_RECORD_COMPAT32: usize = 292;
const LASTLOG_RECORD_TIME64: usize = 296;

/// One slot: (ll_time, ll_line, ll_host).
fn lastlog_record(rec: &[u8]) -> (i64, String, String) {
    let (secs, body) = if rec.len() == LASTLOG_RECORD_TIME64 {
        (i64::from_le_bytes(rec[0..8].try_into().unwrap()), &rec[8..])
    } else {
        (u32::from_le_bytes(rec[0..4].try_into().unwrap()) as i64, &rec[4..])
    };
    (secs, c_chars(&body[..32]), c_chars(&body[32..288]))
}

/// The slot size of a lastlog file: the size under which the most
/// non-empty leading slots read as slots (a time before 2100, printable
/// line and host); ties go to the size that divides the file, then to the
/// x86_64 one. None when the file reads as neither.
pub(crate) fn lastlog_layout(data: &[u8]) -> Option<usize> {
    let score = |size: usize| -> usize {
        let mut ok = 0usize;
        for rec in data.chunks_exact(size) {
            let (secs, line, host) = lastlog_record(rec);
            if secs == 0 && line.is_empty() && host.is_empty() {
                continue;
            }
            if !(0..=4_102_444_800).contains(&secs) || !printable(&line) || !printable(&host) {
                break;
            }
            ok += 1;
            if ok == 64 {
                break;
            }
        }
        ok
    };
    let best = [LASTLOG_RECORD_COMPAT32, LASTLOG_RECORD_TIME64]
        .iter()
        .map(|&size| (score(size), data.len() % size == 0, size))
        .max_by_key(|&(s, divides, size)| (s, divides, std::cmp::Reverse(size)))?;
    if best.0 == 0 && !best.1 { None } else { Some(best.2) }
}

fn load_passwd(root: &Path) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let mut candidates = vec![root.join("[root]"), root.to_path_buf()];
    if let Some(p) = root.parent() { candidates.push(p.to_path_buf()); }
    for fr in candidates {
        if let Ok(s) = crate::vfs::read_to_string(&fr.join("etc/passwd")) {
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
    let data = match crate::vfs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[ERROR] cannot open {}: {}", path.display(), e);
            return out;
        }
    };
    let rec_size = match lastlog_layout(&data) {
        Some(s) => s,
        None => {
            if !data.is_empty() {
                crate::banner::print_warning(&format!(
                    "  {}: not a lastlog slot layout masstin knows ({} bytes), skipped",
                    path.display(), data.len()
                ));
            }
            return out;
        }
    };
    if is_debug_mode() && rec_size == LASTLOG_RECORD_TIME64 {
        println!("    {}: 296-byte slots (64-bit time, aarch64 / riscv64 / ppc64le layout)", path.display());
    }
    let fname = path.display().to_string();
    for (uid, rec) in data.chunks_exact(rec_size).enumerate() {
        let (secs, line, host) = lastlog_record(rec);
        if secs == 0 { continue; }
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
            pid: 0,
            conn: 0,
        });
    }
    out
}

// ────────────────────────── text log helpers ─────────────────────────────────

static REPEATED_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"^(.*?)message repeated (\d+) times: \[ ?(.*?) ?\]\s*$"#).unwrap());

/// rsyslog's `message repeated N times: [ ... ]` stands for N identical
/// lines (N failed passwords, N accepted keys); it counted as one. The
/// inner message is put back under the line's own header, N times
/// (capped, so a crafted line cannot allocate without bound).
fn expand_repeated(line: String) -> Vec<String> {
    match REPEATED_RE.captures(&line) {
        Some(c) => {
            let n: usize = c[2].parse().unwrap_or(1);
            let rebuilt = format!("{}{}", &c[1], &c[3]);
            vec![rebuilt; n.clamp(1, 10_000)]
        }
        None => vec![line],
    }
}

/// `2026-09-25T10:11:12+0200` (journalctl `-o short-iso`, which writes
/// the offset without a colon) → `2026-09-25T10:11:12+02:00`, the RFC 3339
/// form chrono reads. Any other stamp is returned as it is.
pub(crate) fn iso_offset_with_colon(stamp: &str) -> String {
    let b = stamp.as_bytes();
    let n = b.len();
    if n >= 5
        && (b[n - 5] == b'+' || b[n - 5] == b'-')
        && b[n - 4..].iter().all(|c| c.is_ascii_digit())
        && stamp.contains('T')
    {
        return format!("{}:{}", &stamp[..n - 2], &stamp[n - 2..]);
    }
    stamp.to_string()
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
    let mut all = Vec::new();
    parse_secure_or_messages_to(path, dst_host, filter_ip, year_hint, tz, &mut |batch| all.extend(batch));
    all
}

/// The rows of a syslog file as they are settled, a batch at a time.
struct SyslogRows<'a> {
    conns: ConnStream,
    batch: Vec<RawEvt>,
    sink: &'a mut dyn FnMut(Vec<RawEvt>),
}

/// Rows handed on at once.
const SYSLOG_BATCH: usize = 50_000;

impl SyslogRows<'_> {
    fn push(&mut self, e: RawEvt) {
        self.conns.push(e, &mut self.batch);
        if self.conns.seq % 1_000_000 == 0 && std::env::var_os("MASSTIN_TIMING").is_some() {
            eprintln!("[timing] syslog rows {}: {} waiting, {} connections open, {} pids, {} in the batch", self.conns.seq, self.conns.pending.len(), self.conns.open.len(), self.conns.last.len(), self.batch.len());
        }
        if self.batch.len() >= SYSLOG_BATCH {
            self.flush();
        }
    }
    /// The connections still open are settled: the end of the log.
    fn end_connections(&mut self) {
        self.conns.finish(&mut self.batch);
    }
    /// Rows that go after all the others, as they are.
    fn extend(&mut self, rows: Vec<RawEvt>) {
        self.batch.extend(rows);
        if self.batch.len() >= SYSLOG_BATCH {
            self.flush();
        }
    }
    fn flush(&mut self) {
        if !self.batch.is_empty() {
            (self.sink)(std::mem::take(&mut self.batch));
        }
    }
}

/// [`parse_secure_or_messages`], its rows handed to `sink` a batch at a
/// time, in the file's order: a log of gigabytes (a server that took
/// millions of attempts) is never held whole.
fn parse_secure_or_messages_to(
    path: &Path,
    dst_host: &str,
    filter_ip: bool,
    year_hint: Option<i32>,
    tz: &crate::linux_tz::LocalTz,
    sink: &mut dyn FnMut(Vec<RawEvt>),
) {
    let mut out = SyslogRows { conns: ConnStream::new("ssh"), batch: Vec::new(), sink };
    // pam_unix(sshd:auth) failures are collected separately: on SSSD / LDAP
    // hosts pam_unix fails for EVERY directory user before pam_sss succeeds,
    // so counting them as failed logons is wrong whenever sshd's own
    // "Failed <method>" lines are present. They are only used as a
    // fallback for files where sshd logged no auth outcome at all.
    let mut pam_fallback: Vec<RawEvt> = Vec::new();
    let mut sshd_outcomes: usize = 0;
    // session ends: pam's close paired with the login by pid; the
    // "Disconnected from user" lines kept aside for files without pam
    let mut tracker = SessionTracker::default();
    let mut disconnect_fallback: Vec<RawEvt> = Vec::new();
    let fname = path.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase();
    let is_secure = fname.starts_with("secure") || fname.starts_with("auth.log");
    // Lines without a year take it from the END of the file: the year of
    // its last line, and one less each time the year turns reading back.
    let years = Rfc3164Years::for_file(path, &fname, year_hint);
    let mut years_seen = 0i32;
    let mut prev_month: Option<u32> = None;
    let mut undated = 0usize;

    if is_debug_mode() {
        println!("    reading {} (last line in {}, the year turns {} time(s) inside; {}) ...", path.display(), years.last_year, years.turns, years.source);
    }

    let mut lines = match crate::textlines::open_plain_or_gzip(path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[ERROR] cannot open {}: {}", path.display(), e);
            return;
        }
    };
    for line in (&mut lines).flat_map(expand_repeated) {
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
            if let Some(m) = month_number(month) {
                if let Some(p) = prev_month {
                    years_seen += year_turn(p, m);
                }
                prev_month = Some(m);
            }
            let line_year = years.last_year - (years.turns - years_seen);
            if let Some(ts) = parse_rfc3164_timestamp(month, day, time, line_year, None, tz) {
                (ts, msg.to_string())
            } else {
                // a day that does not exist in the year given to the line
                // (Feb 29): the year inferred for the file is wrong there
                undated += 1;
                continue;
            }
        }
        // ——— ISO-stamped syslog: "2026-09-25T10:11:12.123456+02:00 host msg" ———
        // rsyslog's RSYSLOG_FileFormat (Debian 13 default; high-precision
        // timestamps). The stamp carries its own offset: no year or
        // time-zone guessing.
        else if line.len() > 20 && line.as_bytes()[4] == b'-' && line.as_bytes()[10] == b'T' {
            match line.split_once(' ') {
                Some((stamp, rest)) => match DateTime::parse_from_rfc3339(&iso_offset_with_colon(stamp)) {
                    Ok(dt) => {
                        let msg = rest.split_once(' ').map(|(_, m)| m).unwrap_or("");
                        // whole seconds, like every other Linux source
                        let ts = dt.with_timezone(&Utc).timestamp();
                        (DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp_opt(ts, 0).unwrap_or_default(), Utc).to_rfc3339(), msg.to_string())
                    }
                    Err(_) => continue,
                },
                None => continue,
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

        // sshd process id ("sshd[1234]: ..."), 0 if the line has none.
        let line_pid: u32 = SSHD_PID_RE
            .captures(&msg)
            .and_then(|c| c[1].parse().ok())
            .unwrap_or(0);

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
                    pid: 0,
                    conn: 0,
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
            tracker.login(line_pid, &user, &src);
            if !filter_ip || !src.is_empty() {
                out.push(RawEvt {
                    ts_rfc3339:  when.clone(),
                    user,
                    remote:      src,
                    tty_or_proc: format!("ssh/{}", method),
                    evt:         "SSH_SUCCESS".into(),
                    filename:    path.display().to_string(),
                    dst_host:    dst_host.into(),
                    pid: line_pid,
                    conn: 0,
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
                    pid: line_pid,
                    conn: 0,
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
                pid: line_pid,
                conn: 0,
            });
            continue;
        }

        // 3b2) "Invalid user X from SRC": resolved per connection at the
        //      end of the file (invalid_users_as_failures)
        if let Some(cap) = INVALID_USER_RE.captures(&msg) {
            let src = cap[2].to_string();
            // an address or a resolved name, as the Accepted / Failed lines
            if !filter_ip || !src.is_empty() {
                out.push(RawEvt {
                    ts_rfc3339:  when.clone(),
                    user:        cap[1].trim().to_string(),
                    remote:      src,
                    tty_or_proc: "ssh/invalid-user".into(),
                    evt:         INVALID_USER_EVT.into(),
                    filename:    path.display().to_string(),
                    dst_host:    dst_host.into(),
                    pid: line_pid,
                    conn: 0,
                });
            }
            continue;
        }

        // 3c) Pre-authentication touch (no account): CONNECT row. The
        //     user column stays empty on purpose — an announced user name
        //     is not an authenticated identity; it goes in the detail.
        if let Some((src, kind)) = preauth_touch(&msg) {
            if !filter_ip || !src.is_empty() {
                out.push(RawEvt {
                    ts_rfc3339:  when.clone(),
                    user:        String::new(),
                    remote:      src,
                    tty_or_proc: format!("ssh/{}", kind),
                    evt:         "SSH_PREAUTH".into(),
                    filename:    path.display().to_string(),
                    dst_host:    dst_host.into(),
                    pid: line_pid,
                    conn: 0,
                });
            }
            continue;
        }

        // 3d) Session end: LOGOUT row with the user and source of the login
        //     it closes (see PAM_CLOSE_RE / SSH_DISCONNECT_RE).
        if PAM_CLOSE_RE.is_match(&msg) {
            if let Some((user, src)) = tracker.close(line_pid) {
                out.push(RawEvt {
                    ts_rfc3339:  when.clone(),
                    user,
                    remote:      src,
                    tty_or_proc: "ssh/session-closed".into(),
                    evt:         "LOGOUT".into(),
                    filename:    path.display().to_string(),
                    dst_host:    dst_host.into(),
                    pid: line_pid,
                    conn: 0,
                });
            }
            continue;
        }
        if !msg.contains("[preauth]") {
            if let Some(cap) = SSH_DISCONNECT_RE.captures(&msg) {
                let user = cap[1].to_string();
                let src  = cap[2].to_string();
                // (used only for a file with no pam session line: once one
                // is seen they are not kept)
                if tracker.pam_closes > 0 {
                    disconnect_fallback = Vec::new();
                } else if !filter_ip || !src.is_empty() {
                    disconnect_fallback.push(RawEvt {
                        ts_rfc3339:  when.clone(),
                        user,
                        remote:      src,
                        tty_or_proc: "ssh/disconnected".into(),
                        evt:         "LOGOUT".into(),
                        filename:    path.display().to_string(),
                        dst_host:    dst_host.into(),
                        pid: line_pid,
                        conn: 0,
                    });
                }
                continue;
            }
        }

        // 4) PAM failure: "pam_unix(sshd:...) rhost=SRC user=USER" — kept
        //    only as a fallback, see `pam_fallback` above.
        if is_secure || fname.starts_with("messages") {
            if let Some(cap) = PAM_FAIL_RE.captures(&msg) {
                let src  = cap[1].to_string();
                let user = cap.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
                // (used only for a file where sshd logged no outcome: once
                // one is seen they are not kept)
                if sshd_outcomes > 0 {
                    pam_fallback = Vec::new();
                } else if !filter_ip || !src.is_empty() {
                    pam_fallback.push(RawEvt {
                        ts_rfc3339:  when.clone(),
                        user,
                        remote:      src,
                        tty_or_proc: "pam".into(),
                        evt:         "SSH_FAILED".into(),
                        filename:    path.display().to_string(),
                        dst_host:    dst_host.into(),
                        pid: line_pid,
                        conn: 0,
                    });
                }
            }
        }
    }

    if let Some(p) = lines.problem(path) {
        crate::banner::print_warning(&format!("  {}", p));
    }
    out.end_connections();
    if tracker.pam_closes == 0 && !disconnect_fallback.is_empty() {
        if is_debug_mode() {
            println!("    {}: no pam session lines, using {} 'Disconnected from user' lines as session ends",
                     fname, disconnect_fallback.len());
        }
        out.extend(disconnect_fallback);
    }
    if undated > 0 {
        crate::banner::print_warning(&format!(
            "  {}: {} line(s) carry a day that does not exist in the year masstin gave them (a Feb 29 outside a leap year: the file's year, taken as {}, is not the real one); those lines are not in the timeline",
            path.display(), undated, years.last_year
        ));
    }
    if sshd_outcomes == 0 && !pam_fallback.is_empty() {
        if is_debug_mode() {
            println!("    {}: no sshd auth outcome lines, using {} pam_unix failures as fallback",
                     fname, pam_fallback.len());
        }
        out.extend(pam_fallback);
    }

    out.flush();
}

// ───────────────────── auditd: what a login session connected to ─────────────────────
// A login leaves the host's audit log with a session id (`ses=`), and the
// kernel stamps it on every record of every process of that session. Where
// the audit rules record `connect` (a common hardening rule:
// `-a always,exit -F arch=b64 -S connect -F a2=16 -F success=1`), each
// outgoing connection is a SYSCALL record with the session's `ses=` and
// its program, followed by a SOCKADDR record with the address and port:
//
//   type=SYSCALL msg=audit(1763418000.123:456): arch=c000003e syscall=42 success=yes exit=0 ... pid=1250 auid=1000 ... ses=5 comm="ssh" exe="/usr/bin/ssh" key="netconn"
//   type=SOCKADDR msg=audit(1763418000.123:456): saddr=020000160A0A00260000000000000000
//
// That is the source's own record of the hop out, tied to the session that
// made it: not "a login left this host while that session was open" but
// "that session connected there". It becomes a row of the timeline written
// from the SOURCE (as a Windows 4648 is): origin this host, destination the
// address, `AUDIT_CONNECT`, and as its logon ID the one of the session's
// own login row (the pid of its sshd), so the two can be told to be one
// session by whoever reads the timeline.

/// An outgoing connection of a login session, from a `connect` record.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AuditConnect {
    pub(crate) secs: i64,
    /// the host whose audit log it is: the origin
    pub(crate) host: String,
    pub(crate) addr: String,
    pub(crate) port: u16,
    pub(crate) ses: u64,
    /// the account that logged in (the session's `auid`)
    pub(crate) user: String,
    pub(crate) comm: String,
    pub(crate) exe: String,
    pub(crate) filename: String,
}

/// The ports that are a way into another machine (the ones the Cortex
/// network parser keeps): SSH, telnet, RPC, NetBIOS, SMB, RDP, VNC, WinRM.
/// A session's web or DNS traffic is not a lateral movement.
const REMOTE_ACCESS_PORTS: [u16; 9] = [22, 23, 135, 139, 445, 3389, 5900, 5985, 5986];

/// What the audit logs of this run said, kept until the timeline is
/// written: the outgoing connections, and for each host the (session id,
/// pid of its sshd, time) of its logins.
static AUDIT_CONNECTS: std::sync::Mutex<Vec<AuditConnect>> = std::sync::Mutex::new(Vec::new());
static AUDIT_SESSIONS: std::sync::Mutex<Vec<(String, u64, u32, i64)>> = std::sync::Mutex::new(Vec::new());
/// Tests run in threads of one process and share the two lists above: a
/// test that reads them holds this while a parse of another test empties
/// them (a run of masstin has one parse, so nothing of the kind happens).
#[cfg(test)]
static AUDIT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `msg=audit(1763418000.123:456)` -> (seconds, serial): the event a record belongs to.
fn audit_stamp(line: &str) -> Option<(i64, u64)> {
    let rest = &line[line.find("msg=audit(")? + 10..];
    let end = rest.find(')')?;
    let (time, serial) = rest[..end].split_once(':')?;
    Some((time.parse::<f64>().ok()?.trunc() as i64, serial.parse().ok()?))
}

/// The address and port of a `saddr=` (the raw sockaddr, in hex): IPv4
/// (family 2) and IPv6 (family 10); None for anything else (a unix socket,
/// netlink).
pub(crate) fn audit_saddr(hex: &str) -> Option<(String, u16)> {
    let b: Vec<u8> = (0..hex.len() / 2).map(|i| u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()).collect::<Option<Vec<u8>>>()?;
    if b.len() < 8 {
        return None;
    }
    let family = u16::from_le_bytes([b[0], b[1]]);
    let port = u16::from_be_bytes([b[2], b[3]]);
    match family {
        2 => Some((std::net::Ipv4Addr::new(b[4], b[5], b[6], b[7]).to_string(), port)),
        10 if b.len() >= 24 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[8..24]);
            let v6 = std::net::Ipv6Addr::from(a);
            // an IPv4 destination reached through an IPv6 socket
            Some((v6.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_else(|| v6.to_string()), port))
        }
        _ => None,
    }
}

static AUDIT_SYSCALL_NR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\bsyscall=(\d+)\b"#).unwrap());
static AUDIT_EXIT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\bexit=(-?\d+)\b"#).unwrap());
static AUDIT_COMM_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\bcomm="([^"]*)""#).unwrap());
static AUDIT_EXE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\bexe="([^"]*)""#).unwrap());
static AUDIT_SADDR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\bsaddr=([0-9A-Fa-f]+)\b"#).unwrap());
static AUDIT_LADDR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\bladdr=([0-9A-Fa-f:.]+) lport=(\d+)"#).unwrap());

/// A `connect` SYSCALL record of a login session: (event, session id,
/// account, program, executable). `connect` is 42 on x86-64, 203 on
/// arm64, 362 on 32-bit x86; an enriched log also names it. A connect that
/// is still in progress when the call returns (`exit=-115`, a non-blocking
/// socket) is a connection being made, like one that returned 0.
fn audit_connect_syscall(line: &str, uid_name: &dyn Fn(&str) -> Option<String>) -> Option<((i64, u64), u64, String, String, String)> {
    let named = line.contains("SYSCALL=connect");
    let nr = AUDIT_SYSCALL_NR_RE.captures(line).and_then(|c| c[1].parse::<u32>().ok());
    if !named && !matches!(nr, Some(42) | Some(203) | Some(362)) {
        return None;
    }
    let exit: i64 = AUDIT_EXIT_RE.captures(line).and_then(|c| c[1].parse().ok())?;
    if exit != 0 && exit != -115 {
        return None;
    }
    let ses: u64 = AUDIT_SES_RE.captures(line).and_then(|c| c.get(1)?.as_str().parse().ok())?;
    if ses == 4294967295 {
        // no login session: a daemon
        return None;
    }
    let user = AUDIT_USER_AUID_RE
        .captures(line)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        .or_else(|| AUDIT_USER_AUID_NUM_RE.captures(line).and_then(|c| uid_name(c.get(1)?.as_str())))
        .unwrap_or_default();
    let text = |re: &Regex| re.captures(line).map(|c| c[1].to_string()).unwrap_or_default();
    Some((audit_stamp(line)?, ses, user, text(&AUDIT_COMM_RE), text(&AUDIT_EXE_RE)))
}

/// The rows of the outgoing connections, in time order, as lines of the
/// timeline: `(timestamp, line)`. The logon ID of each is the pid of the
/// sshd of its session's login on that host (the logon ID of that login's
/// row), from the latest login record with that session id before it; a
/// session whose login is not in the logs is named by its id (`ses:5`).
/// The same program connecting to the same place again within half a
/// minute is the same connection being made (a retry, both address
/// families), and is written once.
pub(crate) fn audit_connect_rows(mut connects: Vec<AuditConnect>, sessions: &[(String, u64, u32, i64)]) -> Vec<(String, String)> {
    fn q(s: &str) -> String {
        if s.is_empty() {
            "\"\"".to_string()
        } else if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }
    connects.sort_by(|a, b| (a.secs, &a.host, a.ses, &a.addr, a.port).cmp(&(b.secs, &b.host, b.ses, &b.addr, b.port)));
    let mut last: HashMap<(String, u64, String, u16), i64> = HashMap::new();
    let mut out = Vec::new();
    for c in connects {
        let key = (c.host.clone(), c.ses, c.addr.clone(), c.port);
        if last.get(&key).map_or(false, |t| c.secs - *t < 30) {
            last.insert(key, c.secs);
            continue;
        }
        last.insert(key, c.secs);
        let Some(t) = NaiveDateTime::from_timestamp_opt(c.secs, 0) else { continue };
        let ts = DateTime::<Utc>::from_utc(t, Utc).to_rfc3339();
        let pid = sessions.iter().filter(|(h, ses, _, at)| *h == c.host && *ses == c.ses && *at <= c.secs).max_by_key(|x| x.3).map(|x| x.2);
        let logon_id = match pid {
            Some(p) => p.to_string(),
            None => format!("ses:{}", c.ses),
        };
        let logon_type = match c.port {
            22 => "SSH",
            3389 | 5900 => "10",
            _ => "3",
        };
        let program = if c.exe.is_empty() || c.exe.ends_with(&format!("/{}", c.comm)) { c.comm.clone() } else { format!("{} ({})", c.comm, c.exe) };
        let detail = format!("{} to {}:{}, auditd login session {}", if program.is_empty() { "a program" } else { &program }, c.addr, c.port, c.ses);
        let line = format!(
            "{},{},CONNECT,AUDIT_CONNECT,{},\"\",\"\",{},\"\",{},\"\",{},{},{}{}\n",
            q(&ts),
            q(&c.addr),
            logon_type,
            q(&c.host),
            q(&c.user),
            q(&logon_id),
            q(&detail),
            q(&c.filename),
            crate::csv_out::EMPTY_TAIL,
        );
        out.push((ts, line));
    }
    out
}

// audit.log* ------------------------------------------------------------------
// One SSH login leaves several auditd records: USER_AUTH for each PAM /
// key stage (`op=pubkey_auth`, `op=key`, `op=PAM:authentication`) and then
// USER_LOGIN with the final outcome — often written twice by the same
// sshd pid. USER_LOGIN is the record we want (one per connection, success
// or failure, `acct="(unknown)"` for non-existent accounts). USER_AUTH is
// only used as a fallback for files that carry no USER_LOGIN at all.
// Repeats of one connection are collapsed by its audit session id.
fn parse_audit(path: &Path, dst_host: &str, filter_ip: bool, passwd: &HashMap<u32, String>) -> Vec<RawEvt> {
    let mut all = Vec::new();
    parse_audit_to(path, dst_host, filter_ip, passwd, &mut |batch| all.extend(batch));
    all
}

/// [`parse_audit`], its rows handed to `sink` a batch at a time, in the
/// file's order: an audit log left to grow is never held whole.
fn parse_audit_to(path: &Path, dst_host: &str, filter_ip: bool, passwd: &HashMap<u32, String>, sink: &mut dyn FnMut(Vec<RawEvt>)) {
    let mut out: Vec<RawEvt> = Vec::new();
    // USER_AUTH records with their `op=`, used only when the file has no
    // USER_LOGIN at all (see the fallback at the end).
    let mut auth_fallback: Vec<(RawEvt, String)> = Vec::new();
    let mut has_login = false;
    let uid_name = |uid: &str| -> Option<String> {
        let u: u32 = uid.parse().ok()?;
        if u == 4294967295 { return None; }
        Some(passwd.get(&u).cloned().unwrap_or_else(|| format!("uid:{}", u)))
    };
    let mut lines = match crate::textlines::open_plain_or_gzip(path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[ERROR] cannot open {}: {}", path.display(), e);
            return;
        }
    };
    // the `connect` of a login session waiting for the record with its address
    let mut connecting: Option<((i64, u64), u64, String, String, String)> = None;
    for line in &mut lines {
        if line.contains("type=SYSCALL") {
            connecting = audit_connect_syscall(&line, &uid_name);
            continue;
        }
        if line.contains("type=SOCKADDR") {
            if let Some((event, ses, user, comm, exe)) = connecting.take() {
                if audit_stamp(&line) == Some(event) {
                    let to = AUDIT_LADDR_RE
                        .captures(&line)
                        .and_then(|c| Some((c[1].to_string(), c[2].parse::<u16>().ok()?)))
                        .or_else(|| AUDIT_SADDR_RE.captures(&line).and_then(|c| audit_saddr(&c[1])));
                    if let Some((addr, port)) = to {
                        let local = addr.parse::<std::net::IpAddr>().map_or(true, |a| a.is_loopback() || a.is_unspecified());
                        if !local && REMOTE_ACCESS_PORTS.contains(&port) {
                            if let Ok(mut all) = AUDIT_CONNECTS.lock() {
                                all.push(AuditConnect { secs: event.0, host: dst_host.to_string(), addr, port, ses, user, comm, exe, filename: path.display().to_string() });
                            }
                        }
                    }
                }
            }
            continue;
        }
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

        // the session a login opened, and the pid of its sshd (the logon
        // ID of its row): what an outgoing connection of that session is
        // tied to its login by
        if res == "success" && (evt_type == "USER_LOGIN" || evt_type == "USER_START") {
            let ses: Option<u64> = AUDIT_SES_RE.captures(&line).and_then(|c| c.get(1)?.as_str().parse().ok());
            let pid: Option<u32> = AUDIT_PID_RE.captures(&line).and_then(|c| c.get(1)?.as_str().parse().ok());
            if let (Some(ses), Some(pid), Some((secs, _))) = (ses, pid, audit_stamp(&line)) {
                if ses != 4294967295 && pid != 0 {
                    if let Ok(mut all) = AUDIT_SESSIONS.lock() {
                        all.push((dst_host.to_string(), ses, pid, secs));
                    }
                }
            }
        }

        if filter_ip && !looks_like_ip(&ip) {
            continue;
        }

        // Only USER_LOGIN (outcome), USER_END (session end) and, as
        // fallback, USER_AUTH (PAM stage). USER_ACCT / USER_START fire once
        // more per session and would double-count.
        if evt_type != "USER_LOGIN" && evt_type != "USER_AUTH" && evt_type != "USER_END" && evt_type != "USER_ERR" {
            continue;
        }

        // Extract timestamp from msg=audit(<epoch>.<ms>:<serial>)
        let secs = match line.find("msg=audit(") {
            Some(idx_start) => {
                let rest = &line[idx_start + 10..];
                match rest.find(':') {
                    Some(idx_colon) => match rest[..idx_colon].parse::<f64>() {
                        Ok(frac) => frac.trunc() as i64,
                        Err(_) => continue,
                    },
                    None => continue,
                }
            }
            None => continue,
        };
        let ts = match NaiveDateTime::from_timestamp_opt(secs, 0) {
            Some(t) => DateTime::<Utc>::from_utc(t, Utc).to_rfc3339(),
            None => continue,
        };

        // Username: acct="..." (USER_AUTH, failed USER_LOGIN — "(unknown)"
        // for non-existent accounts), then the numeric id= / auid= of a
        // successful USER_LOGIN resolved through the collected /etc/passwd,
        // then the ausearch-style AUID="..." / UID="..." forms.
        let acct = AUDIT_USER_ACCT_RE
            .captures(&line)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        let invalid_user = acct.as_deref() == Some("(unknown)");
        let user = acct
            .or_else(|| AUDIT_USER_ID_RE.captures(&line).and_then(|c| uid_name(c.get(1)?.as_str())))
            .or_else(|| AUDIT_USER_AUID_NUM_RE.captures(&line).and_then(|c| uid_name(c.get(1)?.as_str())))
            .or_else(|| AUDIT_USER_AUID_RE
                .captures(&line)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string())))
            .or_else(|| AUDIT_USER_UID_RE
                .captures(&line)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string())))
            .unwrap_or_default();

        let evt = if evt_type == "USER_END" {
            "LOGOUT"
        } else if res == "success" {
            "SSH_SUCCESS"
        } else {
            "SSH_FAILED"
        };

        // One connection = one row, identified by what auditd itself
        // records, not by a time window:
        //   * a successful USER_LOGIN carries the login session id (`ses=`)
        //     that sshd opened; every further USER_LOGIN of the same
        //     connection (one per channel: scp, sftp, ansible modules, a
        //     second shell) repeats the same (pid, ses). Verified on
        //     one host: 780 success records = 667 distinct (pid, ses) =
        //     667 `USER_AUTH op=success` records. The repeats are collapsed
        //     per host after all files are read (a session can straddle an
        //     audit.log rotation), see `conn`.
        //   * a failed USER_LOGIN (ses unset) is written once per
        //     connection; the same pid seen again is pid reuse by a later
        //     connection (hours apart on the same host), so failures are
        //     never collapsed.
        let pid: u32 = AUDIT_PID_RE
            .captures(&line)
            .and_then(|c| c.get(1)?.as_str().parse().ok())
            .unwrap_or(0);
        let ses: u64 = AUDIT_SES_RE
            .captures(&line)
            .and_then(|c| c.get(1)?.as_str().parse().ok())
            .unwrap_or(4294967295);
        let op: String = AUDIT_OP_RE
            .captures(&line)
            .map(|c| c[1].to_string())
            .unwrap_or_default();

        let raw = RawEvt {
            ts_rfc3339: ts,
            user,
            remote: ip,
            // acct="(unknown)" is what sshd audits when a connection ends
            // without an authenticated user: a guess against a non-existent
            // account, but also a scanner that connects and hangs up, or a
            // client that exceeds MaxAuthTries. The username, if any, is
            // only in the sshd text log.
            tty_or_proc: if evt_type == "USER_END" {
                "audit session-end".into()
            } else if invalid_user {
                "audit unauthenticated".into()
            } else {
                "audit".into()
            },
            evt: evt.into(),
            filename: path.display().to_string(),
            dst_host: dst_host.into(),
            pid,
            // a session end carries the same ses= as its login; the last
            // USER_END of a session is its end (see the collapse)
            conn: if ((evt_type == "USER_LOGIN" && res == "success") || evt_type == "USER_END") && ses != 4294967295 { ses } else { 0 },
        };
        if evt_type == "USER_LOGIN" {
            has_login = true;
            // (the USER_AUTH records are used only for a file with no USER_LOGIN)
            auth_fallback = Vec::new();
            out.push(raw);
        } else if evt_type == "USER_END" {
            out.push(raw);
        } else if !has_login {
            auth_fallback.push((raw, op));
        }
        if out.len() >= SYSLOG_BATCH {
            sink(std::mem::take(&mut out));
        }
    }
    // No USER_LOGIN in the file: take from USER_AUTH only the records that
    // sshd writes once per outcome. A successful connection ends with one
    // `op=success` record (the pubkey_auth / key stage records before it
    // are not logins); older sshd audit code without `op=success` writes
    // one `op=PAM:authentication` per password login. A failed attempt is
    // `op=PAM:authentication res=failed` — `op=pubkey res=failed` is not
    // one: it is an agent offering a key the server does not accept, which
    // happens before most successful key logins.
    if !has_login && !auth_fallback.is_empty() {
        let has_op_success = auth_fallback.iter().any(|(_, op)| op == "success");
        let n = auth_fallback.len();
        let picked: Vec<RawEvt> = auth_fallback
            .into_iter()
            .filter(|(r, op)| {
                if r.evt == "SSH_SUCCESS" {
                    if has_op_success { op == "success" } else { op == "PAM:authentication" }
                } else {
                    op == "PAM:authentication"
                }
            })
            .map(|(r, _)| r)
            .collect();
        if is_debug_mode() {
            println!("    {}: no USER_LOGIN records, {} of {} USER_AUTH records used as fallback",
                     path.display(), picked.len(), n);
        }
        out.extend(picked);
    }
    if let Some(p) = lines.problem(path) {
        crate::banner::print_warning(&format!("  {}", p));
    }
    if !out.is_empty() {
        sink(out);
    }
}

// ────────────────────────── audit uid resolution ─────────────────────────────
fn ts_secs(rfc3339: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(rfc3339).ok().map(|d| d.timestamp())
}

/// Successful `USER_LOGIN` audit records name the account by uid, and
/// directory users (SSSD / LDAP) are not in the collected /etc/passwd, so
/// they come out of `parse_audit` as `uid:<n>`. The same login is almost
/// always also in the sshd text log and in wtmp with the real name, at the
/// same second and from the same source: learn `uid → name` from those
/// coincidences (per host; for directory-range uids, >= 10000, the vote is
/// also pooled across hosts since the uid is global there) and rewrite.
#[allow(dead_code)]
fn resolve_audit_uids(rows: &mut Vec<RawEvt>) {
    let mut votes = UidVotes::default();
    for r in rows.iter() {
        votes.note(r);
    }
    let resolved = votes.resolve();
    let mut changed = 0usize;
    for r in rows.iter_mut() {
        if resolved.apply(r) {
            changed += 1;
        }
    }
    if changed > 0 {
        crate::banner::print_info(&format!(
            "{} audit records: uid resolved to account name via sshd/wtmp coincidence", changed
        ));
    }
}

/// What [`resolve_audit_uids`] needs of every row, gathered as the rows go
/// by (they are written to disk host by host and read back one host at a
/// time): the named logins by host, source and second, and the audit
/// records that carry a uid. The uids of directory users (10000 and up)
/// are voted on across hosts, so this is gathered over all of them before
/// any host is written.
#[derive(Default)]
struct UidVotes {
    by_key: HashMap<(String, String, i64), Vec<String>>,
    /// (host, remote, "uid:n", second)
    uid_rows: Vec<(String, String, String, Option<i64>)>,
}

/// The names the uids resolved to: (host, "uid:n") and, for directory
/// users, ("", "uid:n").
struct UidNames(HashMap<(String, String), String>);

impl UidVotes {
    fn note(&mut self, r: &RawEvt) {
        if r.user.starts_with("uid:") {
            self.uid_rows.push((r.dst_host.clone(), r.remote.clone(), r.user.clone(), ts_secs(&r.ts_rfc3339)));
            return;
        }
        if r.user.is_empty() { return; }
        if r.evt != "SSH_SUCCESS" && r.evt != "LOGIN" { return; }
        if r.tty_or_proc.starts_with("audit") { return; }
        if let Some(sec) = ts_secs(&r.ts_rfc3339) {
            self.by_key.entry((r.dst_host.clone(), r.remote.clone(), sec)).or_default().push(r.user.clone());
        }
    }

    fn resolve(&self) -> UidNames {
        if self.by_key.is_empty() { return UidNames(HashMap::new()); }
        // (host, "uid:n") -> name -> votes ; ("", "uid:n") pools directory uids
        let mut votes: HashMap<(String, String), HashMap<String, usize>> = HashMap::new();
        for (host, remote, user, sec) in &self.uid_rows {
            let sec = match sec { Some(s) => *s, None => continue };
            let directory = user[4..].parse::<u32>().map(|u| u >= 10_000).unwrap_or(false);
            for d in -2i64..=2 {
                if let Some(names) = self.by_key.get(&(host.clone(), remote.clone(), sec + d)) {
                    for n in names {
                        *votes.entry((host.clone(), user.clone())).or_default().entry(n.clone()).or_default() += 1;
                        if directory {
                            *votes.entry((String::new(), user.clone())).or_default().entry(n.clone()).or_default() += 1;
                        }
                    }
                }
            }
        }
        let winner = |m: &HashMap<String, usize>| -> Option<String> {
            let total: usize = m.values().sum();
            m.iter().max_by_key(|(_, &c)| c).filter(|(_, &c)| c * 2 > total).map(|(n, _)| n.clone())
        };
        UidNames(votes.iter().filter_map(|(k, m)| winner(m).map(|n| (k.clone(), n))).collect())
    }

    /// How many of the uid records gathered get a name.
    fn changed(&self, names: &UidNames) -> usize {
        self.uid_rows.iter().filter(|(host, _, user, _)| names.name_of(host, user).is_some()).count()
    }
}

impl UidNames {
    fn name_of(&self, host: &str, user: &str) -> Option<&String> {
        if !user.starts_with("uid:") { return None; }
        let directory = user[4..].parse::<u32>().map(|u| u >= 10_000).unwrap_or(false);
        self.0
            .get(&(host.to_string(), user.to_string()))
            .or_else(|| if directory { self.0.get(&(String::new(), user.to_string())) } else { None })
    }

    /// The record's uid replaced by its name; whether it was.
    fn apply(&self, r: &mut RawEvt) -> bool {
        match self.name_of(&r.dst_host, &r.user) {
            Some(n) => {
                r.user = n.clone();
                true
            }
            None => false,
        }
    }
}

// ────────────────────────── log coverage ─────────────────────────────────────
/// Log family of an artifact file name, e.g. `secure-20260830.gz` -> secure.
pub(crate) fn log_family(filename: &str) -> &'static str {
    let base = filename
        .rsplit(|c| c == '/' || c == '\\' || c == ':')
        .next()
        .unwrap_or(filename)
        .to_lowercase();
    if base.starts_with("secure") || base.starts_with("auth.log") { "secure" }
    else if base.starts_with("messages") { "messages" }
    else if base.starts_with("wtmp") { "wtmp" }
    else if base.starts_with("btmp") { "btmp" }
    else if base.starts_with("utmp") { "utmp" }
    else if base == "lastlog" { "lastlog" }
    else if base.starts_with("audit.log") { "audit" }
    else if base.ends_with(".journal") || base.ends_with(".journal~") { "journal" }
    else if base.ends_with(".evtx") { "evtx" }
    else { "other" }
}

/// First day of the most recent stretch of days with no gap longer than
/// `max_gap` days. A log family whose files were rotated away has old,
/// isolated records (a 2023 wtmp, a lastlog entry) and then a continuous
/// recent block; only the block is usable as a baseline.
pub(crate) fn continuous_since(days: &mut Vec<NaiveDate>, max_gap: i64) -> Option<NaiveDate> {
    days.sort();
    days.dedup();
    let mut start = *days.last()?;
    for w in days.windows(2).rev() {
        if (w[1] - w[0]).num_days() > max_gap { break; }
        start = w[0];
    }
    Some(start)
}

/// Print, per destination host, from when each log family has continuous
/// data. Anomaly detection against a baseline is only meaningful from the
/// point every relevant source is present: before the first surviving
/// `secure` rotation, sshd-only facts (source IP, auth method) are simply
/// not visible.
type CoverageDays = HashMap<(String, &'static str), Vec<NaiveDate>>;

fn coverage_days(rows: &[&RawEvt], days: &mut CoverageDays) {
    for r in rows {
        let d = match r.ts_rfc3339.get(..10).and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()) {
            Some(d) => d,
            None => continue,
        };
        let h = r.dst_host.split('.').next().unwrap_or(&r.dst_host).to_string();
        let v = days.entry((h, log_family(&r.filename))).or_default();
        v.push(d);
        // (a row a day at most is what counts: millions of rows are not kept)
        if v.len() > 8192 {
            v.sort();
            v.dedup();
        }
    }
}

fn print_coverage(rows: &[&RawEvt]) {
    let mut days = CoverageDays::new();
    coverage_days(rows, &mut days);
    print_coverage_days(days);
}

fn print_coverage_days(mut days: CoverageDays) {
    let fams = ["secure", "journal", "audit", "wtmp", "btmp", "lastlog"];
    let mut hosts: Vec<String> = days.keys().map(|(h, _)| h.clone()).collect();
    hosts.sort();
    hosts.dedup();
    crate::banner::print_info("Log coverage per host (continuous since, gaps <= 7 days; lastlog = oldest record):");
    for h in hosts {
        let mut parts = Vec::new();
        for f in fams {
            if let Some(v) = days.get_mut(&(h.clone(), f)) {
                let since = if f == "lastlog" { v.iter().min().copied() } else { continuous_since(v, 7) };
                if let Some(d) = since { parts.push(format!("{} {}", f, d)); }
            }
        }
        crate::banner::print_info(&format!("  {:<18} {}", h, parts.join(" | ")));
    }
}

// ────────────────────────── DataFrame builder ────────────────────────────────
/// Write a masstin CSV containing only the canonical header.
/// Used when no Linux events match, so downstream merge steps in parse-image /
/// parse-massive find a valid (empty) file instead of erroring with ENOENT.
fn write_empty_csv(output: Option<&String>) {
    if let Some(path) = output {
        let _ = crate::csv_out::write_empty_timeline(path);
    }
}

/// What [`reduce_rows`] kept of a set of rows, and what it dropped.
struct Reduced {
    /// indices of the rows kept, in the order the reduction leaves them
    /// (the channel's rank, then the order the rows were read in)
    kept: Vec<usize>,
    /// rows past the noise filter
    filtered: usize,
    duplicates: usize,
    session_dups: usize,
    audit_dups: usize,
}

#[allow(dead_code)]
fn build_dataframe(rows: &[RawEvt], outgoing: Vec<(String, String)>, output: Option<&String>) {
    if rows.is_empty() && outgoing.is_empty() {
        eprintln!("[WARN] nothing matched lateral-movement filter");
        write_empty_csv(output);
        return;
    }
    let red = reduce_rows(rows);
    if red.filtered == 0 {
        eprintln!("[WARN] all rows filtered by --ignore-local / --exclude-* flags");
        write_empty_csv(output);
        return;
    }
    print_reduction(red.duplicates, red.session_dups, red.audit_dups);
    let mut ordered: Vec<&RawEvt> = red.kept.iter().map(|&i| &rows[i]).collect();
    ordered.sort_by(|a, b| a.ts_rfc3339.cmp(&b.ts_rfc3339));
    print_coverage(&ordered);
    let mut sink: Box<dyn std::io::Write> = match output {
        Some(p) => Box::new(std::io::BufWriter::with_capacity(1 << 20, File::create(p).unwrap())),
        None => Box::new(std::io::BufWriter::new(std::io::stdout())),
    };
    write_rows(&mut sink, ordered.iter().map(|r| (r.ts_rfc3339.clone(), row_line(r))), outgoing);
}

/// The banner lines of what the reduction dropped.
fn print_reduction(removed: usize, session_dups: usize, audit_dups: usize) {
    if removed > 0 {
        crate::banner::print_info(&format!("{} duplicate events removed (journald + rsyslog overlap)", removed));
    }
    if session_dups > 0 {
        crate::banner::print_info(&format!("{} audit records collapsed (further channels of an already counted session)", session_dups));
    }
    if audit_dups > 0 {
        crate::banner::print_info(&format!("{} audit records dropped (same connection already in the sshd log, paired by pid)", audit_dups));
    }
}

/// The rank of a row's channel in the reduction: the rsyslog text before
/// the journal (the file the analyst can open). Also the order of rows of
/// the same second in the timeline.
fn channel_rank(t: &str) -> u8 {
    if t.starts_with("journal-ssh") { 1 } else { 0 }
}

/// The noise filter, then the copies of one event dropped: the same event
/// through two channels of a kind, an audit session's further channels,
/// an audit record whose connection the sshd log already has. Every key
/// carries the host (a log file is one host's), so a set of rows reduced
/// host by host keeps exactly what the whole set reduced at once keeps.
fn reduce_rows(rows: &[RawEvt]) -> Reduced {
    let first = reduce_first(rows);
    let mut spans = FileSpans::new();
    add_spans(rows, &first.deduped, &mut spans);
    let (kept, audit_dups) = reduce_second(rows, first.deduped, &spans);
    Reduced { kept, filtered: first.filtered, duplicates: first.removed, session_dups: first.session_dups, audit_dups }
}

/// The channel class of a row, for the reduction's keys.
fn channel_class(t: &str) -> &'static str {
    if t.starts_with("ssh") || t.starts_with("journal-ssh") { "ssh" }
    else if t.starts_with("audit") { "audit" }
    else if t == "pam" { "pam" }
    else { "other" }
}

/// What the first step of the reduction leaves: the rows kept (by index, in
/// the order of the channel's rank, then of reading) and what it dropped.
struct FirstStep {
    deduped: Vec<usize>,
    filtered: usize,
    removed: usize,
    session_dups: usize,
}

/// The first step: the noise filter, the copies of one event through two
/// channels of a kind, the further channels of an audit session. Every key
/// carries the host and the source of the row, so a set of rows split by
/// host and source keeps, piece by piece, what the whole set keeps.
fn reduce_first(rows: &[RawEvt]) -> FirstStep {
    // Apply noise filter (--ignore-local / --exclude-*). We build a minimal
    // LogData view of each RawEvt just for the filter check — RawEvt's
    // `remote` field can be either an IP or a hostname, so we route it to
    // both src_ip and workstation_name for the classifier.
    let filtered: Vec<usize> = (0..rows.len())
        .filter(|&i| {
            let r = &rows[i];
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
        .collect();
    // Same event seen through two channels of the SAME kind is one event:
    // on RHEL 7+ rsyslog's imjournal copies every sshd line from journald
    // into /var/log/secure, so a login parsed from both would appear twice.
    // Channels of different kinds (sshd log vs auditd vs wtmp) are kept —
    // they corroborate each other and carry different detail. Key: second-
    // resolution timestamp (journald has µs, syslog has seconds), host,
    // event, user, source, channel class. Preference within a class:
    // rsyslog text over journal (the file the analyst can open).
    let mut ordered: Vec<usize> = filtered.clone();
    ordered.sort_by_key(|&i| channel_rank(&rows[i].tty_or_proc));
    // Keys are 64-bit hashes of the tuple instead of owned tuples.
    fn key_hash(parts: &[&str], sec: i64) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for p in parts { p.hash(&mut h); }
        sec.hash(&mut h);
        h.finish()
    }
    // Filenames interned to a small id so the claim map stores u32s.
    let mut file_ids: HashMap<String, u32> = HashMap::new();
    let file_id = |f: &str, ids: &mut HashMap<String, u32>| -> u32 {
        if let Some(&id) = ids.get(f) { return id; }
        let next = ids.len() as u32;
        ids.insert(f.to_string(), next);
        next
    };
    // A key is claimed by the first FILE that produced it; rows for the same
    // key from OTHER files are the cross-channel copies and go. Rows from
    // the claiming file itself are all kept: automation (Ansible, batch
    // scp) legitimately opens several sessions per second from the same
    // account and source, and those are distinct logins, not duplicates.
    let mut owner: HashMap<u64, u32> = HashMap::with_capacity(ordered.len());
    let mut deduped: Vec<usize> = Vec::with_capacity(ordered.len());
    for i in ordered {
        let r = &rows[i];
        let sec = ts_secs(&r.ts_rfc3339).unwrap_or(0);
        let key = key_hash(&[&r.dst_host, &r.evt, &r.user, &r.remote, channel_class(&r.tty_or_proc)], sec);
        let fid = file_id(&r.filename, &mut file_ids);
        let claimant = owner.entry(key).or_insert(fid);
        if *claimant == fid { deduped.push(i); }
    }
    let removed = filtered.len() - deduped.len();
    drop(owner);
    // One successful audit connection = one row: records sharing (host,
    // pid, ses, source) are the channels of one sshd connection, possibly
    // spread over two rotated audit.log files. The earliest is kept.
    let session_dups = {
        // logins keep the earliest record of the session, session ends
        // (USER_END, one per channel) the latest
        let mut first: HashMap<(&str, u32, u64, &str, bool), (i64, usize)> = HashMap::new();
        for (k, &i) in deduped.iter().enumerate() {
            let r = &rows[i];
            if r.conn == 0 { continue; }
            let is_end = r.evt == "LOGOUT";
            let sec = ts_secs(&r.ts_rfc3339).unwrap_or(if is_end { i64::MIN } else { i64::MAX });
            let e = first.entry((r.dst_host.as_str(), r.pid, r.conn, r.remote.as_str(), is_end)).or_insert((sec, k));
            if (is_end && sec > e.0) || (!is_end && sec < e.0) { *e = (sec, k); }
        }
        let keep: std::collections::HashSet<usize> = first.values().map(|v| v.1).collect();
        let before = deduped.len();
        let mut k = 0usize;
        deduped.retain(|&i| { let ok = rows[i].conn == 0 || keep.contains(&k); k += 1; ok });
        before - deduped.len()
    };
    FirstStep { deduped, filtered: filtered.len(), removed, session_dups }
}

/// The time each log file's sshd rows span, after the first step: what the
/// second step checks an audit record against. Of the whole set, whatever
/// the pieces it is reduced in.
type FileSpans = HashMap<String, (i64, i64)>;

fn add_spans(rows: &[RawEvt], deduped: &[usize], spans: &mut FileSpans) {
    for &i in deduped {
        let r = &rows[i];
        if channel_class(&r.tty_or_proc) != "ssh" { continue; }
        let sec = match ts_secs(&r.ts_rfc3339) { Some(x) => x, None => continue };
        match spans.get_mut(r.filename.as_str()) {
            Some(e) => {
                if sec < e.0 { e.0 = sec; }
                if sec > e.1 { e.1 = sec; }
            }
            None => {
                spans.insert(r.filename.clone(), (sec, sec));
            }
        }
    }
}

/// The second step: the audit records whose connection the sshd log
/// already has. Returns the rows kept (by index) and how many were dropped.
// auditd's USER_LOGIN is the same connection sshd already wrote to
// secure/auth.log/journald. The two are paired by the identifier they
// share — the sshd process id — never by time proximity or account
// (auditd names successful logins by uid, failed ones as "(unknown)"):
//   * same host, same pid, same source, same outcome (an audit failure
//     pairs with an sshd refusal or pre-authentication close);
//   * the sshd line comes from a log file whose time span covers the
//     audit record, so a pid reused on a day the sshd log does not
//     cover cannot be paired with a different connection;
//   * one-to-one, closest in time first (a pid is reused only after
//     the previous connection has ended).
// Audit rows left unpaired — hosts whose text logs rotated away,
// connections sshd did not log — are kept.
fn reduce_second(rows: &[RawEvt], mut deduped: Vec<usize>, spans: &FileSpans) -> (Vec<usize>, usize) {
    let class = |evt: &str| -> u8 {
        match evt { "SSH_SUCCESS" => 1, "SSH_FAILED" | "SSH_PREAUTH" => 2, "LOGOUT" => 3, _ => 0 }
    };
    // nothing to pair without an audit record: the sshd rows are not indexed
    if !deduped.iter().any(|&i| channel_class(&rows[i].tty_or_proc) == "audit" && rows[i].pid != 0) {
        return (deduped, 0);
    }
    let mut by_key: HashMap<(&str, u32, &str, u8), Vec<(i64, &str)>> = HashMap::new();
    for &i in deduped.iter() {
        let r = &rows[i];
        if channel_class(&r.tty_or_proc) != "ssh" { continue; }
        let sec = match ts_secs(&r.ts_rfc3339) { Some(x) => x, None => continue };
        let c = class(&r.evt);
        if r.pid != 0 && c != 0 {
            by_key.entry((r.dst_host.as_str(), r.pid, r.remote.as_str(), c)).or_default().push((sec, r.filename.as_str()));
        }
    }
    // candidate pairs (|dt|, audit position, sshd slot)
    let mut slots: HashMap<(&str, u32, &str, u8, usize), ()> = HashMap::new();
    let mut pairs: Vec<(i64, usize, (&str, u32, &str, u8, usize))> = Vec::new();
    for (k, &i) in deduped.iter().enumerate() {
        let r = &rows[i];
        if channel_class(&r.tty_or_proc) != "audit" || r.pid == 0 { continue; }
        let sec = match ts_secs(&r.ts_rfc3339) { Some(x) => x, None => continue };
        let key = (r.dst_host.as_str(), r.pid, r.remote.as_str(), class(&r.evt));
        if let Some(v) = by_key.get(&key) {
            for (j, (t, f)) in v.iter().enumerate() {
                let Some(&(lo, hi)) = spans.get(*f) else { continue };
                if sec < lo || sec > hi { continue; }
                pairs.push(((sec - t).abs(), k, (key.0, key.1, key.2, key.3, j)));
            }
        }
    }
    pairs.sort_by_key(|p| p.0);
    let mut drop_idx: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for (_, k, slot) in pairs {
        if drop_idx.contains(&k) || slots.contains_key(&slot) { continue; }
        slots.insert(slot, ());
        drop_idx.insert(k);
    }
    let n = drop_idx.len();
    let mut k = 0usize;
    deduped.retain(|_| { let keep = !drop_idx.contains(&k); k += 1; keep });
    (deduped, n)
}

// Written directly, row by row, instead of through a polars DataFrame:
// materialising 14 Utf8 columns for 1.5M rows and sorting them needed
// several GB on top of the rows themselves and aborted the process on
// the 28-host corpus. Quoting mirrors what polars produced (empty
// fields as "", quotes only when needed) so downstream readers see the
// same CSV they always did.
fn row_line(r: &RawEvt) -> String {
    fn q(s: &str) -> String {
        if s.is_empty() {
            "\"\"".to_string()
        } else if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }
    let event_type = |evt: &str| -> &'static str {
        match evt {
            "SSH_SUCCESS" | "LOGIN" | "LASTLOG" => "SUCCESSFUL_LOGON",
            "SSH_FAILED" | "FAILED_LOGIN" => "FAILED_LOGON",
            "LOGOUT" => "LOGOFF",
            _ => "CONNECT",
        }
    };
    let is_ip = looks_like_ip(&r.remote);
        let (src_computer, src_ip) = if is_ip { ("", r.remote.as_str()) } else { (r.remote.as_str(), "") };
        // Every Linux row with a remote source is an SSH session (sshd
        // logs, pts entries in wtmp/lastlog, auditd sshd records). Naming
        // the channel — as parse-cortex does for port 22 — lets the graph
        // loaders and detectors tell it apart from Windows logon types.
        // logon_id: the sshd process id of the connection (syslog
        // `sshd[pid]`, journald `_PID`, auditd `pid=`, wtmp `ut_pid`), the
        // same on the login and on the LOGOFF row that closes it
        let logon_id = if r.pid != 0 { r.pid.to_string() } else { String::new() };
        format!(
            "{},{},{},{},SSH,{},\"\",{},{},\"\",\"\",{},{},{}{}\n",
            q(&r.ts_rfc3339),
            q(&r.dst_host),
            event_type(&r.evt),
            q(&r.evt),
            q(&r.user),
            q(src_computer),
            q(src_ip),
            q(&logon_id),
            q(&r.tty_or_proc),
            q(&r.filename),
            crate::csv_out::EMPTY_TAIL,
        )
}

/// The header, then the rows (their time and their line, in order) with the
/// outgoing connections of the audit logs in their place in time.
fn write_rows(sink: &mut Box<dyn std::io::Write>, rows: impl Iterator<Item = (String, String)>, outgoing: Vec<(String, String)>) {
    use std::io::Write as _;
    let header = format!("{}\n", crate::csv_out::HEADER);
    sink.write_all(header.as_bytes()).unwrap();
    let mut outgoing = outgoing.into_iter().peekable();
    for (ts, line) in rows {
        while outgoing.peek().map_or(false, |(t, _)| t.as_str() <= ts.as_str()) {
            sink.write_all(outgoing.next().unwrap().1.as_bytes()).unwrap();
        }
        sink.write_all(line.as_bytes()).unwrap();
    }
    for (_, line) in outgoing {
        sink.write_all(line.as_bytes()).unwrap();
    }
    sink.flush().unwrap();
}

// ─────────────────── the rows on disk, one file per host ───────────────────
//
// A folder of Linux packages is millions of rows (a brute force is a row an
// attempt), and every row is seven strings: held all at once they were
// gigabytes (7 GB for a few dozen UAC packages). The rows of each log go to
// a file of their host as the log is read; each host is then read back
// alone, reduced (every key of the reduction carries the host), sorted and
// written to a run of its own; the runs are merged into the timeline. The
// order of the rows is the one the whole set gave: time, then the channel's
// rank, then the order the logs and their rows were read in.

/// Where a row came from: the log's place among the logs read (sorted by
/// path) and the row's place in that log.
type RowOrigin = (u32, u32);

fn put_str(w: &mut impl std::io::Write, s: &str) -> std::io::Result<()> {
    w.write_all(&(s.len() as u32).to_le_bytes())?;
    w.write_all(s.as_bytes())
}

fn get_u32(r: &mut impl Read) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn get_str(r: &mut impl Read) -> std::io::Result<String> {
    let n = get_u32(r)? as usize;
    let mut b = vec![0u8; n];
    r.read_exact(&mut b)?;
    Ok(String::from_utf8(b).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

/// One row of the spill: where it came from, then the row.
fn put_spill_row(w: &mut impl std::io::Write, origin: RowOrigin, r: &RawEvt) -> std::io::Result<()> {
    w.write_all(&origin.0.to_le_bytes())?;
    w.write_all(&origin.1.to_le_bytes())?;
    w.write_all(&r.pid.to_le_bytes())?;
    w.write_all(&r.conn.to_le_bytes())?;
    for s in [&r.ts_rfc3339, &r.user, &r.remote, &r.tty_or_proc, &r.evt, &r.filename, &r.dst_host] {
        put_str(w, s)?;
    }
    Ok(())
}

/// The bytes of rows on disk a piece of a host may hold to be reduced in
/// memory: the run's memory over what a row costs there (crate::threads).
fn row_budget() -> u64 {
    crate::threads::row_budget()
}

/// A host's rows split in `pieces` files by the source of each row: every
/// key of the reduction carries the source, so each piece is reduced alone.
fn split_by_source(path: &Path, pieces: usize, dir: &Path, tag: usize) -> std::io::Result<Vec<PathBuf>> {
    use std::hash::{Hash, Hasher};
    use std::io::Write as _;
    let paths: Vec<PathBuf> = (0..pieces).map(|k| dir.join(format!("piece-{}-{}.rows", tag, k))).collect();
    let mut ws = Vec::with_capacity(pieces);
    for p in &paths {
        ws.push(std::io::BufWriter::with_capacity(1 << 16, crate::space::create(p)?));
    }
    HostSpill::each(path, |origin, r| {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        r.remote.hash(&mut h);
        let k = (h.finish() % pieces as u64) as usize;
        put_spill_row(&mut ws[k], origin, &r)
    })?;
    for w in ws.iter_mut() {
        w.flush()?;
    }
    Ok(paths)
}

/// The rows of each host, on disk.
struct HostSpill {
    dir: PathBuf,
    files: HashMap<String, PathBuf>,
    rows: usize,
}

impl HostSpill {
    fn new(dir: PathBuf) -> HostSpill {
        let _ = fs::create_dir_all(&dir);
        HostSpill { dir, files: HashMap::new(), rows: 0 }
    }

    /// The rows of log `log`, appended to their hosts' files.
    fn add(&mut self, rows: &[RawEvt], log: u32) -> std::io::Result<()> {
        self.add_from(rows, log, 0)
    }

    /// [`add`](Self::add) for a batch of a log's rows: `base` is the place
    /// in the log of the batch's first row.
    fn add_from(&mut self, rows: &[RawEvt], log: u32, base: u32) -> std::io::Result<()> {
        use std::io::Write as _;
        let mut by_host: Vec<(&str, Vec<usize>)> = Vec::new();
        for (i, r) in rows.iter().enumerate() {
            match by_host.iter_mut().find(|(h, _)| *h == r.dst_host.as_str()) {
                Some((_, v)) => v.push(i),
                None => by_host.push((r.dst_host.as_str(), vec![i])),
            }
        }
        for (host, idx) in by_host {
            let next = self.dir.join(format!("host-{}.rows", self.files.len()));
            let path = self.files.entry(host.to_string()).or_insert(next).clone();
            let f = crate::space::append(&path)?;
            let mut w = std::io::BufWriter::with_capacity(1 << 20, f);
            for i in idx {
                put_spill_row(&mut w, (log, base + i as u32), &rows[i])?;
            }
            w.flush()?;
        }
        self.rows += rows.len();
        Ok(())
    }

    /// A host's rows, in the order they were read.
    fn read(path: &Path) -> std::io::Result<Vec<(RowOrigin, RawEvt)>> {
        let mut out = HostSpill::read_as_written(path)?;
        out.sort_by_key(|(o, _)| *o);
        Ok(out)
    }

    /// The rows of a file, in the file's order.
    fn read_as_written(path: &Path) -> std::io::Result<Vec<(RowOrigin, RawEvt)>> {
        let mut out = Vec::new();
        HostSpill::each(path, |o, r| {
            out.push((o, r));
            Ok(())
        })?;
        Ok(out)
    }

    /// Every row of a file handed to `f`, one at a time.
    fn each(path: &Path, mut f: impl FnMut(RowOrigin, RawEvt) -> std::io::Result<()>) -> std::io::Result<()> {
        let mut r = BufReader::with_capacity(1 << 20, File::open(path)?);
        loop {
            let log = match get_u32(&mut r) {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            };
            let idx = get_u32(&mut r)?;
            let pid = get_u32(&mut r)?;
            let mut b = [0u8; 8];
            r.read_exact(&mut b)?;
            let conn = u64::from_le_bytes(b);
            let ts_rfc3339 = get_str(&mut r)?;
            let user = get_str(&mut r)?;
            let remote = get_str(&mut r)?;
            let tty_or_proc = get_str(&mut r)?;
            let evt = get_str(&mut r)?;
            let filename = get_str(&mut r)?;
            let dst_host = get_str(&mut r)?;
            f((log, idx), RawEvt { ts_rfc3339, user, remote, tty_or_proc, evt, filename, dst_host, pid, conn })?;
        }
        Ok(())
    }
}

/// One row of a host's run: its place in the timeline and its line.
fn put_run_row(w: &mut impl std::io::Write, ts: &str, rank: u8, origin: RowOrigin, line: &str) -> std::io::Result<()> {
    put_str(w, ts)?;
    w.write_all(&[rank])?;
    w.write_all(&origin.0.to_le_bytes())?;
    w.write_all(&origin.1.to_le_bytes())?;
    put_str(w, line)
}

/// The next row of a run: (time, rank, origin, line).
fn get_run_row(r: &mut impl Read) -> Option<(String, u8, RowOrigin, String)> {
    let ts = get_str(r).ok()?;
    let mut rank = [0u8; 1];
    r.read_exact(&mut rank).ok()?;
    let a = get_u32(r).ok()?;
    let b = get_u32(r).ok()?;
    let line = get_str(r).ok()?;
    Some((ts, rank[0], (a, b), line))
}

/// The timeline out of the rows on disk: each host reduced and sorted
/// alone into a run, the runs merged. What is printed and written is what
/// [`build_dataframe`] gives for the same rows all at once.
fn write_by_host(spill: &HostSpill, names: &UidNames, outgoing: Vec<(String, String)>, output: Option<&String>) {
    write_by_host_within(spill, names, outgoing, output, row_budget())
}

/// One piece of a host, after the reduction's first step: its rows in the
/// order that step left them, in memory or back on disk.
enum Piece {
    Held(Vec<RowOrigin>, Vec<RawEvt>, Vec<usize>),
    Stored(PathBuf),
}

/// [`write_by_host`] with the bytes of rows a piece may hold. A host whose
/// rows are more than that is split by the source of its rows and reduced
/// a piece at a time (a server that took sixteen million attempts held
/// 23 GB reduced whole): the first step of each piece, then, with the time
/// every log file spans known, the second step of each.
fn write_by_host_within(spill: &HostSpill, names: &UidNames, outgoing: Vec<(String, String)>, output: Option<&String>, budget: u64) {
    if spill.rows == 0 && outgoing.is_empty() {
        eprintln!("[WARN] nothing matched lateral-movement filter");
        write_empty_csv(output);
        return;
    }
    let mut hosts: Vec<(&String, &PathBuf)> = spill.files.iter().collect();
    hosts.sort();
    let mut filtered = 0usize;
    let (mut removed, mut session_dups, mut audit_dups) = (0usize, 0usize, 0usize);
    let mut days = CoverageDays::new();
    let mut runs: Vec<PathBuf> = Vec::new();
    for (n, (host, path)) in hosts.iter().enumerate() {
        let lost = |e: std::io::Error| crate::banner::print_warning(&format!("Could not read back the rows of {} ({}): they are missing from the timeline", host, e));
        let len = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let pieces: Vec<PathBuf> = if len <= budget.max(1) {
            vec![(*path).clone()]
        } else {
            let k = (len.div_ceil(budget.max(1)) as usize).clamp(2, 512);
            crate::banner::print_info(&format!("  {}: {} of rows, reduced in {} pieces (by source) to stay within memory", host, crate::space::human(len), k));
            match split_by_source(path, k, &spill.dir, n) {
                Ok(v) => {
                    let _ = fs::remove_file(path);
                    v
                }
                Err(e) => {
                    lost(e);
                    continue;
                }
            }
        };
        let several = pieces.len() > 1;
        // the first step of every piece; the files' spans over all of them
        let mut spans = FileSpans::new();
        let mut firsts: Vec<Piece> = Vec::new();
        for (k, piece) in pieces.iter().enumerate() {
            let rows = match HostSpill::read(piece) {
                Ok(v) => v,
                Err(e) => {
                    lost(e);
                    continue;
                }
            };
            let _ = fs::remove_file(piece);
            let (origins, mut rows): (Vec<RowOrigin>, Vec<RawEvt>) = rows.into_iter().unzip();
            for r in rows.iter_mut() {
                names.apply(r);
            }
            let first = reduce_first(&rows);
            filtered += first.filtered;
            removed += first.removed;
            session_dups += first.session_dups;
            add_spans(&rows, &first.deduped, &mut spans);
            if !several {
                firsts.push(Piece::Held(origins, rows, first.deduped));
                continue;
            }
            // back to disk, in the order the first step left them
            let stored = spill.dir.join(format!("first-{}-{}.rows", n, k));
            let wrote = (|| -> std::io::Result<()> {
                use std::io::Write as _;
                let mut w = std::io::BufWriter::with_capacity(1 << 20, crate::space::create(&stored)?);
                for &i in &first.deduped {
                    put_spill_row(&mut w, origins[i], &rows[i])?;
                }
                w.flush()
            })();
            match wrote {
                Ok(()) => firsts.push(Piece::Stored(stored)),
                Err(e) => crate::banner::print_warning(&format!("Could not write the rows of {} ({}): is the temporary disk full? They are missing from the timeline", host, e)),
            }
        }
        // the second step of every piece, sorted into a run
        for (k, piece) in firsts.into_iter().enumerate() {
            let (origins, rows, deduped) = match piece {
                Piece::Held(o, r, d) => (o, r, d),
                Piece::Stored(p) => {
                    let got = HostSpill::read_as_written(&p);
                    let _ = fs::remove_file(&p);
                    match got {
                        Ok(v) => {
                            let (o, r): (Vec<RowOrigin>, Vec<RawEvt>) = v.into_iter().unzip();
                            let d = (0..r.len()).collect();
                            (o, r, d)
                        }
                        Err(e) => {
                            lost(e);
                            continue;
                        }
                    }
                }
            };
            let (mut kept, dropped) = reduce_second(&rows, deduped, &spans);
            audit_dups += dropped;
            // time, then rank and origin: the stable sort of the whole set
            kept.sort_by(|&a, &b| rows[a].ts_rfc3339.cmp(&rows[b].ts_rfc3339).then(channel_rank(&rows[a].tty_or_proc).cmp(&channel_rank(&rows[b].tty_or_proc))).then(origins[a].cmp(&origins[b])));
            let refs: Vec<&RawEvt> = kept.iter().map(|&i| &rows[i]).collect();
            coverage_days(&refs, &mut days);
            drop(refs);
            let run = spill.dir.join(format!("run-{}-{}.rows", n, k));
            let written = (|| -> std::io::Result<()> {
                use std::io::Write as _;
                let mut w = std::io::BufWriter::with_capacity(1 << 20, crate::space::create(&run)?);
                for &i in &kept {
                    put_run_row(&mut w, &rows[i].ts_rfc3339, channel_rank(&rows[i].tty_or_proc), origins[i], &row_line(&rows[i]))?;
                }
                w.flush()
            })();
            match written {
                Ok(()) => runs.push(run),
                Err(e) => crate::banner::print_warning(&format!("Could not write the rows of {} ({}): is the temporary disk full? They are missing from the timeline", host, e)),
            }
        }
        let _ = fs::remove_file(path);
    }
    if filtered == 0 {
        eprintln!("[WARN] all rows filtered by --ignore-local / --exclude-* flags");
        write_empty_csv(output);
        return;
    }
    print_reduction(removed, session_dups, audit_dups);
    print_coverage_days(days);
    // the runs merged: the smallest (time, rank, origin) first
    let mut readers: Vec<BufReader<File>> = runs.iter().filter_map(|p| File::open(p).ok().map(|f| BufReader::with_capacity(1 << 16, f))).collect();
    let mut heap: std::collections::BinaryHeap<std::cmp::Reverse<(String, u8, RowOrigin, usize, String)>> = std::collections::BinaryHeap::new();
    for (k, r) in readers.iter_mut().enumerate() {
        if let Some((ts, rank, o, line)) = get_run_row(r) {
            heap.push(std::cmp::Reverse((ts, rank, o, k, line)));
        }
    }
    let merged = std::iter::from_fn(|| {
        let std::cmp::Reverse((ts, _, _, k, line)) = heap.pop()?;
        if let Some((t2, r2, o2, l2)) = get_run_row(&mut readers[k]) {
            heap.push(std::cmp::Reverse((t2, r2, o2, k, l2)));
        }
        Some((ts, line))
    });
    let mut sink: Box<dyn std::io::Write> = match output {
        Some(p) => Box::new(std::io::BufWriter::with_capacity(1 << 20, File::create(p).unwrap())),
        None => Box::new(std::io::BufWriter::new(std::io::stdout())),
    };
    write_rows(&mut sink, merged, outgoing);
    drop(sink);
    for r in runs {
        let _ = fs::remove_file(r);
    }
}

// ────────────────────────── main entry point ─────────────────────────────────
/// Check if a filename is a Linux forensic artifact we care about
fn is_linux_artifact(fname: &str) -> bool {
    let lower = fname.to_lowercase();
    matches!(lower.as_str(), "utmp" | "lastlog" | "auth.log")
        || is_rotated_name(&lower, "wtmp")
        || is_rotated_name(&lower, "btmp")
        || is_log_rotation(&lower, "secure")
        || is_log_rotation(&lower, "messages")
        || lower.starts_with("audit.log")
        || lower.starts_with("auth.log")
        || lower.ends_with(".journal")
        || lower.ends_with(".journal~")
}

/// A file named like a log that is configuration: `/etc/logrotate.d/wtmp`
/// and `btmp` are logrotate's rules for those logs, not the logs.
fn is_config_not_log(p: &Path) -> bool {
    p.components().any(|c| c.as_os_str().eq_ignore_ascii_case("logrotate.d"))
}

/// `base` or one of its rotations, as logrotate and syslog name them:
/// `messages`, `messages.1`, `messages.2.gz`, `messages-20261101`,
/// `secure-20261101.gz`. A file that merely starts with the word
/// (`messages.cpython-310.pyc`, `secure-boot.conf`) is not one.
fn is_log_rotation(lower: &str, base: &str) -> bool {
    let Some(rest) = lower.strip_prefix(base) else { return false };
    let rest = rest.strip_suffix(".gz").unwrap_or(rest);
    if rest.is_empty() {
        return true;
    }
    let digits = |t: &str| !t.is_empty() && t.chars().all(|c| c.is_ascii_digit());
    match rest.as_bytes()[0] {
        b'.' | b'-' => digits(&rest[1..]),
        _ => false,
    }
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

/// What the Linux pass reads, in order: an archive (unpacked into `dir`,
/// read, then deleted) or a log lying loose.
enum LinuxUnit {
    Archive { path: PathBuf, display: String, zip: bool, dir: PathBuf },
    Log(PathBuf),
}

impl LinuxUnit {
    /// The path its logs sort by: an archive's are all under its folder.
    fn key(&self) -> &PathBuf {
        match self {
            LinuxUnit::Archive { dir, .. } => dir,
            LinuxUnit::Log(p) => p,
        }
    }
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
    extract_tar_into(tar_path, dest_base, None, display_path, out)
}

/// The folder a tar archive is unpacked into is named after it: this stem.
fn tar_stem(archive_name: &str) -> String {
    crate::parse::archive_stem(archive_name).unwrap_or_else(|| "extracted".to_string())
}

/// [`extract_tar_recursive`] into `into` when given (the folder the run
/// chose for it beforehand), a fresh folder under `dest_base` otherwise.
fn extract_tar_into(tar_path: &Path, dest_base: &Path, into: Option<&Path>, display_path: &str, out: &mut Vec<TarExtract>) {
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

    let extract_dir = match into {
        Some(d) => {
            let _ = fs::create_dir_all(d);
            d.to_path_buf()
        }
        None => fresh_extract_dir(dest_base, &tar_stem(&archive_name)),
    };

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

        // room for it on the temporary disk first (see crate::space)
        let size = entry.header().size().unwrap_or(0);
        if let Err(e) = crate::space::make_room(&extract_dir, size) {
            // named at the end of the run, with the others
            crate::space::left_out(&format!("{} -> {}", display_path, name), &e.to_string());
            continue;
        }
        // unpack_in() refuses paths that escape `extract_dir` (`..`,
        // absolute) and creates the parent directories itself.
        match entry.unpack_in(&extract_dir) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                // The stream died inside this entry. If it was a nested
                // archive, whatever tar managed to write is still a valid
                // prefix of that archive: walk it (its own extractor will
                // report where IT ends) instead of losing the whole host.
                let partial = extract_dir.join(&rel);
                let size = fs::metadata(&partial).map(|m| m.len()).unwrap_or(0);
                if is_nested && size > 0 {
                    crate::banner::print_warning(&format!(
                        "{}: nested archive {} is cut short ({} MB arrived, {}); parsing what arrived.",
                        archive_name, name, size / 1_048_576, e
                    ));
                    nested.push((partial, name));
                }
                continue;
            }
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

/// A folder of its own for an archive's contents: `<base>/<stem>`, or
/// `<stem>-2`, `-3`... when an archive of the same name was already
/// extracted there. Two collections called `collection.tar.gz`, one per
/// host folder, used to be unpacked into the same folder: the files of the
/// second replaced the first's and one host's events were lost.
fn fresh_extract_dir(base: &Path, stem: &str) -> PathBuf {
    let mut dir = base.join(stem);
    let mut n = 2;
    while dir.exists() {
        dir = base.join(format!("{}-{}", stem, n));
        n += 1;
    }
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Recursively extract ZIPs (including password-protected with common forensic passwords)
/// and return paths to extracted directories
fn extract_zips_recursive(zip_path: &Path, dest_base: &Path, tar_out: &mut Vec<TarExtract>) -> Vec<PathBuf> {
    extract_zips_into(zip_path, dest_base, None, tar_out)
}

/// [`extract_zips_recursive`] into `into` when given.
fn extract_zips_into(zip_path: &Path, dest_base: &Path, into: Option<&Path>, tar_out: &mut Vec<TarExtract>) -> Vec<PathBuf> {
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
    let extract_dir = match into {
        Some(d) => {
            let _ = fs::create_dir_all(d);
            d.to_path_buf()
        }
        None => fresh_extract_dir(dest_base, zip_name),
    };

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
        // The name comes from the archive, and the archive from the
        // evidence: `..\..\x` or `C:\x` would be written outside the
        // extraction folder. Only a path that stays inside is taken.
        let inside = match zip_entry.enclosed_name() {
            Some(p) => p.to_path_buf(),
            None => {
                crate::banner::print_warning(&format!(
                    "{}: entry '{}' points outside the archive (.. or an absolute path); not extracted",
                    zip_path.display(), entry_name
                ));
                continue;
            }
        };
        if zip_entry.is_dir() {
            let dir_path = extract_dir.join(&inside);
            let _ = fs::create_dir_all(&dir_path);
            continue;
        }

        let out_path = extract_dir.join(&inside);
        if let Some(parent) = out_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        // Extract file — streamed, so a multi-GB tarball inside the zip
        // never has to fit in memory.
        let mut out_file = match crate::space::create(&out_path) {
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

/// Open one zip met during discovery: detect the triage it is from its
/// entry listing and its name, extract it (nested archives included) and
/// fold the result into the discovery state.
#[allow(clippy::too_many_arguments)]
fn register_zip_extract(
    p: &Path,
    lower: &str,
    temp_dir: &Path,
    into: Option<&Path>,
    archives_scanned: &mut usize,
    triage_dirs: &mut Vec<(PathBuf, crate::parse::TriageInfo)>,
    triages: &mut Vec<crate::parse::TriageInfo>,
    all_dirs: &mut Vec<PathBuf>,
    archive_dirs: &mut Vec<(PathBuf, String)>,
) {
    if is_debug_mode() {
        println!("[DEBUG] ZIP detected: {}", p.display());
    }
    *archives_scanned += 1;
    let zip_path_str = p.to_string_lossy().to_string();

    // Detect triage type from top-level entries AND zip path
    // BEFORE extraction. The filename + path heuristics catch
    // re-zipped Velociraptor extracts whose JSON metadata
    // markers are missing (happens when users extract a VR
    // collection and re-zip only the C/ subtree).
    let triage_kind = crate::parse::read_zip_top_entries(p)
        .and_then(|entries| crate::parse::detect_triage_type(&zip_path_str, &entries));

    let mut tar_out: Vec<TarExtract> = Vec::new();
    let extracted = extract_zips_into(p, temp_dir, into, &mut tar_out);

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
        archive_dirs.push((outer_dir.clone(), lower.to_string()));
    }

    all_dirs.extend(extracted);
    register_tar_extracts(
        tar_out, archives_scanned, triage_dirs,
        triages, all_dirs, archive_dirs,
    );
}

pub fn parse_linux(files: &[String], dirs: &[String], output: Option<&String>) {
    // a tarball given with -f (a UAC collection, a tar of /etc and /var/log)
    // is opened as the archive it is, as when it lies in a folder given with
    // -d; before, it was read as one log file and nothing matched
    let (archives, logs): (Vec<String>, Vec<String>) = files.iter().cloned().partition(|f| is_tar_archive(&f.to_lowercase()) || f.to_lowercase().ends_with(".zip"));
    parse_linux_inner(&logs, &archives, dirs, output, false);
}

/// Quiet mode: skip phase headers and summary (used when integrated into parse-image mixed pipeline)
pub fn parse_linux_quiet(files: &[String], dirs: &[String], output: Option<&String>) {
    let (archives, logs): (Vec<String>, Vec<String>) = files.iter().cloned().partition(|f| is_tar_archive(&f.to_lowercase()) || f.to_lowercase().ends_with(".zip"));
    parse_linux_inner(&logs, &archives, dirs, output, true);
}

/// parse-massive's Linux side: the logs pulled out of images (`dirs`), plus
/// the Linux evidence lying loose in the case folder (`files`: log files;
/// `archives`: tarballs), each archive opened on its own so the zips of
/// the folder, which belong to the Windows pipeline, are not walked again.
pub fn parse_linux_with_archives(files: &[String], archives: &[String], dirs: &[String], output: Option<&String>, quiet: bool) {
    parse_linux_inner(files, archives, dirs, output, quiet);
}

/// The Linux evidence lying loose under the folders parse-massive was given:
/// tarballs (`.tar`, `.tar.gz`, `.tgz`: a UAC collection, a tar of `/etc` and
/// `/var/log`) and Linux log files (`auth.log`, `secure`, `wtmp`, journals…).
/// Returns `(archives, log files)`, sorted. Zips are not listed: the Windows
/// side opens them.
pub fn find_loose_linux_evidence(dirs: &[String]) -> (Vec<String>, Vec<String>) {
    let mut archives = Vec::new();
    let mut logs = Vec::new();
    for root in dirs {
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let lower = name.to_lowercase();
            let path = entry.path().to_string_lossy().to_string();
            if is_tar_archive(&lower) {
                archives.push(path);
            } else if lower.ends_with(".zip") {
                // a Cortex XDR online triage of a Linux host: its logs are in
                // the collectors' zips, which the Windows walk does not read
                let entries = crate::parse::read_zip_top_entries(entry.path()).unwrap_or_default();
                if crate::parse::is_cortex_online_layout(&entries) && crate::parse::cortex_online_is_linux(&entries) {
                    archives.push(path);
                }
            } else if is_linux_artifact(&name) && !is_config_not_log(entry.path()) {
                logs.push(path);
            }
        }
    }
    archives.sort();
    archives.dedup();
    logs.sort();
    logs.dedup();
    (archives, logs)
}

/// What the bar of the Linux pass says for a log: `host: file`, cut to 80
/// characters on a character boundary.
fn bar_message(host: &str, file: &str) -> String {
    let m = format!("{}: {}", host, file);
    if m.chars().count() > 80 {
        format!("{}...", m.chars().take(77).collect::<String>())
    } else {
        m
    }
}

fn parse_linux_inner(files: &[String], archives: &[String], dirs: &[String], output: Option<&String>, quiet: bool) {
    let start_time = std::time::Instant::now();

    // Phase 1: Search for artifacts (with ZIP support)
    if !quiet { crate::banner::print_search_start(); }

    let mut archives_scanned: usize = 0;

    // Create temp dir for ZIP extraction
    // one per run: two masstin at a time shared the folder and each
    // deleted the other's files
    let temp_dir = crate::space::temp_root().join(format!("masstin_linux_extract_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);

    // Triage tracking: maps each extraction directory to the TriageInfo of
    // the source ZIP, so the per-source breakdown can label artifacts as
    // "[TRIAGE: <type>]" instead of "[FOLDER]" pointing to a temp path.
    let mut triage_dirs: Vec<(PathBuf, crate::parse::TriageInfo)> = Vec::new();
    let mut triages: Vec<crate::parse::TriageInfo> = Vec::new();

    // Maps each archive extraction dir to the archive file it came from, so
    // the CSV `log_filename` column can show `<archive>:<path inside>`
    // instead of a masstin temp path that is gone once the run finishes.
    let mut archive_dirs: Vec<(PathBuf, String)> = Vec::new();

    // The archives (zip / tar / tar.gz / tgz) and the loose logs, found
    // first; nothing is unpacked yet. Tar archives are what Unix collectors
    // such as UAC produce; they are streamed selectively (see
    // extract_tar_recursive) and may nest (UAC wrapped in a zip, tar.gz
    // wrapped in a tar.gz). Each archive is then unpacked, its logs read
    // and its folder deleted before the next one: unpacking every package
    // first held all of them on the temporary disk at once (19 GB for a
    // few dozen UAC packages, on the system drive). The folder each one
    // goes to is chosen here, as unpacking them all in this order named
    // them, and archives and loose logs are read in the order of those
    // paths: the logs are read in the order they always were.
    let mut units: Vec<LinuxUnit> = Vec::new();
    let mut claimed: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut claim = |stem: &str| -> PathBuf {
        let mut name = stem.to_string();
        let mut n = 2;
        while claimed.contains(&name) || temp_dir.join(&name).exists() {
            name = format!("{}-{}", stem, n);
            n += 1;
        }
        claimed.insert(name.clone());
        temp_dir.join(name)
    };
    let mut archive_unit = |p: &Path, display: String, units: &mut Vec<LinuxUnit>| {
        let lower = p.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
        if lower.ends_with(".zip") {
            // (a zip that does not open is passed over, as the extraction did)
            if File::open(p).ok().and_then(|f| ZipArchive::new(f).ok()).is_none() {
                return;
            }
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("extracted").to_string();
            units.push(LinuxUnit::Archive { path: p.to_path_buf(), display, zip: true, dir: claim(&stem) });
        } else if is_tar_archive(&lower) {
            if File::open(p).is_err() {
                return;
            }
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("archive").to_string();
            units.push(LinuxUnit::Archive { path: p.to_path_buf(), display, zip: false, dir: claim(&tar_stem(&name)) });
        }
    };
    for root in dirs {
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            let p = entry.into_path();
            if !p.is_file() { continue; }
            let lower = p.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
            if lower.ends_with(".zip") || is_tar_archive(&lower) {
                if is_debug_mode() && !lower.ends_with(".zip") {
                    println!("[DEBUG] TAR detected: {}", p.display());
                }
                let display = p.to_string_lossy().to_string();
                archive_unit(&p, display, &mut units);
            }
        }
    }
    for a in archives {
        let p = Path::new(a);
        if p.is_file() {
            archive_unit(p, a.clone(), &mut units);
        }
    }
    let archive_count = units.len();
    // the loose logs: given one by one, or lying in the folders given
    let mut loose: Vec<PathBuf> = files.iter().map(PathBuf::from).collect();
    for root in dirs {
        // (a disk image's volume is walked through its listing: crate::vfs)
        for (p, is_file) in crate::vfs::walk(Path::new(root), None) {
            if !is_file { continue; }
            let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if is_linux_artifact(fname) && !is_config_not_log(&p) {
                loose.push(p);
            }
        }
    }
    loose.sort();
    loose.dedup();
    let loose_count = loose.len();
    units.extend(loose.into_iter().map(LinuxUnit::Log));
    units.sort_by(|a, b| a.key().cmp(b.key()));

    if archive_count == 0 && loose_count == 0 {
        eprintln!("[WARN] no candidate logs found");
        // an empty timeline, not none: the step that merges this one with
        // the Windows half finds a file to read (it failed on a missing one)
        write_empty_csv(output);
        let _ = fs::remove_dir_all(&temp_dir);
        return;
    }
    if !quiet {
        crate::banner::print_info(&format!(
            "{} archive(s) to open one at a time (each unpacked, read and deleted before the next), {} log file(s) outside archives",
            archive_count, loose_count
        ));
    }

    // the room this needs in the temporary folder, said before the work: the
    // biggest package unpacked, and the rows of the logs (see space::need_of)
    {
        let packed = |name: &str| [".gz", ".tgz", ".zip", ".bz2", ".xz", ".zst"].iter().any(|x| name.ends_with(x));
        let (mut biggest, mut text) = (0u64, 0u64);
        for u in &units {
            match u {
                LinuxUnit::Archive { path, .. } => {
                    let len = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                    let name = path.to_string_lossy().to_lowercase();
                    // (text logs shrink some ten times packed)
                    biggest = biggest.max(if packed(&name) { len.saturating_mul(10) } else { len });
                }
                LinuxUnit::Log(p) => {
                    let len = crate::vfs::metadata(p).map(|m| m.len()).unwrap_or(0);
                    let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                    if name.ends_with(".journal") || name.ends_with(".journal~") || name.contains("wtmp") || name.contains("btmp") || name == "utmp" || name == "lastlog" {
                        // binary: a small share of it becomes rows
                        text += len / 10;
                    } else {
                        text += if packed(&name) { len.saturating_mul(10) } else { len };
                    }
                }
            }
        }
        let need = crate::space::need_of(biggest, text);
        if let Some((line, warn)) = crate::space::forecast(need, &temp_dir) {
            if warn {
                crate::banner::print_warning(&line);
            } else if !quiet && need.at_most > (1 << 30) {
                crate::banner::print_info(&line);
            }
        }
    }

    // 2) hostname cache
    let mut root2host: HashMap<PathBuf, String> = HashMap::new();
    // Per-root local timezone (syslog lines are wall-clock) and uid map
    // (lastlog). Resolved once per root, like the hostname.
    let mut root2tz: HashMap<PathBuf, crate::linux_tz::LocalTz> = HashMap::new();
    let mut root2passwd: HashMap<PathBuf, HashMap<u32, String>> = HashMap::new();

    // Phase 2: Process artifacts
    if !quiet { crate::banner::print_processing_start(); }
    let pb = crate::banner::create_progress_bar(units.len() as u64);

    // the rows go to disk, a file per host, as each log is read; what the
    // uids resolve to is gathered on the way (see HostSpill)
    let mut spill = HostSpill::new(temp_dir.join("_masstin_rows"));
    let mut uid_votes = UidVotes::default();
    let mut spill_failed = false;
    let mut prefixes: Vec<(String, String)> = Vec::new();
    let mut parsed_count: usize = 0;
    let mut skipped: usize = 0;
    // (source_label, artifact_short_name, vss_index, count) — same structure
    // as parse-windows so banner::print_artifact_detail_grouped can render it.
    // Linux logs never come from VSS snapshots, so vss_index is always None.
    let mut artifact_details: Vec<(String, String, Option<u32>, usize)> = Vec::new();
    let mut year_cache: HashMap<PathBuf, i32> = HashMap::new();
    let mut log_no: usize = 0;
    let mut logs_found: usize = 0;
    let mut logs_in_archives: usize = 0;

    for unit in &units {
    let unit_logs: Vec<PathBuf> = match unit {
        LinuxUnit::Log(p) => vec![p.clone()],
        LinuxUnit::Archive { path, display, zip, dir } => {
            pb.set_message(format!("Reading {}", path.file_name().and_then(|s| s.to_str()).unwrap_or(display)));
            let mut unit_dirs: Vec<PathBuf> = Vec::new();
            let before = triages.len();
            if *zip {
                let lower = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                if is_debug_mode() {
                    println!("[DEBUG] ZIP detected: {}", path.display());
                }
                register_zip_extract(path, &lower, &temp_dir, Some(dir.as_path()), &mut archives_scanned, &mut triage_dirs, &mut triages, &mut unit_dirs, &mut archive_dirs);
            } else {
                let mut tar_out: Vec<TarExtract> = Vec::new();
                extract_tar_into(path, &temp_dir, Some(dir.as_path()), display, &mut tar_out);
                register_tar_extracts(tar_out, &mut archives_scanned, &mut triage_dirs, &mut triages, &mut unit_dirs, &mut archive_dirs);
            }
            // Nested triages live INSIDE their wrapper's extract dir: match the
            // most specific (longest) dir first when labelling sources.
            triage_dirs.sort_by(|a, b| b.0.as_os_str().len().cmp(&a.0.as_os_str().len()));
            archive_dirs.sort_by(|a, b| b.0.as_os_str().len().cmp(&a.0.as_os_str().len()));
            prefixes = archive_dirs.iter().map(|(d, n)| (d.to_string_lossy().replace('\\', "/"), n.clone())).collect();
            // the triages found in it, as they are (the full archive path, so
            // two copies of the same host's triage can be told apart)
            if !quiet {
                for t in &triages[before..] {
                    pb.suspend(|| crate::banner::print_triage_found(t.kind.label(), t.hostname.as_deref(), &t.zip_path, t.artifact_count));
                }
            }
            let mut logs: Vec<PathBuf> = Vec::new();
            for root in &unit_dirs {
                for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
                    let p = entry.into_path();
                    if !p.is_file() { continue; }
                    let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                    if is_linux_artifact(fname) && !is_config_not_log(&p) {
                        logs.push(p);
                    }
                }
            }
            logs.sort();
            logs.dedup();
            logs_in_archives += logs.len();
            logs
        }
    };
    logs_found += unit_logs.len();
    for path in &unit_logs {
        let log_no_now = log_no;
        log_no += 1;
        let path_str = path.to_string_lossy().to_string();

        // Find the root dir the hostname heuristics should scan. UAC lays
        // the collected filesystem out under `[root]/` with uac.log as its
        // sibling, so the dir holding `[root]` is the natural root: /etc/
        // hostname, /etc/hosts and /var/log/* all hang from it, and
        // /var/run/utmp (which has no `log` ancestor) resolves too.
        // Otherwise: walk upwards until a "log" folder and take its parent.
        let root = match path.components().position(|c| c.as_os_str() == "[root]") {
            Some(idx) => path.components().take(idx).collect::<PathBuf>(),
            None => {
                let mut found_log = false;
                let mut temp = path.parent().unwrap_or(Path::new("/"));
                let mut root_cand = temp;
                while temp.parent().is_some() {
                    if temp.file_name() == Some(OsStr::new("log")) {
                        found_log = true;
                        root_cand = temp.parent().and_then(|p| p.parent()).unwrap_or(temp);
                        break;
                    }
                    temp = temp.parent().unwrap();
                }
                if found_log {
                    root_cand.to_path_buf()
                } else {
                    // Direct/flat per-host layout: path is .../<hostname>/<logfile>
                    path.parent().unwrap_or(Path::new("/")).to_path_buf()
                }
            }
        };
        // A Cortex XDR online triage keeps each file under a made-up folder
        // (`entry_1_0/auth.log`): the folders say nothing about the host,
        // the package's tables do.
        let from_package = triage_dirs
            .iter()
            .find(|(dir, info)| info.kind == crate::parse::TriageType::CortexXdrOnline && path.starts_with(dir))
            .and_then(|(_, info)| info.hostname.clone());
        let mut dst_host = match from_package {
            Some(h) => h,
            None => root2host
                .entry(root.clone())
                .or_insert_with(|| discover_hostname(&root))
                .clone(),
        };

        // Fallback: if hostname is still unknown/generic, extract from the log's RFC3164 header
        if dst_host == "unknown" || dst_host == "C:" || dst_host.len() <= 2 {
            if let Ok(file) = crate::vfs::open(path) {
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

        // Final fallback: use the directory name itself if it is not a generic name
        if dst_host == "unknown" || dst_host == "C:" || dst_host.len() <= 2 {
            if let Some(folder_name) = root.file_name().and_then(|n| n.to_str()) {
                if !folder_name.is_empty() && folder_name != "log" && folder_name != "var" && folder_name != "/" {
                    crate::banner::print_info(&format!(
                        "Hostname identified: {} (from directory name)", folder_name
                    ));
                    dst_host = folder_name.to_string();
                    root2host.insert(root.clone(), dst_host.clone());
                }
            }
        }

        // the bar names the host and the log, not the folder of the extraction
        // (a temporary path, or the machine id a journal sits under)
        pb.set_message(bar_message(&dst_host, path.file_name().and_then(|f| f.to_str()).unwrap_or("")));

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

        // the log's rows, a batch at a time (a syslog of gigabytes hands
        // them on as it is read): renamed, counted for the uids, to disk
        let mut count = 0usize;
        {
            let mut take = |mut parsed: Vec<RawEvt>| {
                if parsed.is_empty() {
                    return;
                }
                // the log's own name instead of the temporary folder it was unpacked
                // into: `<archive>:<path inside>` (longest prefix: nested archives
                // unpack inside their wrapper's folder)
                if !prefixes.is_empty() {
                    for evt in parsed.iter_mut() {
                        let norm = evt.filename.replace('\\', "/");
                        if let Some((prefix, name)) = prefixes.iter().find(|(pfx, _)| norm.starts_with(pfx.as_str())) {
                            let inside = norm[prefix.len()..].trim_start_matches('/');
                            evt.filename = format!("{}:{}", name, inside);
                        }
                    }
                }
                for evt in &parsed {
                    uid_votes.note(evt);
                }
                if let Err(e) = spill.add_from(&parsed, log_no_now as u32, count as u32) {
                    // named with the others at the end of the run; said once here
                    crate::space::left_out(&format!("the rows of {}", path_str), &e.to_string());
                    if !spill_failed {
                        spill_failed = true;
                        crate::banner::print_warning(&format!(
                            "Could not write the rows of {} to the temporary folder ({}): they are missing from the timeline, and so are the next ones that find no room (all named at the end).",
                            path_str, e
                        ));
                    }
                }
                count += parsed.len();
            };
            if fname == "lastlog" {
                let passwd = root2passwd
                    .entry(root.clone())
                    .or_insert_with(|| load_passwd(&root));
                take(parse_lastlog(path, &dst_host, passwd));
            } else if fname == "utmp"
                || is_rotated_name(&fname, "wtmp") || is_rotated_name(&fname, "btmp")
            {
                take(parse_utmp_file(path, &dst_host, true));
            } else if fname.starts_with("secure") || fname.starts_with("auth.log") || fname.starts_with("messages") {
                parse_secure_or_messages_to(path, &dst_host, true, cached_year, tz, &mut take);
            } else if fname.starts_with("audit.log") {
                let passwd = root2passwd
                    .entry(root.clone())
                    .or_insert_with(|| load_passwd(&root));
                parse_audit_to(path, &dst_host, true, passwd, &mut take);
            } else if fname.ends_with(".journal") || fname.ends_with(".journal~") {
                take(crate::parse_journal::parse_journal_file(path, &dst_host));
            }
        }

        if count == 0 {
            skipped += 1;
        } else {
            parsed_count += 1;
            let mut source = crate::parse::source_label_for_linux_path(&path_str, &triage_dirs);
            if source.starts_with("[FOLDER]") {
                // a log out of an archive that is no known triage: name the
                // archive, not the temp folder it was unpacked into
                let norm = path_str.replace('\\', "/");
                let inside = archive_dirs
                    .iter()
                    .filter(|(d, _)| {
                        let d = d.to_string_lossy().replace('\\', "/");
                        !d.is_empty() && norm.starts_with(&d)
                    })
                    .max_by_key(|(d, _)| d.as_os_str().len());
                if let Some((_, name)) = inside {
                    let name = name.replace('\\', "/");
                    let short = name.rsplit('/').next().unwrap_or(&name);
                    source = format!("[ARCHIVE]  {}", short);
                }
            }
            let short = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&path_str)
                .to_string();
            // Linux logs never come from VSS; always None.
            artifact_details.push((source, short, None, count));
        }

        if is_debug_mode() {
            println!(
                "        {:<8} events {:>5}",
                fname.split('.').next().unwrap_or("log"),
                count,
            );
        }

    }
    // the archive's folder is deleted before the next one is unpacked
    if let LinuxUnit::Archive { dir, .. } = unit {
        let _ = fs::remove_dir_all(dir);
    }
    pb.inc(1);
    }

    pb.finish_and_clear();
    if logs_found == 0 {
        eprintln!("[WARN] no candidate logs found");
        // an empty timeline, not none: the step that merges this one with
        // the Windows half finds a file to read (it failed on a missing one)
        write_empty_csv(output);
        let _ = fs::remove_dir_all(&temp_dir);
        return;
    }
    if !quiet {
        crate::banner::print_search_results_labeled(logs_found, logs_in_archives, dirs.len(), files.len(), "Linux log artifacts");
    }
    if is_debug_mode() {
        println!("[DEBUG] {} archive(s) opened, {} candidate files", archives_scanned, logs_found);
    }
    crate::banner::print_artifact_detail_grouped(&artifact_details);

    if is_debug_mode() {
        println!(
            "[DEBUG] SUMMARY  total {:>6}",
            spill.rows
        );
    }


    // Phase 3: Generate output
    if !quiet { crate::banner::print_output_start(); }
    let uid_names = uid_votes.resolve();
    let changed = uid_votes.changed(&uid_names);
    drop(uid_votes);
    if changed > 0 {
        crate::banner::print_info(&format!(
            "{} audit records: uid resolved to account name via sshd/wtmp coincidence", changed
        ));
    }
    // what the login sessions connected to, by the audit logs' own records
    #[cfg(test)]
    let _audit_lists = AUDIT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut connects = AUDIT_CONNECTS.lock().map(|mut a| std::mem::take(&mut *a)).unwrap_or_default();
    let sessions = AUDIT_SESSIONS.lock().map(|mut a| std::mem::take(&mut *a)).unwrap_or_default();
    if !archive_dirs.is_empty() {
        for c in connects.iter_mut() {
            let norm = c.filename.replace('\\', "/");
            if let Some((d, name)) = archive_dirs.iter().map(|(d, n)| (d.to_string_lossy().replace('\\', "/"), n)).find(|(d, _)| !d.is_empty() && norm.starts_with(d.as_str())) {
                c.filename = format!("{}:{}", name, norm[d.len()..].trim_start_matches('/'));
            }
        }
    }
    let outgoing = audit_connect_rows(connects, &sessions);
    if !outgoing.is_empty() && !quiet {
        crate::banner::print_info(&format!("{} outgoing connection(s) of login sessions (auditd connect records): each is a row written from its origin, with the logon ID of the session's login", outgoing.len()));
    }
    let total_events = spill.rows + outgoing.len();
    write_by_host(&spill, &uid_names, outgoing, output);

    if !quiet {
        crate::banner::print_summary(total_events, parsed_count, skipped, output.map(|s| s.as_str()), start_time);
    }

    // Cleanup temp extraction dir
    let _ = fs::remove_dir_all(&temp_dir);
}

#[cfg(test)]
mod rfc3164_year_tests {
    use super::*;

    /// The bar of the Linux pass names the host and the log, cut on a
    /// character boundary.
    #[test]
    fn the_bar_names_the_host_and_the_log() {
        assert_eq!(bar_message("web01", "auth.log"), "web01: auth.log");
        let long = bar_message("bastion01", &format!("system@{}.journal", "é".repeat(90)));
        assert_eq!(long.chars().count(), 80);
        assert!(long.starts_with("bastion01: system@") && long.ends_with("..."));
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("masstin_y_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn written(path: &Path, text: &str, ymd: Option<(i32, u32, u32)>) {
        fs::write(path, text).unwrap();
        if let Some((y, m, d)) = ymd {
            let t = NaiveDate::from_ymd_opt(y, m, d).unwrap().and_hms_opt(12, 0, 0).unwrap().and_utc();
            fs::File::options().write(true).open(path).unwrap().set_modified(t.into()).unwrap();
        }
    }

    fn times(path: &Path) -> Vec<String> {
        parse_secure_or_messages(path, "srv01", true, Some(1999), &crate::linux_tz::LocalTz::Utc).into_iter().map(|e| format!("{} {}", &e.ts_rfc3339[..19], e.remote)).collect()
    }

    fn line(stamp: &str, pid: u32, ip: &str) -> String {
        format!("{} srv01 sshd[{}]: Accepted password for admin from {} port 50000 ssh2\n", stamp, pid, ip)
    }

    fn crossing() -> String {
        [line("Dec 31 23:58:10", 1201, "10.0.0.9"), line("Jan  2 10:00:00", 1302, "10.0.0.66"), line("Jan  5 03:12:44", 1407, "203.0.113.50")].concat()
    }

    #[test]
    fn a_file_in_use_that_crosses_the_new_year() {
        // dpkg.log was last rotated in December: its year is the old one
        let d = dir("live");
        written(&d.join("dpkg.log"), "2024-12-14 06:25:01 startup archives unpack\n", None);
        written(&d.join("auth.log"), &crossing(), Some((2025, 1, 6)));
        assert_eq!(times(&d.join("auth.log")), ["2024-12-31T23:58:10 10.0.0.9", "2025-01-02T10:00:00 10.0.0.66", "2025-01-05T03:12:44 203.0.113.50"]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_copy_that_lost_its_dates_is_dated_by_the_systems_records() {
        let d = dir("copy");
        written(&d.join("dpkg.log"), "2024-12-14 06:25:01 startup archives unpack\n", None);
        written(&d.join("auth.log"), &crossing(), Some((2026, 5, 1)));
        assert_eq!(times(&d.join("auth.log")), ["2024-12-31T23:58:10 10.0.0.9", "2025-01-02T10:00:00 10.0.0.66", "2025-01-05T03:12:44 203.0.113.50"]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn pam_failures_are_the_fallback_of_a_file_without_sshd_results() {
        // RHEL 4/5: `sshd(pam_unix)[pid]`, in `messages`, no user when the
        // account does not exist
        let d = dir("pam");
        let old = "Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 
Jun 15 02:04:59 combo sshd(pam_unix)[20882]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
";
        written(&d.join("messages"), old, Some((2005, 6, 20)));
        let rows: Vec<String> = parse_secure_or_messages(&d.join("messages"), "combo", false, None, &crate::linux_tz::LocalTz::Utc).into_iter().map(|e| format!("{} {} {} [{}]", &e.ts_rfc3339[..19], e.evt, e.remote, e.user)).collect();
        assert_eq!(rows, ["2005-06-14T15:16:01 SSH_FAILED 218.188.2.4 []", "2005-06-15T02:04:59 SSH_FAILED 220-135-151-1.hinet-ip.hinet.net [root]"]);
        // today's shape still read; a success of pam_sss is not a failure
        let new = "Jun 14 15:16:01 srv sshd[77]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.5  user=ana
Jun 14 15:16:02 srv sshd[77]: pam_sss(sshd:auth): authentication success; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.5 user=ana
";
        written(&d.join("secure"), new, Some((2005, 6, 20)));
        let rows: Vec<String> = parse_secure_or_messages(&d.join("secure"), "srv", false, None, &crate::linux_tz::LocalTz::Utc).into_iter().map(|e| format!("{} {} [{}]", e.evt, e.remote, e.user)).collect();
        assert_eq!(rows, ["SSH_FAILED 10.0.0.5 [ana]"]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_quiet_stretch_is_not_a_turn_of_the_year() {
        assert_eq!((year_turn(12, 1), year_turn(1, 12), year_turn(2, 1), year_turn(1, 8), year_turn(3, 10), year_turn(6, 12), year_turn(6, 1), year_turn(11, 2), year_turn(5, 5)), (1, -1, 0, 0, 0, 0, 1, 1, 0));
        // a host that logged in January and again in August, same year
        let d = dir("quiet");
        written(&d.join("auth.log"), &[line("Jan 10 08:00:00", 1, "10.0.0.1"), line("Aug 20 09:00:00", 2, "10.0.0.2")].concat(), Some((2025, 8, 21)));
        assert_eq!(times(&d.join("auth.log")), ["2025-01-10T08:00:00 10.0.0.1", "2025-08-20T09:00:00 10.0.0.2"]);
        // quiet from June to January: the year turned in between
        written(&d.join("secure"), &[line("Jun 10 08:00:00", 1, "10.0.0.1"), line("Jan 20 09:00:00", 2, "10.0.0.2")].concat(), Some((2025, 1, 21)));
        assert_eq!(times(&d.join("secure")), ["2024-06-10T08:00:00 10.0.0.1", "2025-01-20T09:00:00 10.0.0.2"]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_rotated_file_is_dated_by_its_suffix() {
        let d = dir("rot");
        let log = [line("Dec 30 08:00:00", 1, "10.0.0.1"), line("Jan  2 09:00:00", 2, "10.0.0.2")].concat();
        written(&d.join("secure-20260104"), &log, Some((2030, 5, 1)));
        assert_eq!(times(&d.join("secure-20260104")), ["2025-12-30T08:00:00 10.0.0.1", "2026-01-02T09:00:00 10.0.0.2"]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_late_line_at_midnight_does_not_turn_the_year_twice() {
        let d = dir("plain");
        let log = [line("Nov  3 10:00:00", 1, "10.0.0.1"), line("Jan  1 00:00:01", 2, "10.0.0.2"), line("Dec 31 23:59:59", 3, "10.0.0.3"), line("Jan  1 00:00:02", 4, "10.0.0.4")].concat();
        written(&d.join("auth.log"), &log, Some((2025, 1, 1)));
        assert_eq!(times(&d.join("auth.log")), ["2024-11-03T10:00:00 10.0.0.1", "2025-01-01T00:00:01 10.0.0.2", "2024-12-31T23:59:59 10.0.0.3", "2025-01-01T00:00:02 10.0.0.4"]);
        let _ = fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod repeated_tests {
    use super::{expand_repeated, invalid_users_as_failures, RawEvt, INVALID_USER_EVT, INVALID_USER_RE};

    #[test]
    fn invalid_user_is_a_failed_logon() {
        let ev = |t: &str, evt: &str, user: &str, detail: &str, pid: u32| RawEvt {
            ts_rfc3339: t.into(), user: user.into(), remote: "203.0.113.9".into(),
            tty_or_proc: detail.into(), evt: evt.into(), filename: "auth.log".into(),
            dst_host: "web01".into(), pid, conn: 0,
        };
        let mut out = vec![
            // key-only server: announcement and pre-auth close, nothing else
            ev("t1", INVALID_USER_EVT, "admin", "ssh/invalid-user", 10),
            ev("t2", "SSH_PREAUTH", "", "ssh/preauth-closed invalid-user=admin", 10),
            // password server: the Failed line is the failure, no extra row
            ev("t3", INVALID_USER_EVT, "guest", "ssh/invalid-user", 11),
            ev("t4", "SSH_FAILED", "guest", "ssh/password invalid-user", 11),
            // only the close names the invalid user
            ev("t5", "SSH_PREAUTH", "", "ssh/preauth-closed invalid-user=test", 12),
            // an existing account that gave up: still a pre-auth touch
            ev("t6", "SSH_PREAUTH", "", "ssh/preauth-closed user=root", 13),
        ];
        invalid_users_as_failures(&mut out, "ssh");
        let got: Vec<(&str, &str, &str)> = out.iter().map(|e| (e.ts_rfc3339.as_str(), e.evt.as_str(), e.user.as_str())).collect();
        assert_eq!(got, vec![
            ("t1", "SSH_FAILED", "admin"),
            ("t4", "SSH_FAILED", "guest"),
            ("t5", "SSH_FAILED", "test"),
            ("t6", "SSH_PREAUTH", ""),
        ]);
        assert!(INVALID_USER_RE.is_match("web01 sshd[4242]: Invalid user admin from 203.0.113.9 port 4242"));
        assert_eq!(&INVALID_USER_RE.captures("Invalid user  0101 from 5.188.10.180").unwrap()[1], " 0101");
    }

    #[test]
    fn repeated_lines_are_expanded() {
        let l = "Sep 25 10:11:12 host sshd[12]: message repeated 3 times: [ Failed password for root from 10.0.0.9 port 1 ssh2]".to_string();
        let v = expand_repeated(l);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], "Sep 25 10:11:12 host sshd[12]: Failed password for root from 10.0.0.9 port 1 ssh2");
        let plain = "Sep 25 10:11:12 host sshd[12]: Accepted publickey for u from 10.0.0.9 port 1 ssh2".to_string();
        assert_eq!(expand_repeated(plain.clone()), vec![plain]);
    }

    #[test]
    fn port_scan_and_timeouts_are_captured() {
        use super::{PREAUTH_PORT_CLOSED_RE, PREAUTH_TIMEOUT_RE};
        assert!(PREAUTH_PORT_CLOSED_RE.is_match("Connection closed by 203.0.113.86 port 23048"));
        assert_eq!(&PREAUTH_PORT_CLOSED_RE.captures("Connection closed by 203.0.113.86 port 23048").unwrap()[1], "203.0.113.86");
        assert!(PREAUTH_TIMEOUT_RE.is_match("Timeout before authentication for connection from 203.0.113.86 to 192.0.2.12, pid = 770043"));
        assert!(PREAUTH_TIMEOUT_RE.is_match("drop connection #0 from [203.0.113.86]:40399 on [192.0.2.12]:22 penalty: exceeded LoginGraceTime"));
        assert_eq!(&PREAUTH_TIMEOUT_RE.captures("drop connection #0 from [203.0.113.86]:40399 on [192.0.2.12]:22 penalty: exceeded LoginGraceTime").unwrap()[1], "203.0.113.86");
    }

    #[test]
    fn preauth_sources_may_be_names_and_never_peer() {
        use super::preauth_touch;
        // a host with UseDNS yes writes the resolved name, as in Accepted / Failed
        assert_eq!(preauth_touch("Connection closed by invalid user admin ws07.corp.example port 4242 [preauth]"),
                   Some(("ws07.corp.example".into(), "preauth-closed invalid-user=admin".into())));
        assert_eq!(preauth_touch("Received disconnect from 2001:db8::7 port 51000:11: Bye Bye [preauth]"),
                   Some(("2001:db8::7".into(), "preauth-closed".into())));
        assert_eq!(preauth_touch("Received disconnect from 203.0.113.9: 11: disconnected by user [preauth]"),
                   Some(("203.0.113.9".into(), "preauth-closed".into())));
        assert_eq!(preauth_touch("Read from socket failed: Connection reset by peer [preauth]"), None);
        assert_eq!(preauth_touch("Disconnected from user alice 203.0.113.9 port 51000"), None);
    }

    #[test]
    fn short_iso_offsets_get_their_colon() {
        use super::iso_offset_with_colon;
        assert_eq!(iso_offset_with_colon("2026-09-25T10:11:12+0200"), "2026-09-25T10:11:12+02:00");
        assert_eq!(iso_offset_with_colon("2026-09-25T10:11:12.123456-0500"), "2026-09-25T10:11:12.123456-05:00");
        assert_eq!(iso_offset_with_colon("2026-09-25T10:11:12+02:00"), "2026-09-25T10:11:12+02:00");
        assert_eq!(iso_offset_with_colon("2026-09-25T10:11:12Z"), "2026-09-25T10:11:12Z");
        assert!(chrono::DateTime::parse_from_rfc3339(&iso_offset_with_colon("2026-09-25T10:11:12+0200")).is_ok());
    }

    /// A utmp record of either glibc size: USER_PROCESS, pid 4242, line
    /// pts/0, user alice, host 10.0.0.5, time 2026-01-01T08:00:00Z.
    fn utmp_bytes(size: usize) -> Vec<u8> {
        let mut r = vec![0u8; size];
        r[0..2].copy_from_slice(&7i16.to_le_bytes());
        r[4..8].copy_from_slice(&4242i32.to_le_bytes());
        r[8..13].copy_from_slice(b"pts/0");
        r[44..49].copy_from_slice(b"alice");
        r[76..84].copy_from_slice(b"10.0.0.5");
        let secs: i64 = 1_767_254_400;
        if size == 400 {
            // offsetof(struct utmp, ut_tv) on aarch64, from its compiler
            r[344..352].copy_from_slice(&secs.to_le_bytes());
        } else {
            r[340..344].copy_from_slice(&(secs as u32).to_le_bytes());
        }
        r
    }

    #[test]
    fn utmp_layout_is_detected_per_file() {
        use super::{utmp_layout, utmp_record};
        let x86: Vec<u8> = (0..5).flat_map(|_| utmp_bytes(384)).collect();
        assert_eq!(utmp_layout(&x86), Some((384, false)));
        let arm: Vec<u8> = (0..5).flat_map(|_| utmp_bytes(400)).collect();
        assert_eq!(utmp_layout(&arm), Some((400, true)));
        let (t, pid, line, user, host, secs) = utmp_record(&arm[400..800], true);
        assert_eq!((t, pid, line.as_str(), user.as_str(), host.as_str(), secs), (7, 4242, "pts/0", "alice", "10.0.0.5", 1_767_254_400));
        assert_eq!(utmp_layout(b"not a utmp file at all, just text that is long enough to try"), None);
        assert_eq!(utmp_layout(&[]), None);
    }

    #[test]
    fn lastlog_layout_is_detected_per_file() {
        use super::{lastlog_layout, lastlog_record};
        let slot = |size: usize, secs: i64| {
            let mut r = vec![0u8; size];
            let body = if size == 296 { r[0..8].copy_from_slice(&secs.to_le_bytes()); 8 } else { r[0..4].copy_from_slice(&(secs as u32).to_le_bytes()); 4 };
            r[body..body + 5].copy_from_slice(b"pts/1");
            r[body + 32..body + 40].copy_from_slice(b"10.0.0.9");
            r
        };
        let mut x86 = vec![0u8; 292 * 1000];
        x86[292 * 1000..].copy_from_slice(&[]);
        x86.extend(slot(292, 1_767_254_400));
        assert_eq!(lastlog_layout(&x86), Some(292));
        let mut arm = vec![0u8; 296 * 1000];
        arm.extend(slot(296, 1_767_254_400));
        assert_eq!(lastlog_layout(&arm), Some(296));
        let (secs, line, host) = lastlog_record(&arm[296 * 1000..]);
        assert_eq!((secs, line.as_str(), host.as_str()), (1_767_254_400, "pts/1", "10.0.0.9"));
    }
}

#[cfg(test)]
mod loose_evidence_tests {
    use super::{find_loose_linux_evidence, parse_linux_with_archives, is_linux_artifact};

    #[test]
    fn rotations_count_and_lookalikes_do_not() {
        for n in ["messages", "messages.1", "messages.2.gz", "messages-20261101", "secure", "secure-20261101.gz", "auth.log", "auth.log.1", "wtmp", "btmp.1"] {
            assert!(is_linux_artifact(n), "{n}");
        }
        for n in ["messages.cpython-310.pyc", "messages_old.txt", "secure-boot.conf", "securefile", "messages.json"] {
            assert!(!is_linux_artifact(n), "{n}");
        }
    }
    use std::io::Write;

    fn tar_gz(path: &std::path::Path, files: &[(&str, &str)]) {
        let f = std::fs::File::create(path).unwrap();
        let gz = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
        let mut b = tar::Builder::new(gz);
        for (name, body) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(1_794_268_800); // 2026-11-10
            h.set_cksum();
            b.append_data(&mut h, name, body.as_bytes()).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap();
    }

    /// parse-massive used to read Linux logs only out of disk images: a
    /// Linux triage lying in the case folder as a tarball was skipped
    /// without a word. The folder's tarballs and loose Linux logs are now
    /// found (its zips are left to the Windows side), and a tarball named
    /// on its own is opened and parsed.
    #[test]
    fn loose_linux_tarballs_and_logs_are_found_and_parsed() {
        let dir = std::env::temp_dir().join(format!("masstin_loose_linux_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("triage-linux")).unwrap();
        std::fs::create_dir_all(dir.join("copied/var/log")).unwrap();
        std::fs::create_dir_all(dir.join("triage-windows")).unwrap();

        let tgz = dir.join("triage-linux").join("web01-triage.tgz");
        tar_gz(&tgz, &[
            ("etc/hostname", "web01\n"),
            ("var/log/auth.log", "Nov 10 08:00:00 web01 sshd[100]: Accepted password for deploy from 203.0.113.45 port 55555 ssh2\n"),
        ]);
        std::fs::write(dir.join("copied/var/log/auth.log"), "Nov 10 09:00:00 db01 sshd[7]: Failed password for root from 198.51.100.7 port 1 ssh2\n").unwrap();
        std::fs::write(dir.join("triage-windows").join("dc01-triage.zip"), b"not opened here").unwrap();
        std::fs::write(dir.join("triage-windows").join("notes.txt"), b"x").unwrap();
        std::fs::create_dir_all(dir.join("copied/etc/logrotate.d")).unwrap();
        std::fs::write(dir.join("copied/etc/logrotate.d/wtmp"), b"/var/log/wtmp { monthly }").unwrap();

        let (archives, logs) = find_loose_linux_evidence(&[dir.to_string_lossy().to_string()]);
        assert_eq!(archives.len(), 1, "{archives:?}");
        assert!(archives[0].ends_with("web01-triage.tgz"));
        assert_eq!(logs.len(), 1, "{logs:?}");
        assert!(logs[0].replace('\\', "/").ends_with("copied/var/log/auth.log"));

        let out = dir.join("out.csv").to_string_lossy().to_string();
        parse_linux_with_archives(&[], &archives, &[], Some(&out), true);
        let mut csv = String::new();
        std::io::Read::read_to_string(&mut std::fs::File::open(&out).unwrap(), &mut csv).unwrap();
        let row = csv.lines().find(|l| l.contains("203.0.113.45")).unwrap_or_else(|| panic!("no row from the tarball:\n{csv}"));
        assert!(row.contains("deploy") && row.contains("SUCCESSFUL_LOGON"), "{row}");
        assert!(row.to_lowercase().contains("web01"), "the host comes from the tarball's /etc/hostname: {row}");
        let _ = std::io::stdout().flush();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod review_2026_11_tests {
    use super::*;

    /// What a login session connected to, by the audit log's own records:
    /// a row written from the origin, with the logon ID of the session's
    /// login (the pid of its sshd), one per connection.
    #[test]
    fn auditd_connect_records_become_rows_of_the_session() {
        // (no parse of another test empties the shared lists between the read and the look)
        let _audit_lists = AUDIT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("masstin-auditconn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        let log = [
            // the login: sshd 4242 opens login session 5 for uid 1000
            r#"type=USER_LOGIN msg=audit(1763418000.100:400): pid=4242 uid=0 auid=1000 ses=5 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=10.0.0.5 addr=10.0.0.5 terminal=/dev/pts/0 res=success'"#,
            // that session runs ssh to 10.10.0.38:22 (0x0A0A0026, port 0x0016)
            r#"type=SYSCALL msg=audit(1763418060.200:410): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffd0 a2=10 a3=0 items=0 ppid=4250 pid=4300 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=5 comm="ssh" exe="/usr/bin/ssh" key="netconn""#,
            r#"type=SOCKADDR msg=audit(1763418060.200:410): saddr=020000160A0A00260000000000000000"#,
            // the same again a few seconds later: the same connection being made
            r#"type=SYSCALL msg=audit(1763418065.200:411): arch=c000003e syscall=42 success=yes exit=0 a0=3 a2=10 items=0 ppid=4250 pid=4300 auid=1000 uid=1000 tty=pts0 ses=5 comm="ssh" exe="/usr/bin/ssh" key="netconn""#,
            r#"type=SOCKADDR msg=audit(1763418065.200:411): saddr=020000160A0A00260000000000000000"#,
            // a web request of the session, a daemon's connect, a loopback one, a failed one: not rows
            r#"type=SYSCALL msg=audit(1763418070.200:412): arch=c000003e syscall=42 success=yes exit=0 a0=3 a2=10 items=0 pid=4301 auid=1000 uid=1000 ses=5 comm="curl" exe="/usr/bin/curl" key="netconn""#,
            r#"type=SOCKADDR msg=audit(1763418070.200:412): saddr=020001BB5DB8D8220000000000000000"#,
            r#"type=SYSCALL msg=audit(1763418071.200:413): arch=c000003e syscall=42 success=yes exit=0 a0=3 a2=10 items=0 pid=900 auid=4294967295 uid=0 ses=4294967295 comm="smbd" exe="/usr/sbin/smbd" key="netconn""#,
            r#"type=SOCKADDR msg=audit(1763418071.200:413): saddr=020001BD0A0A00260000000000000000"#,
            r#"type=SYSCALL msg=audit(1763418072.200:414): arch=c000003e syscall=42 success=yes exit=0 a0=3 a2=10 items=0 pid=4302 auid=1000 uid=1000 ses=5 comm="ssh" exe="/usr/bin/ssh" key="netconn""#,
            r#"type=SOCKADDR msg=audit(1763418072.200:414): saddr=020000167F0000010000000000000000"#,
            r#"type=SYSCALL msg=audit(1763418073.200:415): arch=c000003e syscall=42 success=no exit=-111 a0=3 a2=10 items=0 pid=4303 auid=1000 uid=1000 ses=5 comm="ssh" exe="/usr/bin/ssh" key="netconn""#,
            r#"type=SOCKADDR msg=audit(1763418073.200:415): saddr=020000160A0A00270000000000000000"#,
            // SMB from the same session, on a non-blocking socket (still connecting), in the enriched form
            r#"type=SYSCALL msg=audit(1763418120.300:420): arch=c000003e syscall=42 success=no exit=-115 a0=4 a2=10 items=0 pid=4310 auid=1000 uid=1000 ses=5 comm="smbclient" exe="/usr/bin/smbclient" key="netconn" ARCH=x86_64 SYSCALL=connect AUID="alice" UID="alice""#,
            r#"type=SOCKADDR msg=audit(1763418120.300:420): saddr=020001BD0A0A00250000000000000000 SADDR={ saddr_fam=inet laddr=10.10.0.37 lport=445 }"#,
            // a session with no login in the log, to RDP over IPv6
            r#"type=SYSCALL msg=audit(1763418200.300:430): arch=c00000b7 syscall=203 success=yes exit=0 a0=4 items=0 pid=5000 auid=1001 uid=1001 ses=9 comm="xfreerdp" exe="/usr/bin/xfreerdp" key="netconn""#,
            r#"type=SOCKADDR msg=audit(1763418200.300:430): saddr=0A000D3D00000000FD000000000000000000000000000007000000000000"#,
        ]
        .join("\n");
        std::fs::write(&path, format!("{}\n", log)).unwrap();
        let host = format!("auditconn-{}", std::process::id());
        let passwd: HashMap<u32, String> = [(1000u32, "alice".to_string())].into_iter().collect();
        let logins = parse_audit(&path, &host, true, &passwd);
        assert_eq!(logins.iter().filter(|e| e.evt == "SSH_SUCCESS").count(), 1);
        assert_eq!(logins[0].pid, 4242);
        // (the lists are shared by every audit log read in this process: take this host's)
        let mine: Vec<AuditConnect> = AUDIT_CONNECTS.lock().unwrap().iter().filter(|c| c.host == host).cloned().collect();
        let sessions: Vec<(String, u64, u32, i64)> = AUDIT_SESSIONS.lock().unwrap().iter().filter(|x| x.0 == host).cloned().collect();
        AUDIT_CONNECTS.lock().unwrap().retain(|c| c.host != host);
        AUDIT_SESSIONS.lock().unwrap().retain(|x| x.0 != host);
        assert_eq!(sessions, vec![(host.clone(), 5, 4242, 1763418000)]);
        assert_eq!(mine.iter().map(|c| (c.addr.as_str(), c.port, c.ses, c.user.as_str(), c.comm.as_str())).collect::<Vec<_>>(), vec![
            ("10.10.0.38", 22, 5, "alice", "ssh"),
            ("10.10.0.38", 22, 5, "alice", "ssh"),
            ("10.10.0.37", 445, 5, "alice", "smbclient"),
            ("fd00::7", 3389, 9, "uid:1001", "xfreerdp"),
        ]);
        let rows = audit_connect_rows(mine, &sessions);
        let cells: Vec<Vec<String>> = rows.iter().map(|(_, l)| l.trim_end().split(',').map(|c| c.trim_matches('"').to_string()).collect()).collect();
        assert_eq!(rows.len(), 3, "{:?}", rows);
        // time, destination, CONNECT, AUDIT_CONNECT, logon type, -, -, origin, -, the session's account, -, the logon ID of the login
        assert_eq!(cells[0][..12], ["2025-11-17T22:21:00+00:00", "10.10.0.38", "CONNECT", "AUDIT_CONNECT", "SSH", "", "", host.as_str(), "", "alice", "", "4242"]);
        assert_eq!(cells[1][..12], ["2025-11-17T22:22:00+00:00", "10.10.0.37", "CONNECT", "AUDIT_CONNECT", "3", "", "", host.as_str(), "", "alice", "", "4242"]);
        assert_eq!((cells[2][1].as_str(), cells[2][4].as_str(), cells[2][11].as_str()), ("fd00::7", "10", "ses:9"));
        assert!(rows[0].1.contains(r#","ssh to 10.10.0.38:22, auditd login session 5","#), "{}", rows[0].1);
        assert_eq!(audit_saddr("0100"), None);
        assert_eq!(audit_saddr("020000160A0A0026"), Some(("10.10.0.38".to_string(), 22)));
        let _ = std::fs::remove_dir_all(dir);
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("masstin_rev_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// sshd's own lines, from the lab (LEO-LNX01, OpenSSH 8.9, 2026-11-16):
    /// a client announced itself with account names written to look like
    /// log lines. Every one is a failed logon from the client's address
    /// and none is a logon of root from the address in the name.
    #[test]
    fn an_account_name_that_looks_like_a_log_line_forges_nothing() {
        let log = "\
Nov 16 07:33:44 LEO-LNX01 sshd[32166]: Invalid user Accepted password for root from 8.8.8.8 port 1 ssh2 from 10.10.0.49 port 59318
Nov 16 07:33:45 LEO-LNX01 sshd[32166]: Connection closed by invalid user Accepted password for root from 8.8.8.8 port 1 ssh2 10.10.0.49 port 59318 [preauth]
Nov 16 07:33:45 LEO-LNX01 sshd[32168]: Invalid user x] from 10.10.0.49 port 59322
Nov 16 07:33:45 LEO-LNX01 sshd[32168]: Connection closed by invalid user x] 10.10.0.49 port 59322 [preauth]
Nov 16 07:33:45 LEO-LNX01 sshd[32170]: Invalid user User root from 8.8.8.7 not allowed because from 10.10.0.49 port 59334
Nov 16 07:33:45 LEO-LNX01 sshd[32170]: Connection closed by invalid user User root from 8.8.8.7 not allowed because 10.10.0.49 port 59334 [preauth]
Nov 16 07:33:45 LEO-LNX01 sshd[32172]: Invalid user masstin b2 plain from 10.10.0.49 port 59346
Nov 16 07:33:45 LEO-LNX01 sshd[32172]: Connection closed by invalid user masstin b2 plain 10.10.0.49 port 59346 [preauth]
";
        let d = tmp("forged");
        let p = d.join("auth.log");
        fs::write(&p, log).unwrap();
        let evs = parse_secure_or_messages(&p, "LEO-LNX01", true, Some(2026), &crate::linux_tz::LocalTz::Utc);
        let got: Vec<(String, String, String)> = evs.iter().map(|e| (e.evt.clone(), e.user.clone(), e.remote.clone())).collect();
        assert_eq!(
            got,
            [
                ("SSH_FAILED".to_string(), "Accepted password for root from 8.8.8.8 port 1 ssh2".to_string(), "10.10.0.49".to_string()),
                ("SSH_FAILED".to_string(), "x]".to_string(), "10.10.0.49".to_string()),
                ("SSH_FAILED".to_string(), "User root from 8.8.8.7 not allowed because".to_string(), "10.10.0.49".to_string()),
                ("SSH_FAILED".to_string(), "masstin b2 plain".to_string(), "10.10.0.49".to_string()),
            ]
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn sshd_lines_are_read_from_their_start_and_their_last_source() {
        // as they come in every source: with the syslog tag, bare (journal,
        // macOS), after an RFC5424 header, with a level
        for l in [
            " web01 sshd[4242]: Accepted publickey for alice from 10.0.0.5 port 50022 ssh2: ED25519 SHA256:abc",
            "Accepted publickey for alice from 10.0.0.5 port 50022 ssh2: ED25519 SHA256:abc",
            " - - Accepted publickey for alice from 10.0.0.5 port 50022 ssh2",
            "web01 sshd-session[4242]: Accepted publickey for alice from 10.0.0.5 port 50022 ssh2",
            "web01 sshd[4242]: [ID 800047 auth.info] Accepted publickey for alice from 10.0.0.5 port 50022 ssh2",
        ] {
            let c = SSH_OK_RE.captures(l).unwrap_or_else(|| panic!("{}", l));
            assert_eq!((&c[1], &c[2], &c[3]), ("publickey", "alice", "10.0.0.5"), "{}", l);
        }
        // the same words inside a line of another kind are not a logon
        for l in [
            "web01 sshd[1]: Invalid user Accepted password for root from 8.8.8.8 port 1 ssh2 from 10.10.0.49 port 59318",
            "web01 sshd[1]: Failed password for invalid user Accepted password for root from 8.8.8.8 port 1 ssh2 from 10.10.0.49 port 5 ssh2",
            "web01 sshd[1]: Connection closed by invalid user Accepted password for root from 8.8.8.8 port 1 ssh2 10.10.0.49 port 59318 [preauth]",
            "web01 sshd[1]: x]: Accepted password for root from 8.8.8.9 port 2 ssh2",
        ] {
            assert!(SSH_OK_RE.captures(l).is_none(), "{}", l);
        }
        let f = |l: &str| SSH_FAIL_RE.captures(l).map(|c| (c[1].to_string(), c.get(2).is_some(), c[3].to_string(), c[4].to_string()));
        assert_eq!(f("web01 sshd[9]: Failed password for root from 203.0.113.9 port 22 ssh2"), Some(("password".into(), false, "root".into(), "203.0.113.9".into())));
        assert_eq!(f("web01 sshd[9]: Failed password for invalid user bob from 203.0.113.9 port 22 ssh2"), Some(("password".into(), true, "bob".into(), "203.0.113.9".into())));
        assert_eq!(f("Failed publickey for git from 203.0.113.9 port 22 ssh2: RSA SHA256:abcdef"), Some(("publickey".into(), false, "git".into(), "203.0.113.9".into())));
        assert_eq!(f("Failed none for invalid user  0101 from 5.188.10.180 port 9 ssh2"), Some(("none".into(), true, " 0101".into(), "5.188.10.180".into())));
        // the source is the one sshd wrote last, not one inside the name
        assert_eq!(
            f("web01 sshd[9]: Failed password for invalid user a from 8.8.8.8 port 1 ssh2 from 203.0.113.9 port 5 ssh2"),
            Some(("password".into(), true, "a from 8.8.8.8 port 1 ssh2".into(), "203.0.113.9".into()))
        );
        assert_eq!(
            f("web01 sshd[9]: Failed password for invalid user a from 8.8.8.8 port 1 ssh2: x y from 203.0.113.9 port 5 ssh2"),
            Some(("password".into(), true, "a from 8.8.8.8 port 1 ssh2: x y".into(), "203.0.113.9".into()))
        );
        assert!(SSH_NOTALLOWED_RE.is_match("web01 sshd[9]: User bob from host.example not allowed because not listed in AllowUsers"));
        assert!(!SSH_NOTALLOWED_RE.is_match("web01 sshd[9]: Invalid user User root from 8.8.8.7 not allowed because from 10.10.0.49 port 59334"));
    }

    #[test]
    fn a_pre_auth_touch_names_the_address_sshd_wrote() {
        let t = |l: &str| preauth_touch(l);
        assert_eq!(t("web01 sshd[1]: Connection closed by 203.0.113.9 port 4242 [preauth]"), Some(("203.0.113.9".into(), "preauth-closed".into())));
        assert_eq!(t("web01 sshd[1]: Connection closed by authenticating user root 203.0.113.9 port 4242 [preauth]"), Some(("203.0.113.9".into(), "preauth-closed user=root".into())));
        assert_eq!(t("web01 sshd[1]: Disconnected from invalid user admin 203.0.113.9 port 4242 [preauth]"), Some(("203.0.113.9".into(), "preauth-closed invalid-user=admin".into())));
        assert_eq!(t("web01 sshd[1]: Received disconnect from 203.0.113.9 port 4242:11: Bye Bye [preauth]"), Some(("203.0.113.9".into(), "preauth-closed".into())));
        assert_eq!(t("web01 sshd[1]: error: Received disconnect from 203.0.113.9 port 4242:3: com.jcraft.jsch.JSchException: Auth fail [preauth]"), Some(("203.0.113.9".into(), "preauth-closed".into())));
        // OpenSSH before 7: no port
        assert_eq!(t("web01 sshd[1]: Connection closed by 203.0.113.9 [preauth]"), Some(("203.0.113.9".into(), "preauth-closed".into())));
        assert_eq!(t("web01 sshd[1]: Received disconnect from 203.0.113.9: 11: Bye Bye [preauth]"), Some(("203.0.113.9".into(), "preauth-closed".into())));
        assert_eq!(t("web01 sshd[1]: Did not receive identification string from 203.0.113.9 port 4242"), Some(("203.0.113.9".into(), "preauth-no-ident".into())));
        assert_eq!(t("web01 sshd[1]: Bad protocol version identification 'GET / from 8.8.8.8' from 203.0.113.9 port 4242"), Some(("203.0.113.9".into(), "preauth-bad-proto".into())));
        // the lab's line: the address is the client's, whatever the name says
        let (src, detail) = t("LEO-LNX01 sshd[32166]: Connection closed by invalid user Accepted password for root from 8.8.8.8 port 1 ssh2 10.10.0.49 port 59318 [preauth]").unwrap();
        assert_eq!(src, "10.10.0.49");
        assert!(detail.starts_with("preauth-closed invalid-user=Accepted password"));
        assert_eq!(t("web01 sshd[1]: Read from socket failed: Connection reset by peer [preauth]"), None);
        // inside another line they are nothing
        assert_eq!(t("web01 sshd[1]: Invalid user Connection closed by 8.8.8.8 port 1 from 203.0.113.9 port 5"), None);
    }

    /// The same pid weeks apart is another connection: the failed password
    /// of January does not cancel the unknown account of February.
    #[test]
    fn a_pid_used_again_is_another_connection() {
        let ev = |t: &str, evt: &str, user: &str, detail: &str, pid: u32| RawEvt {
            ts_rfc3339: t.into(), user: user.into(), remote: "203.0.113.9".into(),
            tty_or_proc: detail.into(), evt: evt.into(), filename: "auth.log".into(),
            dst_host: "web01".into(), pid, conn: 0,
        };
        let mut out = vec![
            ev("2026-01-05T10:00:00+00:00", INVALID_USER_EVT, "guest", "ssh/invalid-user", 4242),
            ev("2026-01-05T10:00:02+00:00", "SSH_FAILED", "guest", "ssh/password invalid-user", 4242),
            ev("2026-02-09T03:00:00+00:00", INVALID_USER_EVT, "oracle", "ssh/invalid-user", 4242),
            ev("2026-02-09T03:00:01+00:00", "SSH_PREAUTH", "", "ssh/preauth-closed invalid-user=oracle", 4242),
        ];
        invalid_users_as_failures(&mut out, "ssh");
        let got: Vec<(&str, &str, &str)> = out.iter().map(|e| (e.ts_rfc3339.as_str(), e.evt.as_str(), e.user.as_str())).collect();
        assert_eq!(got, [("2026-01-05T10:00:02+00:00", "SSH_FAILED", "guest"), ("2026-02-09T03:00:00+00:00", "SSH_FAILED", "oracle")]);
    }

    /// An archive entry whose name leaves the extraction folder is not
    /// written; the entries inside it are.
    #[test]
    fn a_zip_entry_cannot_leave_the_extraction_folder() {
        use std::io::Write;
        let d = tmp("zipslip");
        let dest = d.join("dest");
        fs::create_dir_all(&dest).unwrap();
        let z = d.join("evidence.zip");
        {
            let mut w = zip::ZipWriter::new(File::create(&z).unwrap());
            for (name, body) in [
                ("../escaped.txt", "out"),
                ("../../escaped2.txt", "out"),
                ("a/../../escaped3.txt", "out"),
                ("/escaped-abs.txt", "out"),
                ("var/log/auth.log", "inside"),
            ] {
                w.start_file(name, zip::write::FileOptions::default()).unwrap();
                w.write_all(body.as_bytes()).unwrap();
            }
            w.finish().unwrap();
        }
        let mut tars = Vec::new();
        let dirs = extract_zips_recursive(&z, &dest, &mut tars);
        let root = dirs.last().unwrap().clone();
        assert!(root.starts_with(&dest));
        assert_eq!(fs::read_to_string(root.join("var/log/auth.log")).unwrap(), "inside");
        for outside in [dest.join("escaped.txt"), d.join("escaped.txt"), d.join("escaped2.txt"), dest.join("escaped3.txt"), d.join("escaped3.txt"), root.join("../escaped.txt")] {
            assert!(!outside.exists(), "{}", outside.display());
        }
        // nothing but the one file under the extraction folder, and nothing new beside it
        let written: Vec<String> = WalkDir::new(&d).into_iter().filter_map(Result::ok).filter(|e| e.file_type().is_file()).map(|e| e.file_name().to_string_lossy().to_string()).collect();
        assert!(written.iter().all(|n| !n.starts_with("escaped") || n == "escaped-abs.txt"), "{:?}", written);
        // (an absolute name is taken as a path inside the folder, or left out: never at the root of the disk)
        assert!(!Path::new("/escaped-abs.txt").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn two_archives_of_one_name_get_a_folder_each() {
        let d = tmp("samename");
        let a = fresh_extract_dir(&d, "collection");
        let b = fresh_extract_dir(&d, "collection");
        let c = fresh_extract_dir(&d, "collection");
        assert!(a != b && b != c && a != c);
        assert!(a.is_dir() && b.is_dir() && c.is_dir());
        assert_eq!(a, d.join("collection"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_session_of_the_machine_itself_is_not_a_logon_from_the_network() {
        for local in [":0", ":0.0", ":1", ":pts/0:S.0", "tmux(1234).%0", "login screen"] {
            assert!(utmp_host_is_local(local), "{}", local);
        }
        for remote in ["10.0.0.5", "host.example.org", "fe80::1", "203.0.113.9 via mosh [1234]", ""] {
            assert!(!utmp_host_is_local(remote), "{}", remote);
        }
    }

    /// wtmp: a session of an X display is left out, a remote one kept; a
    /// boot ends the sessions before it, so the first logout after the
    /// boot does not close a session of before on the same terminal.
    #[test]
    fn wtmp_local_sessions_and_boots() {
        let rec = |ut_type: i16, pid: i32, line: &str, user: &str, host: &str, secs: u32| {
            let mut r = vec![0u8; 384];
            r[0..2].copy_from_slice(&ut_type.to_le_bytes());
            r[4..8].copy_from_slice(&pid.to_le_bytes());
            r[8..8 + line.len()].copy_from_slice(line.as_bytes());
            r[44..44 + user.len()].copy_from_slice(user.as_bytes());
            r[76..76 + host.len()].copy_from_slice(host.as_bytes());
            r[340..344].copy_from_slice(&secs.to_le_bytes());
            r
        };
        let t0 = 1_767_254_400u32;
        let mut data = Vec::new();
        data.extend(rec(USER_PROCESS, 10, "pts/0", "alice", "10.0.0.5", t0));
        data.extend(rec(USER_PROCESS, 11, ":0", "bob", ":0", t0 + 60));
        data.extend(rec(USER_PROCESS, 12, "pts/3", "carol", "tmux(900).%1", t0 + 90));
        data.extend(rec(BOOT_TIME, 0, "~", "reboot", "5.15.0", t0 + 120));
        data.extend(rec(USER_PROCESS, 20, "pts/0", "dave", "10.0.0.9", t0 + 300));
        data.extend(rec(DEAD_PROCESS, 20, "pts/0", "", "", t0 + 400));
        data.extend(rec(DEAD_PROCESS, 21, "pts/0", "", "", t0 + 500));
        let d = tmp("wtmp");
        let p = d.join("wtmp");
        fs::write(&p, &data).unwrap();
        let got: Vec<(String, String, String)> = parse_utmp_file(&p, "srv01", true).into_iter().map(|e| (e.evt, e.user, e.remote)).collect();
        assert_eq!(
            got,
            [
                ("LOGIN".to_string(), "alice".to_string(), "10.0.0.5".to_string()),
                ("LOGIN".to_string(), "dave".to_string(), "10.0.0.9".to_string()),
                ("LOGOUT".to_string(), "dave".to_string(), "10.0.0.9".to_string()),
            ]
        );
        let _ = fs::remove_dir_all(&d);
    }
}


#[cfg(test)]
mod host_spill_tests {
    use super::*;

    fn ev(ts: &str, host: &str, user: &str, remote: &str, chan: &str, evt: &str, file: &str, pid: u32) -> RawEvt {
        RawEvt {
            ts_rfc3339: ts.into(),
            user: user.into(),
            remote: remote.into(),
            tty_or_proc: chan.into(),
            evt: evt.into(),
            filename: file.into(),
            dst_host: host.into(),
            pid,
            conn: 0,
        }
    }

    /// The rows written host by host through the disk are the rows the whole
    /// set gives at once, byte for byte: duplicates across channels dropped
    /// per host, a directory uid named from another host's login, rows of
    /// the same second in the same order (rank, then the order read), the
    /// outgoing connections in their place.
    #[test]
    fn host_by_host_writes_what_all_at_once_writes() {
        let t1 = "2026-11-10T10:00:00+00:00";
        let t2 = "2026-11-10T10:00:01+00:00";
        let t3 = "2026-11-10T11:30:00+00:00";
        // logs in the order read; each log is one host's
        let logs: Vec<Vec<RawEvt>> = vec![
            vec![
                ev(t1, "web01", "alice", "10.0.0.5", "ssh", "SSH_SUCCESS", "a.tgz:[root]/var/log/auth.log", 100),
                ev(t1, "web01", "root", "203.0.113.9", "ssh", "SSH_FAILED", "a.tgz:[root]/var/log/auth.log", 101),
                ev(t2, "web01", "root", "203.0.113.9", "ssh", "SSH_FAILED", "a.tgz:[root]/var/log/auth.log", 102),
                ev(t3, "web01", "bob", "10.0.0.6", "ssh", "SSH_SUCCESS", "a.tgz:[root]/var/log/auth.log", 103),
            ],
            vec![
                // journald's copies of web01's lines: one event each, dropped
                ev(t1, "web01", "alice", "10.0.0.5", "journal-ssh", "SSH_SUCCESS", "a.tgz:[root]/var/log/journal/x/system.journal", 100),
                ev(t2, "web01", "root", "203.0.113.9", "journal-ssh", "SSH_FAILED", "a.tgz:[root]/var/log/journal/x/system.journal", 102),
                // only the journal has this one
                ev(t1, "web01", "carol", "10.0.0.7", "journal-ssh", "SSH_SUCCESS", "a.tgz:[root]/var/log/journal/x/system.journal", 104),
            ],
            vec![
                // the same second on another host, read later
                ev(t1, "db01", "root", "203.0.113.9", "ssh", "SSH_FAILED", "b.tgz:[root]/var/log/secure", 200),
                ev(t1, "db01", "alice", "10.0.0.5", "ssh", "SSH_SUCCESS", "b.tgz:[root]/var/log/secure", 201),
                // a directory user's uid, named by db01's own login a second before
                ev(t2, "db01", "uid:15001", "10.0.0.5", "audit", "SSH_SUCCESS", "b.tgz:[root]/var/log/audit/audit.log", 0),
            ],
            vec![
                // the same uid on a host with no login to name it: the pool does
                ev(t3, "app01", "uid:15001", "10.0.0.5", "audit", "SSH_SUCCESS", "c.tgz:[root]/var/log/audit/audit.log", 0),
                ev(t1, "app01", "root", "203.0.113.9", "ssh", "SSH_FAILED", "c.tgz:[root]/var/log/auth.log", 300),
            ],
            vec![
                // web01 again, from a second package: read after the others
                ev(t1, "web01", "dave", "10.0.0.8", "ssh", "SSH_SUCCESS", "d.tgz:[root]/var/log/auth.log", 105),
            ],
        ];
        let outgoing = vec![(t2.to_string(), format!("{},web01,CONNECT,AUDIT_CONNECT,SSH,alice,\"\",\"\",10.0.0.9,\"\",\"\",\"\",audit,x{}\n", t2, crate::csv_out::EMPTY_TAIL))];
        let dir = std::env::temp_dir().join(format!("masstin_spill_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let whole = dir.join("whole.csv").to_string_lossy().to_string();
        let by_host = dir.join("by_host.csv").to_string_lossy().to_string();

        let mut all: Vec<RawEvt> = logs.iter().flatten().cloned().collect();
        resolve_audit_uids(&mut all);
        build_dataframe(&all, outgoing.clone(), Some(&whole));

        let mut spill = HostSpill::new(dir.join("_rows"));
        let mut votes = UidVotes::default();
        for (n, log) in logs.iter().enumerate() {
            for r in log {
                votes.note(r);
            }
            spill.add(log, n as u32).unwrap();
        }
        let names = votes.resolve();
        assert_eq!(votes.changed(&names), 2, "both uids named");
        assert_eq!(spill.rows, 13);
        write_by_host(&spill, &names, outgoing.clone(), Some(&by_host));

        let a = fs::read_to_string(&whole).unwrap();
        let b = fs::read_to_string(&by_host).unwrap();
        assert_eq!(a, b);
        // and with every host split in pieces by the source of its rows
        let in_pieces = dir.join("in_pieces.csv").to_string_lossy().to_string();
        let mut spill2 = HostSpill::new(dir.join("_rows2"));
        for (n, log) in logs.iter().enumerate() {
            spill2.add(log, n as u32).unwrap();
        }
        write_by_host_within(&spill2, &names, outgoing, Some(&in_pieces), 64);
        assert_eq!(a, fs::read_to_string(&in_pieces).unwrap(), "a host reduced in pieces");
        // and the reduction did its work
        assert_eq!(a.lines().count(), 1 + 13 - 2 + 1, "{}", a);
        assert_eq!(a.matches("uid:15001").count(), 0, "{}", a);
        assert!(a.lines().nth(1).unwrap().contains(",web01,") && a.lines().nth(1).unwrap().contains("alice"), "{}", a);
        let _ = fs::remove_dir_all(&dir);
    }
}


#[cfg(test)]
mod conn_stream_tests {
    use super::*;

    fn ev(secs: i64, pid: u32, evt: &str, chan: &str, user: &str) -> RawEvt {
        let ts = DateTime::<Utc>::from_timestamp(1_790_000_000 + secs, 0).unwrap().to_rfc3339();
        RawEvt { ts_rfc3339: ts, user: user.into(), remote: "203.0.113.9".into(), tty_or_proc: chan.into(), evt: evt.into(), filename: "auth.log".into(), dst_host: "web01".into(), pid, conn: 0 }
    }

    /// The connections resolved as the rows go by give what the whole file
    /// resolved at once gives, row for row: an announcement with its own
    /// failed line, one alone with its pre-auth close, a pid used again
    /// later, rows with no pid, and thousands of connections in between.
    #[test]
    fn as_the_rows_go_by_is_what_the_whole_file_gives() {
        let mut rows: Vec<RawEvt> = Vec::new();
        let mut t = 0i64;
        for k in 0..6000u32 {
            let pid = 1000 + (k % 500); // pids come back every 500 connections
            t += 7;
            match k % 5 {
                0 => {
                    // announced, then its own Failed line: the announcement goes
                    rows.push(ev(t, pid, INVALID_USER_EVT, "ssh/invalid-user", "admin"));
                    rows.push(ev(t + 1, pid, "SSH_FAILED", "ssh/password", "admin"));
                }
                1 => {
                    // announced and closed before any outcome: one failed logon
                    rows.push(ev(t, pid, INVALID_USER_EVT, "ssh/invalid-user", "oracle"));
                    rows.push(ev(t + 2, pid, "SSH_PREAUTH", "ssh/preauth-closed invalid-user=oracle", ""));
                }
                2 => rows.push(ev(t, pid, "SSH_PREAUTH", "ssh/preauth-closed invalid-user=git", "")),
                3 => rows.push(ev(t, 0, INVALID_USER_EVT, "ssh/invalid-user", "nopid")),
                _ => {
                    rows.push(ev(t, pid, "SSH_SUCCESS", "ssh/publickey", "alice"));
                    rows.push(ev(t + 3, pid, "SSH_PREAUTH", "ssh/preauth-closed", ""));
                }
            }
        }
        let mut whole = rows.clone();
        invalid_users_as_failures(&mut whole, "ssh");
        let mut stream = ConnStream::new("ssh");
        let mut by = Vec::new();
        let mut held = 0usize;
        for r in rows {
            stream.push(r, &mut by);
            held = held.max(stream.pending.len());
        }
        stream.finish(&mut by);
        let show = |v: &[RawEvt]| v.iter().map(|e| format!("{} {} {} {} {}", e.ts_rfc3339, e.pid, e.evt, e.tty_or_proc, e.user)).collect::<Vec<_>>();
        assert_eq!(show(&whole), show(&by));
        assert!(whole.len() > 6000 && whole.iter().any(|e| e.tty_or_proc == "ssh/invalid-user"));
        // what waits is the last couple of hours, not the file
        assert!(held < 2500, "{} rows held", held);
        assert!(stream.open.is_empty() && stream.pending.is_empty());
    }
}
