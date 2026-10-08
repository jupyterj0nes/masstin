// =============================================================================
//   systemd-journald binary journal parser
//
//   Modern Linux distros (Ubuntu 18+, RHEL 8+, Debian 11+) route sshd/PAM
//   auth events through systemd-journald, NOT to /var/log/auth.log. On a
//   stock Ubuntu 22 + SSSD + AD host like LNX01-oldtown in the DFIR lab,
//   /var/log/auth.log is nearly empty while the binary journals under
//   /var/log/journal/<machine-id>/*.journal[~] hold every SSH login.
//
//   This module opens .journal / .journal~ files (zstd-compressed, compact
//   mode supported) via the systemd-journal-reader crate — pure Rust, no
//   libsystemd, works on Windows — and applies the same SSH Accepted/Failed
//   regexes used by parse_linux::parse_secure_or_messages() so a journal
//   entry yields the exact same RawEvt struct as an auth.log line.
//
//   Handled today (_COMM or SYSLOG_IDENTIFIER = sshd / sshd-session):
//     - "Accepted <method> for USER from SRC"
//     - "Failed <method> for [invalid user] USER from SRC"
//     - pre-authentication touches (no ident string, bad protocol, [preauth] closes)
//     - session ends (pam "session closed" paired by pid, else "Disconnected from user")
//
//   Not yet handled (on roadmap): sudo COMMAND entries, pam_sss auth
//   failures, LZ4/XZ-compressed journals (crate only does zstd — fine for
//   Ubuntu 20+/RHEL 8+).
// =============================================================================

use std::fs::File;
use std::path::Path;
use chrono::{DateTime, NaiveDateTime, Utc};

use crate::parse::is_debug_mode;

// We deliberately reuse the same SSH_OK_RE / SSH_FAIL_RE already compiled in
// parse_linux — exposed via `pub(crate)` there so we don't duplicate regex.
use crate::parse_linux::{preauth_touch, RawEvt, SessionTracker, PAM_CLOSE_RE, SSH_DISCONNECT_RE, SSH_OK_RE, SSH_FAIL_RE};

/// Parse a single journal file, returning SSH lateral-movement events.
/// `dst_host` is the hostname of the machine the journal came from.
pub fn parse_journal_file(path: &Path, dst_host: &str) -> Vec<RawEvt> {
    let mut out = Vec::new();

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            if is_debug_mode() {
                eprintln!("[DEBUG] journal: cannot open {}: {}", path.display(), e);
            }
            return out;
        }
    };

    let mut reader = match systemd_journal_reader::JournalReader::new(file) {
        Ok(r) => r,
        Err(e) => {
            if is_debug_mode() {
                eprintln!("[DEBUG] journal: not a valid journal file {}: {}", path.display(), e);
            }
            return out;
        }
    };

    let mut scanned = 0usize;
    let mut matched = 0usize;
    let mut tracker = SessionTracker::default();
    let mut disconnect_fallback: Vec<RawEvt> = Vec::new();

    while let Some(entry) = reader.next_entry() {
        scanned += 1;

        // Fast reject: we only care about sshd-origin entries here.
        let comm = entry.fields.get("_COMM").map(|s| s.to_string());
        let syslog_id = entry.fields.get("SYSLOG_IDENTIFIER").map(|s| s.to_string());
        // OpenSSH 9.8 and later run each connection in `sshd-session`
        let is_sshd = matches!(comm.as_deref(), Some("sshd") | Some("sshd-session"))
            || matches!(syslog_id.as_deref(), Some("sshd") | Some("sshd-session"));
        if !is_sshd {
            continue;
        }

        // sshd process id (journald trusted field `_PID`, else SYSLOG_PID)
        let pid: u32 = entry.fields.get("_PID")
            .or_else(|| entry.fields.get("SYSLOG_PID"))
            .and_then(|s| s.to_string().trim().parse().ok())
            .unwrap_or(0);

        let msg = match entry.fields.get("MESSAGE") {
            Some(m) => m.to_string(),
            None => continue,
        };

        // __REALTIME_TIMESTAMP is microseconds since Unix epoch.
        let realtime_us = entry.realtime;
        let secs = (realtime_us / 1_000_000) as i64;
        let nsec = ((realtime_us % 1_000_000) * 1_000) as u32;
        let ts_rfc3339 = match NaiveDateTime::from_timestamp_opt(secs, nsec) {
            Some(ndt) => DateTime::<Utc>::from_utc(ndt, Utc).to_rfc3339(),
            None => continue,
        };

        // SSH success: "Accepted <method> for USER from SRC" (captures:
        // 1 method, 2 user, 3 source — shared regex with parse_linux)
        if let Some(cap) = SSH_OK_RE.captures(&msg) {
            let method = cap[1].to_string();
            let user = cap[2].to_string();
            let src = cap[3].to_string();
            tracker.login(pid, &user, &src);
            out.push(RawEvt {
                ts_rfc3339: ts_rfc3339.clone(),
                user,
                remote: src,
                tty_or_proc: format!("journal-ssh/{}", method),
                evt: "SSH_SUCCESS".into(),
                filename: path.display().to_string(),
                dst_host: dst_host.to_string(),
                pid,
                conn: 0,
            });
            matched += 1;
            continue;
        }

        // SSH failure: "Failed <method> for [invalid user] USER from SRC"
        // (captures: 1 method, 2 invalid-user marker, 3 user, 4 source).
        // "Failed none" is the method-query probe, not an attempt.
        if let Some(cap) = SSH_FAIL_RE.captures(&msg) {
            let method = cap[1].to_string();
            if method == "none" { continue; }
            let invalid = cap.get(2).is_some();
            let user = cap[3].to_string();
            let src = cap[4].to_string();
            out.push(RawEvt {
                ts_rfc3339,
                user,
                remote: src,
                tty_or_proc: if invalid { format!("journal-ssh/{} invalid-user", method) } else { format!("journal-ssh/{}", method) },
                evt: "SSH_FAILED".into(),
                filename: path.display().to_string(),
                dst_host: dst_host.to_string(),
                pid,
                conn: 0,
            });
            matched += 1;
            continue;
        }

        // "Invalid user X from SRC" (see parse_linux::invalid_users_as_failures)
        if let Some(cap) = crate::parse_linux::INVALID_USER_RE.captures(&msg) {
            out.push(RawEvt {
                ts_rfc3339,
                user: cap[1].trim().to_string(),
                remote: cap[2].to_string(),
                tty_or_proc: "journal-ssh/invalid-user".into(),
                evt: crate::parse_linux::INVALID_USER_EVT.into(),
                filename: path.display().to_string(),
                dst_host: dst_host.to_string(),
                pid,
                conn: 0,
            });
            matched += 1;
            continue;
        }

        // Pre-authentication touch (see parse_linux::preauth_touch).
        if let Some((src, kind)) = preauth_touch(&msg) {
            out.push(RawEvt {
                ts_rfc3339,
                user: String::new(),
                remote: src,
                tty_or_proc: format!("journal-ssh/{}", kind),
                evt: "SSH_PREAUTH".into(),
                filename: path.display().to_string(),
                dst_host: dst_host.to_string(),
                pid,
                conn: 0,
            });
            matched += 1;
            continue;
        }

        // Session end (see parse_linux: PAM_CLOSE_RE / SSH_DISCONNECT_RE).
        if PAM_CLOSE_RE.is_match(&msg) {
            if let Some((user, src)) = tracker.close(pid) {
                out.push(RawEvt {
                    ts_rfc3339,
                    user,
                    remote: src,
                    tty_or_proc: "journal-ssh/session-closed".into(),
                    evt: "LOGOUT".into(),
                    filename: path.display().to_string(),
                    dst_host: dst_host.to_string(),
                    pid,
                    conn: 0,
                });
                matched += 1;
            }
            continue;
        }
        if !msg.contains("[preauth]") {
            if let Some(cap) = SSH_DISCONNECT_RE.captures(&msg) {
                disconnect_fallback.push(RawEvt {
                    ts_rfc3339,
                    user: cap[1].to_string(),
                    remote: cap[2].to_string(),
                    tty_or_proc: "journal-ssh/disconnected".into(),
                    evt: "LOGOUT".into(),
                    filename: path.display().to_string(),
                    dst_host: dst_host.to_string(),
                    pid,
                    conn: 0,
                });
                continue;
            }
        }
    }
    if tracker.pam_closes == 0 && !disconnect_fallback.is_empty() {
        matched += disconnect_fallback.len();
        out.extend(disconnect_fallback);
    }

    if is_debug_mode() {
        eprintln!("[DEBUG] journal {}: {} entries, {} SSH matches",
            path.display(), scanned, matched);
    }

    crate::parse_linux::invalid_users_as_failures(&mut out, "journal-ssh");
    out
}
