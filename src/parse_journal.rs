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
//   Handled today:
//     - _COMM=sshd  MESSAGE="Accepted (password|publickey) for USER from IP"
//     - _COMM=sshd  MESSAGE="Failed password for USER from IP"
//
//   Not yet handled (on roadmap): sudo COMMAND entries, invalid-user,
//   pam_sss auth failures, LZ4/XZ-compressed journals (crate only does
//   zstd — fine for Ubuntu 20+/RHEL 8+).
// =============================================================================

use std::fs::File;
use std::path::Path;
use chrono::{DateTime, NaiveDateTime, Utc};

use crate::parse::is_debug_mode;

// We deliberately reuse the same SSH_OK_RE / SSH_FAIL_RE already compiled in
// parse_linux — exposed via `pub(crate)` there so we don't duplicate regex.
use crate::parse_linux::{RawEvt, SSH_OK_RE, SSH_FAIL_RE};

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

    while let Some(entry) = reader.next_entry() {
        scanned += 1;

        // Fast reject: we only care about sshd-origin entries here.
        let comm = entry.fields.get("_COMM").map(|s| s.to_string());
        let syslog_id = entry.fields.get("SYSLOG_IDENTIFIER").map(|s| s.to_string());
        let is_sshd = comm.as_deref() == Some("sshd")
            || syslog_id.as_deref() == Some("sshd");
        if !is_sshd {
            continue;
        }

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

        // SSH success: "Accepted (password|publickey) for USER from IP"
        if let Some(cap) = SSH_OK_RE.captures(&msg) {
            let user = cap[1].to_string();
            let ip = cap[2].to_string();
            out.push(RawEvt {
                ts_rfc3339: ts_rfc3339.clone(),
                user,
                remote: ip,
                tty_or_proc: "journal-ssh".into(),
                evt: "SSH_SUCCESS".into(),
                filename: path.display().to_string(),
                dst_host: dst_host.to_string(),
            });
            matched += 1;
            continue;
        }

        // SSH failure: "Failed password for USER from IP"
        if let Some(cap) = SSH_FAIL_RE.captures(&msg) {
            let user = cap[1].to_string();
            let ip = cap[2].to_string();
            out.push(RawEvt {
                ts_rfc3339,
                user,
                remote: ip,
                tty_or_proc: "journal-ssh".into(),
                evt: "SSH_FAILED".into(),
                filename: path.display().to_string(),
                dst_host: dst_host.to_string(),
            });
            matched += 1;
            continue;
        }
    }

    if is_debug_mode() {
        eprintln!("[DEBUG] journal {}: {} entries, {} SSH matches",
            path.display(), scanned, matched);
    }

    out
}
