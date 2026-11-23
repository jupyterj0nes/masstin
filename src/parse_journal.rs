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
/// How far a journal file can be read, and whether it is damaged there.
/// Its objects lie one after the other, each saying its own size; the
/// reader takes that size at its word and asks for as much memory, so one
/// object with a size of garbage (a journal copied while journald wrote to
/// it: a snapshot of a running machine) ended the whole run, with
/// `capacity overflow` or with a failed allocation of a hundred gigabytes.
/// The objects are walked first, by their headers alone: the first one
/// whose size is under a header's or runs past the end of the file is
/// where the reading stops. The zeros journald leaves at the end of the
/// file it has set aside are its end, not damage.
pub(crate) fn journal_sound_len<F: std::io::Read + std::io::Seek + ?Sized>(f: &mut F) -> std::io::Result<(u64, bool)> {
    use std::io::SeekFrom;
    let le64 = |b: &[u8]| u64::from_le_bytes(b[..8].try_into().unwrap());
    let len = f.seek(SeekFrom::End(0))?;
    f.seek(SeekFrom::Start(0))?;
    let mut head = [0u8; 104];
    if f.read_exact(&mut head).is_err() {
        // no header: the reader says what it is not
        f.seek(SeekFrom::Start(0))?;
        return Ok((len, false));
    }
    let (header_size, arena_size) = (le64(&head[88..96]), le64(&head[96..104]));
    let end = header_size.saturating_add(arena_size).min(len);
    let (mut at, mut damaged) = (header_size, false);
    let mut object = [0u8; 16];
    while at.saturating_add(16) <= end {
        f.seek(SeekFrom::Start(at))?;
        if f.read_exact(&mut object).is_err() {
            break;
        }
        let size = le64(&object[8..16]);
        if size == 0 && object[0] == 0 {
            break; // the room set aside and not written yet
        }
        if size < 16 || size > end - at {
            damaged = true;
            break;
        }
        at += (size + 7) & !7;
    }
    f.seek(SeekFrom::Start(0))?;
    Ok((at.min(len), damaged))
}

pub fn parse_journal_file(path: &Path, dst_host: &str) -> Vec<RawEvt> {
    let mut out = Vec::new();

    // from disk, or from an image's volume (crate::vfs)
    let file = match crate::vfs::open(path) {
        Ok(f) => f,
        Err(e) => {
            if is_debug_mode() {
                eprintln!("[DEBUG] journal: cannot open {}: {}", path.display(), e);
            }
            return out;
        }
    };

    // the journal is read up to its last sound object: past an object that
    // says a size it cannot have, the reader would ask for that much memory
    let mut file = file;
    let (sound, damaged) = match journal_sound_len(&mut file) {
        Ok(x) => x,
        Err(e) => {
            crate::banner::print_warning(&format!("  {}: cannot be read ({}), skipped", path.display(), e));
            return out;
        }
    };
    if damaged {
        crate::banner::print_warning(&format!(
            "  {}: the journal is damaged at byte {} (an object there says a size it cannot have, as in a journal copied while it was being written); it is read up to there",
            path.display(), sound
        ));
    }
    let file = std::io::Read::take(file, sound);

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
        // OpenSSH 9.8 and later run each connection in `sshd-session`, and
        // OpenSSH 10 authenticates in `sshd-auth`: every sshd-* process
        let is_sshd = comm.as_deref().map_or(false, |c| c.starts_with("sshd"))
            || syslog_id.as_deref().map_or(false, |c| c.starts_with("sshd"));
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

#[cfg(test)]
mod tests {
    #[test]
    fn a_journal_is_read_up_to_its_last_sound_object() {
        use super::journal_sound_len;
        use std::io::Cursor;
        // a header of 272 bytes, then objects of 40, 24 and 64 bytes and the zeros set aside
        let build = |sizes: &[u64], tail: usize| {
            let mut b = vec![0u8; 272];
            b[..8].copy_from_slice(b"LPKSHHRH");
            let arena: u64 = sizes.iter().map(|s| (s + 7) & !7).sum::<u64>() + tail as u64;
            b[88..96].copy_from_slice(&272u64.to_le_bytes());
            b[96..104].copy_from_slice(&arena.to_le_bytes());
            for s in sizes {
                let at = b.len();
                b.resize(at + ((*s + 7) & !7) as usize, 0);
                b[at] = 1;
                b[at + 8..at + 16].copy_from_slice(&s.to_le_bytes());
            }
            b.resize(b.len() + tail, 0);
            b
        };
        let sound = build(&[40, 24, 64], 4096);
        assert_eq!(journal_sound_len(&mut Cursor::new(&sound)).unwrap(), (272 + 40 + 24 + 64, false));
        // the second object says a size of garbage: read up to it
        for garbage in [0xFFFF_FFFF_FFFF_FFF0u64, 0x20_0000_0000, 8] {
            let mut bad = sound.clone();
            bad[272 + 40 + 8..272 + 40 + 16].copy_from_slice(&garbage.to_le_bytes());
            assert_eq!(journal_sound_len(&mut Cursor::new(&bad)).unwrap(), (272 + 40, true), "{:#x}", garbage);
        }
        // a file cut in the middle of its last object
        let cut = &sound[..272 + 40 + 24 + 30];
        assert_eq!(journal_sound_len(&mut Cursor::new(cut)).unwrap(), (272 + 40 + 24, true));
        // too short for a header: left to the reader
        assert_eq!(journal_sound_len(&mut Cursor::new(&sound[..50])).unwrap(), (50, false));
    }
}
