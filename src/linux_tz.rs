// =============================================================================
//   Local-time resolution for Linux text logs.
//
//   RFC3164 syslog lines ("Sep 24 23:08:00 host sshd[..]: ...") carry neither
//   a year nor a UTC offset: they are the host's LOCAL wall-clock time. Every
//   other Linux source masstin reads — wtmp/btmp/lastlog (epoch), audit.log
//   (epoch), journald (epoch µs) — is absolute. Without converting the syslog
//   lines, the same SSH login lands twice in the timeline two hours apart on
//   a Europe/Madrid host, and cross-host correlation is off by the zone.
//
//   The zone is recovered from the collected filesystem itself, in this
//   order (first hit wins):
//     1. /etc/timezone                      Debian / Ubuntu: "Europe/Madrid"
//     2. /etc/sysconfig/clock  ZONE="..."   RHEL / CentOS 6
//     3. /etc/localtime symlink target      RHEL 7+, systemd distros
//        (tar collectors keep the link; masstin's tar extractor records the
//        target in `etc/localtime.masstin-link` because Windows cannot
//        unpack the symlink itself)
//     4. /etc/localtime as a regular TZif file (RHEL 6 copies it; images
//        mounted read-only by UAC show it as a plain file) — parsed
//        directly: exact historical transitions, no zone name needed
//     5. live_response/system/timedatectl_status.txt — only when the
//        collector ran on the live host (uac.log "Mount Point: /"); on a
//        mounted image that file describes the analyst's machine
//     6. nothing found → UTC, with a warning, so the analyst knows the
//        syslog timestamps are unconverted
// =============================================================================

use chrono::{NaiveDateTime, TimeZone, LocalResult};
use std::fs;
use std::path::{Path, PathBuf};

/// Parsed TZif (RFC 8536) transition table. Only what we need: the UTC
/// offset in force at any instant.
pub(crate) struct TzifTable {
    transitions: Vec<i64>,   // UTC seconds, ascending
    idx: Vec<u8>,            // ttinfo index per transition
    utoff: Vec<i32>,         // per ttinfo
    isdst: Vec<bool>,
}

impl TzifTable {
    pub(crate) fn parse(bytes: &[u8]) -> Option<TzifTable> {
        if bytes.len() < 44 || &bytes[0..4] != b"TZif" { return None; }
        let version = bytes[4];
        let (hdr, times_are_64) = if version >= b'2' {
            // Skip the v1 block: header + 32-bit data, then parse the v2 one.
            let c = Self::counts(&bytes[0..44])?;
            let v1_len = 44 + c.timecnt * 5 + c.typecnt * 6 + c.charcnt + c.leapcnt * 8 + c.isstdcnt + c.isutcnt;
            if bytes.len() < v1_len + 44 { return None; }
            (v1_len, true)
        } else {
            (0, false)
        };
        let c = Self::counts(&bytes[hdr..hdr + 44])?;
        let tsz = if times_are_64 { 8 } else { 4 };
        let mut p = hdr + 44;
        let need = c.timecnt * (tsz + 1) + c.typecnt * 6;
        if bytes.len() < p + need { return None; }
        let mut transitions = Vec::with_capacity(c.timecnt);
        for _ in 0..c.timecnt {
            let t = if times_are_64 {
                i64::from_be_bytes(bytes[p..p + 8].try_into().ok()?)
            } else {
                i32::from_be_bytes(bytes[p..p + 4].try_into().ok()?) as i64
            };
            transitions.push(t);
            p += tsz;
        }
        let idx = bytes[p..p + c.timecnt].to_vec();
        p += c.timecnt;
        let mut utoff = Vec::with_capacity(c.typecnt);
        let mut isdst = Vec::with_capacity(c.typecnt);
        for _ in 0..c.typecnt {
            utoff.push(i32::from_be_bytes(bytes[p..p + 4].try_into().ok()?));
            isdst.push(bytes[p + 4] != 0);
            p += 6;
        }
        if utoff.is_empty() { return None; }
        if idx.iter().any(|&i| (i as usize) >= utoff.len()) { return None; }
        Some(TzifTable { transitions, idx, utoff, isdst })
    }

    fn counts(h: &[u8]) -> Option<Counts> {
        let rd = |o: usize| -> Option<usize> {
            Some(u32::from_be_bytes(h[o..o + 4].try_into().ok()?) as usize)
        };
        Some(Counts {
            isutcnt: rd(20)?, isstdcnt: rd(24)?, leapcnt: rd(28)?,
            timecnt: rd(32)?, typecnt: rd(36)?, charcnt: rd(40)?,
        })
    }

    /// UTC offset (seconds east of UTC) in force at `utc_secs`.
    pub(crate) fn offset_at(&self, utc_secs: i64) -> i32 {
        if self.transitions.is_empty() || utc_secs < self.transitions[0] {
            // Before the first transition: the first standard-time ttinfo,
            // as RFC 8536 prescribes.
            let i = (0..self.utoff.len()).find(|&i| !self.isdst[i]).unwrap_or(0);
            return self.utoff[i];
        }
        let pos = match self.transitions.binary_search(&utc_secs) {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        self.utoff[self.idx[pos] as usize]
    }

    /// Wall-clock → UTC. Tries every offset the zone has ever used and keeps
    /// the ones consistent with the table (a fold yields two, the earlier
    /// wins; a gap yields none and we fall back to the pre-gap offset).
    fn local_to_utc(&self, local: &NaiveDateTime) -> NaiveDateTime {
        let l = local.and_utc().timestamp();
        let mut offs: Vec<i32> = self.utoff.clone();
        offs.sort_unstable();
        offs.dedup();
        let mut best: Option<i64> = None;
        for off in offs {
            let u = l - off as i64;
            if self.offset_at(u) == off {
                best = Some(best.map_or(u, |b: i64| b.min(u)));
            }
        }
        let u = best.unwrap_or_else(|| l - self.offset_at(l) as i64);
        NaiveDateTime::from_timestamp_opt(u, 0).unwrap_or(*local)
    }
}

struct Counts { isutcnt: usize, isstdcnt: usize, leapcnt: usize, timecnt: usize, typecnt: usize, charcnt: usize }

/// The zone a Linux host's syslog wall-clock times are expressed in.
pub(crate) enum LocalTz {
    Utc,
    Named(chrono_tz::Tz),
    Table(TzifTable),
}

impl LocalTz {
    /// Convert a naive local timestamp to UTC.
    pub(crate) fn to_utc(&self, local: &NaiveDateTime) -> NaiveDateTime {
        match self {
            LocalTz::Utc => *local,
            LocalTz::Named(tz) => match tz.from_local_datetime(local) {
                LocalResult::Single(dt) => dt.naive_utc(),
                LocalResult::Ambiguous(a, _) => a.naive_utc(),
                // Spring-forward gap: the clock never showed this time;
                // interpret it with the pre-gap (standard) offset.
                LocalResult::None => {
                    let before = *local - chrono::Duration::hours(1);
                    match tz.from_local_datetime(&before) {
                        LocalResult::Single(dt) | LocalResult::Ambiguous(dt, _) => {
                            dt.naive_utc() + chrono::Duration::hours(1)
                        }
                        LocalResult::None => *local,
                    }
                }
            },
            LocalTz::Table(t) => t.local_to_utc(local),
        }
    }

    pub(crate) fn is_utc(&self) -> bool {
        matches!(self, LocalTz::Utc)
    }
}

fn named(name: &str) -> Option<LocalTz> {
    let n = name.trim().trim_matches('"').trim_matches('\'');
    if n.is_empty() { return None; }
    if n.eq_ignore_ascii_case("UTC") || n.eq_ignore_ascii_case("Etc/UTC") {
        return Some(LocalTz::Utc);
    }
    n.parse::<chrono_tz::Tz>().ok().map(LocalTz::Named)
}

/// Zone name from a zoneinfo path: "../usr/share/zoneinfo/Europe/Madrid"
/// → "Europe/Madrid". Also handles "/usr/share/zoneinfo/posix/Europe/Madrid".
fn zone_from_path(p: &str) -> Option<String> {
    let p = p.trim().replace('\\', "/");
    let i = p.rfind("zoneinfo/")?;
    let rest = &p[i + 9..];
    let rest = rest.strip_prefix("posix/").or_else(|| rest.strip_prefix("right/")).unwrap_or(rest);
    if rest.is_empty() { None } else { Some(rest.to_string()) }
}

/// Mount point UAC was run against, from the run log at the extract root.
/// "/" means a live host; anything else ("/mnt/sysroot") is a mounted image
/// whose live_response/ output describes the COLLECTOR, not the evidence.
pub(crate) fn uac_mount_point(root: &Path) -> Option<String> {
    let content = fs::read_to_string(root.join("uac.log")).ok()?;
    content.lines().take(40).find_map(|l| l.trim().strip_prefix("Mount Point:").map(|v| v.trim().to_string()))
}

/// Filesystem roots where /etc may live relative to the parse root:
/// `<root>/[root]` (UAC), `<root>` (a full-FS extract) and `<root>/..`
/// (parse root = /var because it was found by walking up to `log`).
fn fs_roots(root: &Path) -> Vec<PathBuf> {
    let mut v = vec![root.join("[root]"), root.to_path_buf()];
    if let Some(p) = root.parent() { v.push(p.to_path_buf()); }
    v
}

/// Resolve the host's local zone. Returns the zone plus a human-readable
/// description of where it came from, for the phase-2 info line.
pub(crate) fn discover_timezone(root: &Path) -> (LocalTz, String) {
    for fr in fs_roots(root) {
        // 1. Debian / Ubuntu
        if let Ok(s) = fs::read_to_string(fr.join("etc/timezone")) {
            if let Some(tz) = s.lines().next().and_then(named) {
                return (tz, format!("{} (from /etc/timezone)", s.trim()));
            }
        }
        // 2. RHEL / CentOS 6
        if let Ok(s) = fs::read_to_string(fr.join("etc/sysconfig/clock")) {
            for l in s.lines() {
                if let Some(v) = l.trim().strip_prefix("ZONE=") {
                    if let Some(tz) = named(v) {
                        return (tz, format!("{} (from /etc/sysconfig/clock)", v.trim().trim_matches('"')));
                    }
                }
            }
        }
        // 3. /etc/localtime symlink target, recorded by the tar extractor
        if let Ok(s) = fs::read_to_string(fr.join("etc/localtime.masstin-link")) {
            if let Some(z) = zone_from_path(&s) {
                if let Some(tz) = named(&z) {
                    return (tz, format!("{} (from /etc/localtime symlink)", z));
                }
            }
        }
        // 4. /etc/localtime as a regular TZif file
        if let Ok(b) = fs::read(fr.join("etc/localtime")) {
            if let Some(t) = TzifTable::parse(&b) {
                let now_off = t.offset_at(chrono::Utc::now().timestamp());
                return (LocalTz::Table(t), format!("TZif table, current offset {:+}h (from /etc/localtime)", now_off as f64 / 3600.0));
            }
        }
    }
    // 5. Live collection only: timedatectl output
    let live = uac_mount_point(root).map(|m| m == "/").unwrap_or(false);
    if live {
        if let Ok(s) = fs::read_to_string(root.join("live_response/system/timedatectl_status.txt")) {
            for l in s.lines() {
                if let Some(v) = l.trim().strip_prefix("Time zone:") {
                    let z = v.trim().split_whitespace().next().unwrap_or("");
                    if let Some(tz) = named(&z) {
                        return (tz, format!("{} (from timedatectl, live collection)", z));
                    }
                }
            }
        }
    }
    (LocalTz::Utc, "not found — syslog timestamps assumed UTC".to_string())
}
