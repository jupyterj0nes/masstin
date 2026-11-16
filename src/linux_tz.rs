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
    /// The rule for every instant after the last transition (the TZ string
    /// that ends a version 2+ file). A "slim" file, what `zic` writes by
    /// default since 2020, lists the transitions only up to the last
    /// change of rules (1996 for most of Europe) and leaves every year
    /// since to this rule: without it the zone stayed for ever in the
    /// offset of its last listed transition, and half of every year was
    /// read an hour off.
    footer: Option<PosixTz>,
}

/// One end of the daylight period of a POSIX TZ rule.
#[derive(Clone, Copy, Debug, PartialEq)]
enum RuleDay {
    /// `Mm.w.d`: month, week (5 = the last), day of the week (0 = Sunday)
    Month(u32, u32, u32),
    /// `Jn`: day 1..=365, February 29 never counted
    Julian1(u32),
    /// `n`: day 0..=365, February 29 counted
    Julian0(u32),
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Change {
    day: RuleDay,
    /// local time of the change, seconds from midnight (02:00 when not
    /// written; may be negative or beyond a day)
    secs: i64,
}

/// A POSIX TZ string: `CET-1CEST,M3.5.0,M10.5.0/3`, `JST-9`,
/// `<-04>4<-03>,M9.1.6/24,M4.1.6/24`. Offsets are kept in seconds EAST of
/// UTC (the string writes them west).
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct PosixTz {
    std: i32,
    /// (offset, the change into it, the change out of it)
    dst: Option<(i32, Change, Change)>,
}

impl PosixTz {
    pub(crate) fn parse(s: &str) -> Option<PosixTz> {
        let b = s.trim().as_bytes();
        let mut p = 0usize;
        let name = |p: &mut usize| -> Option<()> {
            if *p < b.len() && b[*p] == b'<' {
                while *p < b.len() && b[*p] != b'>' {
                    *p += 1;
                }
                if *p >= b.len() {
                    return None;
                }
                *p += 1;
                Some(())
            } else {
                let start = *p;
                while *p < b.len() && b[*p].is_ascii_alphabetic() {
                    *p += 1;
                }
                if *p - start >= 3 { Some(()) } else { None }
            }
        };
        // [+-]hh[:mm[:ss]] as seconds, sign as written
        let hms = |p: &mut usize| -> Option<i64> {
            let mut sign = 1i64;
            if *p < b.len() && (b[*p] == b'+' || b[*p] == b'-') {
                if b[*p] == b'-' {
                    sign = -1;
                }
                *p += 1;
            }
            let mut total = 0i64;
            for (k, unit) in [3600i64, 60, 1].iter().enumerate() {
                if k > 0 {
                    if *p < b.len() && b[*p] == b':' {
                        *p += 1;
                    } else {
                        break;
                    }
                }
                let start = *p;
                let mut n = 0i64;
                while *p < b.len() && b[*p].is_ascii_digit() && *p - start < 3 {
                    n = n * 10 + (b[*p] - b'0') as i64;
                    *p += 1;
                }
                if *p == start {
                    return None;
                }
                total += n * unit;
            }
            Some(sign * total)
        };
        let change = |p: &mut usize| -> Option<Change> {
            if *p >= b.len() || b[*p] != b',' {
                return None;
            }
            *p += 1;
            let num = |p: &mut usize| -> Option<u32> {
                let start = *p;
                let mut n = 0u32;
                while *p < b.len() && b[*p].is_ascii_digit() && *p - start < 4 {
                    n = n * 10 + (b[*p] - b'0') as u32;
                    *p += 1;
                }
                if *p == start { None } else { Some(n) }
            };
            let day = if *p < b.len() && b[*p] == b'M' {
                *p += 1;
                let m = num(p)?;
                if *p >= b.len() || b[*p] != b'.' { return None; }
                *p += 1;
                let w = num(p)?;
                if *p >= b.len() || b[*p] != b'.' { return None; }
                *p += 1;
                let d = num(p)?;
                if !(1..=12).contains(&m) || !(1..=5).contains(&w) || d > 6 { return None; }
                RuleDay::Month(m, w, d)
            } else if *p < b.len() && b[*p] == b'J' {
                *p += 1;
                let n = num(p)?;
                if !(1..=365).contains(&n) { return None; }
                RuleDay::Julian1(n)
            } else {
                let n = num(p)?;
                if n > 365 { return None; }
                RuleDay::Julian0(n)
            };
            let secs = if *p < b.len() && b[*p] == b'/' {
                *p += 1;
                hms(p)?
            } else {
                7200
            };
            Some(Change { day, secs })
        };
        name(&mut p)?;
        let std = -hms(&mut p)? as i32;
        if p >= b.len() {
            return Some(PosixTz { std, dst: None });
        }
        name(&mut p)?;
        let dst_off = if p < b.len() && b[p] != b',' { -hms(&mut p)? as i32 } else { std + 3600 };
        let start = change(&mut p)?;
        let end = change(&mut p)?;
        if p != b.len() {
            return None;
        }
        Some(PosixTz { std, dst: Some((dst_off, start, end)) })
    }

    /// Days from 1970-01-01 to the day a change falls on in `year`.
    fn day_of(day: RuleDay, year: i32) -> Option<i64> {
        use chrono::{Datelike, NaiveDate};
        let epoch = NaiveDate::from_ymd_opt(1970, 1, 1)?;
        let jan1 = NaiveDate::from_ymd_opt(year, 1, 1)?;
        let leap = NaiveDate::from_ymd_opt(year, 2, 29).is_some();
        let date = match day {
            RuleDay::Julian0(n) => jan1 + chrono::Duration::days(n as i64),
            RuleDay::Julian1(n) => jan1 + chrono::Duration::days(n as i64 - 1 + if leap && n >= 60 { 1 } else { 0 }),
            RuleDay::Month(m, w, d) => {
                let first = NaiveDate::from_ymd_opt(year, m, 1)?;
                let next = if m == 12 { NaiveDate::from_ymd_opt(year + 1, 1, 1)? } else { NaiveDate::from_ymd_opt(year, m + 1, 1)? };
                let days_in_month = (next - first).num_days() as u32;
                let first_wd = first.weekday().num_days_from_sunday();
                let mut dom = 1 + (d + 7 - first_wd) % 7 + 7 * (w - 1);
                while dom > days_in_month {
                    dom -= 7;
                }
                NaiveDate::from_ymd_opt(year, m, dom)?
            }
        };
        Some((date - epoch).num_days())
    }

    /// UTC offset (seconds east) in force at `utc_secs`.
    pub(crate) fn offset_at(&self, utc_secs: i64) -> i32 {
        let Some((dst, start, end)) = self.dst else { return self.std };
        use chrono::Datelike;
        let year = match chrono::DateTime::from_timestamp(utc_secs + self.std as i64, 0) {
            Some(d) => d.year(),
            None => return self.std,
        };
        // the change into daylight time is written in standard time, the
        // change out of it in daylight time; a period that began last year
        // or ends next year is looked at too (changes near the new year)
        for y in [year - 1, year, year + 1] {
            let (Some(s), Some(e)) = (Self::day_of(start.day, y), Self::day_of(end.day, if Self::day_of(end.day, y) > Self::day_of(start.day, y) { y } else { y + 1 })) else { continue };
            let s_utc = s * 86_400 + start.secs - self.std as i64;
            let e_utc = e * 86_400 + end.secs - dst as i64;
            if utc_secs >= s_utc && utc_secs < e_utc {
                return dst;
            }
        }
        self.std
    }
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
        // the footer of a version 2+ file: after the abbreviations, the
        // leap seconds and the two indicator arrays, a TZ string between
        // two line feeds
        let footer = if times_are_64 {
            let at = p + c.charcnt + c.leapcnt * 12 + c.isstdcnt + c.isutcnt;
            bytes.get(at..).filter(|rest| rest.first() == Some(&b'\n')).and_then(|rest| {
                let line = &rest[1..];
                let end = line.iter().position(|&x| x == b'\n').unwrap_or(line.len());
                std::str::from_utf8(&line[..end]).ok().and_then(PosixTz::parse)
            })
        } else {
            None
        };
        Some(TzifTable { transitions, idx, utoff, isdst, footer })
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
        // after the last transition listed, the footer's rule
        if let Some(rule) = &self.footer {
            if self.transitions.last().map_or(true, |last| utc_secs >= *last) {
                return rule.offset_at(utc_secs);
            }
        }
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
        if let Some(rule) = &self.footer {
            offs.push(rule.std);
            if let Some((dst, _, _)) = rule.dst {
                offs.push(dst);
            }
        }
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

#[cfg(test)]
mod footer_tests {
    use super::*;
    use chrono::Offset;

    #[test]
    fn posix_tz_strings_are_read() {
        let p = |s: &str| PosixTz::parse(s);
        assert_eq!(p("JST-9"), Some(PosixTz { std: 32400, dst: None }));
        assert_eq!(p("<+00>0"), Some(PosixTz { std: 0, dst: None }));
        let madrid = p("CET-1CEST,M3.5.0,M10.5.0/3").unwrap();
        assert_eq!(madrid.std, 3600);
        assert_eq!(madrid.dst, Some((7200, Change { day: RuleDay::Month(3, 5, 0), secs: 7200 }, Change { day: RuleDay::Month(10, 5, 0), secs: 10800 })));
        let ny = p("EST5EDT,M3.2.0,M11.1.0").unwrap();
        assert_eq!((ny.std, ny.dst.unwrap().0), (-18000, -14400));
        let chatham = p("<+1245>-12:45<+1345>,M9.5.0/2:45,M4.1.0/3:45").unwrap();
        assert_eq!((chatham.std, chatham.dst.unwrap().0, chatham.dst.unwrap().1.secs), (45900, 49500, 9900));
        let santiago = p("<-04>4<-03>,M9.1.6/24,M4.1.6/24").unwrap();
        assert_eq!(santiago.dst.unwrap().1.secs, 86400);
        assert_eq!(p("EST5EDT,J60,300/-1").unwrap().dst.unwrap().2, Change { day: RuleDay::Julian0(300), secs: -3600 });
        for bad in ["", "X", "CET", "CET-1CEST", "CET-1CEST,M13.1.0,M10.5.0", "CET-1CEST,M3.5.0", "CET-1CEST,M3.5.0,M10.5.0/3x", "<+00"] {
            assert_eq!(p(bad), None, "{:?}", bad);
        }
    }

    /// Real "slim" zoneinfo files (tzdata 2026.6, as RHEL, Fedora and
    /// Python's tzdata ship them): every hour from 2015 to 2037, the
    /// offset masstin reads from the file is the zone's.
    #[test]
    fn a_slim_file_gives_the_zones_offset_every_hour() {
        let zones: [(&str, &[u8], chrono_tz::Tz); 7] = [
            ("Europe/Madrid", include_bytes!("testdata/tzif/Europe_Madrid.tzif"), chrono_tz::Europe::Madrid),
            ("Europe/Dublin", include_bytes!("testdata/tzif/Europe_Dublin.tzif"), chrono_tz::Europe::Dublin),
            ("America/Santiago", include_bytes!("testdata/tzif/America_Santiago.tzif"), chrono_tz::America::Santiago),
            ("Australia/Sydney", include_bytes!("testdata/tzif/Australia_Sydney.tzif"), chrono_tz::Australia::Sydney),
            ("Asia/Tokyo", include_bytes!("testdata/tzif/Asia_Tokyo.tzif"), chrono_tz::Asia::Tokyo),
            ("America/New_York", include_bytes!("testdata/tzif/America_New_York.tzif"), chrono_tz::America::New_York),
            ("Pacific/Chatham", include_bytes!("testdata/tzif/Pacific_Chatham.tzif"), chrono_tz::Pacific::Chatham),
        ];
        let from = chrono::NaiveDate::from_ymd_opt(2015, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
        let to = chrono::NaiveDate::from_ymd_opt(2037, 12, 31).unwrap().and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
        for (name, bytes, tz) in zones {
            let table = TzifTable::parse(bytes).unwrap_or_else(|| panic!("{}", name));
            let mut t = from;
            let mut wrong = 0usize;
            let mut first = None;
            while t < to {
                let want = tz.offset_from_utc_datetime(&chrono::DateTime::from_timestamp(t, 0).unwrap().naive_utc()).fix().local_minus_utc();
                let got = table.offset_at(t);
                if got != want {
                    wrong += 1;
                    first.get_or_insert((t, got, want));
                }
                t += 3600;
            }
            assert_eq!(wrong, 0, "{}: {} hour(s) with another offset, the first {:?}", name, wrong, first);
        }
    }

    /// A syslog time of a July afternoon and of a January one in Madrid,
    /// from the slim file: two hours and one hour ahead of UTC.
    #[test]
    fn local_times_are_converted_with_the_footers_rule() {
        let table = TzifTable::parse(include_bytes!("testdata/tzif/Europe_Madrid.tzif")).unwrap();
        let tz = LocalTz::Table(table);
        let at = |s: &str| tz.to_utc(&NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()).format("%Y-%m-%d %H:%M:%S").to_string();
        assert_eq!(at("2026-07-15 16:00:00"), "2026-07-15 14:00:00");
        assert_eq!(at("2026-01-15 16:00:00"), "2026-01-15 15:00:00");
        // the night the clocks go back: 02:30 happens twice, the earlier one is taken
        assert_eq!(at("2026-10-25 02:30:00"), "2026-10-25 00:30:00");
        assert_eq!(at("2026-10-25 03:30:00"), "2026-10-25 02:30:00");
    }
}
