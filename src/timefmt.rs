//! Fallback timestamp formats for `time_created` values that are not the
//! ISO / RFC 3339 shapes masstin's own parsers write. Custom rules keep the
//! vendor's timestamp as it comes, and two vendors in the rule library do
//! not write ISO: Zscaler ZPA logs `LogTimestamp` in C asctime form
//! ("Fri May 31 17:35:42 2019"), and Cloudflare Logpush can be configured
//! to write `CreatedAt` as a Unix epoch in seconds, milliseconds,
//! microseconds or nanoseconds. Every place that reads a timeline (the
//! loaders, the hunt, `merge`, the parsers' own sort) tries its usual
//! formats first and then this one.

use chrono::{Datelike, NaiveDate, NaiveDateTime};

/// asctime ("Fri May 31 17:35:42 2019", also "Fri May  1 ..." and without
/// the weekday), the same with the year after the day ("Apr 13 2026
/// 09:00:15", Cisco ASA with `logging timestamp`), slashed dates
/// ("2026/04/13 09:15:18", Palo Alto), and Unix epoch (10 digits =
/// seconds, 13 = ms, 16 = µs, 19 = ns; seconds may carry a fraction,
/// "1744530015.123", Squid). Returns naive UTC.
pub fn parse_fallback(raw: &str) -> Option<NaiveDateTime> {
    let s = raw.trim().trim_matches('"');
    if s.is_empty() {
        return None;
    }
    // epoch seconds with a fraction
    if let Some((secs, frac)) = s.split_once('.') {
        if secs.len() == 10 && secs.bytes().all(|c| c.is_ascii_digit())
            && !frac.is_empty() && frac.len() <= 9 && frac.bytes().all(|c| c.is_ascii_digit())
        {
            let nanos: u32 = format!("{:0<9}", frac).parse().ok()?;
            return chrono::DateTime::from_timestamp(secs.parse().ok()?, nanos).map(|d| d.naive_utc());
        }
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        let n: i128 = s.parse().ok()?;
        let (secs, nanos) = match s.len() {
            10 => (n, 0),
            13 => (n / 1_000, (n % 1_000) * 1_000_000),
            16 => (n / 1_000_000, (n % 1_000_000) * 1_000),
            19 => (n / 1_000_000_000, n % 1_000_000_000),
            _ => return None,
        };
        return chrono::DateTime::from_timestamp(secs as i64, nanos as u32).map(|d| d.naive_utc());
    }
    // asctime, with or without the weekday, single or double space before
    // the day of month
    let squeezed: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    for f in [
        "%a %b %d %H:%M:%S %Y", "%b %d %H:%M:%S %Y", "%a %b %d %H:%M:%S %Z %Y",
        "%b %d %Y %H:%M:%S", "%b %d %Y %H:%M:%S%.f",
        "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M:%S%.f",
    ] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(&squeezed, f) {
            return Some(dt);
        }
    }
    None
}

/// What a parser writes into `time_created`: a value already in one of
/// masstin's own shapes (RFC 3339, `YYYY-MM-DDTHH:MM:SS[.f][Z]`,
/// `YYYY-MM-DD HH:MM:SS[.f]`) is kept exactly as it came; a value only the
/// fallback understands (asctime, epoch) is rewritten as ISO UTC so the
/// CSV stays homogeneous; anything else is kept as it came and will be
/// reported as unparseable downstream.
pub fn normalise_for_csv(raw: &str) -> String {
    normalise_for_csv_bounded(raw, None)
}

/// A syslog (RFC 3164) stamp carries no year: "Apr 13 09:14:22". Given the
/// last day the file can hold (its logrotate suffix, or the day after it
/// was last written), the year is that day's, or the one before when the
/// stamp would fall after it (a file written in January holding December
/// lines), as parse-linux dates its syslog files. Taken as UTC.
pub fn syslog_without_year(raw: &str, bound: NaiveDate) -> Option<NaiveDateTime> {
    let squeezed: String = raw.trim().split_whitespace().collect::<Vec<_>>().join(" ");
    let mut parts = squeezed.splitn(3, ' ');
    let (mon, day, time) = (parts.next()?, parts.next()?, parts.next()?);
    if mon.len() != 3 || !day.bytes().all(|c| c.is_ascii_digit()) || time.contains(' ') {
        return None;
    }
    let at = |y: i32| -> Option<NaiveDateTime> {
        let text = format!("{} {} {} {}", mon, day, y, time);
        NaiveDateTime::parse_from_str(&text, "%b %d %Y %H:%M:%S%.f")
            .or_else(|_| NaiveDateTime::parse_from_str(&text, "%b %d %Y %H:%M:%S"))
            .ok()
    };
    let dt = at(bound.year())?;
    if dt.date() > bound { at(bound.year() - 1) } else { Some(dt) }
}

/// `normalise_for_csv`, plus syslog stamps without a year when the file
/// gives a bound (see `syslog_without_year`).
pub fn normalise_for_csv_bounded(raw: &str, bound: Option<NaiveDate>) -> String {
    let t = raw.trim();
    if let Some(b) = bound {
        if let Some(dt) = syslog_without_year(t, b) {
            return iso(dt);
        }
    }
    if t.is_empty() {
        return String::new();
    }
    if chrono::DateTime::parse_from_rfc3339(t).is_ok() || chrono::DateTime::parse_from_rfc3339(&t.replacen(' ', "T", 1)).is_ok() {
        return t.to_string();
    }
    let bare = t.trim_end_matches('Z').replacen(' ', "T", 1);
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if NaiveDateTime::parse_from_str(&bare, f).is_ok() {
            return t.to_string();
        }
    }
    match parse_fallback(t) {
        Some(dt) => iso(dt),
        None => t.to_string(),
    }
}

fn iso(dt: NaiveDateTime) -> String {
    if dt.and_utc().timestamp_subsec_nanos() == 0 {
        dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        dt.format("%Y-%m-%dT%H:%M:%S%.fZ").to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{normalise_for_csv, parse_fallback};

    #[test]
    fn csv_values_come_out_iso() {
        assert_eq!(normalise_for_csv("Fri May 31 17:35:42 2019"), "2019-05-31T17:35:42Z");
        assert_eq!(normalise_for_csv("1684862313"), "2023-05-23T17:18:33Z");
        assert_eq!(normalise_for_csv("1684862313500"), "2023-05-23T17:18:33.500Z");
        assert_eq!(normalise_for_csv("2023-05-24T02:48:33+09:30"), "2023-05-24T02:48:33+09:30", "masstin's own shapes are kept as they come");
        assert_eq!(normalise_for_csv("2020-09-19T03:21:47.000Z"), "2020-09-19T03:21:47.000Z");
        assert_eq!(normalise_for_csv("2020-09-19 03:21:47"), "2020-09-19 03:21:47");
        assert_eq!(normalise_for_csv("not a date"), "not a date");
    }

    #[test]
    fn asctime_and_epoch() {
        let t = parse_fallback("Fri May 31 17:35:42 2019").unwrap();
        assert_eq!(t.to_string(), "2019-05-31 17:35:42");
        assert_eq!(parse_fallback("Wed May  1 09:05:00 2024").unwrap().to_string(), "2024-05-01 09:05:00");
        assert_eq!(parse_fallback("1684862313").unwrap().to_string(), "2023-05-23 17:18:33");
        assert_eq!(parse_fallback("1684862313000").unwrap().to_string(), "2023-05-23 17:18:33");
        assert_eq!(parse_fallback("1684862313000000000").unwrap().to_string(), "2023-05-23 17:18:33");
        assert!(parse_fallback("2023-05-24T02:48:33+09:30").is_none(), "ISO is for the regular parsers");
        assert!(parse_fallback("12345").is_none());
        assert!(parse_fallback("").is_none());
    }

    #[test]
    fn vendor_shapes_from_the_rule_library() {
        assert_eq!(normalise_for_csv("2026/04/13 09:15:18"), "2026-04-13T09:15:18Z");
        assert_eq!(normalise_for_csv("1744530015.123"), "2025-04-13T07:40:15.123Z");
        assert_eq!(normalise_for_csv("Apr 13 2026 09:00:15"), "2026-04-13T09:00:15Z");
    }

    #[test]
    fn syslog_year_comes_from_the_file() {
        use chrono::NaiveDate;
        let b = NaiveDate::from_ymd_opt(2026, 10, 9);
        assert_eq!(super::normalise_for_csv_bounded("Apr 13 09:14:22", b), "2026-04-13T09:14:22Z");
        // a January file holding December lines
        let jan = NaiveDate::from_ymd_opt(2026, 1, 2);
        assert_eq!(super::normalise_for_csv_bounded("Dec 31 23:59:01", jan), "2025-12-31T23:59:01Z");
        assert_eq!(super::normalise_for_csv_bounded("Apr  3 09:14:22", b), "2026-04-03T09:14:22Z");
        // without a bound the stamp is left as it came
        assert_eq!(normalise_for_csv("Apr 13 09:14:22"), "Apr 13 09:14:22");
        // ISO is never touched
        assert_eq!(super::normalise_for_csv_bounded("2026-04-13T09:14:22Z", b), "2026-04-13T09:14:22Z");
    }
}
