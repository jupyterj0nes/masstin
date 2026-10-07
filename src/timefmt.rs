//! Fallback timestamp formats for `time_created` values that are not the
//! ISO / RFC 3339 shapes masstin's own parsers write. Custom rules keep the
//! vendor's timestamp as it comes, and two vendors in the rule library do
//! not write ISO: Zscaler ZPA logs `LogTimestamp` in C asctime form
//! ("Fri May 31 17:35:42 2019"), and Cloudflare Logpush can be configured
//! to write `CreatedAt` as a Unix epoch in seconds, milliseconds,
//! microseconds or nanoseconds. Every place that reads a timeline (the
//! loaders, the hunt, `merge`, the parsers' own sort) tries its usual
//! formats first and then this one.

use chrono::NaiveDateTime;

/// asctime ("Fri May 31 17:35:42 2019", also "Fri May  1 ..." and without
/// the weekday) and Unix epoch (10 digits = seconds, 13 = ms, 16 = µs,
/// 19 = ns). Returns naive UTC.
pub fn parse_fallback(raw: &str) -> Option<NaiveDateTime> {
    let s = raw.trim().trim_matches('"');
    if s.is_empty() {
        return None;
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
    for f in ["%a %b %d %H:%M:%S %Y", "%b %d %H:%M:%S %Y", "%a %b %d %H:%M:%S %Z %Y"] {
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
    let t = raw.trim();
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
        Some(dt) => {
            if dt.and_utc().timestamp_subsec_nanos() == 0 {
                dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
            } else {
                dt.format("%Y-%m-%dT%H:%M:%S%.fZ").to_string()
            }
        }
        None => t.to_string(),
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
}
