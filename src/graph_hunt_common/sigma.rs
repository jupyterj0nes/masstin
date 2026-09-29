// Sigma hits from Hayabusa / Chainsaw (or any JSON with a time, a host and
// a rule title), read once and matched to the graph's machines. masstin does
// not detect PsExec, WMI or service installs itself; those tools do, with
// thousands of rules. What masstin adds is the join: a hit on a machine
// while a login session is open on it corroborates that connection, and
// the report says which rule fired and when.
//
// Accepted shapes: a JSON array, one object per line (JSONL) or a single
// object. Field names tried, in order:
//   time : Timestamp, timestamp, @timestamp, time, time_created
//   host : Computer, computer, host, hostname,
//          document.data.Event.System.Computer (Chainsaw), Event.System.Computer
//   rule : RuleTitle, name, title, rule, RuleName
//   level: Level, level
//   tags : MitreTags, MitreTactics, tags, OtherTags (array or string)

use chrono::{DateTime, NaiveDateTime};
use serde_json::Value;
use std::path::Path;

pub struct SigmaHit {
    /// Unix seconds, UTC
    pub t: i64,
    /// host as written (normalised for matching by the engine)
    pub host: String,
    pub title: String,
    pub level: String,
    pub tags: String,
}

/// Short upper-case host name: "ws01.corp.local" -> "WS01"; an IP is kept
/// whole.
pub fn norm_host(s: &str) -> String {
    let t = s.trim();
    if t.parse::<std::net::IpAddr>().is_ok() {
        return t.to_string();
    }
    t.split('.').next().unwrap_or("").to_uppercase()
}

fn parse_time(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Some(t.timestamp());
    }
    for f in ["%Y-%m-%d %H:%M:%S%.f %:z", "%Y-%m-%d %H:%M:%S %:z", "%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%d %H:%M:%S%.f%z"] {
        if let Ok(t) = DateTime::parse_from_str(s, f) {
            return Some(t.timestamp());
        }
    }
    let n = s.trim_end_matches('Z');
    for f in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(t) = NaiveDateTime::parse_from_str(n, f) {
            return Some(t.and_utc().timestamp());
        }
    }
    None
}

fn first<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|k| v.get(*k))
}

fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => Some(a.iter().filter_map(as_text).collect::<Vec<_>>().join(" ")),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn one(v: &Value) -> Option<SigmaHit> {
    if !v.is_object() {
        return None;
    }
    let t = parse_time(&as_text(first(v, &["Timestamp", "timestamp", "@timestamp", "time", "time_created"])?)?)?;
    let host = first(v, &["Computer", "computer", "host", "hostname"])
        .and_then(as_text)
        .or_else(|| v.pointer("/document/data/Event/System/Computer").and_then(as_text))
        .or_else(|| v.pointer("/Event/System/Computer").and_then(as_text))?;
    let title = first(v, &["RuleTitle", "name", "title", "rule", "RuleName"]).and_then(as_text)?;
    let level = first(v, &["Level", "level"]).and_then(as_text).unwrap_or_default();
    let tags = ["MitreTags", "MitreTactics", "tags", "OtherTags"]
        .iter()
        .filter_map(|k| v.get(*k).and_then(as_text))
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if host.trim().is_empty() || title.trim().is_empty() {
        return None;
    }
    Some(SigmaHit { t, host, title, level, tags })
}

fn files_of(path: &str) -> Vec<String> {
    let p = Path::new(path);
    if p.is_dir() {
        let mut v: Vec<String> = std::fs::read_dir(p)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|q| q.is_file() && q.extension().map(|x| x == "json" || x == "jsonl").unwrap_or(false))
                    .map(|q| q.display().to_string())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    } else {
        vec![path.to_string()]
    }
}

/// Read every hit of the given files (or directories of .json/.jsonl).
/// Returns the hits and one note per file for the run log.
pub fn load(paths: &[String]) -> (Vec<SigmaHit>, Vec<String>) {
    let mut hits = Vec::new();
    let mut notes = Vec::new();
    for path in paths.iter().flat_map(|p| files_of(p)) {
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                notes.push(format!("{}: cannot read ({})", path, e));
                continue;
            }
        };
        let mut n = 0usize;
        let mut skipped = 0usize;
        let trimmed = text.trim_start();
        let mut values: Vec<Value> = Vec::new();
        if trimmed.starts_with('[') {
            match serde_json::from_str::<Value>(trimmed) {
                Ok(Value::Array(a)) => values = a,
                Ok(v) => values.push(v),
                Err(e) => {
                    notes.push(format!("{}: not JSON ({})", path, e));
                    continue;
                }
            }
        } else {
            for line in text.lines() {
                let l = line.trim();
                if l.is_empty() {
                    continue;
                }
                match serde_json::from_str::<Value>(l) {
                    Ok(v) => values.push(v),
                    Err(_) => skipped += 1,
                }
            }
        }
        for v in &values {
            if let Some(h) = one(v) {
                hits.push(h);
                n += 1;
            } else {
                skipped += 1;
            }
        }
        notes.push(format!("{}: {} hit(s){}", path, n, if skipped > 0 { format!(", {} record(s) without time, host or rule", skipped) } else { String::new() }));
    }
    hits.sort_by_key(|h| h.t);
    (hits, notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hayabusa_and_chainsaw_shapes() {
        let hb = r#"{"Timestamp":"2026-09-23 17:35:07.123 +02:00","Computer":"ws01.corp.local","Channel":"Sec","EventID":7045,"Level":"high","RuleTitle":"PsExec Service Installation","MitreTags":["T1021.002"]}"#;
        let cs = r#"{"name":"Service installation","timestamp":"2026-09-23T15:35:07.000000Z","level":"high","tags":["attack.lateral_movement"],"document":{"data":{"Event":{"System":{"Computer":"WS01.corp.local"}}}}}"#;
        let a = one(&serde_json::from_str(hb).unwrap()).unwrap();
        let b = one(&serde_json::from_str(cs).unwrap()).unwrap();
        assert_eq!(a.t, b.t);
        assert_eq!(norm_host(&a.host), "WS01");
        assert_eq!(norm_host(&b.host), "WS01");
        assert_eq!(a.title, "PsExec Service Installation");
        assert_eq!(b.tags, "attack.lateral_movement");
        assert_eq!(norm_host("10.1.2.3"), "10.1.2.3");
        assert!(one(&serde_json::from_str(r#"{"Computer":"x"}"#).unwrap()).is_none());
    }
}
