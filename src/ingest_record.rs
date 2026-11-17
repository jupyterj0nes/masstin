//! The record of an ingest, kept in the file of the timeline it wrote
//! (`<timeline>.masstin`, key `ingests`; see `timeline_file`). A timeline
//! says what happened on the machines;
//! it does not say what evidence it was read from. Whoever takes the
//! timeline further (a case tool, a colleague, the analyst a month later)
//! finds it here: the evidence given, the command that read it, when, and
//! with which masstin. The 19 columns are not touched by it.
//!
//! Written by every action that parses evidence files into a timeline
//! (`-o`). `merge` carries the records of the timelines it merges. An
//! action that reads no file (the Cortex API) leaves none: there is no
//! evidence on disk to name.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Ingest {
    /// the action (`parse`, `parse-image`…)
    #[serde(default)]
    pub action: String,
    /// the evidence given with -f and -d, as absolute paths
    #[serde(default)]
    pub sources: Vec<String>,
    /// the command line
    #[serde(default)]
    pub command: String,
    /// when it started, UTC, `YYYY-MM-DD HH:MM:SS`
    #[serde(default)]
    pub started: String,
    #[serde(default)]
    pub masstin_version: String,
}

/// The key of the timeline's file the ingests are kept under.
pub const KEY: &str = "ingests";

/// The runs of the parsers that made the timeline, in order; None when its
/// file names none.
pub fn read(timeline: &str) -> Option<Vec<Ingest>> {
    let v: Vec<Ingest> = serde_json::from_value(crate::timeline_file::get(timeline, KEY)?).ok()?;
    if v.is_empty() { None } else { Some(v) }
}

pub fn write(timeline: &str, ingests: Vec<Ingest>) -> std::io::Result<PathBuf> {
    crate::timeline_file::set(timeline, KEY, serde_json::to_value(ingests).map_err(std::io::Error::other)?)
}

use crate::timeline_file::absolute;

/// One argument as a shell would need it written.
fn quoted(a: &str) -> String {
    if a.is_empty() || a.contains([' ', '\t', '"', '&', '|', '<', '>', '^', ';', '(', ')']) {
        format!("\"{}\"", a.replace('"', "\\\""))
    } else {
        a.to_string()
    }
}

/// The command line of this process, as it could be typed again.
pub fn command_line(args: &[String]) -> String {
    let mut out = vec!["masstin".to_string()];
    out.extend(args.iter().skip(1).map(|a| quoted(a)));
    out.join(" ")
}

/// The ingest of evidence files into a timeline.
pub fn of_parse(action: &str, files: &[String], dirs: &[String], command: String, started: chrono::DateTime<chrono::Utc>) -> Option<Ingest> {
    let sources: Vec<String> = files.iter().chain(dirs.iter()).map(|p| absolute(p)).collect();
    if sources.is_empty() {
        return None;
    }
    Some(Ingest { action: action.to_string(), sources, command, started: started.format("%Y-%m-%d %H:%M:%S").to_string(), masstin_version: env!("CARGO_PKG_VERSION").to_string() })
}

/// What a merged timeline was made from: the ingests of the timelines
/// merged, each once.
pub fn of_merge(timelines: &[String]) -> Vec<Ingest> {
    let mut out: Vec<Ingest> = Vec::new();
    for t in timelines {
        for i in read(t).unwrap_or_default() {
            if !out.contains(&i) {
                out.push(i);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ingest_is_recorded_next_to_the_timeline_and_a_merge_carries_it() {
        let dir = std::env::temp_dir().join(format!("masstin_ingest_record_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tl = |n: &str| dir.join(n).to_string_lossy().to_string();
        let started = chrono::DateTime::parse_from_rfc3339("2026-11-16T21:40:00Z").unwrap().with_timezone(&chrono::Utc);
        assert!(read(&tl("a.csv")).is_none());
        // evidence files: their absolute paths, the command, the date
        let ev = dir.join("dc01.e01").to_string_lossy().to_string();
        let args: Vec<String> = ["masstin.exe", "-a", "parse", "-f", "D:\\my evidence\\dc01.e01", "-o", "a.csv"].iter().map(|s| s.to_string()).collect();
        let cmd = command_line(&args);
        assert_eq!(cmd, "masstin -a parse -f \"D:\\my evidence\\dc01.e01\" -o a.csv");
        let a = of_parse("parse", &[ev.clone()], &[], cmd.clone(), started).unwrap();
        assert_eq!((a.sources.clone(), a.started.as_str(), a.action.as_str()), (vec![ev.clone()], "2026-11-16 21:40:00", "parse"));
        assert!(std::path::Path::new(&of_parse("parse", &["rel.evtx".to_string()], &[], cmd.clone(), started).unwrap().sources[0]).is_absolute());
        // an action that reads no file names no evidence
        assert!(of_parse("parse-cortex", &[], &[], cmd.clone(), started).is_none());
        assert_eq!(write(&tl("a.csv"), vec![a.clone()]).unwrap(), dir.join("a.masstin"));
        assert_eq!(read(&tl("a.csv")), Some(vec![a.clone()]));
        // a merge carries the ingests of what it merges, each once
        let b = of_parse("parse-linux", &[], &[dir.join("triage").to_string_lossy().to_string()], "masstin -a parse-linux -d triage -o b.csv".into(), started).unwrap();
        write(&tl("b.csv"), vec![b.clone(), a.clone()]).unwrap();
        assert_eq!(of_merge(&[tl("a.csv"), tl("b.csv"), tl("none.csv")]), vec![a, b]);
        // a masstin file without ingests names none
        std::fs::write(crate::timeline_file::path_for(&tl("a.csv")), "{\"views\":[]}").unwrap();
        assert!(read(&tl("a.csv")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
