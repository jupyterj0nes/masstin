//! The record of an ingest, kept next to the timeline it wrote:
//! `<timeline>.ingest.json`. A timeline says what happened on the machines;
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
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct IngestRecord {
    /// the format's version (1)
    #[serde(default)]
    pub masstin_ingest: u32,
    /// the timeline's file name
    #[serde(default)]
    pub timeline: String,
    /// the runs of the parsers that made the timeline, in order
    #[serde(default)]
    pub ingests: Vec<Ingest>,
}

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

/// `timeline.csv` -> `timeline.ingest.json`, next to it.
pub fn path_for(timeline: &str) -> PathBuf {
    let p = Path::new(timeline);
    let stem = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "timeline".to_string());
    p.with_file_name(format!("{}.ingest.json", stem))
}

pub fn read(timeline: &str) -> Option<IngestRecord> {
    let text = std::fs::read_to_string(path_for(timeline)).ok()?;
    let rec: IngestRecord = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    if rec.masstin_ingest == 0 { None } else { Some(rec) }
}

pub fn write(timeline: &str, ingests: Vec<Ingest>) -> std::io::Result<PathBuf> {
    let name = Path::new(timeline).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| timeline.to_string());
    let rec = IngestRecord { masstin_ingest: 1, timeline: name, ingests };
    let path = path_for(timeline);
    std::fs::write(&path, serde_json::to_string_pretty(&rec).map_err(std::io::Error::other)?)?;
    Ok(path)
}

/// A path as given, made absolute (not resolved: a mapped drive stays the
/// drive the analyst typed).
pub fn absolute(p: &str) -> String {
    std::path::absolute(p).map(|a| a.to_string_lossy().to_string()).unwrap_or_else(|_| p.to_string())
}

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
        for i in read(t).map(|r| r.ingests).unwrap_or_default() {
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
        assert_eq!(path_for(&tl("a.case.csv")), dir.join("a.case.ingest.json"));
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
        write(&tl("a.csv"), vec![a.clone()]).unwrap();
        let back = read(&tl("a.csv")).unwrap();
        assert_eq!((back.masstin_ingest, back.timeline.as_str(), back.ingests.len()), (1, "a.csv", 1));
        // a merge carries the ingests of what it merges, each once
        let b = of_parse("parse-linux", &[], &[dir.join("triage").to_string_lossy().to_string()], "masstin -a parse-linux -d triage -o b.csv".into(), started).unwrap();
        write(&tl("b.csv"), vec![b.clone(), a.clone()]).unwrap();
        assert_eq!(of_merge(&[tl("a.csv"), tl("b.csv"), tl("none.csv")]), vec![a, b]);
        // something else under that name is no record
        std::fs::write(path_for(&tl("a.csv")), "{\"views\":[]}").unwrap();
        assert!(read(&tl("a.csv")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
