//! The record of a hunt, kept in the file of the timeline it was written
//! into (`<timeline>.masstin`, key `hunt`; see `timeline_file`). The hunt columns of a timeline say what every
//! row is (significant, candidate, baseline…) but not what the hunt was run
//! with; a timeline hunted with one start of the investigation and read
//! later next to others hunted with another cannot be told apart by its
//! rows. The record says it: the start of the investigation, the end of the
//! window when one was given, alpha, the masstin that hunted and when.
//!
//! The 19 columns are not touched by this. A timeline that travels without
//! its record still shows the day the investigation started: the first day
//! whose rows are not `baseline` (see `docs/csv-format.md`).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HuntRecord {
    /// the format's version (1)
    #[serde(default)]
    pub masstin_hunt: u32,
    #[serde(default)]
    pub masstin_version: String,
    /// when the hunt ran, UTC, `YYYY-MM-DD HH:MM:SS`
    #[serde(default)]
    pub hunted_at: String,
    /// `--investigation-from`, UTC, `YYYY-MM-DD HH:MM:SS`: rows of earlier
    /// days are `baseline`
    #[serde(default)]
    pub investigation_from: String,
    /// the end of the window when one was given (`--end-time`), else empty
    #[serde(default)]
    pub window_end: String,
    /// the false discovery rate (`--alpha`)
    #[serde(default)]
    pub alpha: f64,
    /// connections of the window the hunt gave a verdict on
    #[serde(default)]
    pub connections: u64,
    /// of them, significant at alpha
    #[serde(default)]
    pub significant: u64,
    /// `--merge-hosts`: the level addresses were read as their host at
    /// (`strict`, `standard`, `broad`), empty when they were not, and how
    /// many were
    #[serde(default)]
    pub merge_hosts: String,
    #[serde(default)]
    pub hosts_merged: u64,
    /// the timelines hunted together (their file names): the hunt of one
    /// depends on the others
    #[serde(default)]
    pub timelines: Vec<String>,
}

/// The key of the timeline's file the hunt is kept under.
pub const KEY: &str = "hunt";

pub fn write(timeline: &str, rec: &HuntRecord) -> std::io::Result<PathBuf> {
    crate::timeline_file::set(timeline, KEY, serde_json::to_value(rec).map_err(std::io::Error::other)?)
}

/// The record of a timeline, when it has one that reads.
pub fn read(timeline: &str) -> Option<HuntRecord> {
    let rec: HuntRecord = serde_json::from_value(crate::timeline_file::get(timeline, KEY)?).ok()?;
    if rec.masstin_hunt == 0 { None } else { Some(rec) }
}

/// A timeline written anew from another (`--if-hunted new`) was read from
/// the same evidence: its file says so too, and what that evidence said
/// of whose an address is.
pub fn carry_ingests(from: &str, to: &str) {
    if let Some(i) = crate::ingest_record::read(from) {
        let _ = crate::ingest_record::write(to, i);
    }
    let _ = super::hostmap::write_facts(to, &super::hostmap::read_facts(from));
}

pub fn fmt_utc(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// What to do with a timeline that already carries a hunt when it is hunted
/// again (`--if-hunted`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum IfHunted {
    /// write the new hunt over the one it had (in place)
    #[default]
    Overwrite,
    /// leave the timeline as it is: it still counts in the statistics, its
    /// columns are not written
    Keep,
    /// write the timeline with the new hunt to a new file next to it; the
    /// one given keeps the hunt it had
    New,
}

impl IfHunted {
    pub fn parse(s: &str) -> Option<IfHunted> {
        match s.trim().to_ascii_lowercase().as_str() {
            "overwrite" | "replace" => Some(IfHunted::Overwrite),
            "keep" => Some(IfHunted::Keep),
            "new" | "copy" => Some(IfHunted::New),
            _ => None,
        }
    }
}

/// The hunt a timeline already carries: its record when it has one, and
/// what its own rows say.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Previous {
    pub record: Option<HuntRecord>,
    /// rows with a hunt state, and those `significant`
    pub hunted_rows: u64,
    pub significant: u64,
    /// the last day with `baseline` rows and the first with judged ones
    /// (`YYYY-MM-DD`): the investigation started between them
    pub last_baseline_day: String,
    pub first_judged_day: String,
}

impl Previous {
    /// The start of the investigation of that hunt, in words: exact from
    /// the record, else read off the rows (to the day).
    pub fn started(&self) -> String {
        match &self.record {
            Some(r) if !r.investigation_from.is_empty() => format!("{} UTC", r.investigation_from),
            _ => match (self.last_baseline_day.as_str(), self.first_judged_day.as_str()) {
                ("", "") => "unknown (no row says)".to_string(),
                ("", f) => format!("on or before {} (read off the rows: no baseline row, no record)", f),
                (l, "") => format!("after {} (read off the rows: no judged row, no record)", l),
                (l, f) => format!("after {} and by {} (read off the rows: no record)", l, f),
            },
        }
    }

    /// One line: what the timeline was hunted with.
    pub fn describe(&self) -> String {
        let mut parts = vec![format!("investigation from {}", self.started())];
        if let Some(r) = &self.record {
            if !r.window_end.is_empty() {
                parts.push(format!("window end {} UTC", r.window_end));
            }
            parts.push(format!("alpha {}", r.alpha));
            if !r.merge_hosts.is_empty() {
                parts.push(format!("{} address(es) read as their host (--merge-hosts {})", r.hosts_merged, r.merge_hosts));
            }
            let who = if r.masstin_version.is_empty() { "masstin".to_string() } else { format!("masstin {}", r.masstin_version) };
            parts.push(if r.hunted_at.is_empty() { format!("by {}", who) } else { format!("by {} on {} UTC", who, r.hunted_at) });
        } else {
            parts.push("alpha and date of the hunt unknown".to_string());
        }
        parts.push(format!("{} row(s) with a hunt state, {} significant", self.hunted_rows, self.significant));
        parts.join("; ")
    }
}

/// The hunt a timeline already carries, None when no row of it has a hunt
/// state (and it has no record). The file is read once.
pub fn previous(timeline: &str) -> std::io::Result<Option<Previous>> {
    let rd = std::io::BufReader::new(std::fs::File::open(timeline)?);
    let mut lines = crate::csv_out::records(rd);
    let header = lines.next().transpose()?.unwrap_or_default();
    let mut prev = Previous { record: read(timeline), ..Previous::default() };
    // only the 19-column layout has hunt columns
    if crate::csv_out::Layout::of(&header) == Some(crate::csv_out::Layout::V19) {
        for line in lines {
            let line = line?;
            let mut p: Vec<std::borrow::Cow<str>> = Vec::with_capacity(20);
            super::engine::split_csv_into(line.trim_end_matches(['\r', '\n']), &mut p);
            let (Some(t), Some(h)) = (p.first(), p.get(14)) else { continue };
            let h = h.trim();
            if h.is_empty() {
                continue;
            }
            prev.hunted_rows += 1;
            let day = t.get(..10).unwrap_or("");
            if day.len() != 10 {
                continue;
            }
            if h == "baseline" {
                if day > prev.last_baseline_day.as_str() {
                    prev.last_baseline_day = day.to_string();
                }
            } else {
                if h == "significant" {
                    prev.significant += 1;
                }
                if prev.first_judged_day.is_empty() || day < prev.first_judged_day.as_str() {
                    prev.first_judged_day = day.to_string();
                }
            }
        }
    }
    Ok(if prev.hunted_rows == 0 && prev.record.is_none() { None } else { Some(prev) })
}

/// The file a timeline is written to with a new hunt when the one it has
/// is kept: `timeline.csv` -> `timeline.hunt-2026-11-09.csv` (and `-2`,
/// `-3`… while the name is taken), next to it.
pub fn new_name(timeline: &str, investigation_from: chrono::DateTime<chrono::Utc>) -> PathBuf {
    let p = Path::new(timeline);
    let stem = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "timeline".to_string());
    // a timeline that is itself such a copy does not grow a second suffix
    let stem = match stem.rfind(".hunt-") {
        Some(k) if stem[k + 6..].chars().all(|c| c.is_ascii_digit() || c == '-') => stem[..k].to_string(),
        _ => stem,
    };
    let ext = p.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_else(|| "csv".to_string());
    let day = investigation_from.format("%Y-%m-%d");
    let mut cand = p.with_file_name(format!("{}.hunt-{}.{}", stem, day, ext));
    let mut n = 2;
    while cand.exists() {
        cand = p.with_file_name(format!("{}.hunt-{}-{}.{}", stem, day, n, ext));
        n += 1;
    }
    cand
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_sits_in_the_file_of_the_timeline_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("masstin_hunt_record_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let tl = dir.join("case.2026.csv").to_string_lossy().to_string();
        assert!(read(&tl).is_none());
        let rec = HuntRecord { masstin_hunt: 1, masstin_version: "1.5.0".into(), hunted_at: "2026-11-16 22:00:00".into(), investigation_from: "2026-11-09 00:00:00".into(), window_end: String::new(), alpha: 0.05, connections: 1109, significant: 24, merge_hosts: "standard".into(), hosts_merged: 7, timelines: vec!["case.2026.csv".into()] };
        let path = write(&tl, &rec).unwrap();
        assert_eq!(path, dir.join("case.2026.masstin"));
        assert_eq!(read(&tl), Some(rec.clone()));
        // the ingests kept in the same file stay, and go on to a copy
        let ing = crate::ingest_record::Ingest { action: "parse".into(), sources: vec!["D:\\ev\\dc01".into()], ..Default::default() };
        crate::ingest_record::write(&tl, vec![ing.clone()]).unwrap();
        assert_eq!(read(&tl), Some(rec));
        let copy = dir.join("case.2026.hunt-2026-11-12.csv").to_string_lossy().to_string();
        carry_ingests(&tl, &copy);
        assert_eq!(crate::ingest_record::read(&copy), Some(vec![ing]));
        assert!(read(&copy).is_none());
        // a masstin file without a hunt has no record
        std::fs::write(&path, "{\"views\":[]}").unwrap();
        assert!(read(&tl).is_none());
        std::fs::write(&path, "not json").unwrap();
        assert!(read(&tl).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_hunted_timeline_says_from_when_with_or_without_its_record() {
        let dir = std::env::temp_dir().join(format!("masstin_hunt_previous_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let row = |t: &str, hunt: &str| format!("{t},SRV01,SUCCESSFUL_LOGON,4624,3,alice,CORP,WS01,10.0.0.5,,,0x1,,Security.evtx,{hunt},,,,");
        let write_tl = |name: &str, rows: &[String]| -> String {
            let p = dir.join(name);
            std::fs::write(&p, format!("{}\n{}\n", crate::csv_out::HEADER, rows.join("\n"))).unwrap();
            p.to_string_lossy().to_string()
        };
        // never hunted
        let plain = write_tl("plain.csv", &[row("2026-11-07T08:00:00+00:00", ""), row("2026-11-10T08:00:00+00:00", "")]);
        assert_eq!(previous(&plain).unwrap(), None);
        // hunted, no record: the rows say between which days it started
        let hunted = write_tl("hunted.csv", &[
            row("2026-11-05T08:00:00+00:00", "baseline"),
            row("2026-11-07T08:00:00+00:00", "baseline"),
            row("2026-11-10T09:00:00+00:00", "habitual"),
            row("2026-11-10T10:00:00+00:00", "significant"),
            row("2026-11-12T10:00:00+00:00", "candidate"),
            row("2026-11-13T10:00:00+00:00", ""),
        ]);
        let p = previous(&hunted).unwrap().unwrap();
        assert_eq!((p.hunted_rows, p.significant, p.last_baseline_day.as_str(), p.first_judged_day.as_str()), (5, 1, "2026-11-07", "2026-11-10"));
        assert_eq!(p.started(), "after 2026-11-07 and by 2026-11-10 (read off the rows: no record)");
        assert!(p.describe().contains("alpha and date of the hunt unknown") && p.describe().ends_with("5 row(s) with a hunt state, 1 significant"), "{}", p.describe());
        // with its record: exact
        let rec = HuntRecord { masstin_hunt: 1, masstin_version: "1.5.0".into(), hunted_at: "2026-11-16 22:00:00".into(), investigation_from: "2026-11-09 00:00:00".into(), window_end: String::new(), alpha: 0.05, connections: 3, significant: 1, merge_hosts: String::new(), hosts_merged: 0, timelines: vec!["hunted.csv".into()] };
        write(&hunted, &rec).unwrap();
        let p = previous(&hunted).unwrap().unwrap();
        assert_eq!(p.started(), "2026-11-09 00:00:00 UTC");
        assert_eq!(p.describe(), "investigation from 2026-11-09 00:00:00 UTC; alpha 0.05; by masstin 1.5.0 on 2026-11-16 22:00:00 UTC; 5 row(s) with a hunt state, 1 significant");
        // the name of the copy with a new hunt
        let from = chrono::DateTime::parse_from_rfc3339("2026-11-12T00:00:00Z").unwrap().with_timezone(&chrono::Utc);
        let first = new_name(&hunted, from);
        assert_eq!(first, dir.join("hunted.hunt-2026-11-12.csv"));
        std::fs::write(&first, "x").unwrap();
        assert_eq!(new_name(&hunted, from), dir.join("hunted.hunt-2026-11-12-2.csv"));
        assert_eq!(new_name(&first.to_string_lossy(), from), dir.join("hunted.hunt-2026-11-12-2.csv"), "a copy of a copy keeps one suffix");
        assert_eq!((IfHunted::parse("New"), IfHunted::parse("keep"), IfHunted::parse("overwrite"), IfHunted::parse("x")), (Some(IfHunted::New), Some(IfHunted::Keep), Some(IfHunted::Overwrite), None));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
