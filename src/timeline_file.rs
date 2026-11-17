//! What masstin keeps about a timeline, in one file next to it:
//! `<timeline>.masstin`. It is the case file the viewer opens (see
//! `view::case`): it names the timeline, and besides what the analyst keeps
//! there (views, story, notes) it carries what masstin itself knows of the
//! timeline, each under its own key:
//!
//! - `ingests`: what the timeline was read from (see `ingest_record`)
//! - `hunt`: what its hunt was run with (see `graph_hunt_common::record`)
//! - `hosts`: whose an address is (see `graph_hunt_common::hostmap`)
//! - `agentc00pr`: the case of agentc00pr the timeline was taken to
//!
//! One file, not one per record. Whoever writes a key leaves every other
//! key of the file as it was. The 19 columns are not touched by any of it.

use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

/// The extension of the file.
pub const EXT: &str = "masstin";

/// `timeline.csv` -> `timeline.masstin`, next to it.
pub fn path_for(timeline: &str) -> PathBuf {
    let p = Path::new(timeline);
    let stem = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "timeline".to_string());
    p.with_file_name(format!("{}.{}", stem, EXT))
}

/// A path as given, made absolute (not resolved: a mapped drive stays the
/// drive the analyst typed).
pub fn absolute(p: &str) -> String {
    std::path::absolute(p).map(|a| a.to_string_lossy().to_string()).unwrap_or_else(|_| p.to_string())
}

fn parse(text: &str) -> Option<Map<String, Value>> {
    match serde_json::from_str::<Value>(text.trim_start_matches('\u{feff}')).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

/// The whole file of a timeline, when it has one that reads.
pub fn read_all(timeline: &str) -> Option<Map<String, Value>> {
    parse(&std::fs::read_to_string(path_for(timeline)).ok()?)
}

/// One key of the file of a timeline.
pub fn get(timeline: &str, key: &str) -> Option<Value> {
    read_all(timeline)?.remove(key).filter(|v| !v.is_null())
}

/// Write one key of the file of a timeline, leaving the others as they are.
/// The file is made when it is not there: a case on that one timeline. A
/// file under that name that is not a masstin file is not written over.
pub fn set(timeline: &str, key: &str, value: Value) -> std::io::Result<PathBuf> {
    let path = path_for(timeline);
    let mut map = match std::fs::read_to_string(&path) {
        Ok(text) => parse(&text).ok_or_else(|| std::io::Error::other(format!("{} is there and is not a masstin file: left as it is", path.display())))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut m = Map::new();
            m.insert("masstin_case".to_string(), Value::from(1));
            m.insert("timelines".to_string(), Value::from(vec![absolute(timeline)]));
            m
        }
        Err(e) => return Err(e),
    };
    map.insert(key.to_string(), value);
    write_whole(&path, &serde_json::to_string_pretty(&Value::Object(map)).map_err(std::io::Error::other)?)?;
    Ok(path)
}

/// The keys masstin itself writes: the viewer, saving a case over the file,
/// keeps them as they are on disk.
pub const RECORD_KEYS: [&str; 4] = ["ingests", "hunt", "hosts", "agentc00pr"];

/// The whole text, or the file as it was: never half of it.
pub fn write_whole(path: &Path, text: &str) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".masstin-tmp-{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, text)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_file_per_timeline_and_a_key_leaves_the_others() {
        let dir = std::env::temp_dir().join(format!("masstin_timeline_file_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tl = dir.join("case.2026.csv").to_string_lossy().to_string();
        assert_eq!(path_for(&tl), dir.join("case.2026.masstin"));
        assert!(read_all(&tl).is_none() && get(&tl, "hunt").is_none());
        // made on the first key: a case on that timeline
        let path = set(&tl, "hunt", serde_json::json!({"alpha": 0.05})).unwrap();
        assert_eq!(path, dir.join("case.2026.masstin"));
        let all = read_all(&tl).unwrap();
        assert_eq!(all["masstin_case"], 1);
        assert_eq!(all["timelines"], serde_json::json!([tl.clone()]));
        // a second key, and what someone else keeps there, stay
        let mut all = all;
        all.insert("notes".into(), serde_json::json!([{"text": "start here"}]));
        std::fs::write(&path, serde_json::to_string(&Value::Object(all)).unwrap()).unwrap();
        set(&tl, "ingests", serde_json::json!([{"action": "parse"}])).unwrap();
        set(&tl, "hunt", serde_json::json!({"alpha": 0.01})).unwrap();
        let all = read_all(&tl).unwrap();
        assert_eq!((all["hunt"]["alpha"].as_f64(), all["ingests"][0]["action"].as_str(), all["notes"][0]["text"].as_str()), (Some(0.01), Some("parse"), Some("start here")));
        // only this file was written
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        // something else under that name is not written over
        std::fs::write(&path, "not json").unwrap();
        assert!(set(&tl, "hunt", Value::Null).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not json");
        assert!(read_all(&tl).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
