//! The case file, `<name>.masstin`: what the analyst keeps about a case in
//! one file, wherever they want it (a folder of their own, not the share the
//! evidence sits on). It names the timelines and holds what would otherwise
//! go next to them: the saved views, the style, the merged hosts, the
//! subnets (`views`), the presentation (`story`) and the notes. While a case
//! is open nothing is written next to the timelines; the marks (`verdict`,
//! `notes`) stay in the CSV itself.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::notes::{Note, Notes};
use super::present::Story;
use super::views::ViewsFile;

/// The extension a case file carries.
pub const EXT: &str = "masstin";

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CaseFile {
    /// the format's version
    #[serde(default)]
    pub masstin_case: u32,
    /// the timelines, as they were opened
    #[serde(default)]
    pub timelines: Vec<String>,
    #[serde(default)]
    pub views: ViewsFile,
    #[serde(default)]
    pub story: Story,
    #[serde(default)]
    pub notes: Vec<Note>,
}

/// `case.masstin`, whatever the case of the extension.
pub fn is_case(path: &str) -> bool {
    Path::new(path).extension().map_or(false, |e| e.eq_ignore_ascii_case(EXT))
}

impl CaseFile {
    pub fn load(path: &Path) -> Result<CaseFile, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read the case {}: {}", path.display(), e))?;
        serde_json::from_str(&text).map_err(|e| format!("{} is not a masstin case: {}", path.display(), e))
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut c = self.clone();
        c.masstin_case = 1;
        let text = serde_json::to_string_pretty(&c).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, text)
    }

    /// A new case on these timelines, starting from what is already kept next
    /// to the first of them (read, never written).
    pub fn from_side_files(timelines: &[String]) -> CaseFile {
        let mut c = CaseFile { masstin_case: 1, timelines: timelines.to_vec(), ..Default::default() };
        if let Some(first) = timelines.first() {
            c.views = ViewsFile::load(&ViewsFile::path_for(first));
            c.story = Story::load(&Story::path_for(first));
            c.notes = Notes::load(&Notes::path_for(first)).notes;
        }
        c
    }

    /// The timelines where they are now: as written, or else, a case and its
    /// timelines having been moved together, by name next to the case file.
    /// Returns the ones found and the ones that are not.
    pub fn locate(&self, case_path: &Path) -> (Vec<String>, Vec<String>) {
        let dir = case_path.parent().map(Path::to_path_buf).unwrap_or_default();
        let (mut found, mut missing) = (Vec::new(), Vec::new());
        for t in &self.timelines {
            let p = PathBuf::from(t);
            if p.is_file() {
                found.push(t.clone());
                continue;
            }
            match p.file_name().map(|n| dir.join(n)).filter(|q| q.is_file()) {
                Some(q) => found.push(q.to_string_lossy().to_string()),
                None => missing.push(t.clone()),
            }
        }
        (found, missing)
    }
}

/// The path as an absolute one, so a case names its timelines wherever it is
/// opened from.
pub fn absolute(path: &str) -> String {
    std::path::absolute(path).map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| path.to_string())
}

/// The case `-a view --case` asks for: the file if it is there (the timelines
/// given, if any, replace the ones it names), a new one on the timelines given
/// otherwise. Written at once, so the case exists from the start.
pub fn open_for(path: &Path, timelines: &[String]) -> Result<CaseFile, String> {
    let mut c = if path.is_file() {
        CaseFile::load(path)?
    } else if timelines.is_empty() {
        return Err(format!("the case {} does not exist yet: give its timelines with -f to start it", path.display()));
    } else {
        CaseFile::from_side_files(timelines)
    };
    if timelines.is_empty() {
        let (found, missing) = c.locate(path);
        if !missing.is_empty() {
            return Err(format!("the case {} names timelines that are not there: {}", path.display(), missing.join(", ")));
        }
        c.timelines = found;
    } else {
        c.timelines = timelines.iter().map(|t| absolute(t)).collect();
    }
    c.save(path).map_err(|e| format!("cannot write the case {}: {}", path.display(), e))?;
    Ok(c)
}

/// `D:\x\timeline.csv` -> `timeline.masstin`, the name a new case is offered.
pub fn suggested_name(first_csv: Option<&str>) -> String {
    let stem = first_csv.and_then(|f| Path::new(f).file_stem()).map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "case".into());
    format!("{}.{}", stem, EXT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::notes::NoteTarget;

    #[test]
    fn a_case_keeps_everything_and_finds_moved_timelines() {
        let dir = std::env::temp_dir().join(format!("masstin-case-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("share")).unwrap();
        let csv = dir.join("share").join("timeline.csv");
        std::fs::write(&csv, "x\n").unwrap();
        let csv = csv.to_string_lossy().to_string();

        let mut c = CaseFile::from_side_files(&[csv.clone()]);
        c.views.merges.push(("10.0.0.5".into(), "SRV01".into()));
        c.story.title = "the intrusion".into();
        let mut n = Notes::default();
        n.add(NoteTarget::Free, "start here");
        c.notes = n.notes;
        let case = dir.join("cases").join("acme.masstin");
        c.save(&case).unwrap();
        // nothing went next to the timeline
        assert_eq!(std::fs::read_dir(dir.join("share")).unwrap().count(), 1);

        let back = CaseFile::load(&case).unwrap();
        assert_eq!(back.masstin_case, 1);
        assert_eq!(back.views.merges, vec![("10.0.0.5".to_string(), "SRV01".to_string())]);
        assert_eq!(back.story.title, "the intrusion");
        assert_eq!(back.notes.len(), 1);
        assert_eq!(back.locate(&case), (vec![csv.clone()], vec![]));

        // the case and its timeline moved to another folder together
        let moved = dir.join("elsewhere");
        std::fs::create_dir_all(&moved).unwrap();
        std::fs::rename(&case, moved.join("acme.masstin")).unwrap();
        std::fs::rename(&csv, moved.join("timeline.csv")).unwrap();
        let (found, missing) = back.locate(&moved.join("acme.masstin"));
        assert_eq!(found, vec![moved.join("timeline.csv").to_string_lossy().to_string()]);
        assert!(missing.is_empty());
        let (found, missing) = back.locate(&dir.join("acme.masstin"));
        assert!(found.is_empty());
        assert_eq!(missing, vec![csv]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn names() {
        assert!(is_case(r"D:\cases\acme.masstin"));
        assert!(is_case("acme.MASSTIN"));
        assert!(!is_case("timeline.csv"));
        assert_eq!(suggested_name(Some("/share/ev/timeline.csv")), "timeline.masstin");
        assert_eq!(suggested_name(None), "case.masstin");
    }
}
