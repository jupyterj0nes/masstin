//! The analyst's free notes: on a host, on a connection, or on the case
//! itself. Rows have their own `notes` column in the CSV; these are the
//! ones that have no row to live in. Saved as `<timeline>.notes.json`
//! next to the timeline, where a case tool can read them.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteTarget {
    Free,
    Host(String),
    Edge { src: String, dst: String, user: String },
}

impl NoteTarget {
    pub fn label(&self) -> String {
        match self {
            NoteTarget::Free => "the case".to_string(),
            NoteTarget::Host(h) => h.clone(),
            NoteTarget::Edge { src, dst, user } => {
                if user.is_empty() {
                    format!("{} -> {}", src, dst)
                } else {
                    format!("{} -> {} as {}", src, dst, user)
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    /// UTC, `YYYY-MM-DD HH:MM:SS`
    pub when: String,
    pub target: NoteTarget,
    pub text: String,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Notes {
    #[serde(skip)]
    pub path: PathBuf,
    #[serde(default)]
    pub notes: Vec<Note>,
}

impl Notes {
    pub fn path_for(first_csv: &str) -> PathBuf {
        let p = Path::new(first_csv);
        let stem = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "timeline".into());
        p.with_file_name(format!("{}.notes.json", stem))
    }

    pub fn load(path: &Path) -> Notes {
        let mut n: Notes = std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        n.path = path.to_path_buf();
        n
    }

    pub fn save(&self) -> std::io::Result<()> {
        let s = serde_json::to_string_pretty(self).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&self.path, s)
    }

    pub fn add(&mut self, target: NoteTarget, text: &str) {
        self.notes.push(Note { when: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(), target, text: text.trim().to_string() });
    }

    /// The notes on one host (by name).
    pub fn on_host<'a>(&'a self, host: &'a str) -> impl Iterator<Item = &'a Note> + 'a {
        self.notes.iter().filter(move |n| matches!(&n.target, NoteTarget::Host(h) if h.eq_ignore_ascii_case(host)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_round_trip_next_to_the_timeline() {
        let dir = std::env::temp_dir().join(format!("masstin-notes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let csv = dir.join("case.csv").to_string_lossy().to_string();
        let path = Notes::path_for(&csv);
        assert!(path.ends_with("case.notes.json"));
        let mut n = Notes::load(&path);
        n.add(NoteTarget::Host("SRV01".into()), "  pivot box  ");
        n.add(NoteTarget::Free, "first look");
        n.save().unwrap();
        let back = Notes::load(&path);
        assert_eq!(back.notes.len(), 2);
        assert_eq!(back.notes[0].text, "pivot box");
        assert_eq!(back.on_host("srv01").count(), 1);
        assert_eq!(back.notes[1].target.label(), "the case");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
