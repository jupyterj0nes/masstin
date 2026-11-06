//! Opening and saving a case file (`.masstin`): the timelines and
//! everything the analyst keeps about them, in one file of their choosing.

use std::path::PathBuf;

use super::ingest::{load_recent, remember};
use super::*;

impl Viewer {
    /// Evidence › Open case…
    pub(super) fn pick_case(&mut self) {
        if let Some(p) = rfd::FileDialog::new().set_title("Open a masstin case").add_filter("masstin case", &[case::EXT]).pick_file() {
            self.open_case(p);
        }
    }

    /// Open a case file: its timelines, and the views, style, merged hosts,
    /// subnets, story and notes it keeps.
    pub(super) fn open_case(&mut self, path: PathBuf) -> bool {
        let c = match CaseFile::load(&path) {
            Ok(c) => c,
            Err(e) => {
                self.status = e;
                return false;
            }
        };
        let (found, missing) = c.locate(&path);
        if found.is_empty() {
            self.status = format!("The case {} names no timeline that is there: {}", path.display(), missing.join(", "));
            return false;
        }
        match Store::load_with(&found, self.alpha, &c.views.merges) {
            Ok(s) => {
                self.store = s;
                self.files = found;
                self.merges = c.views.merges.clone();
                self.subnet_defs = c.views.subnets.clone();
                self.saved = c.views.views.clone();
                if let Some(st) = c.views.last_style.clone() {
                    self.style = st;
                }
                self.views_path = ViewsFile::path_for(&self.files[0]);
                self.story_path = Story::path_for(&self.files[0]);
                self.story = c.story.clone();
                self.notes = Notes { path: path.clone(), notes: c.notes.clone() };
                self.case = Some(path.clone());
                self.remembered.clear();
                if self.draft.view == View::Findings && !self.store.edges.iter().any(|e| e.hunt != 0) {
                    self.draft.view = View::All;
                }
                self.fit_pending = true;
                self.requery(true);
                let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                self.status = if missing.is_empty() { format!("Case {}: {}", name, self.status) } else { format!("Case {}, without {} (not found): {}", name, missing.join(", "), self.status) };
                remember(&[path.to_string_lossy().to_string()]);
                self.recent = load_recent();
                true
            }
            Err(e) => {
                self.status = format!("cannot read {}: {}", self.files.first().cloned().unwrap_or_default(), e);
                false
            }
        }
    }

    /// Evidence › Save as a case…: from then on everything kept goes to that
    /// file and nothing is written next to the timelines.
    pub(super) fn save_case_as(&mut self) {
        let mut dialog = rfd::FileDialog::new().set_title("Save the case as").add_filter("masstin case", &[case::EXT]).set_file_name(case::suggested_name(self.files.first().map(|s| s.as_str())));
        if let Some(dir) = self.case.as_ref().and_then(|c| c.parent()) {
            dialog = dialog.set_directory(dir);
        }
        let Some(mut p) = dialog.save_file() else { return };
        if p.extension().is_none() {
            p.set_extension(case::EXT);
        }
        match self.write_case(&p) {
            Ok(()) => {
                self.notes.path = p.clone();
                self.case = Some(p.clone());
                self.status = format!("The case is kept in {}: nothing is written next to the timelines from now on", p.display());
                remember(&[p.to_string_lossy().to_string()]);
                self.recent = load_recent();
            }
            Err(e) => self.status = format!("cannot write the case {}: {}", p.display(), e),
        }
    }
}
