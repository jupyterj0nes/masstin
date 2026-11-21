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
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let merges = c.views.merges.clone();
        let first = found.first().cloned().unwrap_or_default();
        let what = format!("the case {} ({} timeline{})", name, found.len(), if found.len() == 1 { "" } else { "s" });
        self.load_then(
            found.clone(),
            merges,
            what,
            Box::new(move |v: &mut Viewer, r: Result<Store, String>| match r {
                Ok(s) => {
                    v.store = s;
                    v.table_raw_cache.clear();
                    v.files = found;
                    v.case_missing = missing.clone();
                    v.merges = c.views.merges.clone();
                    v.subnet_defs = c.views.subnets.clone();
                    v.saved = c.views.views.clone();
                    if let Some(st) = c.views.last_style.clone() {
                        v.style = st;
                    }
                    v.views_path = ViewsFile::path_for(&v.files[0]);
                    v.story_path = Story::path_for(&v.files[0]);
                    v.story = c.story.clone();
                    v.notes = Notes { path: path.clone(), notes: c.notes.clone() };
                    v.case = Some(path.clone());
                    v.remembered.clear();
                    if v.draft.view == View::Findings && !v.store.edges.iter().any(|e| e.hunt != 0) {
                        v.draft.view = View::All;
                    }
                    v.fit_pending = true;
                    v.requery(true);
                    v.status = if missing.is_empty() { format!("Case {}: {}", name, v.status) } else { format!("Case {}, without {} (not found): {}", name, missing.join(", "), v.status) };
                    remember(&[path.to_string_lossy().to_string()]);
                    v.recent = load_recent();
                }
                Err(e) => v.status = format!("cannot read {}: {}", first, e),
            }),
        );
        true
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
