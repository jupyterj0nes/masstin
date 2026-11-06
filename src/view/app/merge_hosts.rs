//! Merging hosts: the analyst says that an address and a name (or two
//! names) are one machine, the graph is read again with the two as one
//! node and every connection follows. The CSV is not touched; the pairs
//! live in `<timeline>.views.json` next to it and survive sessions.

use super::*;
use crate::view::icons as ic;
use crate::view::theme;

/// The merge window's form: two hosts and which name stays.
pub(super) struct MergeHostsEdit {
    pub a: String,
    pub b: String,
    /// true: `a` is the name that stays
    pub keep_a: bool,
    pub filter: String,
}

impl Viewer {
    /// Read the timelines again with the current merges applied.
    pub(super) fn reload_store(&mut self) -> Result<(), String> {
        match Store::load_with(&self.files, self.alpha, &self.merges) {
            Ok(s) => {
                self.store = s;
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// `from` becomes part of `into`; the picture is rebuilt around it.
    pub(super) fn merge_hosts(&mut self, from: &str, into: &str) {
        let from = from.trim().to_uppercase();
        let into = into.trim().to_uppercase();
        if from.is_empty() || into.is_empty() || from == into {
            return;
        }
        // a host already merged somewhere else moves with its group
        self.merges.retain(|(f, _)| f != &from);
        for (_, i) in self.merges.iter_mut() {
            if *i == from {
                *i = into.clone();
            }
        }
        self.merges.push((from.clone(), into.clone()));
        self.persist();
        self.notes.add(NoteTarget::Host(into.clone()), &format!("Merged host: {} is the same machine as {}; shown as {} (undo in the inspector or Tools › Merged hosts). The timeline CSV keeps both names.", from, into, into));
        if let Err(e) = self.save_notes() {
            self.status = format!("cannot write {}: {}", self.notes.path.display(), e);
        }
        match self.reload_store() {
            Ok(()) => {
                self.remembered.clear();
                self.requery(false);
                self.status = format!("{} merged into {} — {}", from, into, self.status);
            }
            Err(e) => self.status = format!("Cannot read the timeline again: {}", e),
        }
    }

    pub(super) fn unmerge_host(&mut self, from: &str) {
        let n = self.merges.len();
        self.merges.retain(|(f, _)| !f.eq_ignore_ascii_case(from));
        if self.merges.len() == n {
            return;
        }
        self.persist();
        self.notes.add(NoteTarget::Host(from.to_uppercase()), &format!("Unmerged host: {} is its own host again.", from.to_uppercase()));
        if let Err(e) = self.save_notes() {
            self.status = format!("cannot write {}: {}", self.notes.path.display(), e);
        }
        match self.reload_store() {
            Ok(()) => {
                self.remembered.clear();
                self.requery(false);
                self.status = format!("{} is its own host again — {}", from.to_uppercase(), self.status);
            }
            Err(e) => self.status = format!("Cannot read the timeline again: {}", e),
        }
    }

    /// The names merged into this host (the ones the analyst merged, not the
    /// hunt's own address folding).
    pub(super) fn merged_into(&self, host: &str) -> Vec<String> {
        self.merges.iter().filter(|(_, i)| i.eq_ignore_ascii_case(host)).map(|(f, _)| f.clone()).collect()
    }

    /// Right-click › Merge: the two hosts, and which name stays.
    pub(super) fn merge_host_window(&mut self, ctx: &egui::Context) {
        let Some(edit) = self.merge_edit.as_mut() else { return };
        let mut open = true;
        let mut go: Option<(String, String)> = None;
        let mut names: Vec<String> = (0..self.store.hosts.len() as u32).map(|h| self.store.hosts.name(h).to_string()).filter(|n| !n.eq_ignore_ascii_case(&edit.a)).collect();
        names.sort();
        let title = if edit.b.trim().is_empty() { format!("{}  Merge {} with…", ic::ARROWS_CLOCKWISE, edit.a) } else { format!("{}  Merge {} and {}", ic::ARROWS_CLOCKWISE, edit.a, edit.b) };
        egui::Window::new(title).open(&mut open).collapsible(false).resizable(false).default_width(480.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.label(egui::RichText::new("The two become one host in the graph: every connection of both is drawn on the one that stays, which keeps the other among its names. The timeline CSV is not changed (both names stay in it); the pair is kept next to it, a note says so in the case, and it can be undone from the host's inspector or Tools › Merged hosts.").color(theme::MUTED));
            theme::section(ui, "The other host");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut edit.b).hint_text("host name or address").desired_width(220.0));
            });
            ui.add(egui::TextEdit::singleline(&mut edit.filter).hint_text(format!("{}  find in the list", ic::MAGNIFYING_GLASS)).desired_width(f32::INFINITY));
            let needle = edit.filter.trim().to_uppercase();
            egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                for n in names.iter().filter(|n| needle.is_empty() || n.to_uppercase().contains(&needle)).take(300) {
                    if ui.add(egui::Button::selectable(edit.b.eq_ignore_ascii_case(n), n)).clicked() {
                        edit.b = n.clone();
                    }
                }
            });
            let b_ok = !edit.b.trim().is_empty() && !edit.b.trim().eq_ignore_ascii_case(&edit.a);
            if b_ok {
                theme::section(ui, "The name that stays");
                ui.horizontal(|ui| {
                    if ui.add(egui::RadioButton::new(edit.keep_a, &edit.a)).clicked() {
                        edit.keep_a = true;
                    }
                    if ui.add(egui::RadioButton::new(!edit.keep_a, edit.b.trim())).clicked() {
                        edit.keep_a = false;
                    }
                });
            }
            ui.add_space(6.0);
            let label = if b_ok { format!("{}  Merge, keep {}", ic::ARROWS_CLOCKWISE, if edit.keep_a { edit.a.clone() } else { edit.b.trim().to_string() }) } else { format!("{}  Merge", ic::ARROWS_CLOCKWISE) };
            if ui.add_enabled(b_ok, egui::Button::new(theme::semibold(label, 13.5).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 30.0))).clicked() {
                let (a, b) = (edit.a.clone(), edit.b.trim().to_string());
                go = Some(if edit.keep_a { (b, a) } else { (a, b) });
            }
        });
        if let Some((from, into)) = go {
            self.merge_edit = None;
            self.merge_hosts(&from, &into);
        } else if !open {
            self.merge_edit = None;
        }
    }

    /// Tools › Merged hosts: the list, with a way to undo each and to add one.
    pub(super) fn merges_window(&mut self, ctx: &egui::Context) {
        if !self.show_merges {
            return;
        }
        let mut open = true;
        let mut undo: Option<String> = None;
        let mut add: Option<(String, String)> = None;
        egui::Window::new(format!("{}  Merged hosts", ic::ARROWS_CLOCKWISE)).open(&mut open).collapsible(false).resizable(true).default_width(480.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            if self.merges.is_empty() {
                theme::hint(ui, "None yet. Right-click a host and choose Merge into another host…, or select a host and right-click the one it belongs to.");
            }
            let merges = self.merges.clone();
            egui::Grid::new("merges").num_columns(3).spacing([14.0, 6.0]).striped(true).show(ui, |ui| {
                for (from, into) in &merges {
                    ui.label(egui::RichText::new(from).color(IP_FILL));
                    ui.label(format!("{}  {}", ic::ARROW_RIGHT, into));
                    if ui.add(egui::Button::new(egui::RichText::new(format!("{}  undo", ic::X)).color(theme::MUTED)).frame(false)).clicked() {
                        undo = Some(from.clone());
                    }
                    ui.end_row();
                }
            });
            theme::section(ui, "Add");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.merge_add.0).hint_text("this host or address").desired_width(170.0));
                ui.label(ic::ARROW_RIGHT);
                ui.add(egui::TextEdit::singleline(&mut self.merge_add.1).hint_text("belongs to this host").desired_width(170.0));
                let ok = !self.merge_add.0.trim().is_empty() && !self.merge_add.1.trim().is_empty();
                if ui.add_enabled(ok, egui::Button::new("Merge")).clicked() {
                    add = Some((self.merge_add.0.trim().to_string(), self.merge_add.1.trim().to_string()));
                }
            });
            ui.label(egui::RichText::new("The hunt's own folding of an address into a name (the same-login test) is separate and automatic; these are yours.").color(theme::DIM).small());
        });
        if let Some(f) = undo {
            self.unmerge_host(&f);
        }
        if let Some((f, i)) = add {
            self.merge_add = (String::new(), String::new());
            self.merge_hosts(&f, &i);
        }
        self.show_merges = open;
    }
}
