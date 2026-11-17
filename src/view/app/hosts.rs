//! Tools › Hosts and addresses: whose each address of the open timelines
//! is, with the evidence, and the merges it allows. A timeline names an
//! origin by its name when the event gives one and by its address when it
//! does not, so one machine is often two nodes. The table
//! (`graph_hunt_common::hostmap`) says which address is which host and how
//! sure that is; the analyst picks a level and the addresses of that level
//! become part of their hosts, as merges like the ones made by hand:
//! kept with the case, listed in Merged hosts, undone from there. The
//! timeline CSV is not changed. The hunt takes the same table with its own
//! tick box (`--merge-hosts`).

use super::*;
use crate::graph_hunt_common::hostmap::{Level, Table};
use crate::view::icons as ic;
use crate::view::theme;

pub(super) struct HostsDialog {
    pub table: Result<Table, String>,
    pub level: Level,
    pub filter: String,
    /// only the addresses that are an origin on their own in some row
    pub only_origins: bool,
}

/// The addresses of a level that are not merged yet: `(address, host)`.
pub(super) fn pending(table: &Table, level: Level, merges: &[(String, String)]) -> Vec<(String, String)> {
    table.merges(level, &std::collections::HashSet::new()).into_iter().filter(|(a, _)| !merges.iter().any(|(f, _)| f.eq_ignore_ascii_case(a))).collect()
}

impl Viewer {
    /// Tools › Hosts and addresses…
    pub(super) fn open_hosts(&mut self) {
        if self.files.is_empty() {
            self.status = "Open a timeline first: the table is read from it".into();
            return;
        }
        let table = crate::graph_hunt_common::hostmap::build(&self.files, self.alpha).map_err(|e| format!("cannot read the timelines: {}", e));
        let level = self.hosts.as_ref().map(|h| h.level).unwrap_or(Level::Standard);
        self.hosts = Some(HostsDialog { table, level, filter: String::new(), only_origins: true });
    }

    /// Several `(from, into)` at once: one reading of the timelines.
    pub(super) fn merge_many(&mut self, pairs: &[(String, String)], why: &str) {
        let mut done = 0usize;
        for (from, into) in pairs {
            let (from, into) = (from.trim().to_uppercase(), into.trim().to_uppercase());
            if from.is_empty() || into.is_empty() || from == into {
                continue;
            }
            self.merges.retain(|(f, _)| f != &from);
            for (_, i) in self.merges.iter_mut() {
                if *i == from {
                    *i = into.clone();
                }
            }
            self.merges.push((from.clone(), into.clone()));
            self.notes.add(NoteTarget::Host(into.clone()), &format!("Merged host: {} is {} ({}); shown as {} (undo in Tools › Merged hosts). The timeline CSV keeps both.", from, into, why, into));
            done += 1;
        }
        if done == 0 {
            return;
        }
        self.persist();
        if let Err(e) = self.save_notes() {
            self.status = format!("cannot write {}: {}", self.notes.path.display(), e);
        }
        match self.reload_store() {
            Ok(()) => {
                self.remembered.clear();
                self.requery(false);
                self.status = format!("{} address(es) merged into their hosts — {}", done, self.status);
            }
            Err(e) => self.status = format!("Cannot read the timeline again: {}", e),
        }
    }

    pub(super) fn hosts_window(&mut self, ctx: &egui::Context) {
        let Some(d) = self.hosts.as_mut() else { return };
        let mut open = true;
        let mut go: Option<(Vec<(String, String)>, String)> = None;
        let mut undo: Option<String> = None;
        let merges = self.merges.clone();
        egui::Window::new(format!("{}  Hosts and addresses", ic::LINK)).open(&mut open).collapsible(false).resizable(true).default_width(900.0).default_height(720.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.label(egui::RichText::new("One machine is often two hosts in the graph: its name where the event gives one, its address where it does not. This is what the timelines say of whose each address is. Merged, the two are one node with every connection; the CSV is not changed, and a merge is undone here or in Tools › Merged hosts.").color(theme::MUTED));
            let table = match &d.table {
                Ok(t) => t,
                Err(e) => {
                    ui.label(egui::RichText::new(e).color(CANDIDATE));
                    return;
                }
            };
            theme::section(ui, "How much to merge without asking");
            for level in [Level::Strict, Level::Standard, Level::Broad] {
                let n = pending(table, level, &merges).len();
                let all = table.merges(level, &std::collections::HashSet::new()).len();
                let r = theme::card(ui, d.level == level, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(theme::semibold(match level {
                            Level::Strict => "Strict",
                            Level::Standard => "Standard",
                            Level::Broad => "Broad",
                        }, 13.5).color(TEXT));
                        ui.label(egui::RichText::new(format!("{} address(es){}", all, if all != n { format!(", {} not merged yet", n) } else { String::new() })).monospace().size(11.0).color(theme::DIM));
                        ui.label(egui::RichText::new(level.explain()).color(theme::MUTED).size(12.0));
                    });
                });
                if r.clicked() {
                    d.level = level;
                }
            }
            let c = table.counts();
            theme::hint(ui, &format!("At every level an address is left to you when the evidence disagrees ({} here): several names at it (NAT, a proxy, an address that changed hands) or its host seen at two addresses in the same period. {} address(es) have nothing that says whose they are.", c[3], c[4]));
            let todo = pending(table, d.level, &merges);
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let label = format!("{}  Merge the {} of this level", ic::ARROWS_CLOCKWISE, todo.len());
                if ui.add_enabled(!todo.is_empty(), egui::Button::new(theme::semibold(label, 13.5).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 30.0))).clicked() {
                    go = Some((todo.clone(), format!("the evidence of the timelines, level {}", d.level.name())));
                }
                ui.add(egui::TextEdit::singleline(&mut d.filter).hint_text(format!("{}  find an address or a host", ic::MAGNIFYING_GLASS)).desired_width(220.0));
                ui.checkbox(&mut d.only_origins, "only addresses that are an origin on their own").on_hover_text("The addresses some row has as its origin, with no name: the ones a merge moves connections of");
            });
            ui.add_space(4.0);
            let needle = d.filter.trim().to_uppercase();
            let shown: Vec<&crate::graph_hunt_common::hostmap::Entry> = table.entries.iter().filter(|e| (!d.only_origins || e.rows > 0) && (needle.is_empty() || e.address.to_uppercase().contains(&needle) || e.names.iter().any(|(n, _)| n.to_uppercase().contains(&needle)))).collect();
            egui::ScrollArea::both().auto_shrink([false, false]).min_scrolled_height(280.0).show(ui, |ui| {
                egui::Grid::new("hosts_table").num_columns(6).spacing([14.0, 6.0]).striped(true).show(ui, |ui| {
                    for h in ["Address", "Host", "Merge", "Rows", "", "Evidence, or why not"] {
                        ui.label(theme::semibold(h, 12.0).color(theme::MUTED));
                    }
                    ui.end_row();
                    for e in shown.iter().take(500) {
                        let merged = merges.iter().find(|(f, _)| f.eq_ignore_ascii_case(&e.address));
                        ui.label(egui::RichText::new(&e.address).monospace().color(IP_FILL));
                        ui.label(match merged {
                            Some((_, into)) => egui::RichText::new(into).color(TEXT),
                            None if e.host.is_empty() => egui::RichText::new("-").color(theme::DIM),
                            None => egui::RichText::new(&e.host).color(TEXT),
                        });
                        ui.label(match (merged, e.level) {
                            (Some(_), _) => egui::RichText::new("merged").color(theme::ACCENT),
                            (None, Some(l)) => egui::RichText::new(l.name()).color(if l <= d.level { TEXT } else { theme::MUTED }),
                            (None, None) => egui::RichText::new(e.level_name()).color(if e.names.is_empty() { theme::DIM } else { CANDIDATE }),
                        });
                        ui.label(egui::RichText::new(e.rows.to_string()).monospace().color(theme::MUTED));
                        ui.horizontal(|ui| {
                            if merged.is_some() {
                                if ui.add(egui::Button::new(egui::RichText::new(format!("{}  undo", ic::X)).color(theme::MUTED)).frame(false)).clicked() {
                                    undo = Some(e.address.clone());
                                }
                            } else if !e.host.is_empty() {
                                if ui.small_button(format!("{}  merge", ic::ARROW_RIGHT)).on_hover_text(format!("{} becomes part of {}", e.address, e.host)).clicked() {
                                    go = Some((vec![(e.address.clone(), e.host.clone())], if e.level.is_some() { "the evidence of the timelines".to_string() } else { "decided by the analyst: the evidence disagrees".to_string() }));
                                }
                            } else {
                                for (n, _) in e.names.iter().take(3) {
                                    if ui.small_button(format!("{}  {}", ic::ARROW_RIGHT, n)).on_hover_text(format!("Your decision: {} becomes part of {}", e.address, n)).clicked() {
                                        go = Some((vec![(e.address.clone(), n.clone())], "decided by the analyst among several names".to_string()));
                                    }
                                }
                            }
                        });
                        let what = match (e.evidence(), e.note.as_str()) {
                            (ev, "") => ev,
                            (ev, n) if ev.is_empty() => n.to_string(),
                            (ev, n) => format!("{}  —  {}", ev, n),
                        };
                        ui.label(egui::RichText::new(what).size(11.5).color(theme::MUTED));
                        ui.end_row();
                    }
                });
                if shown.len() > 500 {
                    theme::hint(ui, &format!("{} more: narrow with the search box, or see them all with `masstin -a host-map -f <timeline>`.", shown.len() - 500));
                }
            });
        });
        if let Some((pairs, why)) = go {
            self.merge_many(&pairs, &why);
        }
        if let Some(a) = undo {
            self.unmerge_host(&a);
        }
        if !open {
            self.hosts = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_hunt_common::hostmap::Entry;

    #[test]
    fn what_is_left_to_merge_at_a_level() {
        let e = |a: &str, h: &str, l: Option<Level>| Entry { address: a.into(), host: h.into(), level: l, ..Entry::default() };
        let t = Table { entries: vec![e("10.0.0.1", "DC01", Some(Level::Strict)), e("10.0.0.5", "SRV01", Some(Level::Standard)), e("10.0.0.50", "JUMP", Some(Level::Broad)), e("10.0.0.77", "", None)] };
        assert_eq!(pending(&t, Level::Strict, &[]).len(), 1);
        assert_eq!(pending(&t, Level::Standard, &[]).len(), 2);
        assert_eq!(pending(&t, Level::Broad, &[]).len(), 3);
        // one of them merged already, by hand or here
        let merges = vec![("10.0.0.5".to_string(), "SRV01".to_string())];
        assert_eq!(pending(&t, Level::Broad, &merges), vec![("10.0.0.1".to_string(), "DC01".to_string()), ("10.0.0.50".to_string(), "JUMP".to_string())]);
    }
}
