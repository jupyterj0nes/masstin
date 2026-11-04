//! The timeline as a plain table: every row of the open CSVs in time
//! order, with a find box, for a quick look at what a parser wrote before
//! (or instead of) the graph. Rows are drawn on demand, so a million of
//! them scroll as fast as fifteen.

use super::*;
use crate::view::icons as ic;
use crate::view::theme;

const COLS: [(&str, f32); 10] = [("time", 150.0), ("origin", 150.0), ("destination", 150.0), ("account", 160.0), ("type", 48.0), ("event", 56.0), ("result", 72.0), ("hunt", 92.0), ("score", 48.0), ("why", 360.0)];

impl Viewer {
    /// The rows that match the find box, by time; cached by (text, store).
    fn table_rows(&mut self) -> &[u32] {
        let key = (self.table_find.trim().to_lowercase(), self.store.edges.len(), self.files.len());
        if self.table_key != key {
            let needle = key.0.clone();
            let s = &self.store;
            self.table_rows = s
                .by_time
                .iter()
                .copied()
                .filter(|&i| {
                    if needle.is_empty() {
                        return true;
                    }
                    let e = &s.edges[i as usize];
                    s.hosts.name(e.src).to_lowercase().contains(&needle) || s.hosts.name(e.dst).to_lowercase().contains(&needle) || s.users.name(e.user).to_lowercase().contains(&needle)
                })
                .collect();
            self.table_key = key;
        }
        &self.table_rows
    }

    pub(super) fn table_window(&mut self, ctx: &egui::Context) {
        if !self.show_table {
            return;
        }
        let mut open = true;
        let mut external: Option<String> = None;
        let mut reveal: Option<String> = None;
        egui::Window::new(format!("{}  Timeline rows", ic::TABLE)).id(egui::Id::unique("table-window")).open(&mut open).collapsible(true).resizable(true).default_width(980.0).default_height(520.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.table_find).desired_width(240.0).hint_text(format!("{}  host or account", ic::MAGNIFYING_GLASS)));
                let total = self.store.rows_total;
                let n = self.table_rows().len();
                ui.label(egui::RichText::new(if self.table_find.trim().is_empty() { format!("{} rows with an origin, of {} in the file(s)", n, total) } else { format!("{} of {} rows match", n, self.store.edges.len()) }).color(theme::MUTED).size(12.5));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    for f in self.files.iter().take(3) {
                        let name = std::path::Path::new(f).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| f.clone());
                        if ui.add(egui::Button::new(egui::RichText::new(format!("{}  {}", ic::APP_WINDOW, name)).size(12.0))).on_hover_text(format!("Open {} with the system's CSV application", f)).clicked() {
                            external = Some(f.clone());
                        }
                    }
                    if let Some(f) = self.files.first() {
                        if ui.add(egui::Button::new(egui::RichText::new(ic::FOLDER_OPEN).size(13.0))).on_hover_text("Show in folder").clicked() {
                            reveal = Some(f.clone());
                        }
                    }
                });
            });
            theme::hairline(ui);
            let row_h = 20.0;
            let n = self.table_rows().len();
            let width: f32 = COLS.iter().map(|c| c.1 + 8.0).sum();
            egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                ui.set_min_width(width);
                // the header
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    for (name, w) in COLS {
                        ui.add_sized([w, row_h], egui::Label::new(egui::RichText::new(name.to_ascii_uppercase()).size(10.5).color(theme::MUTED)));
                    }
                });
                theme::hairline(ui);
                let rows: Vec<u32> = self.table_rows().to_vec();
                egui::ScrollArea::vertical().id_salt("table-rows").auto_shrink([false, false]).show_rows(ui, row_h, n, |ui, range| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for i in range {
                        let k = rows[i] as usize;
                        let e = &self.store.edges[k];
                        let s = &self.store;
                        let hunt = HUNT_NAMES.get(e.hunt as usize).copied().unwrap_or("");
                        let result = RESULT_NAMES.get(e.result as usize).copied().unwrap_or("");
                        let hunt_color = match e.hunt {
                            super::super::store::H_SIGNIFICANT => SIGNIFICANT,
                            super::super::store::H_CANDIDATE => CANDIDATE,
                            _ => theme::MUTED,
                        };
                        let result_color = match e.result {
                            R_FAIL => EDGE_FAIL,
                            R_OK => EDGE_OK,
                            R_CONNECT => EDGE_CONNECT,
                            R_LOGOFF => EDGE_LOGOFF,
                            _ => theme::MUTED,
                        };
                        let cells: [(String, Color32); 10] = [
                            (fmt_time(e.t), theme::MUTED),
                            (s.hosts.name(e.src).to_string(), TEXT),
                            (s.hosts.name(e.dst).to_string(), TEXT),
                            (s.users.name(e.user).to_string(), TEXT),
                            (s.logon_types.name(e.logon_type).to_string(), theme::MUTED),
                            (s.event_ids.name(e.event_id).to_string(), theme::MUTED),
                            (result.to_string(), result_color),
                            (hunt.to_string(), hunt_color),
                            (if e.score.is_nan() { String::new() } else { format!("{:.0}", e.score) }, hunt_color),
                            (s.whys.name(e.why).to_string(), theme::DIM),
                        ];
                        let r = ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 8.0;
                            for ((text, color), (_, w)) in cells.iter().zip(COLS.iter()) {
                                ui.add_sized([*w, row_h], egui::Label::new(egui::RichText::new(text).size(12.0).color(*color)).truncate());
                            }
                        });
                        if i % 2 == 1 {
                            ui.painter().rect_filled(r.response.rect.expand2(Vec2::new(4.0, 0.0)), CornerRadius::ZERO, Color32::from_rgba_unmultiplied(255, 255, 255, 4));
                        }
                    }
                });
            });
        });
        if let Some(f) = external {
            if let Err(e) = super::ingest::open_external(&f) {
                self.status = format!("Cannot open {} with the system: {}", f, e);
            }
        }
        if let Some(f) = reveal {
            if let Err(e) = super::ingest::reveal_in_folder(&f) {
                self.status = format!("Cannot show {}: {}", f, e);
            }
        }
        self.show_table = open;
    }
}
