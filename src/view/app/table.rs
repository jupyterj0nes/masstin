//! The timeline as a plain table: every row of the open CSVs in time
//! order, with a find box, for a quick look at what a parser wrote before
//! (or instead of) the graph. Rows are drawn on demand, so a million of
//! them scroll as fast as fifteen.

use super::*;
use crate::view::icons as ic;
use crate::view::theme;

const COLS: [(&str, f32); 10] = [("time", 150.0), ("origin", 150.0), ("destination", 150.0), ("account", 160.0), ("type", 48.0), ("event", 56.0), ("result", 72.0), ("hunt", 92.0), ("score", 48.0), ("why", 360.0)];

/// The file's own columns, as `csv_out::HEADER` names them, and their widths.
const RAW_WIDTHS: [f32; 19] = [210.0, 170.0, 140.0, 64.0, 74.0, 150.0, 130.0, 150.0, 120.0, 140.0, 130.0, 100.0, 260.0, 320.0, 92.0, 76.0, 280.0, 80.0, 200.0];

fn raw_columns() -> Vec<&'static str> {
    crate::csv_out::HEADER.split(',').collect()
}

impl Viewer {
    /// Every row of the open files (file, row) whose text holds the find
    /// box, in the files' order; cached by (text, files).
    fn table_raw_rows(&mut self) -> &[(u16, u32)] {
        let key = (self.table_find.trim().to_lowercase(), self.store.files.len(), self.store.rows_total);
        if self.table_raw_key != key {
            let mut out = Vec::new();
            for f in 0..self.store.files.len() as u16 {
                if key.0.is_empty() {
                    out.extend((0..self.store.file_rows(f) as u32).map(|l| (f, l)));
                } else {
                    match self.store.file_rows_matching(f, &key.0) {
                        Ok(v) => out.extend(v.into_iter().map(|l| (f, l))),
                        Err(e) => self.status = format!("Cannot read {}: {}", self.store.files[f as usize].path, e),
                    }
                }
            }
            self.table_raw_rows = out;
            self.table_raw_cache.clear();
            self.table_raw_key = key;
        }
        &self.table_raw_rows
    }

    /// The table in the file's 19 columns: the rows read from the file as
    /// they scroll into view.
    fn table_raw_body(&mut self, ui: &mut egui::Ui) {
        let row_h = 20.0;
        let cols = raw_columns();
        let width: f32 = RAW_WIDTHS.iter().map(|w| w + 8.0).sum();
        let rows: Vec<(u16, u32)> = self.table_raw_rows().to_vec();
        if self.table_raw_cache.len() > 4000 {
            self.table_raw_cache.clear();
        }
        egui::ScrollArea::both().id_salt("table-raw").auto_shrink([false, false]).show(ui, |ui| {
            ui.set_min_width(width);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                for (name, w) in cols.iter().zip(RAW_WIDTHS.iter()) {
                    ui.add_sized([*w, row_h], egui::Label::new(egui::RichText::new(*name).size(10.5).monospace().color(theme::MUTED)));
                }
            });
            theme::hairline(ui);
            egui::ScrollArea::vertical().id_salt("table-raw-rows").auto_shrink([false, false]).show_rows(ui, row_h, rows.len(), |ui, range| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for i in range {
                    let key = rows[i];
                    if !self.table_raw_cache.contains_key(&key) {
                        let fields = self.store.raw_row(key.0, key.1).unwrap_or_else(|e| vec![format!("cannot read the row: {}", e)]);
                        self.table_raw_cache.insert(key, fields);
                    }
                    let fields = &self.table_raw_cache[&key];
                    let r = ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        for (k, w) in RAW_WIDTHS.iter().enumerate() {
                            let text = fields.get(k).map(|s| s.as_str()).unwrap_or("");
                            let color = match k {
                                0 | 3 | 4 | 11 => theme::MUTED,
                                13 | 16 => theme::DIM,
                                14 => match text {
                                    "significant" => SIGNIFICANT,
                                    "candidate" => CANDIDATE,
                                    _ => theme::MUTED,
                                },
                                2 if text == "FAILED_LOGON" => EDGE_FAIL,
                                _ => TEXT,
                            };
                            ui.add_sized([*w, row_h], egui::Label::new(egui::RichText::new(text).size(12.0).color(color)).truncate());
                        }
                    });
                    if i % 2 == 1 {
                        ui.painter().rect_filled(r.response.rect.expand2(Vec2::new(4.0, 0.0)), CornerRadius::ZERO, Color32::from_rgba_unmultiplied(255, 255, 255, 4));
                    }
                }
            });
        });
    }

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
        egui::Window::new(format!("{}  Timeline rows", ic::TABLE)).id(egui::Id::unique("table-window")).open(&mut open).collapsible(true).resizable(true).default_width((ctx.content_rect().width() - 160.0).clamp(980.0, 1600.0)).default_height(520.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.table_csv, false, "Graph columns").on_hover_text("The rows the graph draws (those with an origin), in the viewer's columns");
                ui.selectable_value(&mut self.table_csv, true, "CSV · 19 columns").on_hover_text("Every row of the file, in the timeline's own 19 columns, as written");
                ui.add_space(6.0);
                let hint = if self.table_csv { "find in the rows" } else { "host or account" };
                ui.add(egui::TextEdit::singleline(&mut self.table_find).desired_width(220.0).hint_text(format!("{}  {}", ic::MAGNIFYING_GLASS, hint)));
                let total = self.store.rows_total;
                let label = if self.table_csv {
                    let n = self.table_raw_rows().len();
                    if self.table_find.trim().is_empty() { format!("{} rows, all of the file(s)", n) } else { format!("{} of {} rows hold it", n, total) }
                } else {
                    let n = self.table_rows().len();
                    if self.table_find.trim().is_empty() { format!("{} rows with an origin, of {} in the file(s)", n, total) } else { format!("{} of {} rows match", n, self.store.edges.len()) }
                };
                ui.label(egui::RichText::new(label).color(theme::MUTED).size(12.5));
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
            if self.table_csv {
                self.table_raw_body(ui);
                return;
            }
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
