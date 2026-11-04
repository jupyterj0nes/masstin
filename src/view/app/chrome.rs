//! The window around the canvas: menu bar, toolbar, the row of applied
//! filters, the filter pane on the left, the inspector on the right, the
//! time strip and the status line at the bottom.

use super::*;
use crate::view::icons as ic;
use crate::view::theme::{self, chip, icon_button, pill, primary, section, tool};
use crate::view::query::Grouping;

/// What the time strip's pointer is dragging.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Brush {
    From,
    To,
    Scrub,
}

/// The inspector's tabs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Tab {
    Selection,
    Notes,
    Legend,
}

/// A colour being picked for one account or host (a style rule in the making).
pub(super) struct ColorPick {
    pub field: Field,
    pub pattern: String,
    pub color: Color32,
    pub title: String,
}

impl Viewer {
    // ───────────────────────── menu bar ─────────────────────────

    pub(super) fn menu_bar(&mut self, ui: &mut egui::Ui) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            ui.add_space(4.0);
            ui.label(theme::semibold("masstin", 15.0).color(theme::ACCENT));
            ui.add_space(10.0);
            ui.menu_button("Evidence", |ui| {
                ui.set_min_width(260.0);
                if icon_button(ui, ic::FOLDER_OPEN, "Open timeline…").clicked() {
                    ui.close();
                    self.open_timelines(false);
                }
                if icon_button(ui, ic::PLUS, "Add a timeline to this view…").clicked() {
                    ui.close();
                    self.open_timelines(true);
                }
                if icon_button(ui, ic::ARROW_CLOCKWISE, "Reload from disk").clicked() {
                    ui.close();
                    self.reload();
                }
                ui.separator();
                if icon_button(ui, ic::DOWNLOAD_SIMPLE, "Ingest evidence…").on_hover_text("Parse EVTX, triage folders, images or Linux / macOS logs into a timeline with masstin's parsers").clicked() {
                    ui.close();
                    self.show_ingest = true;
                }
                if icon_button(ui, ic::STACK, "Merge timelines…").clicked() {
                    ui.close();
                    self.show_merge = true;
                }
                ui.separator();
                ui.label(egui::RichText::new("Open now").small().color(theme::DIM));
                for f in self.files.clone() {
                    ui.label(egui::RichText::new(std::path::Path::new(&f).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or(f.clone())).color(theme::MUTED)).on_hover_text(&f);
                }
                ui.separator();
                if icon_button(ui, ic::X, "Quit").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("Hunt", |ui| {
                ui.set_min_width(260.0);
                if icon_button(ui, ic::DETECTIVE, "Run the hunt on this timeline…").clicked() {
                    ui.close();
                    self.show_hunt = true;
                }
                ui.separator();
                if icon_button(ui, ic::FIRE, "Findings only").clicked() {
                    ui.close();
                    self.draft.view = View::Findings;
                    self.requery(false);
                }
                ui.label(egui::RichText::new("Score at least").small().color(theme::DIM));
                let mut s = self.draft.min_score;
                if ui.add(egui::Slider::new(&mut s, 0..=100).show_value(true)).changed() {
                    self.draft.min_score = s;
                }
                ui.label(egui::RichText::new(crate::csv_out::score_words(self.draft.min_score)).small().color(theme::MUTED));
                if primary(ui, "Apply").clicked() {
                    ui.close();
                    self.requery(false);
                }
            });
            ui.menu_button("View", |ui| {
                ui.set_min_width(260.0);
                for (v, label, icon) in [(View::Findings, "Findings", ic::FIRE), (View::All, "Everything", ic::GRAPH), (View::Around, "Neighbourhood", ic::CIRCLES_THREE_PLUS)] {
                    if ui.add(egui::Button::selectable(self.draft.view == v, format!("{icon}  {label}"))).clicked() {
                        ui.close();
                        self.draft.view = v;
                        if v != View::Around || !self.draft.around.trim().is_empty() {
                            self.requery(false);
                        } else {
                            self.show_filters = true;
                        }
                    }
                }
                ui.separator();
                if icon_button(ui, ic::CORNERS_OUT, "Fit to window").clicked() {
                    ui.close();
                    self.fit_pending = true;
                }
                if icon_button(ui, ic::SHUFFLE, "Lay out again").clicked() {
                    ui.close();
                    let f = self.draft.clone();
                    self.draft = f;
                    self.requery(true);
                }
                ui.separator();
                ui.checkbox(&mut self.show_filters, format!("{}  Filter pane", ic::FUNNEL));
                ui.checkbox(&mut self.show_inspector, format!("{}  Inspector", ic::SIDEBAR_SIMPLE));
                ui.checkbox(&mut self.hud, format!("{}  Frame budget (F1)", ic::PULSE));
                ui.separator();
                let mut changed = false;
                changed |= ui.checkbox(&mut self.style.motion, format!("{}  Motion", ic::SPARKLE)).changed();
                changed |= ui.checkbox(&mut self.style.shapes_by_role, format!("{}  Shapes by role", ic::HEXAGON)).changed();
                if ui.checkbox(&mut self.style.size_by_traffic, format!("{}  Host size by traffic", ic::CIRCLES_THREE_PLUS)).on_hover_text("On: a host grows with its events in and out of the view (log scale). Off: every host the same size").changed() {
                    changed = true;
                    let f = self.draft.clone();
                    self.draft = f;
                    self.requery(false);
                }
                ui.horizontal(|ui| {
                    ui.label("Hosts");
                    changed |= ui.add(egui::DragValue::new(&mut self.style.node_scale).range(0.4..=2.5).speed(0.02).fixed_decimals(1)).changed();
                    ui.label("Edges");
                    changed |= ui.add(egui::DragValue::new(&mut self.style.edge_scale).range(0.3..=3.0).speed(0.02).fixed_decimals(1)).changed();
                    ui.label("Text");
                    changed |= ui.add(egui::DragValue::new(&mut self.style.font_scale).range(0.6..=2.0).speed(0.02).fixed_decimals(1)).changed();
                });
                ui.horizontal(|ui| {
                    ui.label("Colour by");
                    egui::ComboBox::from_id_salt("menu-colorby").selected_text(self.style.color_by.label()).show_ui(ui, |ui| {
                        for c in ColorBy::ALL {
                            changed |= ui.selectable_value(&mut self.style.color_by, c, c.label()).changed();
                        }
                    });
                });
                ui.horizontal(|ui| {
                    ui.label("On edges");
                    egui::ComboBox::from_id_salt("menu-caption").selected_text(self.style.caption.label()).show_ui(ui, |ui| {
                        for c in Caption::ALL {
                            changed |= ui.selectable_value(&mut self.style.caption, c, c.label()).changed();
                        }
                    });
                });
                if changed {
                    self.persist();
                }
                ui.separator();
                if icon_button(ui, ic::TAG, "Labels and sizes…").clicked() {
                    ui.close();
                    self.show_labels = true;
                }
                if icon_button(ui, ic::PALETTE, &format!("Style rules ({})", self.style.rules.iter().filter(|r| r.enabled).count())).clicked() {
                    ui.close();
                    self.show_rules = true;
                }
            });
            ui.menu_button("Tools", |ui| {
                ui.set_min_width(260.0);
                if icon_button(ui, ic::PATH, "Paths and reach…").clicked() {
                    ui.close();
                    self.show_paths = true;
                }
                if icon_button(ui, ic::QUESTION, "Questions…").clicked() {
                    ui.close();
                    self.show_questions = true;
                }
                ui.separator();
                if icon_button(ui, ic::PRESENTATION, "Present the story").clicked() {
                    ui.close();
                    self.start_presentation();
                }
                if icon_button(ui, ic::FILM_STRIP, "Story and recording…").clicked() {
                    ui.close();
                    self.show_story = true;
                }
                ui.separator();
                if icon_button(ui, ic::APP_WINDOW, "Open the case in agentc00pr").on_hover_text("Launches agentc00pr, the case tool that reads this timeline and the CSVs of caarea, faramir and allymacb").clicked() {
                    ui.close();
                    self.open_agentc00pr();
                }
                ui.separator();
                if icon_button(ui, ic::ARROWS_CLOCKWISE, &format!("Merged hosts… ({})", self.merges.len())).clicked() {
                    ui.close();
                    self.show_merges = true;
                }
                if icon_button(ui, ic::TERMINAL_WINDOW, "Log of the last run…").clicked() {
                    ui.close();
                    self.show_last_log = true;
                }
            });
            ui.menu_button("Help", |ui| {
                ui.set_min_width(260.0);
                if icon_button(ui, ic::KEYBOARD, "Mouse and keys").clicked() {
                    ui.close();
                    self.show_help = true;
                }
                if icon_button(ui, ic::BOOK_OPEN, "docs/viewer.md").clicked() {
                    ui.close();
                    ui.ctx().open_url(egui::OpenUrl::new_tab("https://github.com/c00pr/masstin/blob/main/docs/viewer.md"));
                }
                ui.separator();
                ui.label(egui::RichText::new(format!("masstin {}", env!("CARGO_PKG_VERSION"))).color(theme::MUTED));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(6.0);
                let names: Vec<String> = self.files.iter().map(|f| std::path::Path::new(f).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()).collect();
                ui.label(egui::RichText::new(names.join(" + ")).color(theme::MUTED).size(12.0));
            });
        });
    }

    // ───────────────────────── toolbar ─────────────────────────

    pub(super) fn toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            if tool(ui, ic::FUNNEL, "Filter pane", self.show_filters).clicked() {
                self.show_filters = !self.show_filters;
            }
            ui.add_space(4.0);
            // the three views as a segmented control
            egui::Frame::new().fill(theme::FIELD).stroke(Stroke::new(1.0, theme::BORDER)).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::same(2)).show(ui, |ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                for (v, label, icon) in [(View::Findings, "Findings", ic::FIRE), (View::All, "Everything", ic::GRAPH), (View::Around, "Neighbourhood", ic::CIRCLES_THREE_PLUS)] {
                    let on = self.draft.view == v;
                    let b = egui::Button::new(egui::RichText::new(format!("{icon}  {label}")).color(if on { theme::ACCENT_INK } else { theme::TEXT })).fill(if on { theme::ACCENT } else { Color32::TRANSPARENT }).stroke(Stroke::NONE).corner_radius(CornerRadius::same(6)).min_size(Vec2::new(0.0, 24.0));
                    if ui.add(b).clicked() && !on {
                        self.draft.view = v;
                        if v == View::Around && self.draft.around.trim().is_empty() {
                            self.show_filters = true;
                            self.focus_around = true;
                        } else {
                            self.requery(false);
                        }
                    }
                }
            });
            ui.add_space(6.0);
            // quick search: a host name, applied on Enter
            let w = (ui.available_width() - 420.0).clamp(160.0, 360.0);
            let r = ui.add(egui::TextEdit::singleline(&mut self.quick).hint_text(format!("{}  find a host and open its neighbourhood", ic::MAGNIFYING_GLASS)).desired_width(w));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !self.quick.trim().is_empty() {
                self.draft.view = View::Around;
                self.draft.around = self.quick.trim().to_string();
                self.requery(false);
            }
            ui.add_space(6.0);
            if tool(ui, ic::CORNERS_OUT, "Fit to window", false).clicked() {
                self.fit_pending = true;
            }
            if tool(ui, ic::SHUFFLE, "Lay out again", false).clicked() {
                let f = self.draft.clone();
                self.draft = f;
                self.requery(true);
            }
            if tool(ui, ic::SPARKLE, "Motion: dots along the connections that matter, pulses, glides", self.style.motion).clicked() {
                self.style.motion = !self.style.motion;
                self.persist();
            }
            if tool(ui, ic::HEXAGON, "Shapes by role: hexagon domain controller, square server, circle workstation, diamond external", self.style.shapes_by_role).clicked() {
                self.style.shapes_by_role = !self.style.shapes_by_role;
                self.persist();
            }
            if tool(ui, ic::TAG, "Labels and sizes", self.show_labels).clicked() {
                self.show_labels = !self.show_labels;
            }
            if tool(ui, ic::PALETTE, "Style rules", self.show_rules).clicked() {
                self.show_rules = !self.show_rules;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                if tool(ui, ic::SIDEBAR_SIMPLE, "Inspector", self.show_inspector).clicked() {
                    self.show_inspector = !self.show_inspector;
                }
                if tool(ui, ic::PULSE, "Frame budget (F1)", self.hud).clicked() {
                    self.hud = !self.hud;
                }
                ui.add_space(4.0);
                if ui.add(egui::Button::new(egui::RichText::new(format!("{}  agentc00pr", ic::APP_WINDOW))).min_size(Vec2::new(0.0, 28.0))).on_hover_text("Open the case tool").clicked() {
                    self.open_agentc00pr();
                }
                let hunt = egui::Button::new(theme::semibold(format!("{}  Hunt", ic::DETECTIVE), 13.5).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 28.0)).corner_radius(CornerRadius::same(7));
                if ui.add(hunt).on_hover_text("Run the statistical hunt on this timeline and watch the findings light up").clicked() {
                    self.show_hunt = true;
                }
                if tool(ui, ic::PATH, "Paths and reach", self.show_paths).clicked() {
                    self.show_paths = !self.show_paths;
                }
                if tool(ui, ic::QUESTION, "Questions", self.show_questions).clicked() {
                    self.show_questions = !self.show_questions;
                }
            });
        });
    }

    // ───────────────────────── applied filters ─────────────────────────

    /// The filters that differ from "everything", as chips; removing one
    /// applies at once.
    pub(super) fn filter_chips(&mut self, ui: &mut egui::Ui) -> bool {
        let f = self.filter.clone();
        let mut chips: Vec<(String, Color32, Box<dyn Fn(&mut Filter)>)> = Vec::new();
        let host_c = theme::ACCENT;
        if f.view == View::Around {
            let around = f.around.clone();
            chips.push((format!("around {}  ·  {} hop{}", around, f.hops, if f.hops == 1 { "" } else { "s" }), HOST_FILL, Box::new(|d: &mut Filter| d.view = View::All)));
        }
        if !f.host.trim().is_empty() {
            chips.push((format!("host: {}", f.host.trim()), HOST_FILL, Box::new(|d: &mut Filter| d.host.clear())));
        }
        if !f.user.trim().is_empty() {
            chips.push((format!("account: {}", f.user.trim()), host_c, Box::new(|d: &mut Filter| d.user.clear())));
        }
        if !f.logon_type.trim().is_empty() {
            chips.push((format!("logon type: {}", f.logon_type.trim()), host_c, Box::new(|d: &mut Filter| d.logon_type.clear())));
        }
        if !f.from.trim().is_empty() || !f.to.trim().is_empty() {
            let text = match (f.from.trim().is_empty(), f.to.trim().is_empty()) {
                (false, false) => format!("{}  →  {}", &f.from[..f.from.len().min(16)], &f.to[..f.to.len().min(16)]),
                (false, true) => format!("from {}", &f.from[..f.from.len().min(16)]),
                _ => format!("until {}", &f.to[..f.to.len().min(16)]),
            };
            chips.push((text, Color32::from_rgb(140, 190, 240), Box::new(|d: &mut Filter| {
                d.from.clear();
                d.to.clear();
            })));
        }
        if f.min_score > 0 {
            chips.push((format!("score ≥ {}", f.min_score), SIGNIFICANT, Box::new(|d: &mut Filter| d.min_score = 0)));
        }
        if f.view == View::Findings {
            chips.push(("findings only".to_string(), CANDIDATE, Box::new(|d: &mut Filter| d.view = View::All)));
        } else if f.hunt.iter().any(|h| !h) {
            let on: Vec<&str> = HUNT_NAMES.iter().enumerate().filter(|(i, _)| f.hunt[*i]).map(|(_, n)| if n.is_empty() { "not hunted" } else { *n }).collect();
            chips.push((format!("hunt: {}", on.join(", ")), CANDIDATE, Box::new(|d: &mut Filter| d.hunt = [true; 6])));
        }
        if f.results != Filter::default().results {
            let on: Vec<&str> = RESULT_NAMES.iter().enumerate().filter(|(i, _)| f.results[*i]).map(|(_, n)| *n).collect();
            let text = if f.results.iter().all(|r| *r) { "logoffs too".to_string() } else { format!("result: {}", on.join(", ")) };
            chips.push((text, EDGE_OK, Box::new(|d: &mut Filter| d.results = Filter::default().results)));
        }
        if f.verdict.iter().any(|v| !v) {
            let on: Vec<&str> = VERDICT_NAMES.iter().enumerate().filter(|(i, _)| f.verdict[*i]).map(|(_, n)| if n.is_empty() { "unmarked" } else { *n }).collect();
            chips.push((format!("verdict: {}", on.join(", ")), CONFIRMED, Box::new(|d: &mut Filter| d.verdict = [true; 4])));
        }
        if f.grouping != Grouping::Fold {
            chips.push((match f.grouping { Grouping::PerAccount => "one edge per account", _ => "one edge per event" }.to_string(), Color32::from_rgb(160, 170, 190), Box::new(|d: &mut Filter| d.grouping = Grouping::Fold)));
        }
        if chips.is_empty() {
            return false;
        }
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = Vec2::new(6.0, 4.0);
            ui.label(egui::RichText::new(format!("{}", ic::FUNNEL)).color(theme::DIM).size(13.0));
            let mut apply: Option<Box<dyn Fn(&mut Filter)>> = None;
            for (text, color, undo) in chips {
                if chip(ui, &text, color) {
                    apply = Some(undo);
                }
            }
            if ui.add(egui::Button::new(egui::RichText::new("clear all").color(theme::MUTED).size(12.0)).frame(false)).clicked() {
                apply = Some(Box::new(|d: &mut Filter| {
                    let limit = d.limit;
                    *d = Filter::default();
                    d.view = View::All;
                    d.limit = limit;
                }));
            }
            if let Some(f) = apply {
                f(&mut self.draft);
                self.requery(false);
            }
        });
        true
    }

    // ───────────────────────── the filter pane ─────────────────────────

    pub(super) fn left_panel(&mut self, ui: &mut egui::Ui) {
        let mut apply = false;
        let mut changed = false;
        let mut edited = false;
        let auto = self.auto_apply;
        // the pane's one action, pinned at the bottom
        egui::Panel::bottom("filters-apply").frame(egui::Frame::new().fill(theme::PANEL).inner_margin(egui::Margin::symmetric(0, 8))).show_separator_line(false).show(ui, |ui| {
            theme::hairline(ui);
            let pending = self.draft != self.filter;
            if ui.add_enabled(pending || true, egui::Button::new(theme::semibold(if pending { "Apply filters" } else { "Filters applied" }, 13.5).color(if pending { theme::ACCENT_INK } else { theme::MUTED })).fill(if pending { theme::ACCENT } else { theme::FIELD }).stroke(Stroke::NONE).min_size(Vec2::new(ui.available_width(), 34.0)).corner_radius(CornerRadius::same(8))).clicked() {
                apply = true;
            }
            ui.checkbox(&mut self.auto_apply, egui::RichText::new("apply as I change them").color(theme::MUTED).size(12.0));
        });
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::semibold("Filters", 15.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(egui::Button::new(egui::RichText::new("reset").color(theme::MUTED).size(12.0)).frame(false)).clicked() {
                        let limit = self.draft.limit;
                        self.draft = Filter::default();
                        self.draft.view = View::All;
                        self.draft.limit = limit;
                        apply = true;
                    }
                });
            });

            section(ui, "View");
            ui.horizontal_wrapped(|ui| {
                for (v, label) in [(View::Findings, "Findings"), (View::All, "Everything"), (View::Around, "Neighbourhood")] {
                    if pill(ui, self.draft.view == v, label, theme::ACCENT).clicked() {
                        self.draft.view = v;
                        changed = true;
                    }
                }
            });
            if self.draft.view == View::Around {
                ui.add_space(4.0);
                let r = ui.add(egui::TextEdit::singleline(&mut self.draft.around).hint_text("host, or several: SRV01, 10.0.0.*").desired_width(f32::INFINITY));
                if self.focus_around {
                    r.request_focus();
                    self.focus_around = false;
                }
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    apply = true;
                }
                edited |= r.changed();
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("hops").color(theme::MUTED));
                    changed |= ui.add(egui::Slider::new(&mut self.draft.hops, 1..=4)).changed();
                });
            }

            section(ui, "Search");
            for (field, hint, icon) in [(0, "hosts: contains, * wildcards, !not, commas", ic::DESKTOP), (1, "accounts: adm*, !*$", ic::USER), (2, "logon type: 10, 3, SSH", ic::TAG)] {
                let text = match field {
                    0 => &mut self.draft.host,
                    1 => &mut self.draft.user,
                    _ => &mut self.draft.logon_type,
                };
                let r = ui.add(egui::TextEdit::singleline(text).hint_text(format!("{icon}  {hint}")).desired_width(f32::INFINITY));
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    apply = true;
                }
                edited |= r.changed();
            }

            section(ui, "Hunt");
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("score ≥").color(theme::MUTED));
                ui.spacing_mut().slider_width = (ui.available_width() - 48.0).max(80.0);
                changed |= ui.add(egui::Slider::new(&mut self.draft.min_score, 0..=100).show_value(true)).on_hover_text("hunt_score: how rare a connection is, 0 to 100; 13 is one in twenty, 30 one in a thousand, 60 one in a million").changed();
            });
            ui.label(egui::RichText::new(if self.draft.min_score == 0 { "any score".to_string() } else { crate::csv_out::score_words(self.draft.min_score).to_string() }).small().color(theme::DIM));
            ui.add_space(2.0);
            let enabled = self.draft.view != View::Findings;
            ui.add_enabled_ui(enabled, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = Vec2::new(4.0, 4.0);
                    for (i, name) in HUNT_NAMES.iter().enumerate() {
                        let label = if name.is_empty() { "not hunted" } else { name };
                        let on = if enabled { self.draft.hunt[i] } else { i == 1 || i == 2 };
                        if pill(ui, on, label, hunt_color(i as u8).unwrap_or(theme::MUTED)).clicked() {
                            self.draft.hunt[i] = !self.draft.hunt[i];
                            changed = true;
                        }
                    }
                });
            });
            if !enabled {
                ui.label(egui::RichText::new("Findings shows significant and candidate; switch to Everything to pick states.").small().color(theme::DIM));
            }

            section(ui, "Result");
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = Vec2::new(4.0, 4.0);
                for (i, name) in RESULT_NAMES.iter().enumerate() {
                    if pill(ui, self.draft.results[i], name, result_color(i as u8)).clicked() {
                        self.draft.results[i] = !self.draft.results[i];
                        changed = true;
                    }
                }
            });

            section(ui, "Verdict");
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = Vec2::new(4.0, 4.0);
                for (i, name) in VERDICT_NAMES.iter().enumerate() {
                    let label = if name.is_empty() { "unmarked" } else { name };
                    if pill(ui, self.draft.verdict[i], label, verdict_color(i as u8).unwrap_or(theme::MUTED)).clicked() {
                        self.draft.verdict[i] = !self.draft.verdict[i];
                        changed = true;
                    }
                }
            });

            section(ui, "Grouping");
            for (g, label, tip) in [
                (Grouping::Fold, "Group accounts", "one edge per origin, destination, account and result; a pair with more than six accounts becomes one edge"),
                (Grouping::PerAccount, "One edge per account", "never fold a busy pair: every account is its own curve"),
                (Grouping::PerEvent, "One edge per event", "every row is its own curve, with its time; for a tight window"),
            ] {
                if ui.add(egui::RadioButton::new(self.draft.grouping == g, label)).on_hover_text(tip).clicked() {
                    self.draft.grouping = g;
                    changed = true;
                }
            }

            section(ui, "Limit");
            ui.horizontal(|ui| {
                changed |= ui.add(egui::DragValue::new(&mut self.draft.limit).range(10..=200_000).speed(10)).changed();
                ui.label(egui::RichText::new("connections drawn, the most pressing first").small().color(theme::DIM));
            });

            section(ui, "Saved filters");
            let mut pick: Option<SavedView> = None;
            let mut delete: Option<String> = None;
            for v in self.saved.clone() {
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(format!("{}  {}", ic::BOOKMARK_SIMPLE, v.name)).frame(false)).clicked() {
                        pick = Some(v.clone());
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(egui::Button::new(egui::RichText::new(ic::TRASH).color(theme::DIM)).frame(false)).on_hover_text("Delete this saved filter").clicked() {
                            delete = Some(v.name.clone());
                        }
                    });
                });
            }
            egui::CollapsingHeader::new(egui::RichText::new("Built in").color(theme::MUTED)).default_open(self.saved.is_empty()).show(ui, |ui| {
                for v in self.builtin.clone() {
                    if ui.add(egui::Button::new(format!("{}  {}", ic::DOT_OUTLINE, v.name)).frame(false)).clicked() {
                        pick = Some(v);
                    }
                }
            });
            if let Some(v) = pick {
                self.preset = v.name.clone();
                self.draft = v.filter.clone();
                if self.saved.iter().any(|x| x.name == v.name) {
                    self.style = v.style.clone();
                    self.persist();
                }
                apply = true;
            }
            if let Some(name) = delete {
                self.saved.retain(|x| x.name != name);
                if self.preset == name {
                    self.preset.clear();
                }
                self.persist();
            }
            if ui.add(egui::Button::new(format!("{}  Save the current filter…", ic::FLOPPY_DISK)).frame(false)).clicked() {
                self.show_save = true;
                if self.save_name.is_empty() {
                    self.save_name = self.preset.clone();
                }
            }
            ui.add_space(12.0);
        });
        if apply || (auto && changed) {
            self.requery(false);
        } else if auto && edited {
            // text fields apply when the user pauses
            self.auto_apply_at = Some(std::time::Instant::now() + std::time::Duration::from_millis(600));
        }
        if let Some(at) = self.auto_apply_at {
            if std::time::Instant::now() >= at {
                self.auto_apply_at = None;
                if self.draft != self.filter {
                    self.requery(false);
                }
            } else {
                ui.ctx().request_repaint_after(std::time::Duration::from_millis(100));
            }
        }
    }

    // ───────────────────────── inspector ─────────────────────────

    pub(super) fn inspector(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            for (t, label, icon) in [(Tab::Selection, "Selection", ic::TARGET), (Tab::Notes, "Notes", ic::NOTE_PENCIL), (Tab::Legend, "Legend", ic::LIST_BULLETS)] {
                let on = self.tab == t;
                if ui.add(egui::Button::new(egui::RichText::new(format!("{icon}  {label}")).color(if on { theme::TEXT } else { theme::MUTED })).fill(if on { theme::FIELD } else { Color32::TRANSPARENT }).stroke(if on { Stroke::new(1.0, theme::BORDER_2) } else { Stroke::NONE }).corner_radius(CornerRadius::same(7))).clicked() {
                    self.tab = t;
                }
            }
        });
        theme::hairline(ui);
        // a selection the last query no longer has
        match self.selected {
            Some(Sel::Node(i)) if i >= self.graph.nodes.len() => self.selected = None,
            Some(Sel::Edge(k)) if k >= self.graph.edges.len() => self.selected = None,
            _ => {}
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| match self.tab {
            Tab::Selection => match self.selected {
                None => {
                    theme::hint(ui, "Click a host or a connection to inspect it. Right-click for what you can do with it. Drag a host to move it, drag the background to pan, scroll to zoom, double-click a host to open its neighbourhood.");
                    ui.add_space(8.0);
                    self.view_summary(ui);
                }
                Some(Sel::Node(i)) => self.node_details(ui, i),
                Some(Sel::Edge(i)) => self.edge_details(ui, i),
            },
            Tab::Notes => self.notes_tab(ui),
            Tab::Legend => self.legend(ui),
        });
    }

    /// What is in the view now: counts by state and verdict.
    fn view_summary(&self, ui: &mut egui::Ui) {
        section(ui, "In this view");
        let g = &self.graph;
        ui.label(format!("{} hosts · {} connections · {} rows", g.nodes.len(), g.edges.len(), g.events.len()));
        let mut per_hunt = [0usize; 6];
        let mut per_verdict = [0usize; 4];
        for e in &g.edges {
            per_hunt[e.hunt as usize] += 1;
            per_verdict[e.verdict() as usize] += 1;
        }
        ui.horizontal_wrapped(|ui| {
            for (i, n) in per_hunt.iter().enumerate() {
                if *n > 0 {
                    let _ = pill(ui, true, &format!("{} {}", n, if HUNT_NAMES[i].is_empty() { "not hunted" } else { HUNT_NAMES[i] }), hunt_color(i as u8).unwrap_or(theme::MUTED));
                }
            }
            for (i, n) in per_verdict.iter().enumerate().skip(1) {
                if *n > 0 {
                    let _ = pill(ui, true, &format!("{} {}", n, VERDICT_NAMES[i]), verdict_color(i as u8).unwrap_or(theme::MUTED));
                }
            }
        });
        if g.truncated {
            ui.add_space(6.0);
            ui.label(egui::RichText::new(format!("{}  Limit reached: {} of {} connections drawn. Narrow the filters or raise the limit.", ic::WARNING, g.edges.len(), g.connections)).color(CANDIDATE).small());
        }
    }

    /// Every row of the timeline that carries a note or a verdict, newest
    /// file order first; click to open its connection.
    fn notes_tab(&mut self, ui: &mut egui::Ui) {
        section(ui, "Notes of the case");
        if self.notes.notes.is_empty() {
            ui.label(egui::RichText::new("None yet: right-click a host, a connection or the background and choose Add a note.").color(theme::DIM).small());
        }
        let mut delete: Option<usize> = None;
        for (i, n) in self.notes.notes.iter().enumerate() {
            egui::Frame::new().fill(theme::PANEL_2).stroke(Stroke::new(1.0, theme::BORDER)).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::same(8)).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(theme::medium(n.target.label(), 12.5).color(theme::ACCENT));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(egui::Button::new(egui::RichText::new(ic::TRASH).color(theme::DIM)).frame(false)).on_hover_text("Delete this note").clicked() {
                            delete = Some(i);
                        }
                        ui.label(egui::RichText::new(&n.when[..16]).color(theme::DIM).small());
                    });
                });
                ui.label(egui::RichText::new(&n.text).size(12.5));
            });
        }
        if let Some(i) = delete {
            self.notes.notes.remove(i);
            if let Err(e) = self.notes.save() {
                self.status = format!("cannot write {}: {}", self.notes.path.display(), e);
            }
        }
        if ui.add(egui::Button::new(format!("{}  Add a note to the case…", ic::NOTE_PENCIL)).frame(false)).clicked() {
            self.note_draft = Some((NoteTarget::Free, String::new()));
        }
        section(ui, "Marks and notes in the timeline");
        let mut marked: Vec<(u16, u32)> = self.store.notes.keys().copied().collect();
        for e in &self.store.edges {
            if e.verdict != 0 && !self.store.notes.contains_key(&(e.file, e.line)) {
                marked.push((e.file, e.line));
            }
        }
        marked.sort_unstable();
        marked.dedup();
        if marked.is_empty() {
            theme::hint(ui, "Nothing marked yet. Select a connection and give it a verdict or a note; both are written into the timeline's verdict and notes columns, which agentc00pr reads.");
            return;
        }
        ui.label(egui::RichText::new(format!("{} row(s)", marked.len())).color(theme::MUTED).small());
        let mut open: Option<usize> = None;
        for (file, line) in marked.into_iter().take(500) {
            let Some(ei) = self.store.edge_at(file, line) else { continue };
            let e = self.store.edges[ei];
            let note = self.store.notes.get(&(file, line)).cloned().unwrap_or_default();
            let who = self.store.users.name(e.user).to_string();
            let text = format!("{} -> {}  as {}\n{} · {}{}", self.store.hosts.name(e.src), self.store.hosts.name(e.dst), if who.is_empty() { "(no account)" } else { &who }, fmt_time(e.t), VERDICT_NAMES[e.verdict as usize], if note.is_empty() { String::new() } else { format!("\n{}", note) });
            let mut rt = egui::RichText::new(text).size(12.5);
            if let Some(c) = verdict_color(e.verdict) {
                rt = rt.color(c);
            }
            if ui.add(egui::Button::new(rt).min_size(Vec2::new(ui.available_width(), 0.0))).clicked() {
                open = Some(ei);
            }
        }
        if let Some(ei) = open {
            // the drawn edge that holds this row, if the view shows it
            if let Some(k) = self.graph.edges.iter().position(|g| g.rows.contains(&(ei as u32))) {
                self.selected = Some(Sel::Edge(k));
                self.tab = Tab::Selection;
                self.load_rows(k);
            } else {
                self.status = "That row is not in the current view; widen the filters to see it.".into();
            }
        }
    }

    // ───────────────────────── the time strip ─────────────────────────

    /// The whole timeline's events over time, with the window the filter
    /// selects as a bright band between two handles (drag them, or drag
    /// the band's edges), the replay head inside it; drag elsewhere to
    /// scrub. Double-click frees the window.
    pub(super) fn time_strip(&mut self, ui: &mut egui::Ui) {
        let n_view = self.graph.events.len();
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            let label = if self.playing { ic::PAUSE } else { ic::PLAY };
            if tool(ui, label, "Replay the connections in time order", self.playing).clicked() {
                if self.playing {
                    self.playing = false;
                } else {
                    if self.cursor >= n_view {
                        self.cursor = 0;
                    }
                    self.playing = true;
                    self.acc = 0.0;
                }
            }
            egui::ComboBox::from_id_salt("rate").selected_text(format!("{} rows/s", self.rate as u32)).width(96.0).show_ui(ui, |ui| {
                for r in [1.0, 4.0, 15.0, 60.0, 250.0] {
                    ui.selectable_value(&mut self.rate, r, format!("{} rows/s", r as u32));
                }
            });
            let w = (ui.available_width() - 470.0).max(160.0);
            self.histogram_brush(ui, w);
            // the brush may have applied a new window: the view can be another one now
            let n_view = self.graph.events.len();
            let at = if n_view == 0 {
                String::new()
            } else {
                let k = self.cursor.min(n_view).saturating_sub(1);
                fmt_time(self.store.edges[self.graph.events[k] as usize].t)
            };
            ui.label(egui::RichText::new(at).monospace().size(12.0));
            ui.label(egui::RichText::new(format!("{} / {}", self.cursor.min(n_view), n_view)).color(theme::MUTED).size(12.0));
            if ui.add(egui::Button::new("All").min_size(Vec2::new(0.0, 26.0))).on_hover_text("Show every row of the view again").clicked() {
                self.cursor = n_view;
                self.playing = false;
            }
            ui.add_space(4.0);
            let present = egui::Button::new(theme::semibold(format!("{}  Present", ic::PRESENTATION), 13.0).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 28.0)).corner_radius(CornerRadius::same(7));
            if ui.add(present).on_hover_text("Play the story full window (Esc leaves)").clicked() {
                self.start_presentation();
            }
            if tool(ui, ic::FILM_STRIP, "Story: timing, captions, recording", self.show_story).clicked() {
                self.show_story = !self.show_story;
            }
        });
    }

    fn histogram_brush(&mut self, ui: &mut egui::Ui, w: f32) {
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, 44.0), Sense::click_and_drag());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, CornerRadius::same(8), BG);
        painter.rect_stroke(rect, CornerRadius::same(8), Stroke::new(1.0, theme::BORDER), egui::StrokeKind::Inside);
        let total = self.store.edges.len();
        if total == 0 {
            return;
        }
        let pad = 8.0;
        let inner = Rect::from_min_max(Pos2::new(rect.left() + pad, rect.top() + 4.0), Pos2::new(rect.right() - pad, rect.bottom() - 4.0));
        let bins = (inner.width() / 3.0).max(1.0) as usize;
        let t0 = self.store.t_min;
        let t1 = self.store.t_max;
        let span = (t1 - t0).max(1) as f64;
        let x_of = |t: i64| inner.left() + (((t - t0) as f64 / span).clamp(0.0, 1.0) as f32) * inner.width();
        let t_of = |x: f32| t0 + ((((x - inner.left()) / inner.width()).clamp(0.0, 1.0) as f64) * span) as i64;
        // the whole timeline, binned once; the view's rows, binned per view
        if self.hist_all.as_ref().map_or(true, |h| h.0 != total || h.1 != bins) {
            let mut h = vec![(0u32, 0u32); bins];
            for e in &self.store.edges {
                let b = ((((e.t - t0) as f64 / span) * bins as f64) as usize).min(bins - 1);
                h[b].0 += 1;
                if e.hunt == super::super::store::H_SIGNIFICANT {
                    h[b].1 += 1;
                }
            }
            self.hist_all = Some((total, bins, h));
        }
        let n_view = self.graph.events.len();
        if self.hist.as_ref().map_or(true, |h| h.0 != n_view || h.1 != bins || h.2 != self.graph_id as i64) {
            let mut h = vec![(0u32, 0u32); bins];
            for &ei in &self.graph.events {
                let e = &self.store.edges[ei as usize];
                let b = ((((e.t - t0) as f64 / span) * bins as f64) as usize).min(bins - 1);
                h[b].0 += 1;
                if e.hunt == super::super::store::H_SIGNIFICANT {
                    h[b].1 += 1;
                }
            }
            self.hist = Some((n_view, bins, self.graph_id as i64, h));
        }
        let all = &self.hist_all.as_ref().unwrap().2;
        let view = &self.hist.as_ref().unwrap().3;
        let max = all.iter().map(|b| b.0).max().unwrap_or(1).max(1) as f32;
        // the window
        let from = parse_time(&self.filter.from).unwrap_or(t0);
        let to = parse_time(&self.filter.to).unwrap_or(t1);
        let (xf, xt) = (x_of(from), x_of(to));
        painter.rect_filled(Rect::from_min_max(Pos2::new(xf, inner.top()), Pos2::new(xt, inner.bottom())), CornerRadius::ZERO, Color32::from_rgba_unmultiplied(255, 198, 88, 16));
        let cursor_t = if self.cursor == 0 || n_view == 0 { i64::MIN } else { self.store.edges[self.graph.events[self.cursor.min(n_view) - 1] as usize].t };
        let h_in = inner.height();
        for i in 0..bins {
            let (c_all, s_all) = all[i];
            if c_all == 0 {
                continue;
            }
            let x = inner.left() + i as f32 * 3.0;
            let bin_t = t0 + (i as f64 / bins as f64 * span) as i64;
            let in_window = bin_t >= from && bin_t <= to;
            let hh = ((c_all as f32).ln_1p() / max.ln_1p()) * h_in;
            // the whole timeline, faint
            painter.rect_filled(Rect::from_min_max(Pos2::new(x, inner.bottom() - hh.max(1.0)), Pos2::new(x + 2.0, inner.bottom())), CornerRadius::same(1), draw::fade(if s_all > 0 { SIGNIFICANT } else { theme::MUTED }, if in_window { 0.22 } else { 0.12 }));
            // the view's rows, bright, dimmer past the replay head
            let (c_v, s_v) = view[i];
            if c_v > 0 {
                let hv = ((c_v as f32).ln_1p() / max.ln_1p()) * h_in;
                let past = bin_t <= cursor_t;
                painter.rect_filled(Rect::from_min_max(Pos2::new(x, inner.bottom() - hv.max(1.5)), Pos2::new(x + 2.0, inner.bottom())), CornerRadius::same(1), draw::fade(if s_v > 0 { SIGNIFICANT } else { HOST_FILL }, if past { 0.95 } else { 0.4 }));
            }
        }
        // handles
        let handle = |x: f32| Rect::from_center_size(Pos2::new(x, inner.center().y), Vec2::new(8.0, inner.height() + 2.0));
        for (x, which) in [(xf, Brush::From), (xt, Brush::To)] {
            let r = handle(x);
            let hot = self.brush == Some(which) || resp.hover_pos().map_or(false, |p| r.expand2(Vec2::new(4.0, 0.0)).contains(p));
            painter.rect_filled(r, CornerRadius::same(3), if hot { theme::ACCENT } else { draw::fade(theme::ACCENT, 0.75) });
            painter.vline(x, inner.top()..=inner.bottom(), Stroke::new(1.0, draw::fade(theme::ACCENT, 0.5)));
        }
        // replay head
        if cursor_t > i64::MIN {
            let cx = x_of(cursor_t);
            painter.line_segment([Pos2::new(cx, inner.top()), Pos2::new(cx, inner.bottom())], Stroke::new(1.5, Color32::WHITE));
            painter.circle_filled(Pos2::new(cx, inner.top() + 2.0), 3.0, Color32::WHITE);
        }
        // interaction
        if resp.drag_started() {
            if let Some(p) = resp.interact_pointer_pos() {
                let near = |x: f32| (p.x - x).abs() <= 7.0;
                self.brush = Some(if near(xf) && (!near(xt) || (p.x - xf).abs() <= (p.x - xt).abs()) {
                    Brush::From
                } else if near(xt) {
                    Brush::To
                } else {
                    Brush::Scrub
                });
            }
        }
        if resp.dragged() || resp.clicked() {
            if let Some(p) = resp.interact_pointer_pos() {
                let t = t_of(p.x);
                match self.brush.unwrap_or(Brush::Scrub) {
                    Brush::From => {
                        self.draft.from = if t <= t0 { String::new() } else { fmt_time(t.min(to - 1)) };
                        self.filter.from = self.draft.from.clone();
                    }
                    Brush::To => {
                        self.draft.to = if t >= t1 { String::new() } else { fmt_time(t.max(from + 1)) };
                        self.filter.to = self.draft.to.clone();
                    }
                    Brush::Scrub => {
                        let edges = &self.store.edges;
                        self.cursor = self.graph.events.partition_point(|&ei| edges[ei as usize].t <= t);
                        self.playing = false;
                    }
                }
            }
        }
        if resp.drag_stopped() {
            if matches!(self.brush, Some(Brush::From) | Some(Brush::To)) {
                self.requery(false);
            }
            self.brush = None;
        }
        if resp.double_clicked() {
            self.draft.from.clear();
            self.draft.to.clear();
            self.requery(false);
        }
        if let Some(p) = resp.hover_pos() {
            let t = t_of(p.x);
            let galley = painter.layout_no_wrap(fmt_time(t), FontId::monospace(10.5), TEXT);
            let at = Pos2::new(p.x.clamp(rect.left() + galley.size().x / 2.0 + 10.0, rect.right() - galley.size().x / 2.0 - 10.0), rect.top() + 10.0);
            draw::pill(&painter, at, galley, CAPTION_BG, None, TEXT);
            if self.brush.is_none() {
                let near = (p.x - xf).abs() <= 7.0 || (p.x - xt).abs() <= 7.0;
                ui.ctx().set_cursor_icon(if near { egui::CursorIcon::ResizeHorizontal } else { egui::CursorIcon::Crosshair });
            }
        }
    }

    // ───────────────────────── status line ─────────────────────────

    pub(super) fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(&self.status).color(if self.graph.truncated { CANDIDATE } else { theme::MUTED }).size(12.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(egui::RichText::new(format!("{:.0} %", self.zoom * 100.0)).color(theme::DIM).size(12.0));
                ui.label(egui::RichText::new(format!("{} rows · {} edges · {} hosts · {} accounts · {} → {}", self.store.rows_total, self.store.edges.len(), self.store.hosts.len(), self.store.users.len(), &fmt_time(self.store.t_min)[..10], &fmt_time(self.store.t_max)[..10])).color(theme::DIM).size(12.0));
            });
        });
    }

    // ───────────────────────── context menus ─────────────────────────

    /// The right-click menu of what was under the pointer.
    pub(super) fn context_menu(&mut self, ui: &mut egui::Ui) {
        ui.set_min_width(240.0);
        // the target may be gone if the view changed while the menu was open
        let target = match self.ctx_target {
            Some(Sel::Node(i)) if i >= self.graph.nodes.len() => None,
            Some(Sel::Edge(k)) if k >= self.graph.edges.len() => None,
            t => t,
        };
        match target {
            Some(Sel::Node(i)) => {
                let host = self.graph.nodes[i].host;
                let name = self.store.hosts.name(host).to_string();
                ui.label(theme::semibold(&name, 13.5));
                ui.separator();
                if icon_button(ui, ic::CIRCLES_THREE_PLUS, "Expand around").clicked() {
                    ui.close();
                    self.draft.view = View::Around;
                    self.draft.around = name.clone();
                    self.requery(false);
                }
                if icon_button(ui, ic::TARGET, "Only this host").clicked() {
                    ui.close();
                    self.draft.view = View::All;
                    self.draft.host = name.clone();
                    self.requery(false);
                }
                if icon_button(ui, ic::ARROW_RIGHT, "Paths from here").clicked() {
                    ui.close();
                    self.path_origin = name.clone();
                    self.show_paths = true;
                }
                if icon_button(ui, ic::ARROW_LEFT, "Paths to here").clicked() {
                    ui.close();
                    self.path_dest = name.clone();
                    self.show_paths = true;
                }
                ui.separator();
                let other = match self.selected {
                    Some(Sel::Node(j)) if j != i => self.graph.nodes.get(j).map(|n| self.store.hosts.name(n.host).to_string()),
                    _ => None,
                };
                if let Some(sel) = other {
                    if icon_button(ui, ic::ARROWS_CLOCKWISE, &format!("Merge {} into this host", sel)).on_hover_text("The selected host becomes part of this one").clicked() {
                        ui.close();
                        self.merge_hosts(&sel, &name);
                    }
                }
                if icon_button(ui, ic::ARROWS_CLOCKWISE, "Merge into another host…").on_hover_text("This host is the same machine as another one (an address and its name): make them one").clicked() {
                    ui.close();
                    self.merge_edit = Some(MergeHostsEdit { from: name.clone(), into: String::new(), filter: String::new() });
                }
                ui.separator();
                let pinned = self.layout.fixed.get(i).copied().unwrap_or(false);
                if icon_button(ui, ic::PUSH_PIN, if pinned { "Unpin" } else { "Pin where it is" }).clicked() {
                    ui.close();
                    if let Some(f) = self.layout.fixed.get_mut(i) {
                        *f = !pinned;
                    }
                    self.layout.reheat(0.1);
                }
                if icon_button(ui, ic::PALETTE, "Style of this host…").on_hover_text("Name position, text size, box, size and colour of this host alone").clicked() {
                    ui.close();
                    self.host_edit = Some(HostEdit { name: name.clone() });
                }
                if icon_button(ui, ic::EYE_SLASH, "Hide this host").clicked() {
                    ui.close();
                    self.style.rules.push(Rule { enabled: true, field: Field::Host, pattern: format!("={}", name), color: None, hide: true, ..Rule::default() });
                    self.persist();
                }
                ui.separator();
                if icon_button(ui, ic::NOTE_PENCIL, "Add a note…").clicked() {
                    ui.close();
                    self.note_draft = Some((NoteTarget::Host(name.clone()), String::new()));
                }
                if icon_button(ui, ic::LINK, "Copy the name").clicked() {
                    ui.close();
                    ui.ctx().copy_text(name.clone());
                }
            }
            Some(Sel::Edge(k)) => {
                let e = &self.graph.edges[k];
                let title = format!("{} -> {}", self.store.hosts.name(e.src), self.store.hosts.name(e.dst));
                let users: Vec<u32> = e.users.clone();
                let (src, dst) = (e.src, e.dst);
                ui.label(theme::semibold(&title, 13.5));
                ui.label(egui::RichText::new(match e.user {
                    Some(u) => format!("as {} · {} event(s)", self.store.users.name(u), e.count),
                    None => format!("{} accounts · {} event(s)", e.users.len(), e.count),
                }).color(theme::MUTED).small());
                ui.separator();
                if icon_button(ui, ic::TARGET, "Open in the inspector").clicked() {
                    ui.close();
                    self.selected = Some(Sel::Edge(k));
                    self.tab = Tab::Selection;
                    self.show_inspector = true;
                    self.load_rows(k);
                }
                ui.separator();
                for v in 1..4u8 {
                    let c = verdict_color(v).unwrap();
                    if ui.add(egui::Button::new(egui::RichText::new(format!("{}  Mark {}", ic::FLAG, VERDICT_NAMES[v as usize])).color(c)).min_size(Vec2::new(0.0, 26.0))).clicked() {
                        ui.close();
                        self.begin_mark(k, v);
                    }
                }
                if icon_button(ui, ic::NOTE_PENCIL, "Add a note…").clicked() {
                    ui.close();
                    self.note_draft = Some((NoteTarget::Edge { src: self.store.hosts.name(src).to_string(), dst: self.store.hosts.name(dst).to_string(), user: users.first().map(|&u| self.store.users.name(u).to_string()).unwrap_or_default() }, String::new()));
                }
                ui.separator();
                let names: Vec<String> = users.iter().map(|&u| self.store.users.name(u).to_string()).collect();
                if icon_button(ui, ic::PALETTE, "Style of this connection…").on_hover_text("Colour, width, dashes, glow or hide, for every connection of the account").clicked() {
                    ui.close();
                    self.edge_edit = Some(EdgeEdit { user: names.first().cloned().unwrap_or_default(), choices: names.clone() });
                }
                if users.len() == 1 {
                    let uname = names[0].clone();
                    if icon_button(ui, ic::EYE_SLASH, &format!("Hide {}", uname)).clicked() {
                        ui.close();
                        self.style.rules.push(Rule { enabled: true, field: Field::User, pattern: format!("={}", uname), color: None, hide: true, ..Rule::default() });
                        self.persist();
                    }
                    if icon_button(ui, ic::USER, &format!("Only {}", uname)).clicked() {
                        ui.close();
                        self.draft.user = format!("={}", uname);
                        self.requery(false);
                    }
                }
            }
            None => {
                if icon_button(ui, ic::CORNERS_OUT, "Fit to window").clicked() {
                    ui.close();
                    self.fit_pending = true;
                }
                if icon_button(ui, ic::SHUFFLE, "Lay out again").clicked() {
                    ui.close();
                    let f = self.draft.clone();
                    self.draft = f;
                    self.requery(true);
                }
                ui.separator();
                if icon_button(ui, ic::FIRE, "Findings").clicked() {
                    ui.close();
                    self.draft.view = View::Findings;
                    self.requery(false);
                }
                if icon_button(ui, ic::GRAPH, "Everything").clicked() {
                    ui.close();
                    self.draft.view = View::All;
                    self.requery(false);
                }
                if self.overlay.is_some() && icon_button(ui, ic::ARROW_LEFT, "Back to the view").clicked() {
                    ui.close();
                    self.overlay = None;
                    self.requery(false);
                }
                ui.separator();
                if icon_button(ui, ic::X, "Clear the selection").clicked() {
                    ui.close();
                    self.selected = None;
                }
                if icon_button(ui, ic::NOTE_PENCIL, "Add a note to the case…").clicked() {
                    ui.close();
                    self.note_draft = Some((NoteTarget::Free, String::new()));
                }
            }
        }
    }

    /// The legend chips over the canvas as real widgets: counts per
    /// category, and when coloured by account a click picks its colour.
    pub(super) fn legend_overlay(&mut self, ctx: &egui::Context, canvas: Rect) {
        let n_ip = self.scene.n_ip;
        let n_host = self.graph.nodes.len() - n_ip;
        let chips: Vec<(String, Color32, usize)> = self.scene.chips.clone();
        let by_user = self.style.color_by == ColorBy::User;
        egui::Area::new(egui::Id::unique("legend-overlay")).fixed_pos(canvas.min + Vec2::new(10.0, 10.0)).order(egui::Order::Middle).show(ctx, |ui| {
            ui.set_max_width(canvas.width() - 20.0);
            ui.spacing_mut().item_spacing = Vec2::new(5.0, 5.0);
            ui.horizontal_wrapped(|ui| {
                let legend_chip = |ui: &mut egui::Ui, text: String, c: Color32, strong: bool| -> egui::Response {
                    let fill = if strong { draw::fade(c, 0.22) } else { CHIP_BG };
                    ui.add(egui::Button::new(egui::RichText::new(text).size(11.5).color(if strong { c } else { TEXT })).fill(fill).stroke(Stroke::new(1.0, draw::fade(c, if strong { 0.7 } else { 0.85 }))).corner_radius(CornerRadius::same(11)).min_size(Vec2::new(0.0, 20.0)))
                };
                legend_chip(ui, format!("{}  Host  {}", ic::CIRCLE, n_host), HOST_FILL, true).on_hover_text("hosts with a name");
                legend_chip(ui, format!("{}  IP  {}", ic::CIRCLE, n_ip), IP_FILL, true).on_hover_text("addresses the hunt could not tie to a name");
                ui.add_space(6.0);
                for (text, c, n) in chips {
                    let r = legend_chip(ui, format!("{}  {}", text, n), c, false);
                    if by_user {
                        let r = r.on_hover_text("Click to pick this account's colour");
                        if r.clicked() {
                            self.color_pick = Some(ColorPick { field: Field::User, pattern: format!("={}", text), color: c, title: format!("Colour of {}", text) });
                        }
                    }
                }
            });
        });
    }

    /// The colour picker window for a host or an account; OK writes a
    /// style rule (replacing one on the same name).
    pub(super) fn color_window(&mut self, ctx: &egui::Context) {
        let Some(pick) = self.color_pick.as_mut() else { return };
        let mut open = true;
        let mut done = false;
        let mut clear = false;
        egui::Window::new(pick.title.clone()).open(&mut open).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.horizontal(|ui| {
                egui::color_picker::color_edit_button_srgba(ui, &mut pick.color, egui::color_picker::Alpha::Opaque);
                ui.label(egui::RichText::new("pick, or take one of these").color(theme::MUTED));
            });
            ui.horizontal_wrapped(|ui| {
                for c in [[255, 198, 88], [70, 198, 236], [255, 92, 108], [120, 214, 150], [196, 140, 222], [86, 150, 232], [255, 152, 86], [240, 240, 240], [255, 110, 199], [130, 220, 220], [200, 200, 90], [160, 170, 190]] {
                    let col = Color32::from_rgb(c[0], c[1], c[2]);
                    let (r, p) = ui.allocate_painter(Vec2::splat(22.0), Sense::click());
                    p.circle_filled(r.rect.center(), 9.0, col);
                    if pick.color == col {
                        p.circle_stroke(r.rect.center(), 11.0, Stroke::new(2.0, Color32::WHITE));
                    }
                    if r.clicked() {
                        pick.color = col;
                    }
                }
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new(theme::semibold("Use this colour", 13.0).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE)).clicked() {
                    done = true;
                }
                if ui.button("Back to the palette colour").clicked() {
                    clear = true;
                }
            });
        });
        if done || clear {
            let pick = self.color_pick.take().unwrap();
            if pick.field == Field::Host {
                // a host keeps one rule with everything of its own
                let rule = self.host_rule_mut(&pick.pattern);
                rule.color = if done { Some([pick.color.r(), pick.color.g(), pick.color.b()]) } else { None };
            } else {
                self.style.rules.retain(|r| !(r.field == pick.field && r.pattern.eq_ignore_ascii_case(&pick.pattern) && r.color.is_some() && !r.hide));
                if done {
                    self.style.rules.insert(0, Rule { enabled: true, field: pick.field, pattern: pick.pattern, color: Some([pick.color.r(), pick.color.g(), pick.color.b()]), ..Rule::default() });
                }
            }
            self.persist();
        } else if !open {
            self.color_pick = None;
        }
    }

    // ───────────────────────── files ─────────────────────────

    pub(super) fn open_timelines(&mut self, add: bool) {
        let picked = rfd::FileDialog::new().set_title(if add { "Add timeline CSVs to this view" } else { "Open timeline CSVs" }).add_filter("masstin timeline", &["csv"]).pick_files();
        let Some(paths) = picked else { return };
        let mut files: Vec<String> = if add { self.files.clone() } else { Vec::new() };
        for p in paths {
            let s = p.to_string_lossy().to_string();
            if !files.contains(&s) {
                files.push(s);
            }
        }
        if files.is_empty() {
            return;
        }
        let merges = ViewsFile::load(&ViewsFile::path_for(&files[0])).merges;
        match Store::load_with(&files, self.alpha, &merges) {
            Ok(s) => {
                self.store = s;
                self.files = files;
                self.merges = merges;
                self.views_path = ViewsFile::path_for(&self.files[0]);
                self.story_path = Story::path_for(&self.files[0]);
                self.remembered.clear();
                self.requery(true);
                self.status = format!("Opened: {}", self.status);
            }
            Err(e) => self.status = format!("Cannot read: {}", e),
        }
    }

    pub(super) fn open_agentc00pr(&mut self) {
        let exe = std::env::current_exe().ok();
        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        if let Some(e) = &exe {
            if let Some(dir) = e.parent() {
                candidates.push(dir.join("agentc00pr.exe"));
                candidates.push(dir.join("agentc00pr"));
            }
        }
        candidates.push(std::path::PathBuf::from("agentc00pr"));
        for c in candidates {
            if std::process::Command::new(&c).spawn().is_ok() {
                self.status = format!("agentc00pr started ({})", c.display());
                return;
            }
        }
        self.status = "agentc00pr is not next to masstin nor on the PATH".into();
    }
}
