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

/// How far from a handle of the time strip, in points, a press still takes it.
pub(super) const HANDLE_GRAB: f32 = 10.0;

/// What a press at `x` on the time strip takes: the nearer handle within
/// [`HANDLE_GRAB`] (From when both are as near), else the replay head.
/// The press is where the button went down, not where the pointer is when
/// egui calls it a drag: that is 6 points or more away, and judged there a
/// press on a handle missed it and moved the replay head instead.
pub(super) fn pick_brush(x: f32, from_x: f32, to_x: f32) -> Brush {
    let (df, dt) = ((x - from_x).abs(), (x - to_x).abs());
    if df <= HANDLE_GRAB && df <= dt {
        Brush::From
    } else if dt <= HANDLE_GRAB {
        Brush::To
    } else {
        Brush::Scrub
    }
}

/// [`pick_brush`] for a drag pressed at `press` and now at `now`: when both
/// handles are within reach of the press (a narrow window), the direction
/// decides, From to the left and To to the right, so the window can always
/// be widened.
pub(super) fn pick_brush_dragging(press: f32, now: f32, from_x: f32, to_x: f32) -> Brush {
    let both = (press - from_x).abs() <= HANDLE_GRAB && (press - to_x).abs() <= HANDLE_GRAB;
    if both && now != press {
        if now > press { Brush::To } else { Brush::From }
    } else {
        pick_brush(press, from_x, to_x)
    }
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
            ui.add_space(2.0);
            if let Some(t) = &self.logo_small {
                let r = ui.add(egui::Image::new((t.id(), Vec2::new(40.0, 25.0))).sense(Sense::click())).on_hover_text("About masstin");
                if r.clicked() {
                    self.show_about = true;
                }
            }
            theme::wordmark(ui, 16.0);
            ui.add_space(10.0);
            ui.menu_button("Evidence", |ui| {
                ui.set_min_width(260.0);
                if icon_button(ui, ic::FOLDER_OPEN, "Open timeline…").on_hover_text("Open a timeline CSV masstin wrote (or several) in this window, instead of what is open").clicked() {
                    ui.close();
                    self.open_timelines(false);
                }
                if icon_button(ui, ic::PLUS, "Add a timeline to this view…").on_hover_text("Open another timeline CSV together with the ones already open: one picture of all of them").clicked() {
                    ui.close();
                    self.open_timelines(true);
                }
                if icon_button(ui, ic::ARROW_CLOCKWISE, "Reload from disk").on_hover_text("Read the timeline files again: for when another program or another masstin changed them").clicked() {
                    ui.close();
                    self.reload();
                }
                ui.separator();
                if icon_button(ui, ic::ARCHIVE, "Open case…").on_hover_text("A case file (.masstin): its timelines, and the views, style, merged hosts, subnets, story and notes kept in it").clicked() {
                    ui.close();
                    self.pick_case();
                }
                let save_case = ui.add_enabled_ui(!self.files.is_empty(), |ui| icon_button(ui, ic::FLOPPY_DISK, if self.case.is_some() { "Save case as…" } else { "Save as a case…" })).inner;
                if save_case.on_hover_text("Keep this case in one file, wherever you choose: from then on nothing is written next to the timelines").clicked() {
                    ui.close();
                    self.save_case_as();
                }
                ui.separator();
                if icon_button(ui, ic::DOWNLOAD_SIMPLE, "Ingest evidence…").on_hover_text("Evidence into a timeline with masstin's parsers: a folder, images, EVTX, Linux or macOS logs, a triage package. Or drop it on the window.").clicked() {
                    ui.close();
                    self.ingest.open = true;
                }
                if icon_button(ui, ic::TABLE, "Timeline: the rows of the CSV").on_hover_text("The timeline row by row in its 19 columns, with a find box and \"Open in…\" (a spreadsheet, an editor). The same as the Graph / Timeline switch of the toolbar").clicked() {
                    ui.close();
                    self.show_table = true;
                }
                if icon_button(ui, ic::STACK, "Merge timelines…").on_hover_text("Join several timeline CSVs into one file, in time order, without duplicates").clicked() {
                    ui.close();
                    self.show_merge = true;
                }
                if icon_button(ui, ic::CLOUD, "Cortex XDR API…").on_hover_text("Lateral movement straight from a Cortex XDR tenant through its XQL API: the endpoints' network connections, or the Windows event logs of the forensics add-on").clicked() {
                    ui.close();
                    self.show_cortex = true;
                }
                ui.menu_button(format!("{}  Graph databases", ic::DATABASE), |ui| {
                    ui.set_min_width(300.0);
                    let items = [(super::remote::DbOp::Load, "Load the timeline into Neo4j / Memgraph…"), (super::remote::DbOp::MergeNodes, "Merge two host nodes there…"), (super::remote::DbOp::Hunt, "Hunt on the graph there…")];
                    for (op, text) in items {
                        if ui.button(text).clicked() {
                            ui.close();
                            self.db_form.op = op;
                            self.show_db = true;
                        }
                    }
                });
                ui.separator();
                if let Some(c) = &self.case {
                    ui.label(egui::RichText::new("Case").small().color(theme::DIM));
                    ui.label(egui::RichText::new(format!("{}  {}", ic::ARCHIVE, c.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default())).color(theme::MUTED)).on_hover_text(c.to_string_lossy());
                }
                if !self.files.is_empty() {
                    ui.label(egui::RichText::new("Open now").small().color(theme::DIM));
                    for f in self.files.clone() {
                        ui.label(egui::RichText::new(std::path::Path::new(&f).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or(f.clone())).color(theme::MUTED)).on_hover_text(&f);
                    }
                }
                let here = self.case.as_ref().map(|c| c.to_string_lossy().to_string());
                let recent: Vec<String> = self.recent.iter().filter(|f| !self.files.contains(f) && here.as_ref() != Some(*f) && std::path::Path::new(f).is_file()).take(8).cloned().collect();
                if !recent.is_empty() {
                    ui.label(egui::RichText::new("Recent").small().color(theme::DIM));
                    let mut pick: Option<String> = None;
                    for f in &recent {
                        let name = std::path::Path::new(f).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or(f.clone());
                        let (glyph, hint) = if case::is_case(f) { (ic::ARCHIVE, f.clone()) } else { (ic::CLOCK, format!("{}\n(Ctrl adds it to the view)", f)) };
                        if ui.add(egui::Button::new(format!("{}  {}", glyph, name)).frame(false)).on_hover_text(hint).clicked() {
                            pick = Some(f.clone());
                        }
                    }
                    if let Some(f) = pick.clone().filter(|f| case::is_case(f)) {
                        ui.close();
                        self.open_case(f.into());
                    } else if let Some(f) = pick {
                        ui.close();
                        let add = ui.input(|i| i.modifiers.ctrl);
                        let mut files: Vec<String> = if add { self.files.clone() } else { Vec::new() };
                        files.push(f);
                        self.open_files(files);
                    }
                }
                ui.separator();
                if icon_button(ui, ic::X, "Quit").on_hover_text("Close masstin. Everything is already saved").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("Hunt", |ui| {
                ui.set_min_width(260.0);
                if icon_button(ui, ic::DETECTIVE, "Run the hunt on this timeline…").on_hover_text("Open the hunt's assistant: it scores every connection by how unusual it is and marks the findings").clicked() {
                    ui.close();
                    self.show_hunt = true;
                }
                if icon_button(ui, ic::LIST_BULLETS, "The findings, as a list…").on_hover_text("The summary of the last hunt: every connection flagged, with its explanation and score").clicked() {
                    ui.close();
                    self.hunt_report = Some(self.build_report());
                }
                if let Some(r) = self.hunt_last_report.clone().filter(|r| std::path::Path::new(r).is_file()) {
                    if icon_button(ui, ic::ARCHIVE, "The analyst's report…").on_hover_text(format!("The Markdown report the last hunt wrote: {}", r)).clicked() {
                        ui.close();
                        if let Err(e) = super::ingest::open_external(&r) {
                            self.status = format!("Cannot open {}: {}", r, e);
                        }
                    }
                }
                ui.separator();
                if icon_button(ui, ic::FIRE, "Findings only").on_hover_text("Draw only the connections the hunt marked significant or candidate").clicked() {
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
                if icon_button(ui, ic::CORNERS_OUT, "Fill the window").on_hover_text("Zoom and centre so every host on the canvas is in sight").clicked() {
                    ui.close();
                    self.layout.stop();
                    self.fill_pending = true;
                }
                if icon_button(ui, ic::SHUFFLE, "Lay out again").on_hover_text("Place the hosts again from scratch (pinned ones stay where they are): for when the picture got tangled").clicked() {
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
                changed |= ui.checkbox(&mut self.style.motion, format!("{}  Motion", ic::WAVEFORM)).changed();
                changed |= ui.checkbox(&mut self.style.shapes_by_role, format!("{}  Shapes by role", ic::HEXAGON)).changed();
                if ui.checkbox(&mut self.style.show_subnets, format!("{}  Subnet regions", ic::WIFI_HIGH)).on_hover_text("Hosts grouped by the /24 of their address, or by your named CIDRs (Tools › Subnets…), each group a region behind them").changed() {
                    changed = true;
                    self.compute_subnets();
                    self.layout.reheat(0.5);
                }
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
                if icon_button(ui, ic::TAG, "Style: mode, sizes, names, connections, canvas…").on_hover_text("How everything is drawn: the look of hosts, sizes, names, lines, captions, effects").clicked() {
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
                if icon_button(ui, ic::TERMINAL_WINDOW, "Rule studio (custom logs)…").on_hover_text("A rule for a log masstin does not know (a VPN, a firewall, a proxy), built against the log itself: its lines, the fields, the timeline's columns and the rows it writes, live").clicked() {
                    ui.close();
                    self.studio.open = true;
                }
                ui.separator();
                if icon_button(ui, ic::PATH, "Paths and reach…").on_hover_text("Find how one host could have reached another, hop by hop in time order; or everything a host could reach").clicked() {
                    ui.close();
                    self.show_paths = true;
                }
                if icon_button(ui, ic::QUESTION, "Questions…").on_hover_text("Ready-made questions about the view (who reached the most hosts, the first logon to each server…) answered on the canvas").clicked() {
                    ui.close();
                    self.show_questions = true;
                }
                ui.separator();
                if icon_button(ui, ic::PRESENTATION, "Present the story").on_hover_text("Play the animation of this view full screen, as it is set in Story and recording. Esc ends it").clicked() {
                    ui.close();
                    self.start_presentation();
                }
                if icon_button(ui, ic::FILM_STRIP, "Story and recording…").on_hover_text("Set the pace of the animation, what is written on it, and record it as a GIF or a video").clicked() {
                    ui.close();
                    self.show_story = true;
                }
                if self.film.is_none() {
                    if icon_button(ui, ic::VIDEO_CAMERA, "Film the window").on_hover_text("Records the window as you use it, in real time, until you stop it: an MP4 next to the timeline (ffmpeg on the PATH), or a GIF without it").clicked() {
                        ui.close();
                        let ctx = ui.ctx().clone();
                        self.start_film(&ctx, Format::Mp4, 20, 0, None, false);
                    }
                } else if icon_button(ui, ic::VIDEO_CAMERA, "Stop filming").on_hover_text("End the recording now and keep what was recorded").clicked() {
                    ui.close();
                    self.stop_film(false);
                }
                ui.separator();
                if icon_button(ui, ic::APP_WINDOW, "Open the case in agentc00pr").on_hover_text("Takes the timelines open here into a case of agentc00pr (a new one, or one it has), with the evidence they were read from, and opens it there").clicked() {
                    ui.close();
                    self.open_agentc00pr();
                }
                ui.separator();
                if icon_button(ui, ic::LINK, "Hosts and addresses…").on_hover_text("Whose each address of the timelines is, with the evidence (the machine's own account, the domain controller a member found, the name a client gave), and the merges it allows: an address and its host drawn as one").clicked() {
                    ui.close();
                    self.open_hosts();
                }
                if icon_button(ui, ic::ARROWS_CLOCKWISE, &format!("Merged hosts… ({})", self.merges.len())).on_hover_text("Two names of the same machine drawn as one host, in this view and case only: the timeline CSV is not changed").clicked() {
                    ui.close();
                    self.show_merges = true;
                }
                if icon_button(ui, ic::WIFI_HIGH, &format!("Subnets… ({})", self.subnet_defs.len())).clicked() {
                    ui.close();
                    self.show_subnets_window = true;
                }
                if icon_button(ui, ic::TERMINAL_WINDOW, "Log of the last run…").on_hover_text("What the last ingest or hunt wrote while it ran: its steps, counts and any error").clicked() {
                    ui.close();
                    self.show_last_log = true;
                }
            });
            ui.menu_button("Help", |ui| {
                ui.set_min_width(260.0);
                if icon_button(ui, ic::KEYBOARD, "Mouse and keys").on_hover_text("Every mouse gesture and keyboard shortcut of the window").clicked() {
                    ui.close();
                    self.show_help = true;
                }
                if icon_button(ui, ic::BOOK_OPEN, "docs/viewer.md").on_hover_text("The viewer's manual, in the browser").clicked() {
                    ui.close();
                    ui.ctx().open_url(egui::OpenUrl::new_tab("https://github.com/c00pr/masstin/blob/main/docs/viewer.md"));
                }
                ui.separator();
                if icon_button(ui, ic::INFO, &format!("About masstin {}", env!("CARGO_PKG_VERSION"))).clicked() {
                    ui.close();
                    self.show_about = true;
                }
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
        theme::brand_line(ui);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            // the two faces of the same timeline: the picture and the rows
            egui::Frame::new().fill(theme::FIELD).stroke(Stroke::new(1.0, theme::ACCENT)).corner_radius(CornerRadius::same(9)).inner_margin(egui::Margin::same(2)).show(ui, |ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                for (timeline, label, icon, tip) in [
                    (false, "Graph", ic::GRAPH, "The timeline as a picture: who connected to what"),
                    (true, "Timeline", ic::TABLE, "The timeline row by row, in the 19 columns of the CSV, as written. A right click on a connection or a host of the graph shows its rows here; a double click on a row here shows its connection in the graph"),
                ] {
                    let on = self.show_table == timeline;
                    let b = egui::Button::new(egui::RichText::new(format!("{icon}  {label}")).size(14.0).strong().color(if on { theme::ACCENT_INK } else { theme::TEXT })).fill(if on { theme::ACCENT } else { Color32::TRANSPARENT }).corner_radius(CornerRadius::same(7)).min_size(Vec2::new(104.0, 30.0));
                    if ui.add(b).on_hover_text(tip).clicked() {
                        self.show_table = timeline;
                    }
                }
            });
            ui.add_space(8.0);
            if self.show_table {
                // the picture's tools wait in Graph mode
                ui.label(egui::RichText::new("the rows of the CSV, as written").color(theme::MUTED).size(12.5));
                return;
            }
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
            let w = (ui.available_width() - 610.0).clamp(90.0, 360.0);
            let r = ui.add(egui::TextEdit::singleline(&mut self.quick).hint_text(format!("{}  find a host and open its neighbourhood", ic::MAGNIFYING_GLASS)).desired_width(w));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !self.quick.trim().is_empty() {
                self.draft.view = View::Around;
                self.draft.around = self.quick.trim().to_string();
                self.requery(false);
            }
            ui.add_space(6.0);
            if tool(ui, ic::CORNERS_OUT, "Fill the window: stretch the picture to its shape and frame it", false).clicked() {
                self.layout.stop();
                self.fill_pending = true;
            }
            if tool(ui, ic::SHUFFLE, "Lay out again", false).clicked() {
                let f = self.draft.clone();
                self.draft = f;
                self.requery(true);
            }
            if tool(ui, ic::WAVEFORM, "Motion: dots along the connections that matter, the sheen on the hosts, pulses, glides", self.style.motion).clicked() {
                self.style.motion = !self.style.motion;
                self.persist();
            }
            if tool(ui, ic::HEXAGON, "Shapes by role: hexagon domain controller, square server, circle workstation, diamond external", self.style.shapes_by_role).clicked() {
                self.style.shapes_by_role = !self.style.shapes_by_role;
                self.persist();
            }
            if tool(ui, ic::TAG, "Style: mode, sizes, names, connections, canvas", self.show_labels).clicked() {
                self.show_labels = !self.show_labels;
            }
            if tool(ui, ic::WIFI_HIGH, "Subnet regions: hosts grouped by where they sit on the network", self.style.show_subnets).clicked() {
                self.style.show_subnets = !self.style.show_subnets;
                self.persist();
                self.compute_subnets();
                self.layout.reheat(0.5);
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
                if ui.add(egui::Button::new(egui::RichText::new(format!("{}  agentc00pr", ic::APP_WINDOW))).min_size(Vec2::new(0.0, 28.0))).on_hover_text("On to agentc00pr, the case workbench: the timelines open here go into a case of it, with the evidence they were read from").clicked() {
                    self.open_agentc00pr();
                }
                let hunt = egui::Button::new(theme::semibold(format!("{}  Hunt", ic::DETECTIVE), 13.5).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 28.0)).corner_radius(CornerRadius::same(7));
                if ui.add(hunt).on_hover_text("Run the statistical hunt on this timeline and watch the findings light up").clicked() {
                    self.show_hunt = true;
                }
                let ingest = egui::Button::new(egui::RichText::new(format!("{}  Ingest", ic::DOWNLOAD_SIMPLE))).min_size(Vec2::new(0.0, 28.0)).corner_radius(CornerRadius::same(7));
                if ui.add(ingest).on_hover_text("Evidence into a timeline: a folder, images, EVTX, logs, a triage package. Or drop it anywhere on the window.").clicked() {
                    self.ingest.open = true;
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
        // A selection, a path or a cone is on the canvas instead of what the
        // filters select: said by one chip, which goes back to the view. The
        // filters' own chips would say something the canvas is not showing.
        if let Some((title, missing)) = self.trail.as_ref().map(|t| (t.title.clone(), t.missing)) {
            // a path marked on the map: the filters still say what the map
            // is, so their chips follow this one
            let mut back = false;
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = Vec2::new(6.0, 4.0);
                ui.label(egui::RichText::new(format!("{}", ic::PATH)).color(theme::MAGENTA).size(13.0));
                if chip(ui, &format!("{} · marked on the map", title), theme::MAGENTA) {
                    back = true;
                }
                let note = if missing > 0 { format!("{} of its connections were outside the filters and are drawn with it. The chip takes the mark away", missing) } else { "the map is as the filters draw it; the path stands out. The chip takes the mark away".to_string() };
                ui.label(egui::RichText::new(note).color(theme::DIM).size(12.0));
            });
            if back {
                self.trail = None;
                self.requery(false);
            }
        }
        if let Some(title) = self.overlay.as_ref().map(|o| o.title.clone()) {
            let mut back = false;
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = Vec2::new(6.0, 4.0);
                ui.label(egui::RichText::new(format!("{}", ic::CROSSHAIR)).color(theme::DIM).size(13.0));
                if chip(ui, &title, theme::ACCENT) {
                    back = true;
                }
                ui.label(egui::RichText::new("only this is drawn: the filters are not applied to it. The chip goes back to the view").color(theme::DIM).size(12.0));
            });
            if back {
                self.overlay = None;
                self.requery(false);
            }
            return true;
        }
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
        if f.grouping != Grouping::PerAccount {
            chips.push((match f.grouping { Grouping::PerPair => "grouped by hosts", _ => "ungrouped: one edge per event" }.to_string(), Color32::from_rgb(160, 170, 190), Box::new(|d: &mut Filter| d.grouping = Grouping::PerAccount)));
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

            theme::section_help(ui, "View", "What the canvas draws. Findings: only the connections the hunt marked significant or candidate (run Hunt first). Everything: every connection the filters below let through. Neighbourhood: one host and what it talks to, as far as the hops say.");
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

            theme::section_help(ui, "Search", "Narrow the picture by name. Hosts and accounts: a text is «contains»; * is a wildcard, ! in front leaves it out, a comma separates several (srv*, !dc01). Logon type: 3 network, 10 RDP, SSH… as the timeline writes them.");
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

            theme::section_help(ui, "Time window", "Only the rows between these two moments, in the timeline's time (UTC). Type a date (2026-11-03 or 2026-11-03 14:30), use the calendars, or drag the handles of the strip at the bottom: they are the same window.");
            let w = self.time_window_fields(ui, "pane");
            changed |= w.changed;
            apply |= w.commit;
            ui.label(egui::RichText::new("To the second, the timeline's time (UTC). The strip's handles follow.").small().color(theme::DIM));

            theme::section_help(ui, "Hunt", "What the hunt said of each connection. The score (0 to 100) is how unusual it is; the slider keeps the ones at or above it. The pills keep or leave out each state: significant (the hunt would bet on it), candidate (worth a look), habitual and baseline (what this network normally does), not hunted (before the hunt's start or never judged).");
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("score ≥").color(theme::MUTED));
                ui.spacing_mut().slider_width = (ui.available_width() - 48.0).max(80.0);
                changed |= ui.add(egui::Slider::new(&mut self.draft.min_score, 0..=100).show_value(true)).on_hover_text("hunt_score: how rare a connection is among the connections of normal days, 0 to 100; 13 is one in twenty, 20 one in a hundred, 30 one in a thousand, 40 one in ten thousand").changed();
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

            theme::section_help(ui, "Result", "What happened in the event: a logon that succeeded, one that failed, a logoff, or a connection with no logon in it. Each is a colour in the graph.");
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = Vec2::new(4.0, 4.0);
                for (i, name) in RESULT_NAMES.iter().enumerate() {
                    if pill(ui, self.draft.results[i], name, result_color(i as u8)).clicked() {
                        self.draft.results[i] = !self.draft.results[i];
                        changed = true;
                    }
                }
            });

            theme::section_help(ui, "Verdict", "Your own marks: the connections you marked as malicious, suspicious or legitimate (right click on a connection, Mark…). Keep only the ones with the marks ticked.");
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

            theme::section_help(ui, "Grouping", "How rows become lines. Grouped by hosts: one line between two hosts, whoever logged on. By connection: one line per account between two hosts, which is what the hunt judges. Ungrouped: one line per row, for a short window or an exact selection.");
            for (g, label, tip) in [
                (Grouping::PerPair, "Grouped by hosts", "one edge per origin, destination and result: every account between two hosts in it. Its rows are all the events of all of them"),
                (Grouping::PerAccount, "By connection", "one edge per origin, destination, account and result: the connection the hunt judges. Every pair alike, however many accounts it has"),
                (Grouping::PerEvent, "Ungrouped", "one edge per event: every row is its own curve, with its time; for a tight window or a selection"),
            ] {
                if ui.add(egui::RadioButton::new(self.draft.grouping == g, label)).on_hover_text(tip).clicked() {
                    self.draft.grouping = g;
                    changed = true;
                }
            }

            theme::section_help(ui, "Limit", "The most connections drawn at once. Above it the most pressing are kept (findings first) and a banner says so: narrow the filters or raise it. A very large number makes the canvas slow.");
            ui.horizontal(|ui| {
                changed |= ui.add(egui::DragValue::new(&mut self.draft.limit).range(10..=200_000).speed(10)).changed();
                ui.label(egui::RichText::new("connections drawn, the most pressing first").small().color(theme::DIM));
            });

            theme::section_help(ui, "Saved filters", "The filters as they are now, kept under a name to come back to with one click (for instance «RDP at night»). They are saved with the timeline.");
            let mut pick: Option<SavedView> = None;
            let mut delete: Option<String> = None;
            if self.saved.is_empty() {
                ui.label(egui::RichText::new("Yours will be here: Save the current filter… below.").color(theme::DIM).small());
            }
            for v in self.saved.clone() {
                let sel = self.preset == v.name;
                let summary = describe_filter(&v.filter);
                let r = theme::card(ui, sel, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(ic::BOOKMARK_SIMPLE).color(theme::CYAN).size(14.0));
                        ui.vertical(|ui| {
                            ui.label(theme::medium(&v.name, 13.0));
                            ui.label(egui::RichText::new(&summary).color(theme::MUTED).size(11.5));
                            if !v.places.is_empty() {
                                ui.label(egui::RichText::new(format!("{}  {} hosts in their places", ic::PUSH_PIN, v.places.len())).color(theme::DIM).size(11.0))
                                    .on_hover_text("This filter keeps where the hosts were on the canvas; picking it puts them back there.");
                            }
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(egui::Button::new(egui::RichText::new(ic::TRASH).color(theme::DIM)).frame(false)).on_hover_text("Delete this saved filter…").clicked() {
                                delete = Some(v.name.clone());
                            }
                        });
                    });
                });
                if r.clicked() {
                    pick = Some(v.clone());
                }
            }
            egui::CollapsingHeader::new(egui::RichText::new(format!("Built in ({})", self.builtin.len())).color(theme::MUTED)).default_open(self.saved.is_empty()).show(ui, |ui| {
                for v in self.builtin.clone() {
                    let sel = self.preset == v.name;
                    let summary = describe_filter(&v.filter);
                    let icon = builtin_icon(&v.name);
                    let r = theme::card(ui, sel, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(icon).color(theme::VIOLET).size(14.0));
                            ui.vertical(|ui| {
                                ui.label(theme::medium(&v.name, 13.0));
                                ui.label(egui::RichText::new(&summary).color(theme::MUTED).size(11.5));
                            });
                        });
                    });
                    if r.clicked() {
                        pick = Some(v);
                    }
                }
            });
            if let Some(v) = pick {
                self.preset = v.name.clone();
                self.draft = v.filter.clone();
                if self.saved.iter().any(|x| x.name == v.name) {
                    self.style = v.style.clone();
                    if !v.places.is_empty() {
                        self.restore_places = Some(v.places.clone());
                    }
                    self.persist();
                }
                apply = true;
            }
            if let Some(name) = delete {
                self.confirm_delete = Some(name);
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
                    theme::hint(ui, "Click a host or a connection to inspect it. Right-click for what you can do with it. Drag a host to move it (it stays pinned where you drop it), drag the background to pan, scroll to zoom, double-click a host to open its neighbourhood.");
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
        theme::section_help(ui, "In this view", "What is on the canvas now: how many hosts, connections and rows, and how many of each state of the hunt. Click a host or a connection to see it here instead.");
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
                        ui.label(egui::RichText::new(n.when.get(..16).unwrap_or(&n.when)).color(theme::DIM).small());
                    });
                });
                ui.label(egui::RichText::new(&n.text).size(12.5));
            });
        }
        if let Some(i) = delete {
            self.notes.notes.remove(i);
            if let Err(e) = self.save_notes() {
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
                    self.start_replay();
                }
            }
            let clock = [(60.0, "1 min/s"), (600.0, "10 min/s"), (3600.0, "1 h/s"), (6.0 * 3600.0, "6 h/s"), (24.0 * 3600.0, "1 day/s"), (7.0 * 24.0 * 3600.0, "1 week/s")];
            let current = match self.rate_secs {
                None => if (self.rate - self.rate.round()).abs() < 0.05 { format!("{} rows/s", self.rate.round() as u32) } else { format!("{:.1} rows/s", self.rate) },
                Some(s) => clock.iter().find(|(v, _)| (*v - s).abs() < 0.5).map(|(_, l)| l.to_string()).unwrap_or_else(|| crate::view::present::clock_label(s)),
            };
            let r = egui::ComboBox::from_id_salt("rate").selected_text(current).width(104.0).show_ui(ui, |ui| {
                ui.label(egui::RichText::new("By rows: so many rows of the view a second, whatever their times").small().color(theme::DIM));
                for r in [1.0, 4.0, 15.0, 60.0, 250.0] {
                    if ui.selectable_label(self.rate_secs.is_none() && self.rate == r, format!("{} rows/s", r as u32)).clicked() {
                        self.rate = r;
                        if self.rate_secs.take().is_some() && self.playing {
                            self.acc = 0.0;
                        }
                    }
                }
                ui.horizontal(|ui| {
                    let mut v = self.rate;
                    if ui.add(egui::DragValue::new(&mut v).range(0.1..=100_000.0).speed(0.5).max_decimals(1).suffix(" rows/s")).on_hover_text("Your own: type a number or drag").changed() {
                        self.rate = v;
                        if self.rate_secs.take().is_some() && self.playing {
                            self.acc = 0.0;
                        }
                    }
                    ui.label(egui::RichText::new("your own").small().color(theme::DIM));
                });
                ui.separator();
                ui.label(egui::RichText::new("By the clock: so much of the timeline a second; a quiet hour takes as long as a busy one").small().color(theme::DIM));
                let mut pick_clock: Option<f32> = None;
                for (v, l) in clock {
                    if ui.selectable_label(self.rate_secs.map_or(false, |s| (s - v).abs() < 0.5), l).clicked() {
                        pick_clock = Some(v);
                    }
                }
                ui.horizontal(|ui| {
                    let mut mins = self.rate_secs.unwrap_or(3600.0) / 60.0;
                    if ui.add(egui::DragValue::new(&mut mins).range(0.01..=10_000_000.0).speed(1.0).max_decimals(1).suffix(" min/s")).on_hover_text("Your own: minutes of the timeline a second; type a number or drag").changed() {
                        pick_clock = Some(mins * 60.0);
                    }
                    ui.label(egui::RichText::new("your own").small().color(theme::DIM));
                });
                if let Some(v) = pick_clock {
                    let was_rows = self.rate_secs.is_none();
                    self.rate_secs = Some(v);
                    if self.playing && was_rows {
                        // the clock picks up where the head is
                        let k = self.cursor.saturating_sub(1);
                        self.replay_t = self.graph.events.get(k).map(|&ei| self.store.edges[ei as usize].t as f64).unwrap_or(0.0);
                    }
                }
            });
            r.response.on_hover_text("How fast the replay advances: by rows of the view, or by the timeline's clock.");
            let anim = [(0.0, "instant"), (0.3, "0.3 s"), (0.6, "0.6 s"), (1.0, "1 s"), (1.5, "1.5 s"), (2.5, "2.5 s"), (4.0, "4 s")];
            let cur_anim = anim.iter().find(|(v, _)| (*v - self.replay_anim).abs() < 0.01).map(|(_, l)| l.to_string()).unwrap_or_else(|| format!("{:.1} s", self.replay_anim));
            let r = egui::ComboBox::from_id_salt("replay-anim").selected_text(format!("draw {}", cur_anim)).width(92.0).show_ui(ui, |ui| {
                ui.label(egui::RichText::new("How long a connection takes to draw itself from origin to destination when the replay reaches it").small().color(theme::DIM));
                for (v, l) in anim {
                    if ui.selectable_label((self.replay_anim - v).abs() < 0.01, l).clicked() {
                        self.replay_anim = v;
                    }
                }
            });
            r.response.on_hover_text("The drawing of each connection in the replay: instant, or a line that grows from the origin to the destination over so many seconds, the host popping in when it arrives.");
            if tool(ui, "\u{E108}", "Time window: From and To to the second, on a calendar", self.show_when).clicked() {
                self.show_when = !self.show_when;
            }
            let w = (ui.available_width() - 570.0).max(160.0);
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
        let under = resp.hover_pos().map(|p| pick_brush(p.x, xf, xt));
        for (x, which) in [(xf, Brush::From), (xt, Brush::To)] {
            let r = handle(x);
            let hot = self.brush == Some(which) || (self.brush.is_none() && under == Some(which));
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
            // where the button went down: by now the pointer has moved on
            let now = resp.interact_pointer_pos();
            if let Some(p) = ui.input(|i| i.pointer.press_origin()).or(now) {
                self.brush = Some(pick_brush_dragging(p.x, now.map_or(p.x, |n| n.x), xf, xt));
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
                let near = pick_brush(p.x, xf, xt) != Brush::Scrub;
                ui.ctx().set_cursor_icon(if near { egui::CursorIcon::ResizeHorizontal } else { egui::CursorIcon::Crosshair });
            } else if matches!(self.brush, Some(Brush::From) | Some(Brush::To)) {
                ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
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
                if icon_button(ui, ic::TABLE, "Show its rows in the timeline").on_hover_text("Timeline mode, on the rows of the CSV behind every connection of this host that the graph shows").clicked() {
                    ui.close();
                    self.timeline_of_node(i);
                }
                if icon_button(ui, ic::CIRCLES_THREE_PLUS, "Expand around").on_hover_text("Add to the canvas the hosts this one talks to, and their connections, keeping what is there").clicked() {
                    ui.close();
                    self.draft.view = View::Around;
                    self.draft.around = name.clone();
                    self.requery(false);
                }
                if icon_button(ui, ic::TARGET, "Only this host").on_hover_text("Reduce the canvas to this host and what it talks to directly (its neighbourhood)").clicked() {
                    ui.close();
                    self.draft.view = View::All;
                    self.draft.host = name.clone();
                    self.requery(false);
                }
                if icon_button(ui, ic::ARROW_RIGHT, "Paths from here").on_hover_text("Open Paths with this host as the origin: where could someone go from it?").clicked() {
                    ui.close();
                    self.path_origin = name.clone();
                    self.show_paths = true;
                }
                if icon_button(ui, ic::ARROW_LEFT, "Paths to here").on_hover_text("Open Paths with this host as the destination: how could someone have got here?").clicked() {
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
                    if icon_button(ui, ic::ARROWS_CLOCKWISE, &format!("Merge with {}…", sel)).on_hover_text("This host and the selected one are the same machine; you choose the name that stays").clicked() {
                        ui.close();
                        self.merge_edit = Some(MergeHostsEdit { a: name.clone(), b: sel, keep_a: true, filter: String::new() });
                    }
                }
                if icon_button(ui, ic::ARROWS_CLOCKWISE, "Merge with another host…").on_hover_text("This host is the same machine as another one (an address and its name): make them one, and choose the name that stays").clicked() {
                    ui.close();
                    self.merge_edit = Some(MergeHostsEdit { a: name.clone(), b: String::new(), keep_a: true, filter: String::new() });
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
                if icon_button(ui, ic::EYE_SLASH, "Hide this host").on_hover_text("Take this host and its connections off the canvas. View › Style › hidden hosts brings it back").clicked() {
                    ui.close();
                    self.style.rules.push(Rule { enabled: true, field: Field::Host, pattern: format!("={}", name), color: None, hide: true, ..Rule::default() });
                    self.persist();
                }
                ui.separator();
                if icon_button(ui, ic::NOTE_PENCIL, "Add a note…").on_hover_text("Write a note about this: it stays with the timeline, shows in the Notes tab and marks the thing on the canvas").clicked() {
                    ui.close();
                    self.note_draft = Some((NoteTarget::Host(name.clone()), String::new()));
                }
                if icon_button(ui, ic::LINK, "Copy the name").on_hover_text("The host's name to the clipboard").clicked() {
                    ui.close();
                    ui.ctx().copy_text(name.clone());
                }
                theme::menu_help(ui, "A host: a machine by its name, or an address when no name is known. Its size is how much goes through it; a red ring is a host the hunt found significant. Double click opens its neighbourhood; drag moves and pins it.");
            }
            Some(Sel::Edge(k)) => {
                let e = &self.graph.edges[k];
                let title = format!("{} -> {}", self.store.hosts.name(e.src), self.store.hosts.name(e.dst));
                let users: Vec<u32> = e.users.clone();
                let (src, dst) = (e.src, e.dst);
                let n_rows = e.rows.len();
                ui.label(theme::semibold(&title, 13.5));
                ui.label(egui::RichText::new(match e.user {
                    Some(u) => format!("as {} · {} event(s)", self.store.users.name(u), e.count),
                    None => format!("{} accounts · {} event(s)", e.users.len(), e.count),
                }).color(theme::MUTED).small());
                ui.separator();
                if icon_button(ui, ic::TARGET, "Open in the inspector").on_hover_text("Select it: the panel on the right shows its details and its rows").clicked() {
                    ui.close();
                    self.selected = Some(Sel::Edge(k));
                    self.tab = Tab::Selection;
                    self.show_inspector = true;
                    self.load_rows(k);
                }
                if icon_button(ui, ic::TABLE, &format!("Show its {} row(s) in the timeline", n_rows)).on_hover_text("Timeline mode, on the rows of the CSV this connection is drawn from").clicked() {
                    ui.close();
                    self.timeline_of_edge(k);
                }
                if icon_button(ui, ic::APP_WINDOW, &format!("Show its {} event(s) in agentc00pr", n_rows)).on_hover_text("agentc00pr's viewer on the case this timeline is in, showing only the events of this connection (every account of a grouped one). A timeline that is in no case yet is taken to one first").clicked() {
                    ui.close();
                    let (label, rows) = (self.graph_edge_label(k), self.rows_of_graph_edge(k));
                    self.rows_to_agentc00pr(&rows, &label);
                }
                ui.separator();
                for v in 1..4u8 {
                    let c = verdict_color(v).unwrap();
                    if ui.add(egui::Button::new(egui::RichText::new(format!("{}  Mark {}", ic::FLAG, VERDICT_NAMES[v as usize])).color(c)).min_size(Vec2::new(0.0, 26.0))).clicked() {
                        ui.close();
                        self.begin_mark(k, v);
                    }
                }
                if icon_button(ui, ic::NOTE_PENCIL, "Add a note…").on_hover_text("Write a note about this: it stays with the timeline, shows in the Notes tab and marks the thing on the canvas").clicked() {
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
                theme::menu_help(ui, "A connection: logons from the host it leaves to the host its arrow points at. Its colour is the result (or the hunt's state), its width how many times. The inspector on the right shows its rows; from there or from here they open in the Timeline or agentc00pr.");
            }
            None => {
                if icon_button(ui, ic::CORNERS_OUT, "Fill the window").on_hover_text("Zoom and centre so every host on the canvas is in sight").clicked() {
                    ui.close();
                    self.layout.stop();
                    self.fill_pending = true;
                }
                if icon_button(ui, ic::SHUFFLE, "Lay out again").on_hover_text("Place the hosts again from scratch (pinned ones stay where they are): for when the picture got tangled").clicked() {
                    ui.close();
                    let f = self.draft.clone();
                    self.draft = f;
                    self.requery(true);
                }
                let pinned = self.layout.fixed.iter().filter(|&&f| f).count();
                if pinned > 0 && icon_button(ui, ic::PUSH_PIN, &format!("Unpin all ({})", pinned)).on_hover_text("The pinned hosts go back to the forces").clicked() {
                    ui.close();
                    self.layout.fixed.iter_mut().for_each(|f| *f = false);
                    self.layout.reheat(0.3);
                }
                ui.separator();
                if icon_button(ui, ic::FIRE, "Findings").on_hover_text("Draw only the connections the hunt marked significant or candidate").clicked() {
                    ui.close();
                    self.draft.view = View::Findings;
                    self.requery(false);
                }
                if icon_button(ui, ic::GRAPH, "Everything").on_hover_text("Draw every connection the filters let through, not only the hunt's findings").clicked() {
                    ui.close();
                    self.draft.view = View::All;
                    self.requery(false);
                }
                if (self.overlay.is_some() || self.trail.is_some()) && icon_button(ui, ic::ARROW_LEFT, "Back to the view").on_hover_text("Leave the path, the cone or the selection and draw again what the filters select").clicked() {
                    ui.close();
                    self.trail = None;
                    self.overlay = None;
                    self.requery(false);
                }
                ui.separator();
                if icon_button(ui, ic::X, "Clear the selection").on_hover_text("Nothing selected: the inspector goes back to the summary of the view").clicked() {
                    ui.close();
                    self.selected = None;
                }
                if icon_button(ui, ic::NOTE_PENCIL, "Add a note to the case…").on_hover_text("A note about the case as a whole, kept with the timeline and shown in the Notes tab").clicked() {
                    ui.close();
                    self.note_draft = Some((NoteTarget::Free, String::new()));
                }
                theme::menu_help(ui, "The canvas: every host of the view and the connections between them. Scroll to zoom, drag the background to move, right click a host or a line for its own actions. The filters on the left decide what is drawn.");
            }
        }
    }

    /// The banner over the canvas when the limit cut the picture.
    pub(super) fn limit_banner(&mut self, ctx: &egui::Context, canvas: Rect) {
        if !self.graph.truncated {
            return;
        }
        let drawn = self.graph.edges.len();
        let total = self.graph.connections;
        egui::Area::new(egui::Id::unique("limit-banner")).fixed_pos(Pos2::new(canvas.center().x - 260.0, canvas.top() + 66.0)).order(egui::Order::Middle).show(ctx, |ui| {
            egui::Frame::new().fill(draw::fade(Color32::from_rgb(58, 34, 10), 0.96)).stroke(Stroke::new(1.0, draw::fade(CANDIDATE, 0.9))).corner_radius(CornerRadius::same(10)).inner_margin(egui::Margin::symmetric(12, 8)).show(ui, |ui| {
                ui.set_width(520.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(ic::WARNING).color(CANDIDATE).size(18.0));
                    ui.vertical(|ui| {
                        ui.label(theme::medium(format!("Only {} of {} connections are drawn", drawn, total), 13.0).color(TEXT));
                        ui.label(egui::RichText::new(format!("The limit is {}. The most pressing come first: significant, then candidate, then by number of events. Raise it, or narrow the filters.", self.filter.limit)).color(theme::MUTED).size(11.5));
                        ui.horizontal(|ui| {
                            if ui.add(egui::Button::new(egui::RichText::new(format!("Draw all {}", total)).color(theme::ACCENT_INK)).fill(CANDIDATE).stroke(Stroke::NONE)).on_hover_text("Could be slow with tens of thousands").clicked() {
                                self.draft.limit = total.max(10);
                                self.requery(false);
                            }
                            if ui.button("Filters").on_hover_text("Show or hide the filters pane on the left").clicked() {
                                self.show_filters = true;
                            }
                        });
                    });
                });
            });
        });
    }

    /// The legend chips over the canvas as real widgets: counts per
    /// category, and when coloured by account a click picks its colour.
    pub(super) fn legend_overlay(&mut self, ctx: &egui::Context, canvas: Rect) {
        let n_ip = self.scene.n_ip;
        // (the scene's count is of the frame before: after a query that leaves
        // fewer hosts than it had addresses, it is the larger of the two)
        let n_host = self.graph.nodes.len().saturating_sub(n_ip);
        let chips: Vec<(String, Color32, usize)> = self.scene.chips.clone();
        let by_user = self.style.color_by == ColorBy::User;
        let area = egui::Area::new(egui::Id::unique("legend-overlay")).fixed_pos(canvas.min + Vec2::new(10.0, 10.0)).order(egui::Order::Middle).show(ctx, |ui| {
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
        self.legend_h = area.response.rect.height() + 10.0;
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
                if ui.button("Back to the palette colour").on_hover_text("Forget the colour chosen here: it takes the one of the palette again").clicked() {
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
        self.open_files(files);
    }

}

/// One line that says what a filter keeps, for the cards.
fn describe_filter(f: &Filter) -> String {
    let mut parts: Vec<String> = Vec::new();
    match f.view {
        View::Findings => parts.push("findings only".into()),
        View::Around => parts.push(format!("around {}", f.around)),
        View::All => {}
    }
    if !f.host.trim().is_empty() {
        parts.push(format!("host {}", f.host.trim()));
    }
    if !f.user.trim().is_empty() {
        parts.push(format!("account {}", f.user.trim()));
    }
    if !f.logon_type.trim().is_empty() {
        parts.push(format!("logon type {}", f.logon_type.trim()));
    }
    if f.min_score > 0 {
        parts.push(format!("score ≥ {}", f.min_score));
    }
    if f.results != [true, true, true, true] {
        let on: Vec<&str> = RESULT_NAMES.iter().enumerate().filter(|(i, _)| f.results[*i]).map(|(_, n)| *n).collect();
        parts.push(on.join(" + "));
    }
    if f.verdict.iter().any(|v| !v) {
        let on: Vec<&str> = VERDICT_NAMES.iter().enumerate().filter(|(i, _)| f.verdict[*i]).map(|(_, n)| if n.is_empty() { "unmarked" } else { *n }).collect();
        parts.push(format!("verdict {}", on.join(" + ")));
    }
    if !f.from.trim().is_empty() || !f.to.trim().is_empty() {
        parts.push(format!("{} → {}", if f.from.trim().is_empty() { "start" } else { &f.from[..f.from.len().min(16)] }, if f.to.trim().is_empty() { "end" } else { &f.to[..f.to.len().min(16)] }));
    }
    if parts.is_empty() {
        "everything".into()
    } else {
        parts.join(" · ")
    }
}

fn builtin_icon(name: &str) -> &'static str {
    let n = name.to_ascii_lowercase();
    if n.starts_with("findings") {
        ic::FIRE
    } else if n.starts_with("everything") {
        ic::GRAPH
    } else if n.starts_with("rdp") {
        ic::MONITOR
    } else if n.starts_with("network") {
        ic::PLUGS_CONNECTED
    } else if n.starts_with("ssh") {
        ic::TERMINAL_WINDOW
    } else if n.starts_with("admin") {
        ic::KEY
    } else if n.starts_with("service") {
        ic::ROBOT
    } else if n.starts_with("without") {
        ic::EYE_SLASH
    } else if n.starts_with("failures") {
        ic::SIREN
    } else if n.starts_with("marked") {
        ic::FLAG
    } else if n.starts_with("last") {
        ic::CLOCK
    } else {
        ic::DOT_OUTLINE
    }
}

impl Viewer {
    /// The trash on a saved filter asks before anything goes.
    pub(super) fn confirm_delete_window(&mut self, ctx: &egui::Context) {
        let Some(name) = self.confirm_delete.clone() else { return };
        let mut open = true;
        let mut done = false;
        egui::Window::new(format!("{}  Delete this saved filter?", ic::TRASH))
            .id(egui::Id::new("confirm-delete-view"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(400.0)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
                let (summary, places) = self.saved.iter().find(|v| v.name == name).map(|v| (describe_filter(&v.filter), v.places.len())).unwrap_or_default();
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(ic::BOOKMARK_SIMPLE).color(theme::CYAN).size(15.0));
                    ui.label(theme::medium(&name, 14.0));
                });
                ui.label(egui::RichText::new(summary).color(theme::MUTED).size(12.0));
                if places > 0 {
                    ui.label(egui::RichText::new(format!("{}  and the arrangement of {} hosts", ic::PUSH_PIN, places)).color(theme::MUTED).size(12.0));
                }
                ui.add_space(4.0);
                ui.label(egui::RichText::new("It is removed from the views file next to the timeline. The filter in use stays as it is, and the built-in filters are not touched.").color(theme::DIM).size(11.5));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(theme::semibold("Delete", 13.0).color(TEXT)).fill(Color32::from_rgb(140, 40, 56)).stroke(Stroke::NONE).min_size(Vec2::new(90.0, 30.0))).clicked() {
                        self.saved.retain(|x| x.name != name);
                        if self.preset == name {
                            self.preset.clear();
                        }
                        self.persist();
                        self.status = format!("Saved filter \"{}\" deleted.", name);
                        done = true;
                    }
                    if ui.add(egui::Button::new("Keep it").min_size(Vec2::new(90.0, 30.0))).clicked() {
                        done = true;
                    }
                });
            });
        if done || !open {
            self.confirm_delete = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A press near a handle of the time strip takes that handle, judged at
    /// the press: egui calls it a drag only once the pointer is 6 points
    /// away, and that point alone missed a handle pressed a little off it.
    #[test]
    fn a_press_near_a_handle_takes_it() {
        let (from_x, to_x) = (100.0, 300.0);
        assert_eq!(pick_brush(100.0, from_x, to_x), Brush::From);
        assert_eq!(pick_brush(100.0 + HANDLE_GRAB, from_x, to_x), Brush::From);
        assert_eq!(pick_brush(100.0 - HANDLE_GRAB, from_x, to_x), Brush::From);
        assert_eq!(pick_brush(297.0, from_x, to_x), Brush::To);
        assert_eq!(pick_brush(310.0, from_x, to_x), Brush::To);
        assert_eq!(pick_brush(200.0, from_x, to_x), Brush::Scrub, "between the handles: the replay head");
        assert_eq!(pick_brush(100.0 + HANDLE_GRAB + 0.5, from_x, to_x), Brush::Scrub);
        // a press 3 points off the handle that becomes a drag 6 points further on:
        // judged where the pointer then is (9 points), the old 7-point reach missed it
        let pressed = 103.0;
        assert_eq!(pick_brush(pressed, from_x, to_x), Brush::From);
    }

    /// Handles close together: the nearer one, From when both are as near.
    #[test]
    fn handles_close_together_give_the_nearer() {
        assert_eq!(pick_brush(104.0, 100.0, 106.0), Brush::To);
        assert_eq!(pick_brush(102.0, 100.0, 106.0), Brush::From);
        assert_eq!(pick_brush(103.0, 100.0, 106.0), Brush::From, "as near: From");
        // both at the same place (a window of one second): From, on a press alone
        assert_eq!(pick_brush(100.0, 100.0, 100.0), Brush::From);
    }

    /// A narrow window can always be widened: with both handles in reach of
    /// the press, dragging right takes To and left takes From.
    #[test]
    fn a_narrow_window_widens_either_way() {
        assert_eq!(pick_brush_dragging(100.0, 112.0, 100.0, 100.0), Brush::To);
        assert_eq!(pick_brush_dragging(100.0, 88.0, 100.0, 100.0), Brush::From);
        assert_eq!(pick_brush_dragging(103.0, 115.0, 100.0, 106.0), Brush::To);
        assert_eq!(pick_brush_dragging(103.0, 90.0, 100.0, 106.0), Brush::From);
        // handles apart: the one pressed, whatever the direction
        assert_eq!(pick_brush_dragging(100.0, 140.0, 100.0, 300.0), Brush::From);
        assert_eq!(pick_brush_dragging(300.0, 250.0, 100.0, 300.0), Brush::To);
        assert_eq!(pick_brush_dragging(200.0, 230.0, 100.0, 300.0), Brush::Scrub);
    }
}
