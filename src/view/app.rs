//! The window: filter bar on top, the graph in the middle, a details pane
//! on the right, the replay bar at the bottom.
//!
//! The graph is drawn as Neo4j Browser draws one: a host is a filled
//! circle with a darker ring and its name inside, an edge a thin line (a
//! curve when the pair has several) with an arrowhead at the destination
//! and the account written on it; hovering lights up a host and what
//! touches it, selecting opens it in the pane. The force layout runs while
//! warm and the analyst can drag any host.

use std::collections::{HashMap, HashSet};

use egui::{Align2, Color32, CornerRadius, FontId, Pos2, Rect, Sense, Stroke, Vec2};

use super::layout::{Layout, V2};
use super::query::{fmt_time, hunt_rank, Filter, GraphView, View};
use super::store::{Store, HUNT_NAMES, RESULT_NAMES, R_CONNECT, R_FAIL, R_LOGOFF, R_OK, VERDICT_NAMES};
use super::Options;

// ───────────────────────────── palette ──────────────────────────────────────
// Neo4j Browser's node colours, on a dark canvas.

const BG: Color32 = Color32::from_rgb(24, 26, 31);
const PANEL: Color32 = Color32::from_rgb(31, 34, 41);
const BORDER: Color32 = Color32::from_rgb(52, 56, 66);
const TEXT: Color32 = Color32::from_rgb(230, 232, 238);
const MUTED: Color32 = Color32::from_rgb(150, 157, 172);
const ACCENT: Color32 = Color32::from_rgb(255, 196, 84);
const HOST_FILL: Color32 = Color32::from_rgb(87, 199, 227);
const HOST_RING: Color32 = Color32::from_rgb(35, 179, 213);
const IP_FILL: Color32 = Color32::from_rgb(255, 196, 84);
const IP_RING: Color32 = Color32::from_rgb(214, 161, 54);
const SIGNIFICANT: Color32 = Color32::from_rgb(241, 102, 103);
const CANDIDATE: Color32 = Color32::from_rgb(247, 151, 103);
const SUSPICIOUS: Color32 = Color32::from_rgb(255, 99, 132);
const CONFIRMED: Color32 = Color32::from_rgb(201, 144, 192);
const BENIGN: Color32 = Color32::from_rgb(141, 204, 147);
const EDGE_OK: Color32 = Color32::from_rgb(165, 171, 182);
const EDGE_FAIL: Color32 = Color32::from_rgb(241, 102, 103);
const EDGE_CONNECT: Color32 = Color32::from_rgb(201, 144, 192);
const EDGE_LOGOFF: Color32 = Color32::from_rgb(110, 116, 128);
const CAPTION_BG: Color32 = Color32::from_rgba_premultiplied(24, 26, 31, 200);

fn result_color(r: u8) -> Color32 {
    match r {
        R_OK => EDGE_OK,
        R_FAIL => EDGE_FAIL,
        R_CONNECT => EDGE_CONNECT,
        R_LOGOFF => EDGE_LOGOFF,
        _ => EDGE_OK,
    }
}

fn hunt_color(h: u8) -> Option<Color32> {
    match h {
        super::store::H_SIGNIFICANT => Some(SIGNIFICANT),
        super::store::H_CANDIDATE => Some(CANDIDATE),
        _ => None,
    }
}

fn verdict_color(v: u8) -> Option<Color32> {
    match v {
        1 => Some(SUSPICIOUS),
        2 => Some(CONFIRMED),
        3 => Some(BENIGN),
        _ => None,
    }
}

fn dim(c: Color32, k: f32) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), (c.a() as f32 * k) as u8)
}

// ───────────────────────────── state ────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sel {
    Node(usize),
    Edge(usize),
}

struct RowDetail {
    file: u16,
    line: u32,
    t: String,
    fields: Vec<String>,
    hunt: u8,
    verdict: u8,
    notes: String,
}

pub struct Viewer {
    store: Store,
    files: Vec<String>,
    alpha: f64,
    /// what is being edited in the bar
    draft: Filter,
    /// what the graph shows
    filter: Filter,
    graph: GraphView,
    layout: Layout,
    /// last known position of every host, so a new query keeps the picture
    remembered: HashMap<u32, V2>,
    cam: V2,
    zoom: f32,
    fit_pending: bool,
    selected: Option<Sel>,
    hovered: Option<Sel>,
    dragging: Option<usize>,
    rows: Option<(usize, Vec<RowDetail>, usize)>,
    notes_draft: String,
    pending_verdict: Option<u8>,
    mark_msg: String,
    status: String,
    // replay
    cursor: usize,
    playing: bool,
    rate: f32,
    acc: f32,
    show_edge_captions: bool,
    last_frame: std::time::Instant,
}

impl Viewer {
    pub fn new(cc: &eframe::CreationContext<'_>, store: Store, opts: Options) -> Viewer {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = PANEL;
        visuals.window_fill = PANEL;
        visuals.extreme_bg_color = BG;
        visuals.faint_bg_color = Color32::from_rgb(38, 41, 49);
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(42, 46, 55);
        visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(42, 46, 55);
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(56, 61, 72);
        visuals.widgets.active.bg_fill = Color32::from_rgb(70, 76, 90);
        visuals.selection.bg_fill = Color32::from_rgb(70, 60, 30);
        visuals.selection.stroke = Stroke::new(1.0, ACCENT);
        visuals.override_text_color = Some(TEXT);
        cc.egui_ctx.set_visuals(visuals);
        cc.egui_ctx.all_styles_mut(|style| {
            style.spacing.item_spacing = Vec2::new(8.0, 6.0);
            style.spacing.button_padding = Vec2::new(8.0, 4.0);
        });

        let mut filter = Filter::default();
        if let Some(f) = &opts.focus {
            filter.view = View::Around;
            filter.around = f.clone();
        }
        if let Some(s) = &opts.start {
            filter.from = s.get(..19).unwrap_or(s).to_string();
        }
        if let Some(e) = &opts.end {
            filter.to = e.get(..19).unwrap_or(e).to_string();
        }
        let hunted = store.edges.iter().any(|e| e.hunt != 0);
        if !hunted && filter.view == View::Findings {
            filter.view = View::All;
        }
        if filter.view == View::All && store.edges.len() > 200_000 && filter.from.is_empty() {
            filter.from = fmt_time(store.t_max - 86_400);
        }
        let mut v = Viewer {
            store,
            files: opts.files,
            alpha: opts.alpha,
            draft: filter.clone(),
            filter,
            graph: GraphView::empty(),
            layout: Layout::new(Vec::new(), Vec::new(), &[]),
            remembered: HashMap::new(),
            cam: V2::default(),
            zoom: 1.0,
            fit_pending: true,
            selected: None,
            hovered: None,
            dragging: None,
            rows: None,
            notes_draft: String::new(),
            pending_verdict: None,
            mark_msg: String::new(),
            status: String::new(),
            cursor: 0,
            playing: false,
            rate: 4.0,
            acc: 0.0,
            show_edge_captions: true,
            last_frame: std::time::Instant::now(),
        };
        v.requery(true);
        v
    }

    // ───────────────────────── queries & layout ─────────────────────────

    fn requery(&mut self, fresh_layout: bool) {
        self.filter = self.draft.clone();
        if self.filter.view == View::Around && self.filter.around.trim().is_empty() {
            self.status = "Neighbourhood: name a host (or several) to expand around.".into();
            return;
        }
        for (i, n) in self.graph.nodes.iter().enumerate() {
            if let Some(p) = self.layout.pos.get(i) {
                self.remembered.insert(n.host, *p);
            }
        }
        self.graph = GraphView::build(&self.store, &self.filter);
        let g = &self.graph;
        let max_traffic = g.nodes.iter().map(|n| n.inn + n.out).max().unwrap_or(1).max(1) as f32;
        let radii: Vec<f32> = g.nodes.iter().map(|n| 20.0 + 10.0 * ((1 + n.inn + n.out) as f32).ln() / (1.0 + max_traffic).ln()).collect();
        let mut links: Vec<(usize, usize)> = g.edges.iter().map(|e| (g.node_of_host[&e.src], g.node_of_host[&e.dst])).filter(|(a, b)| a != b).collect();
        links.sort_unstable();
        links.dedup();
        let known: Vec<Option<V2>> = g.nodes.iter().map(|n| if fresh_layout { None } else { self.remembered.get(&n.host).copied() }).collect();
        self.layout = Layout::new(radii, links, &known);
        self.layout.link_distance = if g.nodes.len() > 300 { 120.0 } else { 170.0 };
        self.selected = None;
        self.hovered = None;
        self.rows = None;
        self.cursor = self.graph.events.len();
        self.playing = false;
        let mut parts = vec![
            format!("{} hosts", g.nodes.len()),
            format!("{} connections drawn of {}", g.edges.len(), g.connections),
            format!("{} rows", g.events.len()),
        ];
        if g.truncated {
            parts.push("limit reached: narrow the filters or raise the limit".into());
        }
        self.status = parts.join("  ·  ");
        self.fit_pending = true;
    }

    fn fit(&mut self, canvas: Rect) {
        if let Some((lo, hi)) = self.layout.bounds() {
            let w = (hi.x - lo.x).max(50.0) + 80.0;
            let h = (hi.y - lo.y).max(50.0) + 80.0;
            self.zoom = (canvas.width() / w).min(canvas.height() / h).clamp(0.05, 1.0);
            self.cam = V2::new((lo.x + hi.x) / 2.0, (lo.y + hi.y) / 2.0);
        }
    }

    fn to_screen(&self, canvas: Rect, p: V2) -> Pos2 {
        let c = canvas.center();
        Pos2::new(c.x + (p.x - self.cam.x) * self.zoom, c.y + (p.y - self.cam.y) * self.zoom)
    }

    fn to_world(&self, canvas: Rect, p: Pos2) -> V2 {
        let c = canvas.center();
        V2::new(self.cam.x + (p.x - c.x) / self.zoom, self.cam.y + (p.y - c.y) / self.zoom)
    }

    // ───────────────────────── replay ─────────────────────────

    fn edge_visible(&self, i: usize) -> bool {
        self.graph.edges[i].first_event < self.cursor
    }

    fn node_visible(&self, i: usize) -> bool {
        self.graph.nodes[i].first_event < self.cursor
    }

    // ───────────────────────── rows & marks ─────────────────────────

    fn load_rows(&mut self, edge: usize) {
        if matches!(&self.rows, Some((e, _, _)) if *e == edge) {
            return;
        }
        let g = &self.graph.edges[edge];
        let total = g.rows.len();
        let mut out = Vec::new();
        for &ei in g.rows.iter().take(300) {
            let e = &self.store.edges[ei as usize];
            let fields = self.store.row_fields(e.file, e.line).unwrap_or_default();
            out.push(RowDetail { file: e.file, line: e.line, t: fmt_time(e.t), fields, hunt: e.hunt, verdict: e.verdict, notes: self.store.notes.get(&(e.file, e.line)).cloned().unwrap_or_default() });
        }
        self.notes_draft = out.iter().find(|r| !r.notes.is_empty()).map(|r| r.notes.clone()).unwrap_or_default();
        self.pending_verdict = None;
        self.mark_msg.clear();
        self.rows = Some((edge, out, total));
    }

    fn save_mark(&mut self, edge: usize) {
        let verdict = self.pending_verdict.unwrap_or_else(|| self.graph.edges[edge].verdict());
        let rows: Vec<(u16, u32)> = self.graph.edges[edge].rows.iter().map(|&ei| (self.store.edges[ei as usize].file, self.store.edges[ei as usize].line)).collect();
        match self.store.mark(&rows, verdict, self.notes_draft.trim()) {
            Ok(n) => {
                self.mark_msg = format!("{} row(s) written to the timeline", n);
                let g = &mut self.graph.edges[edge];
                g.verdicts = [0; 4];
                g.verdicts[verdict as usize] = rows.len() as u32;
                self.rows = None;
                self.load_rows(edge);
            }
            Err(e) => self.mark_msg = format!("cannot write the timeline: {}", e),
        }
    }

    fn reload(&mut self) {
        match Store::load(&self.files, self.alpha) {
            Ok(s) => {
                self.store = s;
                self.requery(false);
                self.status = format!("Timeline read again: {}", self.status);
            }
            Err(e) => self.status = format!("Cannot read the timeline: {}", e),
        }
    }

    // ───────────────────────── UI: bars ─────────────────────────

    fn filter_bar(&mut self, ui: &mut egui::Ui) {
        let mut apply = false;
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new("masstin").strong().color(ACCENT).size(16.0));
            ui.label(egui::RichText::new(self.files.iter().map(|f| std::path::Path::new(f).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()).collect::<Vec<_>>().join(", ")).color(MUTED));
            ui.separator();
            ui.label(egui::RichText::new(format!("{} rows · {} edges · {} hosts · {} accounts · {} -> {}", self.store.rows_total, self.store.edges.len(), self.store.hosts.len(), self.store.users.len(), &fmt_time(self.store.t_min)[..10], &fmt_time(self.store.t_max)[..10])).color(MUTED).small());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Reload").on_hover_text("Read the timeline again from disk").clicked() {
                    self.reload();
                }
            });
        });
        ui.horizontal_wrapped(|ui| {
            let d = &mut self.draft;
            ui.label("View");
            egui::ComboBox::from_id_salt("view")
                .selected_text(match d.view {
                    View::Findings => "Findings",
                    View::Around => "Neighbourhood",
                    View::All => "Everything",
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut d.view, View::Findings, "Findings");
                    ui.selectable_value(&mut d.view, View::Around, "Neighbourhood");
                    ui.selectable_value(&mut d.view, View::All, "Everything");
                });
            if d.view == View::Around {
                ui.label("around");
                let r = ui.add(egui::TextEdit::singleline(&mut d.around).hint_text("SRV01, 10.0.0.*").desired_width(140.0));
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    apply = true;
                }
                ui.label("hops");
                ui.add(egui::DragValue::new(&mut d.hops).range(1..=4));
            }
            ui.label("Host");
            let r = ui.add(egui::TextEdit::singleline(&mut d.host).hint_text("contains, * wildcards, !not").desired_width(150.0));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                apply = true;
            }
            ui.label("User");
            let r = ui.add(egui::TextEdit::singleline(&mut d.user).hint_text("adm*, !*$").desired_width(120.0));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                apply = true;
            }
            ui.label("Logon type");
            let r = ui.add(egui::TextEdit::singleline(&mut d.logon_type).hint_text("10, 3, SSH").desired_width(80.0));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                apply = true;
            }
            ui.label("From");
            let r = ui.add(egui::TextEdit::singleline(&mut d.from).hint_text("YYYY-MM-DD HH:MM:SS").desired_width(140.0));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                apply = true;
            }
            ui.label("To");
            let r = ui.add(egui::TextEdit::singleline(&mut d.to).hint_text("YYYY-MM-DD HH:MM:SS").desired_width(140.0));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                apply = true;
            }
            ui.label("Limit");
            ui.add(egui::DragValue::new(&mut d.limit).range(10..=50_000).speed(10));
            if ui.add(egui::Button::new(egui::RichText::new("Apply").strong().color(Color32::from_rgb(30, 24, 8))).fill(ACCENT)).clicked() {
                apply = true;
            }
            if ui.button("Fit").on_hover_text("Fit the graph to the window").clicked() {
                self.fit_pending = true;
            }
            if ui.button("Shake").on_hover_text("Lay the graph out again").clicked() {
                let f = self.draft.clone();
                self.draft = f;
                self.requery(true);
            }
        });
        ui.horizontal_wrapped(|ui| {
            let d = &mut self.draft;
            ui.label(egui::RichText::new("Result").color(MUTED));
            for (i, name) in RESULT_NAMES.iter().enumerate() {
                let c = result_color(i as u8);
                if ui.add(egui::Button::selectable(d.results[i], egui::RichText::new(*name).color(if d.results[i] { c } else { MUTED }))).clicked() {
                    d.results[i] = !d.results[i];
                }
            }
            ui.separator();
            ui.label(egui::RichText::new("Hunt").color(MUTED));
            let enabled = d.view != View::Findings;
            for (i, name) in HUNT_NAMES.iter().enumerate() {
                let label = if name.is_empty() { "not hunted" } else { name };
                let on = if enabled { d.hunt[i] } else { i == 1 || i == 2 };
                let c = hunt_color(i as u8).unwrap_or(TEXT);
                if ui.add_enabled(enabled, egui::Button::selectable(on, egui::RichText::new(label).color(if on { c } else { MUTED }))).clicked() {
                    d.hunt[i] = !d.hunt[i];
                }
            }
            ui.separator();
            ui.label(egui::RichText::new("Verdict").color(MUTED));
            for (i, name) in VERDICT_NAMES.iter().enumerate() {
                let label = if name.is_empty() { "unmarked" } else { name };
                let c = verdict_color(i as u8).unwrap_or(TEXT);
                if ui.add(egui::Button::selectable(d.verdict[i], egui::RichText::new(label).color(if d.verdict[i] { c } else { MUTED }))).clicked() {
                    d.verdict[i] = !d.verdict[i];
                }
            }
            ui.separator();
            ui.checkbox(&mut self.show_edge_captions, "accounts on edges");
        });
        if apply {
            self.requery(false);
        }
        ui.label(egui::RichText::new(&self.status).color(if self.graph.truncated { CANDIDATE } else { MUTED }).small());
    }

    fn time_bar(&mut self, ui: &mut egui::Ui) {
        let n = self.graph.events.len();
        ui.horizontal(|ui| {
            let label = if self.playing { "Pause" } else { "Play" };
            if ui.button(label).on_hover_text("Replay the connections in time order").clicked() {
                if self.playing {
                    self.playing = false;
                } else {
                    if self.cursor >= n {
                        self.cursor = 0;
                    }
                    self.playing = true;
                    self.acc = 0.0;
                }
            }
            egui::ComboBox::from_id_salt("rate").selected_text(format!("{} rows/s", self.rate as u32)).width(90.0).show_ui(ui, |ui| {
                for r in [1.0, 4.0, 15.0, 60.0, 250.0] {
                    ui.selectable_value(&mut self.rate, r, format!("{} rows/s", r as u32));
                }
            });
            let mut c = self.cursor;
            ui.spacing_mut().slider_width = (ui.available_width() - 340.0).max(200.0);
            ui.add(egui::Slider::new(&mut c, 0..=n.max(1)).show_value(false));
            if c != self.cursor {
                self.cursor = c;
                self.playing = false;
            }
            let at = if n == 0 {
                String::new()
            } else {
                let k = self.cursor.min(n).saturating_sub(1);
                fmt_time(self.store.edges[self.graph.events[k] as usize].t)
            };
            ui.label(egui::RichText::new(at).monospace());
            ui.label(egui::RichText::new(format!("{} / {}", self.cursor.min(n), n)).color(MUTED));
            if ui.button("All").clicked() {
                self.cursor = n;
                self.playing = false;
            }
        });
    }

    // ───────────────────────── UI: details pane ─────────────────────────

    fn details(&mut self, ui: &mut egui::Ui) {
        match self.selected {
            None => self.legend(ui),
            Some(Sel::Node(i)) => self.node_details(ui, i),
            Some(Sel::Edge(i)) => self.edge_details(ui, i),
        }
    }

    fn legend(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Click a host or a connection. Drag a host to move it, drag the background to pan, scroll to zoom, double-click a host to open its neighbourhood.").color(MUTED));
        ui.add_space(10.0);
        ui.label(egui::RichText::new("HOSTS").small().color(MUTED));
        let chip = |ui: &mut egui::Ui, fill: Color32, ring: Color32, text: &str| {
            ui.horizontal(|ui| {
                let (r, p) = ui.allocate_painter(Vec2::new(18.0, 18.0), Sense::hover());
                p.circle_filled(r.rect.center(), 8.0, fill);
                p.circle_stroke(r.rect.center(), 8.0, Stroke::new(2.0, ring));
                ui.label(text);
            });
        };
        chip(ui, HOST_FILL, HOST_RING, "host (name)");
        chip(ui, IP_FILL, IP_RING, "address the hunt could not tie to a name");
        chip(ui, HOST_FILL, SIGNIFICANT, "touched by a significant connection");
        chip(ui, HOST_FILL, CANDIDATE, "touched by a candidate");
        ui.add_space(8.0);
        ui.label(egui::RichText::new("CONNECTIONS").small().color(MUTED));
        let line = |ui: &mut egui::Ui, c: Color32, w: f32, text: &str| {
            ui.horizontal(|ui| {
                let (r, p) = ui.allocate_painter(Vec2::new(28.0, 14.0), Sense::hover());
                let y = r.rect.center().y;
                p.line_segment([Pos2::new(r.rect.left(), y), Pos2::new(r.rect.right(), y)], Stroke::new(w, c));
                ui.label(text);
            });
        };
        line(ui, EDGE_OK, 2.0, "logon OK");
        line(ui, EDGE_FAIL, 2.0, "logon FAILED");
        line(ui, EDGE_CONNECT, 2.0, "connect (no authentication)");
        line(ui, EDGE_LOGOFF, 2.0, "logoff");
        line(ui, SIGNIFICANT, 4.0, "significant (hunt)");
        line(ui, CANDIDATE, 3.0, "candidate (hunt)");
        line(ui, SUSPICIOUS, 6.0, "marked suspicious / confirmed (halo)");
        line(ui, BENIGN, 6.0, "marked benign (halo)");
        ui.add_space(8.0);
        ui.label(egui::RichText::new("Edge width grows with the number of events, host size with its traffic. Hosts with more than 6 accounts between them are drawn as one edge that says how many.").color(MUTED).small());
        ui.add_space(12.0);
        ui.label(egui::RichText::new("IN THIS VIEW").small().color(MUTED));
        let mut per_hunt = [0usize; 6];
        let mut per_verdict = [0usize; 4];
        for e in &self.graph.edges {
            per_hunt[e.hunt as usize] += 1;
            per_verdict[e.verdict() as usize] += 1;
        }
        for (i, n) in per_hunt.iter().enumerate() {
            if *n > 0 {
                ui.label(format!("{} {}", n, if HUNT_NAMES[i].is_empty() { "not hunted" } else { HUNT_NAMES[i] }));
            }
        }
        for (i, n) in per_verdict.iter().enumerate().skip(1) {
            if *n > 0 {
                ui.label(format!("{} marked {}", n, VERDICT_NAMES[i]));
            }
        }
    }

    fn node_details(&mut self, ui: &mut egui::Ui, i: usize) {
        let host = self.graph.nodes[i].host;
        let name = self.store.hosts.name(host).to_string();
        let aliases: Vec<String> = self.store.aliases[host as usize].iter().filter(|a| a.as_str() != name).cloned().collect();
        ui.heading(&name);
        if !aliases.is_empty() {
            ui.label(egui::RichText::new(format!("also seen as {}", aliases.join(", "))).color(MUTED));
        } else if crate::load_neo4j::looks_like_ip(&name) {
            ui.label(egui::RichText::new("an address the hunt could not tie to a host name").color(MUTED));
        }
        let n = &self.graph.nodes[i];
        ui.label(format!("{} events in · {} events out (in this view)", n.inn, n.out));
        ui.horizontal(|ui| {
            if ui.button("Expand around").clicked() {
                self.draft.view = View::Around;
                self.draft.around = name.clone();
                self.requery(false);
                return;
            }
            if ui.button("Only this host").clicked() {
                self.draft.view = View::All;
                self.draft.host = name.clone();
                self.requery(false);
            }
        });
        if self.selected != Some(Sel::Node(i)) {
            return;
        }
        ui.add_space(8.0);
        ui.label(egui::RichText::new("CONNECTIONS").small().color(MUTED));
        let mut conns: Vec<usize> = self.graph.edges.iter().enumerate().filter(|(_, e)| e.src == host || e.dst == host).map(|(k, _)| k).collect();
        conns.sort_by(|a, b| hunt_rank(self.graph.edges[*a].hunt).cmp(&hunt_rank(self.graph.edges[*b].hunt)).then(self.graph.edges[*b].count.cmp(&self.graph.edges[*a].count)));
        let mut pick = None;
        egui::ScrollArea::vertical().auto_shrink([false, true]).show(ui, |ui| {
            for k in conns {
                let e = &self.graph.edges[k];
                let who = match e.user {
                    Some(u) => {
                        let s = self.store.users.name(u);
                        if s.is_empty() { "(no account)".to_string() } else { s.to_string() }
                    }
                    None => format!("{} accounts", e.users.len()),
                };
                let text = format!("{} -> {}  as {}\n{} · {} event(s) · {}", self.store.hosts.name(e.src), self.store.hosts.name(e.dst), who, RESULT_NAMES[e.result as usize], e.count, &fmt_time(e.first)[..16]);
                let mut rt = egui::RichText::new(text);
                if let Some(c) = hunt_color(e.hunt) {
                    rt = rt.color(c);
                }
                if ui.add(egui::Button::new(rt).frame(true).min_size(Vec2::new(ui.available_width(), 0.0))).clicked() {
                    pick = Some(k);
                }
            }
        });
        if let Some(k) = pick {
            self.selected = Some(Sel::Edge(k));
            self.load_rows(k);
        }
    }

    fn edge_details(&mut self, ui: &mut egui::Ui, i: usize) {
        self.load_rows(i);
        let (src, dst, who, result, count, first, last, hunt, q, why, verdict, lts, eids, users_n) = {
            let e = &self.graph.edges[i];
            let who = match e.user {
                Some(u) => {
                    let s = self.store.users.name(u);
                    if s.is_empty() { "(no account)".to_string() } else { s.to_string() }
                }
                None => format!("{} accounts: {}{}", e.users.len(), e.users.iter().take(10).map(|&u| self.store.users.name(u)).collect::<Vec<_>>().join(", "), if e.users.len() > 10 { ", …" } else { "" }),
            };
            (
                self.store.hosts.name(e.src).to_string(),
                self.store.hosts.name(e.dst).to_string(),
                who,
                RESULT_NAMES[e.result as usize],
                e.count,
                fmt_time(e.first),
                fmt_time(e.last),
                e.hunt,
                e.hunt_q,
                self.store.whys.name(e.why).to_string(),
                e.verdict(),
                e.logon_types.iter().map(|&k| self.store.logon_types.name(k).to_string()).collect::<Vec<_>>().join(", "),
                e.event_ids.iter().map(|&k| self.store.event_ids.name(k).to_string()).collect::<Vec<_>>().join(", "),
                e.users.len(),
            )
        };
        ui.heading(format!("{} -> {}", src, dst));
        ui.label(format!("as {}", who));
        ui.label(egui::RichText::new(format!("{} · {} event(s) · {}{}", result, count, first, if count > 1 { format!(" -> {}", last) } else { String::new() })).color(MUTED));
        ui.label(egui::RichText::new(format!("logon type {} · event {}", if lts.is_empty() { "-".into() } else { lts }, if eids.is_empty() { "-".into() } else { eids })).color(MUTED));
        ui.add_space(6.0);
        if hunt != 0 {
            ui.horizontal(|ui| {
                let c = hunt_color(hunt).unwrap_or(MUTED);
                ui.label(egui::RichText::new(HUNT_NAMES[hunt as usize]).strong().color(c));
                if !q.is_nan() {
                    ui.label(egui::RichText::new(format!("q = {:.2e}", q)).color(MUTED));
                }
            });
            ui.label(why);
        } else {
            ui.label(egui::RichText::new("not hunted (run graph-hunt-csv to fill the hunt columns)").color(MUTED));
        }
        ui.add_space(10.0);
        ui.label(egui::RichText::new("MARK").small().color(MUTED));
        let current = self.pending_verdict.unwrap_or(verdict);
        ui.horizontal(|ui| {
            for v in 1..4u8 {
                let c = verdict_color(v).unwrap();
                if ui.add(egui::Button::selectable(current == v, egui::RichText::new(VERDICT_NAMES[v as usize]).color(c))).clicked() {
                    self.pending_verdict = Some(v);
                }
            }
            if ui.add(egui::Button::selectable(current == 0, "clear")).clicked() {
                self.pending_verdict = Some(0);
            }
        });
        ui.add(egui::TextEdit::multiline(&mut self.notes_draft).desired_rows(3).desired_width(f32::INFINITY).hint_text("notes (written into the timeline)"));
        ui.horizontal(|ui| {
            let label = if users_n > 1 { format!("Save on every row of these {} accounts", users_n) } else { "Save on every row of this connection".to_string() };
            if ui.add(egui::Button::new(egui::RichText::new(label).color(Color32::from_rgb(30, 24, 8))).fill(ACCENT)).clicked() {
                self.save_mark(i);
            }
            ui.label(egui::RichText::new(&self.mark_msg).color(MUTED).small());
        });
        ui.add_space(10.0);
        if let Some((_, rows, total)) = &self.rows {
            ui.label(egui::RichText::new(format!("ROWS {}", if *total > rows.len() { format!("(first {} of {})", rows.len(), total) } else { total.to_string() })).small().color(MUTED));
            egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                egui::Grid::new("rows").striped(true).min_col_width(40.0).show(ui, |ui| {
                    for h in ["time", "event", "type", "account", "source", "subject", "logon id", "detail", "hunt", "verdict"] {
                        ui.label(egui::RichText::new(h).small().color(MUTED));
                    }
                    ui.end_row();
                    for r in rows {
                        let f = |k: usize| r.fields.get(k).cloned().unwrap_or_default();
                        ui.label(egui::RichText::new(&r.t).monospace().small());
                        ui.label(egui::RichText::new(f(3)).small());
                        ui.label(egui::RichText::new(f(4)).small());
                        ui.label(egui::RichText::new(f(5)).small());
                        let s = if f(7).is_empty() || f(7) == "-" { f(8) } else { f(7) };
                        ui.label(egui::RichText::new(s).small());
                        ui.label(egui::RichText::new(f(9)).small());
                        ui.label(egui::RichText::new(f(11)).small().monospace());
                        let d = f(12);
                        ui.label(egui::RichText::new(if d.chars().count() > 60 { format!("{}…", d.chars().take(60).collect::<String>()) } else { d.clone() }).small()).on_hover_text(d);
                        ui.label(egui::RichText::new(HUNT_NAMES[r.hunt as usize]).small().color(hunt_color(r.hunt).unwrap_or(MUTED)));
                        ui.label(egui::RichText::new(VERDICT_NAMES[r.verdict as usize]).small().color(verdict_color(r.verdict).unwrap_or(MUTED))).on_hover_text(&r.notes);
                        ui.end_row();
                        let _ = (r.file, r.line);
                    }
                });
            });
        }
    }

    // ───────────────────────── UI: canvas ─────────────────────────

    fn canvas(&mut self, ui: &mut egui::Ui) {
        let (resp, painter) = ui.allocate_painter(ui.available_size(), Sense::click_and_drag());
        let canvas = resp.rect;
        painter.rect_filled(canvas, CornerRadius::ZERO, BG);
        if self.fit_pending && self.layout.len() > 0 {
            // give the layout a head start so the first picture is settled
            for _ in 0..150 {
                self.layout.tick();
            }
            self.fit(canvas);
            self.fit_pending = false;
        }
        if self.layout.len() == 0 {
            painter.text(canvas.center(), Align2::CENTER_CENTER, "nothing to draw with these filters", FontId::proportional(16.0), MUTED);
            return;
        }
        if self.layout.tick() {
            ui.ctx().request_repaint();
        }

        // ── input: zoom, pan, drag, hover, click ──
        let pointer = resp.hover_pos();
        if let Some(p) = pointer {
            let scroll = ui.input(|i| i.smooth_scroll_delta.y);
            let zd = ui.input(|i| i.zoom_delta());
            let factor = if scroll != 0.0 { (scroll * 0.0025).exp() } else { zd };
            if (factor - 1.0).abs() > 1e-4 {
                let before = self.to_world(canvas, p);
                self.zoom = (self.zoom * factor).clamp(0.03, 6.0);
                let after = self.to_world(canvas, p);
                self.cam = self.cam + (before - after);
            }
        }
        let hit = pointer.and_then(|p| self.hit_test(canvas, p));
        self.hovered = hit;
        if resp.drag_started() {
            if let Some(Sel::Node(i)) = hit {
                self.dragging = Some(i);
                self.layout.fixed[i] = true;
            } else {
                self.dragging = None;
            }
        }
        if resp.dragged() {
            match self.dragging {
                Some(i) => {
                    if let Some(p) = resp.interact_pointer_pos() {
                        self.layout.pos[i] = self.to_world(canvas, p);
                        self.layout.reheat(0.3);
                        ui.ctx().request_repaint();
                    }
                }
                None => {
                    let d = resp.drag_delta();
                    self.cam = self.cam - V2::new(d.x / self.zoom, d.y / self.zoom);
                }
            }
        }
        if resp.drag_stopped() {
            if let Some(i) = self.dragging.take() {
                self.layout.fixed[i] = false;
                self.layout.reheat(0.2);
            }
        }
        if resp.double_clicked() {
            if let Some(Sel::Node(i)) = hit {
                let name = self.store.hosts.name(self.graph.nodes[i].host).to_string();
                self.draft.view = View::Around;
                self.draft.around = name;
                self.requery(false);
                return;
            }
        } else if resp.clicked() {
            self.selected = hit;
            if let Some(Sel::Edge(k)) = hit {
                self.load_rows(k);
            }
        }

        // ── what is lit: the selection or the hover and its neighbourhood ──
        let focus = self.selected.or(self.hovered);
        let (lit_nodes, lit_edges): (HashSet<usize>, HashSet<usize>) = match focus {
            None => (HashSet::new(), HashSet::new()),
            Some(Sel::Node(i)) => {
                let host = self.graph.nodes[i].host;
                let mut ns = HashSet::new();
                let mut es = HashSet::new();
                ns.insert(i);
                for (k, e) in self.graph.edges.iter().enumerate() {
                    if e.src == host || e.dst == host {
                        es.insert(k);
                        ns.insert(self.graph.node_of_host[&e.src]);
                        ns.insert(self.graph.node_of_host[&e.dst]);
                    }
                }
                (ns, es)
            }
            Some(Sel::Edge(k)) => {
                let e = &self.graph.edges[k];
                ([self.graph.node_of_host[&e.src], self.graph.node_of_host[&e.dst]].into_iter().collect(), [k].into_iter().collect())
            }
        };
        let dimmed = focus.is_some();
        let z = self.zoom;

        // ── edges ──
        let geom = self.edge_geometry();
        let max_count = self.graph.edges.iter().map(|e| e.count).max().unwrap_or(1).max(1) as f32;
        for (k, e) in self.graph.edges.iter().enumerate() {
            if !self.edge_visible(k) {
                continue;
            }
            let (a, b, ctrl) = geom[k];
            let pa = self.to_screen(canvas, a);
            let pb = self.to_screen(canvas, b);
            let pc = self.to_screen(canvas, ctrl);
            let lit = lit_edges.contains(&k);
            let alpha = if dimmed && !lit { 0.12 } else { 1.0 };
            let base = (1.2 + 3.0 * ((1 + e.count) as f32).ln() / (1.0 + max_count).ln()) * z.sqrt();
            let color = hunt_color(e.hunt).unwrap_or_else(|| result_color(e.result));
            let width = if e.hunt == super::store::H_SIGNIFICANT { base * 1.8 } else { base };
            if let Some(vc) = verdict_color(e.verdict()) {
                painter.add(egui::epaint::QuadraticBezierShape { points: [pa, pc, pb], closed: false, fill: Color32::TRANSPARENT, stroke: egui::epaint::PathStroke::new(width + 7.0 * z.sqrt(), dim(vc, 0.35 * alpha)) });
            }
            let stroke_color = if lit && self.selected == Some(Sel::Edge(k)) { ACCENT } else { dim(color, alpha) };
            if e.result == R_LOGOFF || e.result == R_CONNECT {
                // dotted: short dashes along the curve
                let steps = ((pa - pb).length() / (6.0 * z.sqrt().max(0.6))).clamp(4.0, 200.0) as usize;
                for s in 0..steps {
                    if s % 2 == 1 {
                        continue;
                    }
                    let t0 = s as f32 / steps as f32;
                    let t1 = (s + 1) as f32 / steps as f32;
                    painter.line_segment([bez(pa, pc, pb, t0), bez(pa, pc, pb, t1)], Stroke::new(width, stroke_color));
                }
            } else {
                painter.add(egui::epaint::QuadraticBezierShape { points: [pa, pc, pb], closed: false, fill: Color32::TRANSPARENT, stroke: egui::epaint::PathStroke::new(width, stroke_color) });
            }
            // arrowhead at the destination's rim
            let dir = (pb - bez(pa, pc, pb, 0.92)).normalized();
            let size = (7.0 + width * 1.5).min(16.0) * z.sqrt().max(0.5);
            let tip = pb;
            let left = tip - dir * size + dir.rot90() * size * 0.5;
            let right = tip - dir * size - dir.rot90() * size * 0.5;
            painter.add(egui::Shape::convex_polygon(vec![tip, left, right], stroke_color, Stroke::NONE));
            // the account on the edge, like Neo4j's relationship caption
            if self.show_edge_captions && (z > 0.6 || lit) && (pa - pb).length() > 90.0 {
                let caption = match e.user {
                    Some(u) => {
                        let s = self.store.users.name(u);
                        if s.is_empty() { String::new() } else { s.to_string() }
                    }
                    None => format!("{} accounts", e.users.len()),
                };
                let caption: String = if caption.chars().count() > 22 { format!("{}…", caption.chars().take(21).collect::<String>()) } else { caption };
                if !caption.is_empty() {
                    let mid = bez(pa, pc, pb, 0.5);
                    let font = FontId::proportional((10.0 * z.sqrt()).clamp(8.0, 13.0));
                    let galley = painter.layout_no_wrap(caption, font, dim(TEXT, alpha));
                    let r = Rect::from_center_size(mid, galley.size() + Vec2::new(8.0, 3.0));
                    painter.rect_filled(r, CornerRadius::same(3), dim(CAPTION_BG, alpha));
                    painter.galley(r.min + Vec2::new(4.0, 1.5), galley, TEXT);
                }
            }
        }

        // ── nodes ──
        for (i, n) in self.graph.nodes.iter().enumerate() {
            if !self.node_visible(i) {
                continue;
            }
            let p = self.to_screen(canvas, self.layout.pos[i]);
            let r = self.layout.radius[i] * z;
            if !canvas.expand(r).contains(p) {
                continue;
            }
            let name = self.store.hosts.name(n.host);
            let is_ip = crate::load_neo4j::looks_like_ip(name);
            let lit = lit_nodes.contains(&i);
            let alpha = if dimmed && !lit { 0.18 } else { 1.0 };
            let (fill, ring) = if is_ip { (IP_FILL, IP_RING) } else { (HOST_FILL, HOST_RING) };
            let ring = if n.hunt_rank == 0 { SIGNIFICANT } else { ring };
            let selected = self.selected == Some(Sel::Node(i));
            if selected || self.hovered == Some(Sel::Node(i)) {
                painter.circle_filled(p, r + 6.0, dim(if selected { ACCENT } else { Color32::WHITE }, 0.25));
            }
            painter.circle_filled(p, r, dim(fill, alpha));
            painter.circle_stroke(p, r, Stroke::new((2.5 * z).clamp(1.0, 4.0) * if n.hunt_rank == 0 { 1.8 } else { 1.0 }, dim(ring, alpha)));
            if r > 8.0 {
                let chars = name.chars().count().max(1) as f32;
                let wanted = (11.0 * z.sqrt()).clamp(7.0, 14.0);
                let fits = (r * 1.8) / (chars * 0.56);
                let font_size = wanted.min(fits).max(6.5);
                let max_chars = ((r * 1.8) / (font_size * 0.56)).floor().max(3.0) as usize;
                let caption: String = if name.chars().count() > max_chars { format!("{}…", name.chars().take(max_chars.saturating_sub(1)).collect::<String>()) } else { name.to_string() };
                if font_size >= 6.5 {
                    painter.text(p, Align2::CENTER_CENTER, caption, FontId::proportional(font_size), dim(Color32::from_rgb(20, 24, 30), alpha));
                }
            }
        }

        // ── hover tooltip ──
        if let (Some(Sel::Node(i)), Some(p)) = (self.hovered, pointer) {
            let n = &self.graph.nodes[i];
            let name = self.store.hosts.name(n.host);
            let aliases: Vec<&String> = self.store.aliases[n.host as usize].iter().filter(|a| a.as_str() != name).collect();
            let mut text = format!("{}\n{} in · {} out", name, n.inn, n.out);
            if !aliases.is_empty() {
                text.push_str(&format!("\nalso {}", aliases.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
            }
            let galley = painter.layout_no_wrap(text, FontId::proportional(12.0), TEXT);
            let r = Rect::from_min_size(p + Vec2::new(14.0, 10.0), galley.size() + Vec2::new(12.0, 8.0));
            painter.rect_filled(r, CornerRadius::same(4), Color32::from_rgba_premultiplied(40, 44, 52, 240));
            painter.rect_stroke(r, CornerRadius::same(4), Stroke::new(1.0, BORDER), egui::StrokeKind::Outside);
            painter.galley(r.min + Vec2::new(6.0, 4.0), galley, TEXT);
        }

        // ── overlay: legend chips at the top left, like Neo4j's ──
        let mut x = canvas.left() + 12.0;
        let y = canvas.top() + 12.0;
        let n_ip = self.graph.nodes.iter().filter(|n| crate::load_neo4j::looks_like_ip(self.store.hosts.name(n.host))).count();
        let chips: Vec<(String, Color32)> = vec![(format!("Host ({})", self.graph.nodes.len() - n_ip), HOST_FILL), (format!("IP ({})", n_ip), IP_FILL)];
        for (text, c) in chips {
            let galley = painter.layout_no_wrap(text, FontId::proportional(12.0), Color32::from_rgb(20, 24, 30));
            let r = Rect::from_min_size(Pos2::new(x, y), galley.size() + Vec2::new(14.0, 6.0));
            painter.rect_filled(r, CornerRadius::same(12), c);
            painter.galley(r.min + Vec2::new(7.0, 3.0), galley, Color32::from_rgb(20, 24, 30));
            x += r.width() + 6.0;
        }
        let mut per_result = [0usize; 4];
        for e in &self.graph.edges {
            per_result[e.result as usize] += 1;
        }
        let mut x = canvas.left() + 12.0;
        let y = y + 30.0;
        for (i, n) in per_result.iter().enumerate() {
            if *n == 0 {
                continue;
            }
            let c = result_color(i as u8);
            let galley = painter.layout_no_wrap(format!("{} ({})", RESULT_NAMES[i], n), FontId::proportional(11.0), TEXT);
            let r = Rect::from_min_size(Pos2::new(x, y), galley.size() + Vec2::new(14.0, 6.0));
            painter.rect_filled(r, CornerRadius::same(12), Color32::from_rgb(44, 48, 58));
            painter.rect_stroke(r, CornerRadius::same(12), Stroke::new(1.5, c), egui::StrokeKind::Inside);
            painter.galley(r.min + Vec2::new(7.0, 3.0), galley, TEXT);
            x += r.width() + 6.0;
        }
        // zoom hint, bottom right
        painter.text(Pos2::new(canvas.right() - 10.0, canvas.bottom() - 8.0), Align2::RIGHT_BOTTOM, format!("{:.0} %", self.zoom * 100.0), FontId::proportional(11.0), MUTED);
    }

    /// Start, end (on the rims) and control point of every edge, in
    /// world units; parallel edges between a pair fan out.
    fn edge_geometry(&self) -> Vec<(V2, V2, V2)> {
        let mut groups: HashMap<(usize, usize), Vec<usize>> = HashMap::new();
        let mut nodes_of: Vec<(usize, usize)> = Vec::with_capacity(self.graph.edges.len());
        for (k, e) in self.graph.edges.iter().enumerate() {
            let a = self.graph.node_of_host[&e.src];
            let b = self.graph.node_of_host[&e.dst];
            nodes_of.push((a, b));
            groups.entry((a.min(b), a.max(b))).or_default().push(k);
        }
        let mut out = vec![(V2::default(), V2::default(), V2::default()); self.graph.edges.len()];
        for ((_, _), ks) in groups {
            let n = ks.len();
            for (idx, &k) in ks.iter().enumerate() {
                let (a, b) = nodes_of[k];
                let pa = self.layout.pos[a];
                let pb = self.layout.pos[b];
                let ra = self.layout.radius[a];
                let rb = self.layout.radius[b];
                if a == b {
                    out[k] = (pa, pa, pa + V2::new(0.0, -ra * 3.0));
                    continue;
                }
                let d = pb - pa;
                let len = d.len().max(1.0);
                let u = d * (1.0 / len);
                let normal = V2::new(-u.y, u.x);
                let side = if a < b { 1.0 } else { -1.0 };
                let offset = (idx as f32 - (n as f32 - 1.0) / 2.0) * 34.0 * side;
                let mid = pa + d * 0.5 + normal * offset;
                // the curve leaves and enters at the rims, aimed at the control point
                let da = mid - pa;
                let start = pa + da * ((ra + 1.0) / da.len().max(1.0));
                let db = mid - pb;
                let end = pb + db * ((rb + 2.0) / db.len().max(1.0));
                // a quadratic curve through `mid` needs a control point twice as far out
                let ctrl = mid * 2.0 - (start + end) * 0.5;
                out[k] = (start, end, ctrl);
            }
        }
        out
    }

    fn hit_test(&self, canvas: Rect, p: Pos2) -> Option<Sel> {
        // nodes first, nearest wins
        let mut best: Option<(f32, Sel)> = None;
        for i in 0..self.graph.nodes.len() {
            if !self.node_visible(i) {
                continue;
            }
            let c = self.to_screen(canvas, self.layout.pos[i]);
            let r = self.layout.radius[i] * self.zoom;
            let d = (c - p).length();
            if d <= r + 2.0 && best.map_or(true, |(bd, _)| d < bd) {
                best = Some((d, Sel::Node(i)));
            }
        }
        if best.is_some() {
            return best.map(|(_, s)| s);
        }
        let geom = self.edge_geometry();
        for (k, (a, b, c)) in geom.iter().enumerate() {
            if !self.edge_visible(k) {
                continue;
            }
            let pa = self.to_screen(canvas, *a);
            let pb = self.to_screen(canvas, *b);
            let pc = self.to_screen(canvas, *c);
            let mut prev = pa;
            for s in 1..=12 {
                let q = bez(pa, pc, pb, s as f32 / 12.0);
                let d = dist_to_segment(p, prev, q);
                if d < 6.0 && best.map_or(true, |(bd, _)| d < bd) {
                    best = Some((d, Sel::Edge(k)));
                }
                prev = q;
            }
        }
        best.map(|(_, s)| s)
    }
}

fn bez(a: Pos2, c: Pos2, b: Pos2, t: f32) -> Pos2 {
    let u = 1.0 - t;
    Pos2::new(u * u * a.x + 2.0 * u * t * c.x + t * t * b.x, u * u * a.y + 2.0 * u * t * c.y + t * t * b.y)
}

fn dist_to_segment(p: Pos2, a: Pos2, b: Pos2) -> f32 {
    let ab = b - a;
    let l2 = ab.length_sq();
    if l2 < 1e-6 {
        return (p - a).length();
    }
    let t = ((p - a).dot(ab) / l2).clamp(0.0, 1.0);
    (p - (a + ab * t)).length()
}

impl eframe::App for Viewer {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let now = std::time::Instant::now();
        let dt = (now - self.last_frame).as_secs_f32().min(0.25);
        self.last_frame = now;
        if self.playing {
            self.acc += dt * self.rate;
            let step = self.acc.floor() as usize;
            if step > 0 {
                self.acc -= step as f32;
                self.cursor = (self.cursor + step).min(self.graph.events.len());
                if self.cursor >= self.graph.events.len() {
                    self.playing = false;
                }
            }
            ctx.request_repaint();
        }
        egui::Panel::top("filters").frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::symmetric(12, 8))).show(ui, |ui| self.filter_bar(ui));
        egui::Panel::bottom("time").frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::symmetric(12, 8))).show(ui, |ui| self.time_bar(ui));
        egui::Panel::right("details").default_size(400.0).resizable(true).frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::same(12))).show(ui, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| self.details(ui));
        });
        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG)).show(ui, |ui| self.canvas(ui));
    }
}
