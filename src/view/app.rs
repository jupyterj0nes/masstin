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
use super::query::{fmt_time, hunt_rank, Filter, GEdge, GraphView, Role, View};
use super::store::{Pattern, Store, HUNT_NAMES, RESULT_NAMES, R_CONNECT, R_FAIL, R_LOGOFF, R_OK, VERDICT_NAMES};
use super::paths::{self, Path, PathQuery};
use super::present::{self, Anonymiser, Format, Step, StepOverride, Story, Timing};
use super::views::{builtin_views, palette_color, Caption, ColorBy, Field, Rule, SavedView, Shape, Style, ViewsFile};
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
    last_frame: std::time::Instant,
    // style and saved views
    style: Style,
    views_path: std::path::PathBuf,
    saved: Vec<SavedView>,
    builtin: Vec<SavedView>,
    preset: String,
    show_rules: bool,
    show_save: bool,
    save_name: String,
    // presentation and recording
    story: Story,
    story_path: std::path::PathBuf,
    steps: Vec<Step>,
    step_of_event: Vec<usize>,
    presenting: bool,
    present_t: f32,
    present_playing: bool,
    show_story: bool,
    anon: Anonymiser,
    show_export: bool,
    export_fps: u32,
    export_format: Format,
    export_size: usize,
    export_name: String,
    export: Option<ExportJob>,
    ffmpeg: Option<bool>,
    auto: Vec<String>,
    auto_next: std::time::Instant,
    // paths, cones, questions
    show_paths: bool,
    show_questions: bool,
    path_origin: String,
    path_dest: String,
    path_hops: usize,
    path_gap_h: f32,
    path_max: usize,
    path_results: [bool; 4],
    path_skip_machine: bool,
    path_found: Vec<Path>,
    path_msg: String,
    overlay: Option<Overlay>,
}

/// What the canvas shows instead of the filter's selection: the edges of
/// a path or a cone, with a word under each host.
struct Overlay {
    title: String,
    edges: Vec<u32>,
    labels: HashMap<u32, String>,
    hops: HashMap<u32, usize>,
}

/// A recording in progress: one screenshot per frame, streamed to the
/// encoder on its thread.
struct ExportJob {
    fps: u32,
    out: std::path::PathBuf,
    total: usize,
    next: usize,
    waiting: bool,
    rx: std::sync::mpsc::Receiver<(usize, std::sync::Arc<egui::ColorImage>)>,
    tx: std::sync::mpsc::Sender<(usize, std::sync::Arc<egui::ColorImage>)>,
    restore: Option<Vec2>,
    rec: present::Recorder,
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
        let views_path = ViewsFile::path_for(&opts.files[0]);
        let vf = ViewsFile::load(&views_path);
        let style = vf.last_style.clone().unwrap_or_default();
        let builtin = builtin_views(store.t_max);
        let story_path = Story::path_for(&opts.files[0]);
        let story = Story::load(&story_path);
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
            last_frame: std::time::Instant::now(),
            style,
            views_path,
            saved: vf.views,
            builtin,
            preset: String::new(),
            show_rules: false,
            show_save: false,
            save_name: String::new(),
            story,
            story_path,
            steps: Vec::new(),
            step_of_event: Vec::new(),
            presenting: false,
            present_t: 0.0,
            present_playing: false,
            show_story: false,
            anon: Anonymiser::new(),
            show_export: false,
            export_fps: 30,
            export_format: Format::Gif,
            export_size: 0,
            export_name: String::new(),
            export: None,
            ffmpeg: None,
            auto: std::env::var("MASSTIN_VIEW_AUTO").ok().map(|v| v.split(',').map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect()).unwrap_or_default(),
            auto_next: std::time::Instant::now() + std::time::Duration::from_secs(2),
            show_paths: false,
            show_questions: false,
            path_origin: String::new(),
            path_dest: String::new(),
            path_hops: 6,
            path_gap_h: 24.0,
            path_max: 50,
            path_results: [true, false, false, false],
            path_skip_machine: true,
            path_found: Vec::new(),
            path_msg: String::new(),
            overlay: None,
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
        self.graph = match &self.overlay {
            Some(o) => GraphView::from_edges(&self.store, &self.filter, o.edges.clone()),
            None => GraphView::build(&self.store, &self.filter),
        };
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
        if let Some(o) = &self.overlay {
            parts.insert(0, o.title.clone());
        }
        if g.truncated {
            parts.push("limit reached: narrow the filters or raise the limit".into());
        }
        self.rebuild_steps();
        self.status = parts.join("  ·  ");
        self.fit_pending = true;
    }

    fn fit(&mut self, canvas: Rect) {
        if let Some((lo, hi)) = self.layout.bounds() {
            let w = (hi.x - lo.x).max(50.0) + 80.0;
            let h = (hi.y - lo.y).max(50.0) + 80.0;
            let max_zoom = if self.presenting { 1.8 } else { 1.0 };
            self.zoom = (canvas.width() / w).min(canvas.height() / h).clamp(0.05, max_zoom);
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

    fn rebuild_steps(&mut self) {
        let events: Vec<(i64, String, bool)> = self.graph.events.iter().map(|&ei| {
            let e = &self.store.edges[ei as usize];
            (e.t, format!("{}:{}", e.file, e.line), e.hunt == super::store::H_SIGNIFICANT)
        }).collect();
        self.steps = present::build_steps(&events, &self.story);
        self.step_of_event = vec![usize::MAX; self.graph.events.len()];
        for (k, st) in self.steps.iter().enumerate() {
            for ev in st.from..st.to {
                self.step_of_event[ev] = k;
            }
        }
    }

    fn save_story(&self) {
        if let Err(e) = self.story.save(&self.story_path) {
            eprintln!("masstin: cannot save {}: {}", self.story_path.display(), e);
        }
    }

    /// How much of the view is revealed: events fully shown, and the
    /// range of events being drawn right now with its progress.
    fn reveal(&self) -> (usize, Option<(usize, usize, f32)>) {
        if !self.presenting {
            return (self.cursor, None);
        }
        match present::at(&self.steps, self.present_t) {
            None => (0, None),
            Some((k, p)) => {
                let st = &self.steps[k];
                if p >= 1.0 {
                    (st.to, None)
                } else {
                    (st.from, Some((st.from, st.to, p)))
                }
            }
        }
    }

    /// The step a presentation is in, if any.
    fn current_step(&self) -> Option<usize> {
        if !self.presenting {
            return None;
        }
        present::at(&self.steps, self.present_t).map(|(k, _)| k)
    }

    fn edge_visible(&self, i: usize) -> bool {
        let (done, drawing) = self.reveal();
        let f = self.graph.edges[i].first_event;
        f < done || drawing.map_or(false, |(a, b, _)| f >= a && f < b)
    }

    /// 0..1 while an edge is being drawn in a presentation, 1 when whole.
    fn edge_progress(&self, i: usize) -> f32 {
        let (done, drawing) = self.reveal();
        let f = self.graph.edges[i].first_event;
        if f < done {
            return 1.0;
        }
        drawing.map(|(_, _, p)| p).unwrap_or(1.0)
    }

    fn node_visible(&self, i: usize) -> bool {
        let (done, drawing) = self.reveal();
        let f = self.graph.nodes[i].first_event;
        f < done || drawing.map_or(false, |(a, b, p)| f >= a && f < b && p > 0.45)
    }

    /// A host's name as shown (a stand-in when the story is anonymised).
    fn host_label(&self, host: u32) -> String {
        let name = self.store.hosts.name(host).to_string();
        if self.presenting && self.story.anonymise {
            let is_ip = crate::load_neo4j::looks_like_ip(&name);
            self.anon.host(host, is_ip)
        } else {
            name
        }
    }

    fn user_label(&self, user: u32) -> String {
        if self.presenting && self.story.anonymise {
            self.anon.user(user)
        } else {
            self.store.users.name(user).to_string()
        }
    }

    fn start_presentation(&mut self) {
        self.rebuild_steps();
        self.presenting = true;
        self.present_t = 0.0;
        self.present_playing = true;
        self.selected = None;
        self.hovered = None;
        self.anon = Anonymiser::new();
        self.layout.stop();
        // the canvas is the whole window now: frame the graph again
        self.fit_pending = true;
    }

    fn stop_presentation(&mut self) {
        self.presenting = false;
        self.present_playing = false;
        self.cursor = self.graph.events.len();
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
        });
        let mut style_changed = false;
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new("View").color(MUTED));
            let mut pick: Option<SavedView> = None;
            egui::ComboBox::from_id_salt("preset").selected_text(if self.preset.is_empty() { "presets…" } else { self.preset.as_str() }).width(220.0).show_ui(ui, |ui| {
                ui.label(egui::RichText::new("BUILT IN").small().color(MUTED));
                for v in &self.builtin {
                    if ui.selectable_label(self.preset == v.name, &v.name).clicked() {
                        pick = Some(v.clone());
                    }
                }
                if !self.saved.is_empty() {
                    ui.separator();
                    ui.label(egui::RichText::new("SAVED").small().color(MUTED));
                    for v in &self.saved {
                        if ui.selectable_label(self.preset == v.name, &v.name).clicked() {
                            pick = Some(v.clone());
                        }
                    }
                }
            });
            if let Some(v) = pick {
                self.preset = v.name.clone();
                self.draft = v.filter.clone();
                if self.saved.iter().any(|x| x.name == v.name) {
                    self.style = v.style.clone();
                    style_changed = true;
                }
                self.requery(false);
            }
            if ui.button("Save view…").on_hover_text("Keep the current filter and style under a name, next to the timeline").clicked() {
                self.show_save = true;
                if self.save_name.is_empty() {
                    self.save_name = self.preset.clone();
                }
            }
            if self.saved.iter().any(|x| x.name == self.preset) && ui.button("Delete view").clicked() {
                let name = self.preset.clone();
                self.saved.retain(|x| x.name != name);
                self.preset.clear();
                style_changed = true;
            }
            ui.separator();
            ui.label(egui::RichText::new("Colour by").color(MUTED));
            egui::ComboBox::from_id_salt("colorby").selected_text(self.style.color_by.label()).show_ui(ui, |ui| {
                for c in ColorBy::ALL {
                    if ui.selectable_value(&mut self.style.color_by, c, c.label()).changed() {
                        style_changed = true;
                    }
                }
            });
            ui.label(egui::RichText::new("On edges").color(MUTED));
            egui::ComboBox::from_id_salt("caption").selected_text(self.style.caption.label()).show_ui(ui, |ui| {
                for c in Caption::ALL {
                    if ui.selectable_value(&mut self.style.caption, c, c.label()).changed() {
                        style_changed = true;
                    }
                }
            });
            if ui.checkbox(&mut self.style.shapes_by_role, "shapes by role").on_hover_text("hexagon: domain controller · square: server · circle: workstation · diamond: external address").changed() {
                style_changed = true;
            }
            ui.label(egui::RichText::new("Hosts").color(MUTED));
            if ui.add(egui::DragValue::new(&mut self.style.node_scale).range(0.4..=2.5).speed(0.02).fixed_decimals(1)).changed() {
                style_changed = true;
            }
            ui.label(egui::RichText::new("Edges").color(MUTED));
            if ui.add(egui::DragValue::new(&mut self.style.edge_scale).range(0.3..=3.0).speed(0.02).fixed_decimals(1)).changed() {
                style_changed = true;
            }
            ui.label(egui::RichText::new("Text").color(MUTED));
            if ui.add(egui::DragValue::new(&mut self.style.font_scale).range(0.6..=2.0).speed(0.02).fixed_decimals(1)).changed() {
                style_changed = true;
            }
            let n_rules = self.style.rules.iter().filter(|r| r.enabled).count();
            if ui.selectable_label(self.show_rules, format!("Rules ({})", n_rules)).on_hover_text("condition -> colour, width, size, shape, dashes, glow, hide; first match wins").clicked() {
                self.show_rules = !self.show_rules;
            }
            ui.separator();
            if ui.selectable_label(self.show_paths, "Paths…").on_hover_text("Time-respecting paths between two hosts, and what a host could reach (or be reached from)").clicked() {
                self.show_paths = !self.show_paths;
            }
            if ui.selectable_label(self.show_questions, "Questions…").on_hover_text("Fan-out, fan-in, shared accounts, failures then success, first appearances, PageRank and betweenness of the view").clicked() {
                self.show_questions = !self.show_questions;
            }
            if self.overlay.is_some() && ui.button("Back to the view").clicked() {
                self.overlay = None;
                self.requery(false);
            }
        });
        if style_changed {
            self.persist();
        }
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
            ui.spacing_mut().slider_width = (ui.available_width() - 500.0).max(160.0);
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
            ui.separator();
            if ui.add(egui::Button::new(egui::RichText::new("Present").strong().color(Color32::from_rgb(30, 24, 8))).fill(ACCENT)).on_hover_text("Play the story full screen (Esc leaves)").clicked() {
                self.start_presentation();
            }
            if ui.selectable_label(self.show_story, "Story…").on_hover_text("Timing, captions, per-step settings, recording").clicked() {
                self.show_story = !self.show_story;
                if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
                    eprintln!("[view] story window: {}", self.show_story);
                }
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
        ui.horizontal(|ui| {
            if ui.button("Paths from here").clicked() {
                self.path_origin = name.clone();
                self.show_paths = true;
            }
            if ui.button("Paths to here").clicked() {
                self.path_dest = name.clone();
                self.show_paths = true;
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

    // ───────────────────────── style ─────────────────────────

    fn persist(&self) {
        let vf = ViewsFile { views: self.saved.clone(), last_style: Some(self.style.clone()) };
        if let Err(e) = vf.save(&self.views_path) {
            eprintln!("masstin: cannot save {}: {}", self.views_path.display(), e);
        }
    }

    fn save_popup(&mut self, ctx: &egui::Context) {
        if !self.show_save {
            return;
        }
        let mut open = true;
        let mut done = false;
        egui::Window::new("Save view").open(&mut open).collapsible(false).resizable(false).anchor(Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.label("The current filter and style, under a name, in the views file next to the timeline.");
            ui.horizontal(|ui| {
                ui.label("Name");
                let r = ui.add(egui::TextEdit::singleline(&mut self.save_name).desired_width(260.0));
                r.request_focus();
            });
            ui.label(egui::RichText::new(self.views_path.to_string_lossy()).small().color(MUTED));
            ui.horizontal(|ui| {
                let name = self.save_name.trim().to_string();
                let exists = self.saved.iter().any(|v| v.name == name);
                if ui.add_enabled(!name.is_empty(), egui::Button::new(if exists { "Replace" } else { "Save" })).clicked() {
                    self.saved.retain(|v| v.name != name);
                    self.saved.push(SavedView { name: name.clone(), filter: self.draft.clone(), style: self.style.clone() });
                    self.saved.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
                    self.preset = name;
                    self.persist();
                    done = true;
                }
                if ui.button("Cancel").clicked() {
                    done = true;
                }
            });
        });
        if done || !open {
            self.show_save = false;
        }
    }

    fn rules_window(&mut self, ctx: &egui::Context) {
        if !self.show_rules {
            return;
        }
        let mut open = true;
        let mut changed = false;
        egui::Window::new("Style rules").open(&mut open).default_width(760.0).resizable(true).show(ctx, |ui| {
            ui.label(egui::RichText::new("Each rule: a field and a pattern (contains, * wildcards, ! not, commas for several; empty = everything), then the look it gives. The first rule that matches an edge or a host wins; rules on host and hunt also apply to hosts.").color(MUTED));
            let mut remove: Option<usize> = None;
            let mut swap: Option<(usize, usize)> = None;
            let n = self.style.rules.len();
            egui::Grid::new("rules").striped(true).min_col_width(30.0).show(ui, |ui| {
                for h in ["on", "field", "pattern", "colour", "width", "size", "shape", "dashed", "glow", "hide", ""] {
                    ui.label(egui::RichText::new(h).small().color(MUTED));
                }
                ui.end_row();
                for i in 0..n {
                    let r = &mut self.style.rules[i];
                    changed |= ui.checkbox(&mut r.enabled, "").changed();
                    egui::ComboBox::from_id_salt(("field", i)).selected_text(r.field.label()).width(90.0).show_ui(ui, |ui| {
                        for f in Field::ALL {
                            changed |= ui.selectable_value(&mut r.field, f, f.label()).changed();
                        }
                    });
                    changed |= ui.add_sized([170.0, 20.0], egui::TextEdit::singleline(&mut r.pattern).hint_text("adm*, !*$")).changed();
                    let mut has_color = r.color.is_some();
                    if ui.checkbox(&mut has_color, "").changed() {
                        r.color = if has_color { Some([255, 196, 84]) } else { None };
                        changed = true;
                    }
                    if let Some(c) = &mut r.color {
                        changed |= ui.color_edit_button_srgb(c).changed();
                    }
                    changed |= ui.add(egui::DragValue::new(&mut r.width).range(0.2..=6.0).speed(0.05).fixed_decimals(1)).changed();
                    changed |= ui.add(egui::DragValue::new(&mut r.size).range(0.3..=3.0).speed(0.05).fixed_decimals(1)).changed();
                    egui::ComboBox::from_id_salt(("shape", i)).selected_text(r.shape.map(|s| s.label()).unwrap_or("-")).width(80.0).show_ui(ui, |ui| {
                        changed |= ui.selectable_value(&mut r.shape, None, "-").changed();
                        for sh in Shape::ALL {
                            changed |= ui.selectable_value(&mut r.shape, Some(sh), sh.label()).changed();
                        }
                    });
                    changed |= ui.checkbox(&mut r.dashed, "").changed();
                    changed |= ui.checkbox(&mut r.glow, "").changed();
                    changed |= ui.checkbox(&mut r.hide, "").changed();
                    ui.horizontal(|ui| {
                        if i > 0 && ui.small_button("up").clicked() {
                            swap = Some((i, i - 1));
                        }
                        if i + 1 < n && ui.small_button("down").clicked() {
                            swap = Some((i, i + 1));
                        }
                        if ui.small_button("x").clicked() {
                            remove = Some(i);
                        }
                    });
                    ui.end_row();
                }
            });
            if let Some((a, b)) = swap {
                self.style.rules.swap(a, b);
                changed = true;
            }
            if let Some(i) = remove {
                self.style.rules.remove(i);
                changed = true;
            }
            ui.horizontal(|ui| {
                if ui.button("+ rule").clicked() {
                    self.style.rules.push(Rule::default());
                    changed = true;
                }
                if ui.button("+ account in colour").on_hover_text("colour every edge of one account").clicked() {
                    self.style.rules.push(Rule { field: Field::User, pattern: "jdoe".into(), color: Some([255, 196, 84]), width: 1.6, ..Default::default() });
                    changed = true;
                }
                if ui.button("+ hide machine accounts").clicked() {
                    self.style.rules.push(Rule { field: Field::User, pattern: "*$".into(), color: None, hide: true, ..Default::default() });
                    changed = true;
                }
                if ui.button("+ fade benign").clicked() {
                    self.style.rules.push(Rule { field: Field::Verdict, pattern: "benign".into(), color: Some([90, 96, 110]), width: 0.6, ..Default::default() });
                    changed = true;
                }
                if ui.button("+ domain controllers as hexagons").clicked() {
                    self.style.rules.push(Rule { field: Field::Host, pattern: "*DC*".into(), color: Some([201, 144, 192]), shape: Some(Shape::Hexagon), size: 1.3, ..Default::default() });
                    changed = true;
                }
            });
        });
        if changed {
            self.persist();
        }
        if !open {
            self.show_rules = false;
        }
    }

    /// Patterns of the enabled rules, compiled once per frame.
    fn compiled_rules(&self) -> Vec<(usize, Vec<Pattern>)> {
        self.style.rules.iter().enumerate().filter(|(_, r)| r.enabled).map(|(i, r)| (i, Pattern::parse_list(&r.pattern))).collect()
    }

    fn rule_hits_edge(&self, rule: &Rule, pats: &[Pattern], e: &GEdge) -> bool {
        let s = &self.store;
        match rule.field {
            Field::Host => [e.src, e.dst].iter().any(|&h| s.aliases[h as usize].iter().any(|a| Pattern::any(pats, a))),
            Field::User => e.users.iter().any(|&u| Pattern::any(pats, s.users.name(u))),
            Field::LogonType => e.logon_types.iter().any(|&k| Pattern::any(pats, s.logon_types.name(k))),
            Field::EventId => e.event_ids.iter().any(|&k| Pattern::any(pats, s.event_ids.name(k))),
            Field::Result => Pattern::any(pats, RESULT_NAMES[e.result as usize]),
            Field::Hunt => Pattern::any(pats, if HUNT_NAMES[e.hunt as usize].is_empty() { "none" } else { HUNT_NAMES[e.hunt as usize] }),
            Field::Verdict => Pattern::any(pats, if e.verdict() == 0 { "none" } else { VERDICT_NAMES[e.verdict() as usize] }),
        }
    }

    fn rule_hits_node(&self, rule: &Rule, pats: &[Pattern], i: usize) -> bool {
        let n = &self.graph.nodes[i];
        match rule.field {
            Field::Host => self.store.aliases[n.host as usize].iter().any(|a| Pattern::any(pats, a)),
            Field::Hunt => Pattern::any(pats, match n.hunt_rank {
                0 => "significant",
                1 => "candidate",
                2 => "not_evaluated",
                3 => "habitual",
                4 => "baseline",
                _ => "none",
            }),
            _ => false,
        }
    }

    /// Base colour of an edge for the chosen "colour by".
    fn edge_base_color(&self, e: &GEdge) -> Color32 {
        let c3 = |c: [u8; 3]| Color32::from_rgb(c[0], c[1], c[2]);
        match self.style.color_by {
            ColorBy::Result => hunt_color(e.hunt).unwrap_or_else(|| result_color(e.result)),
            ColorBy::User => match e.user {
                Some(u) => c3(palette_color(u)),
                None => EDGE_OK,
            },
            ColorBy::LogonType => e.logon_types.first().map(|&k| c3(palette_color(k))).unwrap_or(EDGE_OK),
            ColorBy::Hunt => hunt_color(e.hunt).unwrap_or(match e.hunt {
                super::store::H_HABITUAL => EDGE_OK,
                super::store::H_BASELINE => EDGE_LOGOFF,
                super::store::H_NOT_EVALUATED => Color32::from_rgb(120, 130, 150),
                _ => Color32::from_rgb(80, 86, 98),
            }),
            ColorBy::Verdict => verdict_color(e.verdict()).unwrap_or(Color32::from_rgb(90, 96, 110)),
        }
    }

    fn edge_caption(&self, e: &GEdge) -> String {
        let anonym = self.presenting && self.story.anonymise;
        let user = || match e.user {
            Some(u) => if anonym { self.anon.user(u) } else { self.store.users.name(u).to_string() },
            None => format!("{} accounts", e.users.len()),
        };
        let time = || fmt_time(e.first)[11..16].to_string();
        let text = match self.style.caption {
            Caption::None => String::new(),
            Caption::User => user(),
            Caption::Time => time(),
            Caption::LogonType => e.logon_types.iter().map(|&k| self.store.logon_types.name(k)).collect::<Vec<_>>().join(", "),
            Caption::UserTime => format!("{} · {}", user(), time()),
            Caption::Count => format!("{} event(s)", e.count),
        };
        if text.chars().count() > 26 { format!("{}…", text.chars().take(25).collect::<String>()) } else { text }
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
        let rules = self.compiled_rules();
        let geom = self.edge_geometry();
        let max_count = self.graph.edges.iter().map(|e| e.count).max().unwrap_or(1).max(1) as f32;
        for (k, e) in self.graph.edges.iter().enumerate() {
            if !self.edge_visible(k) {
                continue;
            }
            let (a, b, ctrl) = geom[k];
            let pa = self.to_screen(canvas, a);
            let pb_full = self.to_screen(canvas, b);
            let pc_full = self.to_screen(canvas, ctrl);
            let progress = self.edge_progress(k);
            // while a presentation draws the edge, the curve grows from the origin
            let (pb, pc) = if progress < 1.0 {
                let pm = bez(pa, pc_full, pb_full, progress);
                let cm = Pos2::new(pa.x + (pc_full.x - pa.x) * progress, pa.y + (pc_full.y - pa.y) * progress);
                (pm, cm)
            } else {
                (pb_full, pc_full)
            };
            let lit = lit_edges.contains(&k);
            let mut alpha = if dimmed && !lit { 0.12 } else { 1.0 };
            if self.presenting && self.story.fade_old {
                if let (Some(cur), Some(&st)) = (self.current_step(), self.step_of_event.get(e.first_event)) {
                    if st != usize::MAX && cur > st + 8 {
                        alpha *= 0.3;
                    }
                }
            }
            let emphasised = self.presenting && self.step_of_event.get(e.first_event).and_then(|&st| self.steps.get(st)).map_or(false, |st| st.emphasis || (st.significant && progress < 1.0));
            let base = (1.2 + 3.0 * ((1 + e.count) as f32).ln() / (1.0 + max_count).ln()) * z.sqrt() * self.style.edge_scale;
            let mut color = self.edge_base_color(e);
            let mut width = if e.hunt == super::store::H_SIGNIFICANT { base * 1.8 } else { base };
            let mut dashed = e.result == R_LOGOFF || e.result == R_CONNECT;
            let mut glow = false;
            if let Some((ri, _)) = rules.iter().find(|(ri, pats)| self.rule_hits_edge(&self.style.rules[*ri], pats, e)) {
                let r = &self.style.rules[*ri];
                if r.hide {
                    continue;
                }
                if let Some(c) = r.color {
                    color = Color32::from_rgb(c[0], c[1], c[2]);
                }
                width *= r.width;
                dashed |= r.dashed;
                glow = r.glow;
            }
            if glow || emphasised || progress < 1.0 {
                painter.add(egui::epaint::QuadraticBezierShape { points: [pa, pc, pb], closed: false, fill: Color32::TRANSPARENT, stroke: egui::epaint::PathStroke::new(width + 10.0 * z.sqrt(), dim(color, if progress < 1.0 { 0.45 } else { 0.22 } * alpha)) });
            }
            if let Some(vc) = verdict_color(e.verdict()) {
                painter.add(egui::epaint::QuadraticBezierShape { points: [pa, pc, pb], closed: false, fill: Color32::TRANSPARENT, stroke: egui::epaint::PathStroke::new(width + 7.0 * z.sqrt(), dim(vc, 0.35 * alpha)) });
            }
            let stroke_color = if lit && self.selected == Some(Sel::Edge(k)) { ACCENT } else { dim(color, alpha) };
            if dashed {
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
            if progress < 1.0 {
                continue;
            }
            let dir = (pb - bez(pa, pc, pb, 0.92)).normalized();
            let size = (7.0 + width * 1.5).min(16.0) * z.sqrt().max(0.5);
            let tip = pb;
            let left = tip - dir * size + dir.rot90() * size * 0.5;
            let right = tip - dir * size - dir.rot90() * size * 0.5;
            painter.add(egui::Shape::convex_polygon(vec![tip, left, right], stroke_color, Stroke::NONE));
            // the account on the edge, like Neo4j's relationship caption
            if self.style.caption != Caption::None && (z > 0.6 || lit) && (pa - pb).length() > 90.0 {
                let caption = self.edge_caption(e);
                if !caption.is_empty() {
                    let mid = bez(pa, pc, pb, 0.5);
                    let font = FontId::proportional((10.0 * z.sqrt() * self.style.font_scale).clamp(7.0, 16.0));
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
            let mut r = self.layout.radius[i] * z * self.style.node_scale;
            if !canvas.expand(r * 2.0).contains(p) {
                continue;
            }
            let raw_name = self.store.hosts.name(n.host).to_string();
            let is_ip = crate::load_neo4j::looks_like_ip(&raw_name);
            let shown_name = if self.presenting && self.story.anonymise { self.anon.host(n.host, is_ip) } else { raw_name.clone() };
            let name = shown_name.as_str();
            let lit = lit_nodes.contains(&i);
            let alpha = if dimmed && !lit { 0.18 } else { 1.0 };
            // a host that has just appeared in a presentation pops a little
            if self.presenting {
                if let (_, Some((a, b, p))) = self.reveal() {
                    if n.first_event >= a && n.first_event < b {
                        r *= 1.0 + 0.35 * (1.0 - ((p - 0.45) / 0.55).clamp(0.0, 1.0));
                    }
                }
            }
            let (mut fill, mut ring) = if self.style.shapes_by_role {
                match n.role {
                    Role::DomainController => (Color32::from_rgb(201, 144, 192), Color32::from_rgb(160, 100, 150)),
                    Role::External => (IP_FILL, IP_RING),
                    Role::Server => (Color32::from_rgb(76, 142, 218), Color32::from_rgb(50, 105, 175)),
                    _ => if is_ip { (IP_FILL, IP_RING) } else { (HOST_FILL, HOST_RING) },
                }
            } else if is_ip {
                (IP_FILL, IP_RING)
            } else {
                (HOST_FILL, HOST_RING)
            };
            let mut shape = if self.style.shapes_by_role {
                match n.role {
                    Role::DomainController => Shape::Hexagon,
                    Role::External => Shape::Diamond,
                    Role::Server => Shape::Square,
                    _ => Shape::Circle,
                }
            } else {
                Shape::Circle
            };
            let mut glow = false;
            if let Some((ri, _)) = rules.iter().filter(|(ri, _)| self.style.rules[*ri].field.on_nodes()).find(|(ri, pats)| self.rule_hits_node(&self.style.rules[*ri], pats, i)) {
                let rule = &self.style.rules[*ri];
                if rule.hide {
                    continue;
                }
                if let Some(c) = rule.color {
                    fill = Color32::from_rgb(c[0], c[1], c[2]);
                    ring = Color32::from_rgb((c[0] as f32 * 0.75) as u8, (c[1] as f32 * 0.75) as u8, (c[2] as f32 * 0.75) as u8);
                }
                if let Some(sh) = rule.shape {
                    shape = sh;
                }
                r *= rule.size;
                glow = rule.glow;
            }
            let ring = if n.hunt_rank == 0 { SIGNIFICANT } else { ring };
            let selected = self.selected == Some(Sel::Node(i));
            if glow {
                draw_shape(&painter, shape, p, r + 9.0 * z.sqrt(), dim(fill, 0.22 * alpha), None);
            }
            if selected || self.hovered == Some(Sel::Node(i)) {
                draw_shape(&painter, shape, p, r + 6.0, dim(if selected { ACCENT } else { Color32::WHITE }, 0.25), None);
            }
            draw_shape(&painter, shape, p, r, dim(fill, alpha), Some(Stroke::new((2.5 * z).clamp(1.0, 4.0) * if n.hunt_rank == 0 { 1.8 } else { 1.0 }, dim(ring, alpha))));
            if r > 8.0 {
                let chars = name.chars().count().max(1) as f32;
                let wanted = (11.0 * z.sqrt() * self.style.font_scale).clamp(7.0, 18.0);
                let fits = (r * 1.8) / (chars * 0.56);
                let font_size = wanted.min(fits).max(6.5);
                let max_chars = ((r * 1.8) / (font_size * 0.56)).floor().max(3.0) as usize;
                let caption: String = if name.chars().count() > max_chars { format!("{}…", name.chars().take(max_chars.saturating_sub(1)).collect::<String>()) } else { name.to_string() };
                if font_size >= 6.5 {
                    painter.text(p, Align2::CENTER_CENTER, caption, FontId::proportional(font_size), dim(Color32::from_rgb(20, 24, 30), alpha));
                }
            }
            if let Some(label) = self.overlay.as_ref().and_then(|o| o.labels.get(&n.host)) {
                let galley = painter.layout_no_wrap(label.clone(), FontId::proportional((10.5 * z.sqrt() * self.style.font_scale).clamp(8.0, 14.0)), ACCENT);
                let rr = Rect::from_center_size(Pos2::new(p.x, p.y + r + 10.0 + galley.size().y / 2.0), galley.size() + Vec2::new(8.0, 3.0));
                painter.rect_filled(rr, CornerRadius::same(3), dim(CAPTION_BG, alpha));
                painter.galley(rr.min + Vec2::new(4.0, 1.5), galley, ACCENT);
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
        let mut x = canvas.left() + 12.0;
        let y = y + 30.0;
        for (text, c, n) in self.legend_chips() {
            let galley = painter.layout_no_wrap(format!("{} ({})", text, n), FontId::proportional(11.0), TEXT);
            let r = Rect::from_min_size(Pos2::new(x, y), galley.size() + Vec2::new(14.0, 6.0));
            painter.rect_filled(r, CornerRadius::same(12), Color32::from_rgb(44, 48, 58));
            painter.rect_stroke(r, CornerRadius::same(12), Stroke::new(1.5, c), egui::StrokeKind::Inside);
            painter.galley(r.min + Vec2::new(7.0, 3.0), galley, TEXT);
            x += r.width() + 6.0;
        }
        // zoom hint, bottom right
        if !self.presenting {
            painter.text(Pos2::new(canvas.right() - 10.0, canvas.bottom() - 8.0), Align2::RIGHT_BOTTOM, format!("{:.0} %", self.zoom * 100.0), FontId::proportional(11.0), MUTED);
        } else {
            self.presentation_overlays(&painter, canvas);
        }
    }

    fn presentation_overlays(&mut self, painter: &egui::Painter, canvas: Rect) {
        let fs = self.style.font_scale;
        if !self.story.title.is_empty() {
            painter.text(Pos2::new(canvas.center().x, canvas.top() + 16.0), Align2::CENTER_TOP, &self.story.title, FontId::proportional(22.0 * fs), TEXT);
        }
        let cur = self.current_step();
        if let Some(k) = cur {
            let st = self.steps[k].clone();
            if self.story.show_clock {
                let t = fmt_time(st.t);
                let galley = painter.layout_no_wrap(t, FontId::monospace(20.0 * fs), TEXT);
                let r = Rect::from_min_size(Pos2::new(canvas.right() - galley.size().x - 26.0, canvas.top() + 12.0), galley.size() + Vec2::new(16.0, 8.0));
                painter.rect_filled(r, CornerRadius::same(6), CAPTION_BG);
                painter.galley(r.min + Vec2::new(8.0, 4.0), galley, TEXT);
            }
            if self.story.show_counter {
                painter.text(Pos2::new(canvas.right() - 12.0, canvas.bottom() - 10.0), Align2::RIGHT_BOTTOM, format!("{} / {}", k + 1, self.steps.len()), FontId::proportional(12.0 * fs), MUTED);
            }
            if self.story.show_caption {
                let text = match &st.caption {
                    Some(c) => c.clone(),
                    None => {
                        let ei = self.graph.events[st.from] as usize;
                        let e = self.store.edges[ei];
                        let src = self.host_label(e.src);
                        let dst = self.host_label(e.dst);
                        let user = self.user_label(e.user);
                        let n = st.to - st.from;
                        let more = if n > 1 { format!("  (+{} more)", n - 1) } else { String::new() };
                        format!("{}  ·  {}  ·  {}  ->  {}{}", &fmt_time(e.t)[11..], if user.is_empty() { "(no account)".to_string() } else { user }, src, dst, more).replace("  ·  (no account)", "")
                    }
                };
                let galley = painter.layout_no_wrap(text, FontId::proportional(18.0 * fs), TEXT);
                let r = Rect::from_center_size(Pos2::new(canvas.center().x, canvas.bottom() - 34.0), galley.size() + Vec2::new(28.0, 14.0));
                painter.rect_filled(r, CornerRadius::same(8), Color32::from_rgba_premultiplied(24, 26, 31, 225));
                if st.significant || st.emphasis {
                    painter.rect_stroke(r, CornerRadius::same(8), Stroke::new(1.5, if st.significant { SIGNIFICANT } else { ACCENT }), egui::StrokeKind::Inside);
                }
                painter.galley(r.min + Vec2::new(14.0, 7.0), galley, TEXT);
            }
        }
        match &self.export {
            None => {
                painter.text(Pos2::new(canvas.left() + 12.0, canvas.bottom() - 10.0), Align2::LEFT_BOTTOM, "Space pause  ·  Left / Right step  ·  Esc leave", FontId::proportional(11.0), MUTED);
            }
            Some(job) if job.rec.finishing() => {
                let galley = painter.layout_no_wrap(format!("finishing {} frames in {}…", job.total, job.out.display()), FontId::proportional(16.0), TEXT);
                let r = Rect::from_center_size(canvas.center(), galley.size() + Vec2::new(40.0, 24.0));
                painter.rect_filled(r, CornerRadius::same(8), Color32::from_rgba_premultiplied(24, 26, 31, 235));
                painter.rect_stroke(r, CornerRadius::same(8), Stroke::new(1.5, ACCENT), egui::StrokeKind::Inside);
                painter.galley(r.min + Vec2::new(20.0, 12.0), galley, TEXT);
            }
            Some(job) => {
                painter.text(Pos2::new(canvas.left() + 12.0, canvas.bottom() - 10.0), Align2::LEFT_BOTTOM, format!("recording frame {} / {} at {} fps", job.next, job.total, job.fps), FontId::proportional(11.0), MUTED);
            }
        }
    }

    // ───────────────────────── paths, cones, questions ─────────────────────────

    /// The host a typed name means: an exact name or alias first, else the
    /// first pattern match.
    fn host_named(&self, text: &str) -> Option<u32> {
        let t = text.trim();
        if t.is_empty() {
            return None;
        }
        let up = t.to_uppercase();
        if let Some(h) = self.store.hosts.get(&up) {
            return Some(h);
        }
        if let Some((h, _)) = self.store.aliases.iter().enumerate().find(|(_, al)| al.iter().any(|a| a.eq_ignore_ascii_case(t))) {
            return Some(h as u32);
        }
        self.store.hosts_matching(&Pattern::parse_list(t)).into_iter().next()
    }

    fn path_query(&self, origin: u32, dest: u32) -> PathQuery {
        PathQuery {
            origin,
            dest,
            from: super::query::parse_time(&self.filter.from),
            to: super::query::parse_time(&self.filter.to),
            max_hops: self.path_hops.max(1),
            max_gap: (self.path_gap_h.max(0.01) * 3600.0) as i64,
            max_paths: self.path_max.max(1),
            results: self.path_results,
            skip_machine_accounts: self.path_skip_machine,
        }
    }

    fn run_paths(&mut self) {
        let (Some(o), Some(d)) = (self.host_named(&self.path_origin), self.host_named(&self.path_dest)) else {
            self.path_msg = "name an origin and a destination the timeline knows".into();
            return;
        };
        let q = self.path_query(o, d);
        self.path_found = paths::find_paths(&self.store, &q);
        if self.path_found.is_empty() {
            self.path_msg = format!("no time-respecting path from {} to {} within {} hops and {:.1} h per hop", self.store.hosts.name(o), self.store.hosts.name(d), q.max_hops, self.path_gap_h);
            return;
        }
        self.path_msg = format!("{} path(s), shortest first", self.path_found.len());
        let all: Vec<u32> = self.path_found.iter().flat_map(|p| p.edges.iter().copied()).collect();
        let hops = self.hops_along(&self.path_found);
        let labels = hops.iter().map(|(h, k)| (*h, if *k == 0 { "origin".to_string() } else { format!("hop {}", k) })).collect();
        self.set_overlay(format!("{} path(s) {} -> {}", self.path_found.len(), self.store.hosts.name(o), self.store.hosts.name(d)), all, labels, hops);
    }

    fn hops_along(&self, found: &[Path]) -> HashMap<u32, usize> {
        let mut hops: HashMap<u32, usize> = HashMap::new();
        for p in found {
            if let Some(&first) = p.edges.first() {
                hops.entry(self.store.edges[first as usize].src).or_insert(0);
            }
            for (k, &ei) in p.edges.iter().enumerate() {
                let e = &self.store.edges[ei as usize];
                hops.entry(e.dst).and_modify(|x| *x = (*x).min(k + 1)).or_insert(k + 1);
            }
        }
        hops
    }

    fn show_one_path(&mut self, i: usize) {
        if let Some(p) = self.path_found.get(i).cloned() {
            let hops = self.hops_along(std::slice::from_ref(&p));
            let labels = p.edges.iter().enumerate().map(|(k, &ei)| {
                let e = &self.store.edges[ei as usize];
                (e.dst, format!("hop {} · {}", k + 1, &fmt_time(e.t)[11..16]))
            }).chain(std::iter::once((self.store.edges[p.edges[0] as usize].src, "origin".to_string()))).collect();
            self.set_overlay(format!("path {} of {}", i + 1, self.path_found.len()), p.edges.clone(), labels, hops);
        }
    }

    fn run_cone(&mut self, forward: bool) {
        let field = if forward { self.path_origin.clone() } else { self.path_dest.clone() };
        let Some(h) = self.host_named(&field) else {
            self.path_msg = if forward { "name the origin of the cone".into() } else { "name the destination of the cone".into() };
            return;
        };
        let q = self.path_query(h, h);
        let reach = if forward {
            paths::forward_cone(&self.store, h, q.from.unwrap_or(self.store.t_min), &q)
        } else {
            paths::backward_cone(&self.store, h, q.to.unwrap_or(self.store.t_max), &q)
        };
        let edges: Vec<u32> = reach.values().filter_map(|r| r.via).collect();
        let labels: HashMap<u32, String> = reach.iter().map(|(host, r)| (*host, if r.hop == 0 { (if forward { "origin" } else { "destination" }).to_string() } else { format!("hop {} · {}", r.hop, &fmt_time(r.t)[5..16]) })).collect();
        let hops: HashMap<u32, usize> = reach.iter().map(|(host, r)| (*host, r.hop)).collect();
        self.path_found.clear();
        self.path_msg = format!("{} host(s) {} {} within {} hops", reach.len().saturating_sub(1), if forward { "reachable from" } else { "that could reach" }, self.store.hosts.name(h), q.max_hops);
        if edges.is_empty() {
            return;
        }
        self.set_overlay(format!("{} {}", if forward { "reach of" } else { "ways into" }, self.store.hosts.name(h)), edges, labels, hops);
    }

    fn set_overlay(&mut self, title: String, edges: Vec<u32>, labels: HashMap<u32, String>, hops: HashMap<u32, usize>) {
        self.overlay = Some(Overlay { title, edges, labels, hops });
        self.requery(true);
        self.arrange_by_hops();
    }

    /// Hosts in columns by hop, pinned, so a path reads left to right.
    fn arrange_by_hops(&mut self) {
        let Some(o) = &self.overlay else { return };
        let mut per_hop: HashMap<usize, Vec<usize>> = HashMap::new();
        for (i, n) in self.graph.nodes.iter().enumerate() {
            let k = o.hops.get(&n.host).copied().unwrap_or(0);
            per_hop.entry(k).or_default().push(i);
        }
        for (k, idx) in per_hop {
            let n = idx.len() as f32;
            for (j, i) in idx.into_iter().enumerate() {
                let y = (j as f32 - (n - 1.0) / 2.0) * 110.0;
                self.layout.pos[i] = V2::new(k as f32 * 240.0, y);
                self.layout.fixed[i] = true;
            }
        }
        self.layout.stop();
        self.fit_pending = true;
    }

    fn paths_window(&mut self, ctx: &egui::Context) {
        if !self.show_paths {
            return;
        }
        let mut open = true;
        let mut find = false;
        let mut cone: Option<bool> = None;
        let mut pick: Option<usize> = None;
        egui::Window::new("Paths").open(&mut open).default_width(560.0).resizable(true).show(ctx, |ui| {
            ui.label(egui::RichText::new("A path is a chain of logins where every hop happens after the previous one and no later than the gap allowed; no host is entered twice. The cones say what a host could reach from the window's start, or what could have reached it by the window's end.").color(MUTED));
            egui::Grid::new("paths-form").num_columns(4).spacing([10.0, 6.0]).show(ui, |ui| {
                ui.label("Origin");
                let r = ui.add_sized([200.0, 20.0], egui::TextEdit::singleline(&mut self.path_origin).hint_text("host or IP"));
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    find = true;
                }
                ui.label("Destination");
                let r = ui.add_sized([200.0, 20.0], egui::TextEdit::singleline(&mut self.path_dest).hint_text("host or IP"));
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    find = true;
                }
                ui.end_row();
                ui.label("Max hops");
                ui.add(egui::DragValue::new(&mut self.path_hops).range(1..=12));
                ui.label("Max gap per hop (h)");
                ui.add(egui::DragValue::new(&mut self.path_gap_h).range(0.05..=24.0 * 90.0).speed(0.5).fixed_decimals(1));
                ui.end_row();
                ui.label("Max paths");
                ui.add(egui::DragValue::new(&mut self.path_max).range(1..=2000).speed(1));
                ui.label("Hops are");
                ui.horizontal(|ui| {
                    for (i, name) in RESULT_NAMES.iter().enumerate() {
                        if ui.add(egui::Button::selectable(self.path_results[i], *name)).clicked() {
                            self.path_results[i] = !self.path_results[i];
                        }
                    }
                    ui.checkbox(&mut self.path_skip_machine, "no machine accounts");
                });
                ui.end_row();
            });
            ui.label(egui::RichText::new(format!("Time window: the bar's From / To ({} → {})", if self.filter.from.is_empty() { "start" } else { &self.filter.from }, if self.filter.to.is_empty() { "end" } else { &self.filter.to })).small().color(MUTED));
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new(egui::RichText::new("Find paths").strong().color(Color32::from_rgb(30, 24, 8))).fill(ACCENT)).clicked() {
                    find = true;
                }
                if ui.button("Reach from origin").on_hover_text("earliest-arrival cone forward in time").clicked() {
                    cone = Some(true);
                }
                if ui.button("Ways into destination").on_hover_text("cone backward in time").clicked() {
                    cone = Some(false);
                }
                if self.overlay.is_some() && ui.button("Back to the view").clicked() {
                    self.overlay = None;
                    self.path_found.clear();
                    self.path_msg.clear();
                    self.requery(false);
                }
            });
            if !self.path_msg.is_empty() {
                ui.label(egui::RichText::new(&self.path_msg).color(if self.path_found.is_empty() && self.overlay.is_none() { CANDIDATE } else { TEXT }));
            }
            if !self.path_found.is_empty() {
                ui.separator();
                egui::ScrollArea::vertical().max_height(320.0).auto_shrink([false, true]).show(ui, |ui| {
                    for (i, p) in self.path_found.iter().enumerate() {
                        let mut text = String::new();
                        if let Some(&first) = p.edges.first() {
                            text.push_str(self.store.hosts.name(self.store.edges[first as usize].src));
                        }
                        for &ei in &p.edges {
                            let e = &self.store.edges[ei as usize];
                            let u = self.store.users.name(e.user);
                            text.push_str(&format!("  -({}{})->  {}", if u.is_empty() { "?" } else { u }, &fmt_time(e.t)[10..16].replace(' ', " "), self.store.hosts.name(e.dst)));
                        }
                        let span = p.span(&self.store);
                        let label = format!("{}.  {} hop(s) · {}  ·  {}", i + 1, p.hops(), if span >= 3600 { format!("{:.1} h", span as f32 / 3600.0) } else { format!("{} min", span / 60) }, text);
                        if ui.add(egui::Button::new(egui::RichText::new(label).small()).frame(false).wrap()).clicked() {
                            pick = Some(i);
                        }
                    }
                });
            }
        });
        if find {
            self.run_paths();
        }
        if let Some(f) = cone {
            self.run_cone(f);
        }
        if let Some(i) = pick {
            self.show_one_path(i);
        }
        if !open {
            self.show_paths = false;
        }
    }

    fn questions_window(&mut self, ctx: &egui::Context) {
        if !self.show_questions {
            return;
        }
        let mut open = true;
        let mut focus: Option<String> = None;
        egui::Window::new("Questions about this view").open(&mut open).default_width(720.0).default_height(560.0).resizable(true).show(ctx, |ui| {
            ui.label(egui::RichText::new(format!("Over the {} rows the view holds. Click a host to open its neighbourhood.", self.graph.events.len())).color(MUTED));
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                let qs = paths::questions(&self.store, &self.graph.events, 10);
                for (qi, q) in qs.iter().enumerate() {
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new(q.title).strong());
                    egui::Grid::new(("q", qi)).striped(true).spacing([12.0, 3.0]).show(ui, |ui| {
                        for c in q.columns {
                            ui.label(egui::RichText::new(c).small().color(MUTED));
                        }
                        ui.end_row();
                        for (a, b, c) in &q.rows {
                            if ui.add(egui::Button::new(egui::RichText::new(a).small()).frame(false)).clicked() {
                                focus = Some(a.split(" -> ").next().unwrap_or(a).to_string());
                            }
                            ui.label(egui::RichText::new(b).small());
                            ui.label(egui::RichText::new(c).small());
                            ui.end_row();
                        }
                    });
                }
                ui.add_space(6.0);
                ui.label(egui::RichText::new("Centrality (PageRank, betweenness, distinct in / out)").strong());
                let ranks = paths::ranking(&self.store, &self.graph.events);
                egui::Grid::new("rank").striped(true).spacing([12.0, 3.0]).show(ui, |ui| {
                    for c in ["host", "pagerank", "betweenness", "in", "out"] {
                        ui.label(egui::RichText::new(c).small().color(MUTED));
                    }
                    ui.end_row();
                    for r in ranks.iter().take(15) {
                        let n = self.store.hosts.name(r.host).to_string();
                        if ui.add(egui::Button::new(egui::RichText::new(&n).small()).frame(false)).clicked() {
                            focus = Some(n.clone());
                        }
                        ui.label(egui::RichText::new(format!("{:.4}", r.pagerank)).small());
                        ui.label(egui::RichText::new(format!("{:.4}", r.betweenness)).small());
                        ui.label(egui::RichText::new(r.inn.to_string()).small());
                        ui.label(egui::RichText::new(r.out.to_string()).small());
                        ui.end_row();
                    }
                });
            });
        });
        if let Some(h) = focus {
            self.overlay = None;
            self.draft.view = View::Around;
            self.draft.around = h;
            self.requery(false);
        }
        if !open {
            self.show_questions = false;
        }
    }

    // ───────────────────────── story editor & export ─────────────────────────

    fn story_window(&mut self, ctx: &egui::Context) {
        if !self.show_story {
            return;
        }
        if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
            eprintln!("[view] story window drawn, {} steps", self.steps.len());
        }
        let mut open = true;
        let mut changed = false;
        let mut start = false;
        let mut preview: Option<usize> = None;
        egui::Window::new("Story").open(&mut open).default_width(820.0).default_height(560.0).resizable(true).show(ctx, |ui| {
            ui.label(egui::RichText::new("The view replayed in time order, one step per row (or per burst of rows close in time). Every setting here is saved next to the timeline; Present plays it full screen, Record writes it as a video.").color(MUTED));
            egui::Grid::new("story-globals").num_columns(6).spacing([10.0, 6.0]).show(ui, |ui| {
                ui.label("Title");
                changed |= ui.add_sized([260.0, 20.0], egui::TextEdit::singleline(&mut self.story.title).hint_text("shown at the top")).changed();
                ui.label("Timing");
                egui::ComboBox::from_id_salt("timing").selected_text(match self.story.timing { Timing::Fixed => "same time per step", Timing::Compressed => "real gaps, compressed" }).show_ui(ui, |ui| {
                    changed |= ui.selectable_value(&mut self.story.timing, Timing::Fixed, "same time per step").changed();
                    changed |= ui.selectable_value(&mut self.story.timing, Timing::Compressed, "real gaps, compressed").changed();
                });
                ui.label("Seconds per step");
                changed |= ui.add(egui::DragValue::new(&mut self.story.step_secs).range(0.1..=20.0).speed(0.05).fixed_decimals(2)).changed();
                ui.end_row();
                ui.label("Compress by");
                changed |= ui.add_enabled(self.story.timing == Timing::Compressed, egui::DragValue::new(&mut self.story.compress).range(1.0..=100000.0).speed(10.0)).on_hover_text("real seconds between rows divided by this").changed();
                ui.label("Gap min / max (s)");
                ui.horizontal(|ui| {
                    changed |= ui.add_enabled(self.story.timing == Timing::Compressed, egui::DragValue::new(&mut self.story.min_gap).range(0.05..=10.0).speed(0.05).fixed_decimals(2)).changed();
                    changed |= ui.add_enabled(self.story.timing == Timing::Compressed, egui::DragValue::new(&mut self.story.max_gap).range(0.1..=60.0).speed(0.1).fixed_decimals(1)).changed();
                });
                ui.label("Group rows within (s)");
                changed |= ui.add(egui::DragValue::new(&mut self.story.group_secs).range(0.0..=3600.0).speed(0.5).fixed_decimals(1)).on_hover_text("rows this close in time appear together as one step").changed();
                ui.end_row();
                ui.label("Pause on significant (s)");
                changed |= ui.add(egui::DragValue::new(&mut self.story.pause_significant).range(0.0..=30.0).speed(0.1).fixed_decimals(1)).changed();
                ui.label("Hold the end (s)");
                changed |= ui.add(egui::DragValue::new(&mut self.story.hold_end).range(0.0..=60.0).speed(0.1).fixed_decimals(1)).changed();
                ui.label("");
                ui.horizontal(|ui| {
                    changed |= ui.checkbox(&mut self.story.fade_old, "fade older").changed();
                    changed |= ui.checkbox(&mut self.story.show_clock, "clock").changed();
                    changed |= ui.checkbox(&mut self.story.show_caption, "caption").changed();
                    changed |= ui.checkbox(&mut self.story.show_counter, "counter").changed();
                    changed |= ui.checkbox(&mut self.story.anonymise, "anonymise").on_hover_text("HOST-01, user-02, 10.x.x.3: consistent stand-ins for a talk").changed();
                });
                ui.end_row();
            });
            if changed {
                self.rebuild_steps();
            }
            let total = present::total_secs(&self.steps, &self.story);
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new(egui::RichText::new("Present").strong().color(Color32::from_rgb(30, 24, 8))).fill(ACCENT)).clicked() {
                    start = true;
                }
                if ui.button("Record…").clicked() {
                    self.show_export = true;
                    if self.export_name.is_empty() {
                        let stem = std::path::Path::new(&self.files[0]).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "timeline".into());
                        self.export_name = format!("{}-story", stem);
                    }
                }
                ui.label(egui::RichText::new(format!("{} steps · {} rows · {:.0} s", self.steps.len(), self.graph.events.len(), total)).color(MUTED));
                ui.label(egui::RichText::new(self.story_path.to_string_lossy()).small().color(MUTED));
            });
            ui.separator();
            ui.label(egui::RichText::new("STEPS   (click a row to see the graph at that moment; a blank duration means the global one)").small().color(MUTED));
            let n_steps = self.steps.len();
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                egui::Grid::new("steps").striped(true).num_columns(9).spacing([8.0, 4.0]).show(ui, |ui| {
                    for h in ["#", "time", "what", "s", "pause", "caption", "skip", "emph", ""] {
                        ui.label(egui::RichText::new(h).small().color(MUTED));
                    }
                    ui.end_row();
                    for k in 0..n_steps {
                        let st = self.steps[k].clone();
                        let ei = self.graph.events[st.from] as usize;
                        let e = self.store.edges[ei];
                        let what = format!("{} -> {} as {}{}", self.store.hosts.name(e.src), self.store.hosts.name(e.dst), self.store.users.name(e.user), if st.to - st.from > 1 { format!(" (+{})", st.to - st.from - 1) } else { String::new() });
                        if ui.add(egui::Button::new(egui::RichText::new(format!("{}", k + 1)).small()).frame(false)).clicked() {
                            preview = Some(k);
                        }
                        ui.label(egui::RichText::new(&fmt_time(st.t)[5..]).small().monospace());
                        let mut rt = egui::RichText::new(if what.chars().count() > 46 { format!("{}…", what.chars().take(45).collect::<String>()) } else { what.clone() }).small();
                        if st.significant {
                            rt = rt.color(SIGNIFICANT);
                        }
                        ui.label(rt).on_hover_text(what);
                        let ov = self.story.steps.entry(st.key.clone()).or_default();
                        let mut secs = ov.secs.unwrap_or(0.0);
                        if ui.add(egui::DragValue::new(&mut secs).range(0.0..=60.0).speed(0.05).fixed_decimals(2)).changed() {
                            ov.secs = if secs <= 0.0 { None } else { Some(secs) };
                            changed = true;
                        }
                        changed |= ui.add(egui::DragValue::new(&mut ov.pause_after).range(0.0..=60.0).speed(0.1).fixed_decimals(1)).changed();
                        let mut cap = ov.caption.clone().unwrap_or_default();
                        if ui.add_sized([220.0, 20.0], egui::TextEdit::singleline(&mut cap).hint_text("own caption")).changed() {
                            ov.caption = if cap.trim().is_empty() { None } else { Some(cap) };
                            changed = true;
                        }
                        changed |= ui.checkbox(&mut ov.skip, "").changed();
                        changed |= ui.checkbox(&mut ov.emphasis, "").changed();
                        if *ov == StepOverride::default() {
                            self.story.steps.remove(&st.key);
                        }
                        ui.label("");
                        ui.end_row();
                    }
                });
            });
        });
        if changed {
            self.rebuild_steps();
            self.save_story();
        }
        if let Some(k) = preview {
            if k < self.steps.len() {
                self.presenting = false;
                self.cursor = self.steps[k].to;
            }
        }
        if start {
            self.start_presentation();
        }
        if !open {
            self.show_story = false;
        }
    }

    fn export_window(&mut self, ctx: &egui::Context) {
        if !self.show_export {
            return;
        }
        if self.ffmpeg.is_none() {
            self.ffmpeg = Some(present::ffmpeg_available());
        }
        let ffmpeg = self.ffmpeg.unwrap_or(false);
        let mut open = true;
        let mut start = false;
        egui::Window::new("Record the story").open(&mut open).collapsible(false).resizable(false).anchor(Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.label(egui::RichText::new("Every frame is a screenshot of this window while the story plays, so the file shows exactly what you see. Leave the window alone while it records.").color(MUTED));
            ui.horizontal(|ui| {
                ui.label("Format");
                for f in [Format::Gif, Format::Png, Format::Mp4] {
                    let enabled = f != Format::Mp4 || ffmpeg;
                    if ui.add_enabled(enabled, egui::Button::selectable(self.export_format == f, f.label())).on_disabled_hover_text("ffmpeg was not found on the PATH; record PNG frames and encode them yourself, or install ffmpeg").clicked() {
                        self.export_format = f;
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("Frames per second");
                for f in [10u32, 15, 24, 30, 60] {
                    if ui.add(egui::Button::selectable(self.export_fps == f, f.to_string())).clicked() {
                        self.export_fps = f;
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("Size");
                for (i, name) in ["this window", "1280 x 720", "1920 x 1080"].iter().enumerate() {
                    if ui.add(egui::Button::selectable(self.export_size == i, *name)).clicked() {
                        self.export_size = i;
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("File");
                ui.add(egui::TextEdit::singleline(&mut self.export_name).desired_width(240.0));
                let ext = match self.export_format {
                    Format::Gif => ".gif",
                    Format::Png => "/ (a folder of frames)",
                    Format::Mp4 => ".mp4",
                };
                ui.label(egui::RichText::new(format!("{}  next to the timeline", ext)).color(MUTED));
            });
            let total = present::total_secs(&self.steps, &self.story);
            let frames = (total * self.export_fps as f32).ceil() as usize;
            ui.label(egui::RichText::new(format!("{:.0} s · {} frames", total, frames)).color(MUTED));
            ui.horizontal(|ui| {
                if ui.add_enabled(!self.export_name.trim().is_empty() && !self.steps.is_empty(), egui::Button::new(egui::RichText::new("Record").strong().color(Color32::from_rgb(30, 24, 8))).fill(ACCENT)).clicked() {
                    start = true;
                }
                if ui.button("Cancel").clicked() {
                    self.show_export = false;
                }
            });
        });
        if !open {
            self.show_export = false;
        }
        if start {
            self.start_export(ctx);
        }
    }

    /// Begin recording the story with the export settings.
    fn start_export(&mut self, ctx: &egui::Context) {
        self.show_export = false;
        self.show_story = false;
        self.rebuild_steps();
        if self.export_name.trim().is_empty() {
            let stem = std::path::Path::new(&self.files[0]).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "timeline".into());
            self.export_name = format!("{}-story", stem);
        }
        let dir = std::path::Path::new(&self.files[0]).parent().map(|p| p.to_path_buf()).unwrap_or_default();
        let name = self.export_name.trim().to_string();
        let out = match self.export_format {
            Format::Gif => dir.join(format!("{}.gif", name)),
            Format::Png => dir.join(name),
            Format::Mp4 => dir.join(format!("{}.mp4", name)),
        };
        let total = present::total_secs(&self.steps, &self.story);
        let frames = ((total * self.export_fps as f32).ceil() as usize).max(1);
        let (tx, rx) = std::sync::mpsc::channel();
        let restore = match self.export_size {
            1 => Some(Vec2::new(1280.0, 720.0)),
            2 => Some(Vec2::new(1920.0, 1080.0)),
            _ => None,
        };
        let current = ctx.input(|i| i.viewport().inner_rect.map(|r| r.size()));
        if let Some(size) = restore {
            let ppp = ctx.pixels_per_point();
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size / ppp));
        }
        if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
            eprintln!("[view] recording {} frames at {} fps to {}", frames, self.export_fps, out.display());
        }
        let rec = present::Recorder::start(self.export_fps, self.export_format, out.clone());
        self.export = Some(ExportJob { fps: self.export_fps, out, total: frames, next: 0, waiting: false, rx, tx, restore: if restore.is_some() { current } else { None }, rec });
        self.start_presentation();
        self.present_playing = false;
    }

    /// `MASSTIN_VIEW_AUTO="story,record=gif:10:0,quit"`: actions run one
    /// per second once the window is up, for tests and demos. Actions:
    /// present, story, rules, fit, record=FORMAT:FPS:SIZE (gif | png | mp4;
    /// size 0 window, 1 720p, 2 1080p), quit.
    fn autopilot(&mut self, ctx: &egui::Context) {
        if self.auto.is_empty() || self.export.is_some() {
            return;
        }
        let now = std::time::Instant::now();
        if now < self.auto_next {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
            return;
        }
        self.auto_next = now + std::time::Duration::from_secs(1);
        let cmd = self.auto.remove(0);
        if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
            eprintln!("[view] auto: {}", cmd);
        }
        match cmd.as_str() {
            "present" => self.start_presentation(),
            "story" => self.show_story = true,
            "rules" => self.show_rules = true,
            "fit" => self.fit_pending = true,
            "questions" => self.show_questions = true,
            "quit" => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            other if other.starts_with("paths=") => {
                let spec = &other["paths=".len()..];
                let mut it = spec.splitn(3, ':');
                self.path_origin = it.next().unwrap_or("").to_string();
                self.path_dest = it.next().unwrap_or("").to_string();
                if let Some(g) = it.next().and_then(|g| g.parse::<f32>().ok()) {
                    self.path_gap_h = g;
                }
                self.show_paths = true;
                self.run_paths();
            }
            other if other.starts_with("cone=") => {
                self.path_origin = other["cone=".len()..].to_string();
                self.show_paths = true;
                self.run_cone(true);
            }
            other => {
                if let Some(spec) = other.strip_prefix("record=") {
                    let parts: Vec<&str> = spec.split(':').collect();
                    self.export_format = match parts.first().copied().unwrap_or("gif") {
                        "png" => Format::Png,
                        "mp4" => Format::Mp4,
                        _ => Format::Gif,
                    };
                    self.export_fps = parts.get(1).and_then(|f| f.parse().ok()).unwrap_or(15);
                    self.export_size = parts.get(2).and_then(|f| f.parse().ok()).unwrap_or(0);
                    self.start_export(ctx);
                } else {
                    eprintln!("masstin: unknown MASSTIN_VIEW_AUTO action '{}'", other);
                }
            }
        }
        ctx.request_repaint();
    }

    /// Drive a recording: one frame per repaint, screenshot taken after
    /// the frame is drawn, encoding at the end.
    fn export_step(&mut self, ctx: &egui::Context) {
        let Some(job) = self.export.as_mut() else { return };
        if let Some(result) = job.rec.result() {
            let restore = job.restore;
            self.export = None;
            self.stop_presentation();
            if let Some(size) = restore {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
            }
            self.status = match result {
                Ok(m) => format!("Recorded: {}", m),
                Err(e) => format!("Recording failed: {}", e),
            };
            if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
                eprintln!("[view] {}", self.status);
            }
            return;
        }
        if job.waiting {
            match job.rx.try_recv() {
                Ok((i, img)) => {
                    if i == job.next {
                        job.rec.push(img);
                        job.next += 1;
                        job.waiting = false;
                    }
                }
                Err(_) => {}
            }
        }
        if job.rec.finishing() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
            return;
        }
        if !job.waiting {
            if job.next >= job.total {
                job.rec.finish();
            } else {
                // the frame about to be drawn
                self.present_t = job.next as f32 / job.fps as f32;
                let tx = job.tx.clone();
                let idx = job.next;
                job.waiting = true;
                ctx.request_screenshot(move |img| {
                    let _ = tx.send((idx, img));
                });
            }
        }
        ctx.request_repaint();
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
            let r = self.layout.radius[i] * self.zoom * self.style.node_scale;
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

impl Viewer {
    /// The chips under the host chips: the categories of the current
    /// "colour by", most frequent first.
    fn legend_chips(&self) -> Vec<(String, Color32, usize)> {
        let c3 = |c: [u8; 3]| Color32::from_rgb(c[0], c[1], c[2]);
        let mut counts: HashMap<(String, [u8; 4]), usize> = HashMap::new();
        for e in &self.graph.edges {
            let (text, color) = match self.style.color_by {
                ColorBy::Result => (RESULT_NAMES[e.result as usize].to_string(), result_color(e.result)),
                ColorBy::User => match e.user {
                    Some(u) => (self.store.users.name(u).to_string(), c3(palette_color(u))),
                    None => ("several accounts".to_string(), EDGE_OK),
                },
                ColorBy::LogonType => match e.logon_types.first() {
                    Some(&k) => (format!("type {}", self.store.logon_types.name(k)), c3(palette_color(k))),
                    None => ("no type".to_string(), EDGE_OK),
                },
                ColorBy::Hunt => ((if HUNT_NAMES[e.hunt as usize].is_empty() { "not hunted" } else { HUNT_NAMES[e.hunt as usize] }).to_string(), self.edge_base_color(e)),
                ColorBy::Verdict => ((if e.verdict() == 0 { "unmarked" } else { VERDICT_NAMES[e.verdict() as usize] }).to_string(), self.edge_base_color(e)),
            };
            *counts.entry((text, color.to_array())).or_insert(0) += 1;
        }
        let mut v: Vec<(String, Color32, usize)> = counts.into_iter().map(|((t, c), n)| (t, Color32::from_rgba_premultiplied(c[0], c[1], c[2], c[3]), n)).collect();
        v.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        v.truncate(10);
        v
    }
}

/// A host's shape: circle, rounded square, diamond or hexagon of
/// "radius" `r`, filled, with an optional ring.
fn draw_shape(painter: &egui::Painter, shape: Shape, c: Pos2, r: f32, fill: Color32, ring: Option<Stroke>) {
    match shape {
        Shape::Circle => {
            painter.circle_filled(c, r, fill);
            if let Some(s) = ring {
                painter.circle_stroke(c, r, s);
            }
        }
        Shape::Square => {
            let rect = Rect::from_center_size(c, Vec2::splat(r * 1.8));
            let cr = CornerRadius::same((r * 0.3).clamp(2.0, 40.0) as u8);
            painter.rect_filled(rect, cr, fill);
            if let Some(s) = ring {
                painter.rect_stroke(rect, cr, s, egui::StrokeKind::Inside);
            }
        }
        Shape::Diamond => {
            let pts = vec![Pos2::new(c.x, c.y - r * 1.15), Pos2::new(c.x + r * 1.15, c.y), Pos2::new(c.x, c.y + r * 1.15), Pos2::new(c.x - r * 1.15, c.y)];
            painter.add(egui::Shape::convex_polygon(pts, fill, ring.unwrap_or(Stroke::NONE)));
        }
        Shape::Hexagon => {
            let pts: Vec<Pos2> = (0..6).map(|k| {
                let a = std::f32::consts::PI / 3.0 * k as f32 + std::f32::consts::PI / 6.0;
                Pos2::new(c.x + r * 1.1 * a.cos(), c.y + r * 1.1 * a.sin())
            }).collect();
            painter.add(egui::Shape::convex_polygon(pts, fill, ring.unwrap_or(Stroke::NONE)));
        }
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
        self.autopilot(&ctx);
        if self.export.is_some() {
            self.export_step(&ctx);
        } else if self.presenting {
            if self.present_playing {
                self.present_t += dt;
                let total = present::total_secs(&self.steps, &self.story);
                if self.present_t >= total {
                    self.present_t = total;
                    self.present_playing = false;
                }
                ctx.request_repaint();
            }
            let (space, left, right, esc, home) = ctx.input(|i| (i.key_pressed(egui::Key::Space), i.key_pressed(egui::Key::ArrowLeft), i.key_pressed(egui::Key::ArrowRight), i.key_pressed(egui::Key::Escape), i.key_pressed(egui::Key::Home)));
            if space {
                self.present_playing = !self.present_playing;
            }
            if esc {
                self.stop_presentation();
            }
            if home {
                self.present_t = 0.0;
            }
            if right || left {
                let cur = present::at(&self.steps, self.present_t).map(|(k, _)| k).unwrap_or(0);
                let k = if right { (cur + 1).min(self.steps.len().saturating_sub(1)) } else { cur.saturating_sub(1) };
                if let Some(st) = self.steps.get(k) {
                    self.present_t = st.start + st.dur;
                }
                ctx.request_repaint();
            }
        }
        if self.presenting {
            egui::CentralPanel::default().frame(egui::Frame::new().fill(BG)).show(ui, |ui| self.canvas(ui));
            return;
        }
        egui::Panel::top("filters").frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::symmetric(12, 8))).show(ui, |ui| self.filter_bar(ui));
        egui::Panel::bottom("time").frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::symmetric(12, 8))).show(ui, |ui| self.time_bar(ui));
        egui::Panel::right("details").default_size(400.0).resizable(true).frame(egui::Frame::new().fill(PANEL).inner_margin(egui::Margin::same(12))).show(ui, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| self.details(ui));
        });
        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG)).show(ui, |ui| self.canvas(ui));
        self.rules_window(&ctx);
        self.save_popup(&ctx);
        self.story_window(&ctx);
        self.export_window(&ctx);
        self.paths_window(&ctx);
        self.questions_window(&ctx);
    }
}
