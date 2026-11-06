//! The window: filter bar on top, the graph in the middle, a details pane
//! on the right, the replay bar at the bottom.
//!
//! The graph is drawn as Neo4j Browser draws one: a host is a filled
//! circle with a darker ring and its name inside, an edge a thin line (a
//! curve when the pair has several) with an arrowhead at the destination
//! and the account written on it; hovering lights up a host and what
//! touches it, selecting opens it in the pane. The force layout runs while
//! warm and the analyst can drag any host.

mod chrome;
mod edge_style;
mod labels;
mod merge_hosts;
mod report;
mod subnets;
mod tasks;
mod ingest;
mod table;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use egui::{Align2, Color32, CornerRadius, FontId, Pos2, Rect, Sense, Stroke, Vec2};

use super::draw;
use super::layout::{Layout, V2};
use super::notes::{NoteTarget, Notes};
use super::query::{fmt_time, hunt_rank, parse_time, Filter, GEdge, GraphView, Role, View};
use super::theme;
use chrome::{Brush, ColorPick, Tab};
use edge_style::EdgeEdit;
use labels::HostEdit;
use merge_hosts::MergeHostsEdit;
use report::HuntReport;
use subnets::SubnetGroup;
use super::views::{LabelPos, NodeStyle};
use ingest::Ingest;
use tasks::{HuntForm, Job, MergeForm};
use super::store::{Pattern, Store, HUNT_NAMES, RESULT_NAMES, R_CONNECT, R_FAIL, R_LOGOFF, R_OK, VERDICT_NAMES};
use super::paths::{self, Path, PathQuery};
use super::present::{self, Anonymiser, Format, LogoPos, Step, StepOverride, Story, Timing};
use super::views::{builtin_views, palette_color, Caption, ColorBy, Field, Rule, SavedView, Shape, Style, ViewsFile};
use super::Options;

// ───────────────────────────── palette ──────────────────────────────────────
// Neo4j Browser's node colours, on a dark canvas.

const BG: Color32 = Color32::from_rgb(9, 12, 19);
const BG_CENTRE: Color32 = Color32::from_rgb(19, 24, 35);
const BORDER: Color32 = Color32::from_rgb(40, 46, 60);
const TEXT: Color32 = Color32::from_rgb(228, 232, 240);
const MUTED: Color32 = Color32::from_rgb(132, 142, 160);
const ACCENT: Color32 = Color32::from_rgb(255, 198, 88);
// hosts: quiet, by what they are; the hunt's red and orange stay the loud ones
const HOST_FILL: Color32 = Color32::from_rgb(86, 122, 176);
const HOST_RING: Color32 = Color32::from_rgb(158, 188, 228);
const IP_FILL: Color32 = Color32::from_rgb(150, 134, 108);
const IP_RING: Color32 = Color32::from_rgb(206, 190, 160);
const DC_FILL: Color32 = Color32::from_rgb(126, 100, 180);
const DC_RING: Color32 = Color32::from_rgb(186, 164, 226);
const SERVER_FILL: Color32 = Color32::from_rgb(50, 140, 148);
const SERVER_RING: Color32 = Color32::from_rgb(124, 200, 204);
const EXTERNAL_FILL: Color32 = Color32::from_rgb(178, 124, 62);
const EXTERNAL_RING: Color32 = Color32::from_rgb(226, 182, 118);
const SIGNIFICANT: Color32 = Color32::from_rgb(255, 92, 108);
const CANDIDATE: Color32 = Color32::from_rgb(255, 152, 86);
const SUSPICIOUS: Color32 = Color32::from_rgb(255, 99, 132);
const CONFIRMED: Color32 = Color32::from_rgb(206, 146, 212);
const BENIGN: Color32 = Color32::from_rgb(120, 214, 150);
const EDGE_OK: Color32 = Color32::from_rgb(158, 170, 190);
const EDGE_FAIL: Color32 = Color32::from_rgb(255, 92, 108);
const EDGE_CONNECT: Color32 = Color32::from_rgb(206, 146, 212);
const EDGE_LOGOFF: Color32 = Color32::from_rgb(104, 112, 130);
const CAPTION_BG: Color32 = Color32::from_rgba_premultiplied(12, 15, 22, 210);
const CHIP_BG: Color32 = Color32::from_rgba_premultiplied(16, 20, 30, 190);

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

/// What an edge looks like, resolved once per query and style: the rules
/// applied, its colour and width, which parallel curve of its pair it is.
struct EdgeLook {
    a: u32,
    b: u32,
    /// index among the edges of the pair, and how many there are
    fan: (u16, u16),
    color: Color32,
    width: f32,
    dashed: bool,
    glow: bool,
    hide: bool,
    /// significant or candidate
    finding: bool,
    verdict: Option<Color32>,
}

struct NodeLook {
    name: String,
    is_ip: bool,
    fill: Color32,
    ring: Color32,
    shape: Shape,
    size: f32,
    glow: bool,
    hide: bool,
    /// the drawn edges touching it
    edges: Vec<u32>,
    label_pos: LabelPos,
    /// text size multiplier of its own
    label_size: f32,
    label_bg: Option<Color32>,
    /// the glyph in the middle, when the style or the host asks for one
    icon: Option<&'static str>,
    /// the machine to draw, in the machines style or when the host's icon names one
    device: Option<super::devices::Device>,
}

#[derive(Default)]
struct Scene {
    fingerprint: String,
    graph_id: u64,
    edges: Vec<EdgeLook>,
    nodes: Vec<NodeLook>,
    /// the legend chips of the current "colour by"
    chips: Vec<(String, Color32, usize)>,
    n_ip: usize,
}

/// An edge's curve on screen this frame.
#[derive(Clone, Copy)]
struct EdgeGeom {
    a: Pos2,
    b: Pos2,
    c: Pos2,
    on_screen: bool,
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
    /// what was under the pointer when the button went down: a drag is only
    /// told from a click 6 points later, and by then (or a frame later, over a
    /// remote desktop) the pointer may be over another host or the background
    press_hit: Option<Sel>,
    /// where in the held host the pointer took it, so it does not jump
    drag_grab: V2,
    rows: Option<(usize, Vec<RowDetail>, usize)>,
    notes_draft: String,
    pending_verdict: Option<u8>,
    mark_msg: String,
    status: String,
    /// what draws the window: the OpenGL renderer / vendor / version, or the software rasteriser
    renderer_info: String,
    /// motion, glow, grid and spotlight off: a software renderer, or frames measured slow
    light_mode: bool,
    light_checked: bool,
    /// seconds and frames sampled while motion was on, to tell a slow renderer
    light_dt: (f32, u32),
    frames_seen: u64,
    /// the real time between the last two frames, not clamped (the HUD)
    frame_gap_ms: f32,
    /// when the last `ui` call ended: the time from there to the next one is eframe's (tessellate, render, present)
    ui_end: Option<std::time::Instant>,
    outside_ms: f32,
    inside_ms: f32,
    /// frames drawn since `fps_since`, for the debug log
    fps_count: u32,
    fps_since: std::time::Instant,
    // replay
    cursor: usize,
    playing: bool,
    /// replay speed in rows a second
    rate: f32,
    acc: f32,
    /// replay by the clock instead of by rows: timeline seconds a second
    rate_secs: Option<f32>,
    /// the replay head's place in timeline seconds when playing by the clock
    replay_t: f64,
    /// seconds a connection takes to draw itself from origin to destination
    /// in the replay (0: it just appears)
    replay_anim: f32,
    /// when each edge was revealed by the replay, for the drawing animation
    edge_born: Vec<f32>,
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
    /// Save the current filter… keeps the hosts' places too
    save_places: bool,
    /// a saved filter asked for: delete it once the analyst confirms
    confirm_delete: Option<String>,
    /// places to give the hosts on the next query (a saved view picked)
    restore_places: Option<Vec<(String, f32, f32)>>,
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
    film: Option<FilmJob>,
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
    // the scene cache, this frame's geometry, the camera's target, timing
    scene: Scene,
    graph_id: u64,
    geom: Vec<EdgeGeom>,
    edges_on_screen: usize,
    /// when each host appeared (seconds since `t0`), for its entrance
    born: Vec<f32>,
    t0: std::time::Instant,
    frame_dt: f32,
    frame_ms: f32,
    layout_ms: f32,
    draw_ms: f32,
    edges_ms: f32,
    nodes_ms: f32,
    bg_ms: f32,
    geom_ms: f32,
    hit_ms: f32,
    nodes_drawn: usize,
    edges_drawn: usize,
    hud: bool,
    bench: Option<(usize, Vec<(f32, f32, f32, f32, f32, f32, f32, f32)>)>,
    cam_t: V2,
    zoom_t: f32,
    /// 0 nothing focused, 1 the rest dimmed; glides between
    focus_t: f32,
    hist: Option<(usize, usize, i64, Vec<(u32, u32)>)>,
    hist_all: Option<(usize, usize, Vec<(u32, u32)>)>,
    /// the picture is stretched to the window's shape when the layout settles
    fill_pending: bool,
    /// the stretch in progress: from, to, when it started
    fill_anim: Option<(Vec<V2>, Vec<V2>, f32)>,
    // the chrome
    show_filters: bool,
    show_inspector: bool,
    show_hunt: bool,
    show_merge: bool,
    /// the timeline as a plain table
    show_table: bool,
    table_find: String,
    table_rows: Vec<u32>,
    table_key: (String, usize, usize),
    /// timelines opened lately, for the welcome and the menu
    recent: Vec<String>,
    show_help: bool,
    quick: String,
    focus_around: bool,
    auto_apply: bool,
    auto_apply_at: Option<std::time::Instant>,
    tab: Tab,
    brush: Option<Brush>,
    canvas_rect: Rect,
    ctx_target: Option<Sel>,
    color_pick: Option<ColorPick>,
    notes: Notes,
    note_draft: Option<(NoteTarget, String)>,
    mark_dialog: Option<MarkDialog>,
    /// the rows ticked in the inspector, to mark some and not the whole block
    row_pick: Vec<bool>,
    // work in progress: a child masstin, the hunt's reveal
    job: Option<Job>,
    hunt_form: HuntForm,
    /// the ingest wizard
    ingest: Ingest,
    merge_form: MergeForm,
    /// a hunt is running: a sweep crosses the canvas
    hunt_sweep: Option<std::time::Instant>,
    /// a hunt just ended: the findings appear one by one
    hunt_reveal: Option<std::time::Instant>,
    reveal_rank: Vec<f32>,
    /// `MASSTIN_VIEW_AUTO=hunt=…`: press Run as soon as the window opens
    hunt_autorun: bool,
    show_labels: bool,
    /// the dog, for the menu bar, and the whole logo for About
    logo_small: Option<egui::TextureHandle>,
    logo_full: Option<egui::TextureHandle>,
    logo_dog: Option<egui::TextureHandle>,
    /// the story's logo as loaded: path, texture, pixels
    brand: Option<(String, egui::TextureHandle, [usize; 2])>,
    /// the path that could not be read, and why
    brand_err: Option<(String, String)>,
    /// the height of the legend chips over the canvas, kept clear by Fit
    legend_h: f32,
    show_about: bool,
    /// the summary shown once the findings have lit up
    hunt_report: Option<HuntReport>,
    hunt_report_at: Option<std::time::Instant>,
    /// how many findings the summary lists, and what it is filtered by
    report_top: usize,
    report_find: String,
    host_edit: Option<HostEdit>,
    edge_edit: Option<EdgeEdit>,
    /// the analyst's merges, `(from, into)`, kept in the views file
    merges: Vec<(String, String)>,
    subnet_defs: Vec<(String, String)>,
    subnets: Vec<SubnetGroup>,
    subnet_of: Vec<Option<u16>>,
    show_subnets_window: bool,
    merge_edit: Option<MergeHostsEdit>,
    show_merges: bool,
    merge_add: (String, String),
    last_log: Option<(String, Vec<String>)>,
    show_last_log: bool,
}

/// A verdict about to be written: on every row of the connection, or on
/// the rows the analyst ticks.
struct MarkDialog {
    edge: usize,
    verdict: u8,
    whole: bool,
    picked: Vec<bool>,
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

/// A film of the window as it is used: a screenshot whenever a frame is
/// due at the chosen rate, in real time (a slow frame is held for the
/// slots it missed), streamed to the encoder until it is stopped.
struct FilmJob {
    fps: u32,
    started: std::time::Instant,
    pushed: usize,
    waiting: bool,
    rx: std::sync::mpsc::Receiver<(usize, std::sync::Arc<egui::ColorImage>)>,
    tx: std::sync::mpsc::Sender<(usize, std::sync::Arc<egui::ColorImage>)>,
    restore: Option<Vec2>,
    rec: present::Recorder,
    /// close the window once the film is written (`quit` while filming)
    quit_after: bool,
}

/// The logo (`resources/masstin_logo.png`, embedded): the dog's head cut
/// out for the menu bar, and the whole picture for About.
fn load_logos(ctx: &egui::Context) -> (Option<egui::TextureHandle>, Option<egui::TextureHandle>, Option<egui::TextureHandle>) {
    let bytes = include_bytes!("../../resources/masstin_logo.png");
    let Ok(img) = image::load_from_memory(bytes) else { return (None, None, None) };
    let rgba = img.to_rgba8();
    let to_tex = |name: &str, im: image::RgbaImage| {
        let (w, h) = (im.width() as usize, im.height() as usize);
        let ci = egui::ColorImage::from_rgba_unmultiplied([w, h], im.as_raw());
        ctx.load_texture(name, ci, egui::TextureOptions::LINEAR)
    };
    let head = image::imageops::crop_imm(&rgba, 290, 380, 560, 350).to_image();
    let head = image::imageops::resize(&head, 93, 58, image::imageops::FilterType::Lanczos3);
    let full = image::imageops::resize(&rgba, 420, 357, image::imageops::FilterType::Lanczos3);
    let big = image::imageops::crop_imm(&rgba, 290, 380, 560, 350).to_image();
    let big = image::imageops::resize(&big, 448, 280, image::imageops::FilterType::Lanczos3);
    (Some(to_tex("masstin-logo-head", head)), Some(to_tex("masstin-logo", full)), Some(to_tex("masstin-logo-dog", big)))
}

/// What draws the window, as the backend names it.
fn renderer_name(cc: &eframe::CreationContext<'_>) -> String {
    if let Some(gl) = &cc.gl {
        use eframe::glow::HasContext;
        // SAFETY: plain GL string queries on the context eframe just made
        let s = |p: u32| unsafe { gl.get_parameter_string(p) };
        return format!("OpenGL · {} · {} · {}", s(eframe::glow::RENDERER), s(eframe::glow::VENDOR), s(eframe::glow::VERSION));
    }
    "an unknown renderer".to_string()
}

/// A renderer that is the CPU pretending: Windows' generic OpenGL (a server,
/// a remote desktop, a VM without a GPU), Mesa's llvmpipe, SwiftShader, WARP.
fn is_software_renderer(info: &str) -> bool {
    let l = info.to_ascii_lowercase();
    ["gdi generic", "llvmpipe", "softpipe", "swiftshader", "microsoft basic render", "warp", "software"].iter().any(|k| l.contains(k))
}

impl Viewer {
    /// Motion, glow, grid and spotlight off, so a window drawn by the CPU
    /// stays usable; View › Style turns any of them back on.
    fn enter_light_mode(&mut self, why: &str) {
        self.light_mode = true;
        self.light_checked = true;
        self.style.motion = false;
        self.style.edge_glow = false;
        self.style.grid = false;
        self.style.vignette = false;
        self.requery(false);
        self.status = format!("{} · light mode: motion and effects off (View › Style turns them on)", why);
        if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
            eprintln!("[view] light mode: {}", why);
        }
    }

    /// On the first frame a software renderer goes to the light mode at
    /// once; otherwise ninety frames with motion on are timed, and a slow
    /// average (under 12 a second) does the same.
    fn watch_frame_cost(&mut self, dt: f32) {
        if self.light_checked {
            return;
        }
        self.frames_seen += 1;
        if self.frames_seen == 1 {
            if std::env::var_os("MASSTIN_VIEW_LIGHT").is_some() {
                self.enter_light_mode("Asked for (MASSTIN_VIEW_LIGHT)");
            } else if is_software_renderer(&self.renderer_info) {
                let why = format!("Drawn by the CPU: {}", self.renderer_info.split(" · ").nth(1).unwrap_or(&self.renderer_info));
                self.enter_light_mode(&why);
            }
            return;
        }
        if self.frames_seen > 20 && self.style.motion {
            self.light_dt.0 += dt;
            self.light_dt.1 += 1;
            if self.light_dt.1 >= 90 {
                let avg = self.light_dt.0 / self.light_dt.1 as f32;
                if avg > 0.085 {
                    let why = format!("Slow drawing, {:.0} ms a frame on {}", avg * 1000.0, self.renderer_info.split(" · ").nth(1).unwrap_or(&self.renderer_info));
                    self.enter_light_mode(&why);
                } else {
                    self.light_checked = true;
                }
            }
        }
        if self.frames_seen > 600 {
            self.light_checked = true;
        }
    }

    fn about_window(&mut self, ctx: &egui::Context) {
        if !self.show_about {
            return;
        }
        let mut open = true;
        egui::Window::new("About masstin").open(&mut open).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).frame(egui::Frame::window(&ctx.global_style()).fill(Color32::from_rgb(4, 4, 8))).show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                if let Some(t) = &self.logo_full {
                    ui.image((t.id(), Vec2::new(420.0, 357.0)));
                }
                ui.label(egui::RichText::new(format!("masstin {}  ·  lateral movement tracker for anything", env!("CARGO_PKG_VERSION"))).color(theme::MUTED));
                ui.label(egui::RichText::new("The graph viewer: the timeline CSV is the truth, no database. Fonts: Inter (OFL), Phosphor icons (MIT), Press Start 2P (OFL) for the arcade.").color(theme::DIM).small());
                ui.add_space(4.0);
                ui.label(egui::RichText::new(format!("Drawn by {}{}", self.renderer_info, if self.light_mode { " · light mode (motion and effects off)" } else { "" })).color(theme::DIM).small());
                ui.label(egui::RichText::new("No GPU, or a remote desktop? masstin draws with its own CPU rasteriser there by itself; `--renderer software` or `--renderer glow` picks by hand.").color(theme::DIM).small());
            });
        });
        self.show_about = open;
    }

    pub fn new(cc: &eframe::CreationContext<'_>, store: Store, opts: Options) -> Viewer {
        Viewer::create(&cc.egui_ctx, renderer_name(cc), store, opts)
    }

    /// The viewer on an egui context, whatever draws it (`renderer_info` names that).
    pub fn create(egui_ctx: &egui::Context, renderer_info: String, store: Store, opts: Options) -> Viewer {
        theme::install(egui_ctx);
        if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
            eprintln!("[view] renderer: {}", renderer_info);
        }
        let logos = load_logos(egui_ctx);

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
        // with no timeline the side files go under the temp folder, so the
        // style chosen on the welcome is kept
        let first = opts.files.first().cloned().unwrap_or_else(ingest::scratch_csv);
        if !opts.files.is_empty() {
            ingest::remember(&opts.files);
        }
        let views_path = ViewsFile::path_for(&first);
        let vf = ViewsFile::load(&views_path);
        let style = vf.last_style.clone().unwrap_or_default();
        let builtin = builtin_views(store.t_max);
        let story_path = Story::path_for(&first);
        let story = Story::load(&story_path);
        let notes_path = first.clone();
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
            press_hit: None,
            drag_grab: V2::default(),
            rows: None,
            notes_draft: String::new(),
            pending_verdict: None,
            mark_msg: String::new(),
            status: String::new(),
            renderer_info,
            light_mode: false,
            light_checked: false,
            light_dt: (0.0, 0),
            frame_gap_ms: 0.0,
            ui_end: None,
            outside_ms: 0.0,
            inside_ms: 0.0,
            fps_count: 0,
            fps_since: std::time::Instant::now(),
            frames_seen: 0,
            cursor: 0,
            playing: false,
            rate: 4.0,
            acc: 0.0,
            rate_secs: None,
            replay_t: 0.0,
            replay_anim: 0.6,
            edge_born: Vec::new(),
            last_frame: std::time::Instant::now(),
            style,
            views_path,
            saved: vf.views,
            builtin,
            preset: String::new(),
            show_rules: false,
            show_save: false,
            save_name: String::new(),
            save_places: true,
            confirm_delete: None,
            restore_places: None,
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
            film: None,
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
            scene: Scene::default(),
            graph_id: 0,
            geom: Vec::new(),
            edges_on_screen: 0,
            born: Vec::new(),
            t0: std::time::Instant::now(),
            frame_dt: 1.0 / 60.0,
            frame_ms: 16.0,
            layout_ms: 0.0,
            draw_ms: 0.0,
            edges_ms: 0.0,
            nodes_ms: 0.0,
            bg_ms: 0.0,
            geom_ms: 0.0,
            hit_ms: 0.0,
            nodes_drawn: 0,
            edges_drawn: 0,
            hud: std::env::var_os("MASSTIN_VIEW_HUD").is_some(),
            bench: None,
            cam_t: V2::default(),
            zoom_t: 1.0,
            focus_t: 0.0,
            hist: None,
            hist_all: None,
            fill_pending: true,
            fill_anim: None,
            show_filters: true,
            show_inspector: true,
            show_hunt: false,
            show_merge: false,
            show_table: false,
            table_find: String::new(),
            table_rows: Vec::new(),
            table_key: (String::new(), usize::MAX, 0),
            recent: ingest::load_recent(),
            show_help: false,
            quick: String::new(),
            focus_around: false,
            auto_apply: false,
            auto_apply_at: None,
            tab: Tab::Selection,
            brush: None,
            canvas_rect: Rect::NOTHING,
            ctx_target: None,
            color_pick: None,
            notes: Notes::load(&Notes::path_for(&notes_path)),
            note_draft: None,
            mark_dialog: None,
            row_pick: Vec::new(),
            job: None,
            hunt_form: HuntForm { from: String::new(), end: String::new(), alpha: String::new() },
            ingest: Ingest::default(),
            merge_form: MergeForm { inputs: Vec::new(), output: String::new() },
            hunt_sweep: None,
            hunt_reveal: None,
            reveal_rank: Vec::new(),
            hunt_autorun: false,
            show_labels: false,
            logo_small: logos.0,
            logo_full: logos.1,
            logo_dog: logos.2,
            brand: None,
            brand_err: None,
            legend_h: 0.0,
            show_about: false,
            hunt_report: None,
            hunt_report_at: None,
            report_top: 10,
            report_find: String::new(),
            host_edit: None,
            edge_edit: None,
            merges: vf.merges.clone(),
            subnet_defs: vf.subnets.clone(),
            subnets: Vec::new(),
            subnet_of: Vec::new(),
            show_subnets_window: false,
            merge_edit: None,
            show_merges: false,
            merge_add: (String::new(), String::new()),
            last_log: None,
            show_last_log: false,
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
        let mut pinned: HashSet<u32> = HashSet::new();
        for (i, n) in self.graph.nodes.iter().enumerate() {
            if let Some(p) = self.layout.pos.get(i) {
                self.remembered.insert(n.host, *p);
            }
            if self.layout.fixed.get(i).copied().unwrap_or(false) {
                pinned.insert(n.host);
            }
        }
        self.graph = match &self.overlay {
            Some(o) => GraphView::from_edges(&self.store, &self.filter, o.edges.clone()),
            None => GraphView::build(&self.store, &self.filter),
        };
        let restore = self.restore_places.take();
        let g = &self.graph;
        // the places a saved view brings, by host name
        let placed: Vec<Option<V2>> = match &restore {
            Some(places) => {
                let by_name: HashMap<&str, V2> = places.iter().map(|(n, x, y)| (n.as_str(), V2::new(*x, *y))).collect();
                g.nodes.iter().map(|n| by_name.get(self.store.hosts.name(n.host)).copied()).collect()
            }
            None => Vec::new(),
        };
        let max_traffic = g.nodes.iter().map(|n| n.inn + n.out).max().unwrap_or(1).max(1) as f32;
        let by_traffic = self.style.size_by_traffic;
        // the base size: bigger when there are few hosts, so fifteen of them
        // fill a window the way three hundred do
        let n_hosts = g.nodes.len().max(1) as f32;
        let base_r = if self.style.auto_size { 20.0 + 14.0 * ((300.0 / n_hosts).ln() / (300.0f32 / 8.0).ln()).clamp(0.0, 1.0) } else { 24.0 };
        let radii: Vec<f32> = g.nodes.iter().map(|n| if by_traffic { base_r * (0.82 + 0.42 * ((1 + n.inn + n.out) as f32).ln() / (1.0 + max_traffic).ln()) } else { base_r }).collect();
        let mut links: Vec<(usize, usize)> = g.edges.iter().map(|e| (g.node_of_host[&e.src], g.node_of_host[&e.dst])).filter(|(a, b)| a != b).collect();
        links.sort_unstable();
        links.dedup();
        let known: Vec<Option<V2>> = g.nodes.iter().enumerate().map(|(i, n)| {
            if let Some(p) = placed.get(i).copied().flatten() {
                Some(p)
            } else if fresh_layout {
                None
            } else {
                self.remembered.get(&n.host).copied()
            }
        }).collect();
        self.layout = Layout::new(radii, links, &known);
        if !fresh_layout {
            // the hosts the analyst pinned stay pinned where they were (Lay out again frees them)
            for (i, n) in g.nodes.iter().enumerate() {
                if pinned.contains(&n.host) && known[i].is_some() {
                    self.layout.fixed[i] = true;
                }
            }
        }
        let restored = restore.is_some();
        if restored {
            // the placed hosts stay where the analyst left them; hosts the
            // saved view did not know settle around them
            for (i, p) in placed.iter().enumerate() {
                if p.is_some() {
                    self.layout.fixed[i] = true;
                }
            }
            if placed.iter().all(|p| p.is_some()) {
                self.layout.stop();
            }
        }
        // the room each host gets: the canvas at 100 % shared out, so a small
        // graph spreads over the window instead of huddling in the middle
        let canvas = if self.canvas_rect.width() > 100.0 { self.canvas_rect } else { Rect::from_min_size(Pos2::ZERO, Vec2::new(1200.0, 700.0)) };
        let per_host = (canvas.width() * canvas.height() / g.nodes.len().max(1) as f32).sqrt();
        self.layout.link_distance = (per_host * 0.95).clamp(120.0, 330.0);
        self.layout.aspect = (canvas.width() / canvas.height().max(1.0)).clamp(0.5, 2.5);
        self.compute_subnets();
        let now = self.t0.elapsed().as_secs_f32();
        self.born = self.graph.nodes.iter().enumerate().map(|(i, n)| if placed.get(i).copied().flatten().is_some() || !(fresh_layout || !self.remembered.contains_key(&n.host)) { now - 10.0 } else { now }).collect();
        self.graph_id += 1;
        self.focus_t = 0.0;
        // a saved arrangement is framed as it is, not stretched to the window
        self.fill_pending = !restored;
        self.fill_anim = None;
        self.selected = None;
        self.hovered = None;
        self.ctx_target = None;
        self.mark_dialog = None;
        self.rows = None;
        self.cursor = self.graph.events.len();
        self.playing = false;
        self.edge_born = vec![f32::NEG_INFINITY; self.graph.edges.len()];
        let mut parts = vec![
            format!("{} hosts", self.graph.nodes.len()),
            format!("{} connections drawn of {}", self.graph.edges.len(), self.graph.connections),
            format!("{} rows", self.graph.events.len()),
        ];
        if let Some(o) = &self.overlay {
            parts.insert(0, o.title.clone());
        }
        if self.graph.truncated {
            parts.push("limit reached: narrow the filters or raise the limit".into());
        }
        self.rebuild_steps();
        self.status = parts.join("  ·  ");
        self.fit_pending = true;
    }

    /// Frame the graph: the camera glides there, or jumps when `snap`.
    /// Stretch the settled picture to the window's shape, so a tall graph
    /// uses the sides and a flat one the height; animated, then framed.
    fn fill_window(&mut self, canvas: Rect) {
        let n = self.layout.len();
        let Some((lo, hi)) = self.layout.bounds() else { return };
        if n < 2 {
            return;
        }
        let gw = (hi.x - lo.x).max(1.0);
        let gh = (hi.y - lo.y).max(1.0);
        let margin = 90.0;
        let inset = if self.presenting { 0.0 } else { self.legend_h + 12.0 };
        let cw = (canvas.width() - margin * 2.0).max(100.0);
        let ch = (canvas.height() - inset - margin * 2.0).max(100.0);
        // the zoom the graph would get as it is, and the stretch that makes it
        // fill both axes at that zoom (never shrinking an axis)
        let z = (cw / gw).min(ch / gh).min(2.2);
        let sx = ((cw / z) / gw).clamp(1.0, 2.6);
        let sy = ((ch / z) / gh).clamp(1.0, 2.6);
        if (sx - 1.0).abs() < 0.03 && (sy - 1.0).abs() < 0.03 {
            return;
        }
        let c = V2::new((lo.x + hi.x) / 2.0, (lo.y + hi.y) / 2.0);
        let from: Vec<V2> = self.layout.pos.clone();
        let to: Vec<V2> = from.iter().map(|p| V2::new(c.x + (p.x - c.x) * sx, c.y + (p.y - c.y) * sy)).collect();
        self.layout.stop();
        self.fill_anim = Some((from, to, self.t0.elapsed().as_secs_f32()));
    }

    fn fit(&mut self, canvas: Rect, snap: bool) {
        if let Some((lo, hi)) = self.layout.bounds() {
            let w = (hi.x - lo.x).max(50.0) + 80.0;
            let h = (hi.y - lo.y).max(50.0) + 80.0;
            let max_zoom = if self.presenting { 1.8 } else { 2.2 };
            // the legend chips sit over the top of the canvas: keep it clear
            let inset = if self.presenting { 0.0 } else { self.legend_h + 12.0 };
            self.zoom_t = (canvas.width() / w).min((canvas.height() - inset).max(50.0) / h).clamp(0.05, max_zoom);
            self.cam_t = V2::new((lo.x + hi.x) / 2.0, (lo.y + hi.y) / 2.0 - (inset / 2.0) / self.zoom_t);
            if snap {
                self.zoom = self.zoom_t;
                self.cam = self.cam_t;
            }
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
    /// The replay head moved from `from` to `to`: the connections whose first
    /// event is in that range start drawing themselves now, and a host they
    /// reach for the first time pops in when the line gets there.
    fn replay_crossed(&mut self, from: usize, to: usize) {
        if self.replay_anim <= 0.0 {
            return;
        }
        let now = self.t0.elapsed().as_secs_f32();
        let n_in_range = to.saturating_sub(from);
        for (k, e) in self.graph.edges.iter().enumerate() {
            if e.first_event >= from && e.first_event < to {
                // several in one step: each a little after the one before
                let stagger = if n_in_range > 1 { 0.35 * self.replay_anim * (e.first_event - from) as f32 / n_in_range as f32 } else { 0.0 };
                if let Some(b) = self.edge_born.get_mut(k) {
                    *b = now + stagger;
                }
                let dst = self.graph.node_of_host[&e.dst];
                if let Some(n) = self.graph.nodes.get(dst) {
                    if n.first_event >= from && n.first_event < to {
                        if let Some(b) = self.born.get_mut(dst) {
                            *b = now + stagger + self.replay_anim * 0.55;
                        }
                    }
                }
            }
        }
    }

    /// Start the replay from the head's place, by rows or by the clock.
    pub(super) fn start_replay(&mut self) {
        let n = self.graph.events.len();
        if self.cursor >= n {
            self.cursor = 0;
        }
        self.playing = true;
        self.acc = 0.0;
        if self.rate_secs.is_some() {
            let k = if self.cursor == 0 { 0 } else { self.cursor - 1 };
            self.replay_t = self.graph.events.get(k).map(|&ei| self.store.edges[ei as usize].t as f64).unwrap_or(0.0);
        }
    }

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
        if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
            eprintln!("[view] presenting {} steps, {:.1} s", self.steps.len(), present::total_secs(&self.steps, &self.story));
        }
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
        self.row_pick = vec![false; out.len()];
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

    /// Whether anything narrows the view beyond "everything".
    fn filters_active(&self) -> bool {
        let f = &self.filter;
        f.view != View::All || !f.host.trim().is_empty() || !f.user.trim().is_empty() || !f.logon_type.trim().is_empty() || !f.from.trim().is_empty() || !f.to.trim().is_empty() || f.min_score > 0 || f.hunt.iter().any(|h| !h) || f.results.iter().any(|r| !r) || f.verdict.iter().any(|v| !v) || f.grouping != super::query::Grouping::Fold
    }

    /// A verdict on a connection: written at once when it is one row,
    /// otherwise the analyst says whether it goes on the whole block or on
    /// the rows they tick.
    fn begin_mark(&mut self, edge: usize, verdict: u8) {
        self.load_rows(edge);
        let n = self.graph.edges[edge].rows.len();
        if n <= 1 {
            self.pending_verdict = Some(verdict);
            self.save_mark(edge);
            return;
        }
        let shown = self.rows.as_ref().map(|(_, r, _)| r.len()).unwrap_or(0);
        self.mark_dialog = Some(MarkDialog { edge, verdict, whole: true, picked: vec![false; shown] });
    }

    fn mark_window(&mut self, ctx: &egui::Context) {
        let Some(mut d) = self.mark_dialog.take() else { return };
        if d.edge >= self.graph.edges.len() {
            return;
        }
        let mut open = true;
        let mut save = false;
        let mut cancel = false;
        let g = &self.graph.edges[d.edge];
        let total = g.rows.len();
        let accounts = g.users.len();
        let title = format!("Mark {} -> {} as {}", self.store.hosts.name(g.src), self.store.hosts.name(g.dst), VERDICT_NAMES[d.verdict as usize]);
        let c = verdict_color(d.verdict).unwrap_or(MUTED);
        egui::Window::new(title).open(&mut open).collapsible(false).resizable(true).default_width(560.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.label(egui::RichText::new(format!("This connection is drawn as one edge but it is {} row(s){}.", total, if accounts > 1 { format!(" of {} accounts", accounts) } else { String::new() })).color(theme::MUTED));
            ui.add_space(4.0);
            if ui.add(egui::RadioButton::new(d.whole, format!("The whole block: every one of the {} rows", total))).clicked() {
                d.whole = true;
            }
            if ui.add(egui::RadioButton::new(!d.whole, "Only the rows I tick")).clicked() {
                d.whole = false;
            }
            if !d.whole {
                if let Some((_, rows, _)) = &self.rows {
                    ui.horizontal(|ui| {
                        if ui.small_button("all").clicked() {
                            d.picked.iter_mut().for_each(|p| *p = true);
                        }
                        if ui.small_button("none").clicked() {
                            d.picked.iter_mut().for_each(|p| *p = false);
                        }
                        ui.label(egui::RichText::new(format!("{} ticked{}", d.picked.iter().filter(|p| **p).count(), if total > rows.len() { format!(" · first {} of {} shown", rows.len(), total) } else { String::new() })).color(theme::MUTED).small());
                    });
                    egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                        egui::Grid::new("mark-rows").striped(true).show(ui, |ui| {
                            for (k, r) in rows.iter().enumerate() {
                                if k >= d.picked.len() {
                                    break;
                                }
                                ui.checkbox(&mut d.picked[k], "");
                                ui.label(egui::RichText::new(&r.t).monospace().small());
                                ui.label(egui::RichText::new(r.fields.get(5).cloned().unwrap_or_default()).small());
                                ui.label(egui::RichText::new(r.fields.get(2).cloned().unwrap_or_default()).small().color(theme::MUTED));
                                ui.label(egui::RichText::new(r.fields.get(4).cloned().unwrap_or_default()).small().color(theme::MUTED));
                                ui.label(egui::RichText::new(VERDICT_NAMES[r.verdict as usize]).small().color(verdict_color(r.verdict).unwrap_or(theme::DIM)));
                                ui.end_row();
                            }
                        });
                    });
                }
            }
            ui.add_space(6.0);
            ui.add(egui::TextEdit::multiline(&mut self.notes_draft).desired_rows(2).desired_width(f32::INFINITY).hint_text("notes, written on the same rows"));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let n = if d.whole { total } else { d.picked.iter().filter(|p| **p).count() };
                if ui.add_enabled(n > 0, egui::Button::new(theme::semibold(format!("Write {} on {} row(s)", VERDICT_NAMES[d.verdict as usize], n), 13.0).color(theme::ACCENT_INK)).fill(c).stroke(Stroke::NONE)).clicked() {
                    save = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if save {
            let rows: Vec<(u16, u32)> = if d.whole {
                self.graph.edges[d.edge].rows.iter().map(|&ei| (self.store.edges[ei as usize].file, self.store.edges[ei as usize].line)).collect()
            } else {
                self.rows.as_ref().map(|(_, r, _)| r.iter().enumerate().filter(|(k, _)| d.picked.get(*k).copied().unwrap_or(false)).map(|(_, r)| (r.file, r.line)).collect()).unwrap_or_default()
            };
            self.mark_rows(d.edge, &rows, d.verdict);
        } else if open && !cancel {
            self.mark_dialog = Some(d);
        }
    }

    /// Write a verdict and the notes draft on these rows of a connection.
    fn mark_rows(&mut self, edge: usize, rows: &[(u16, u32)], verdict: u8) {
        match self.store.mark(rows, verdict, self.notes_draft.trim()) {
            Ok(n) => {
                self.mark_msg = format!("{} row(s) written to the timeline", n);
                self.status = self.mark_msg.clone();
                let g = &mut self.graph.edges[edge];
                let total = g.rows.len() as u32;
                let written = rows.len() as u32;
                if written >= total {
                    g.verdicts = [0; 4];
                    g.verdicts[verdict as usize] = total;
                } else {
                    // the rest keep what they had: recount from the store
                    g.verdicts = [0; 4];
                    for &ei in &g.rows {
                        let e = &self.store.edges[ei as usize];
                        let v = if rows.contains(&(e.file, e.line)) { verdict } else { e.verdict };
                        g.verdicts[v as usize] += 1;
                    }
                }
                self.rows = None;
                self.load_rows(edge);
                self.pending_verdict = None;
            }
            Err(e) => {
                self.mark_msg = format!("cannot write the timeline: {}", e);
                self.status = self.mark_msg.clone();
            }
        }
    }

    fn note_window(&mut self, ctx: &egui::Context) {
        let Some((target, mut text)) = self.note_draft.take() else { return };
        let mut open = true;
        let mut save = false;
        let mut cancel = false;
        egui::Window::new(format!("Note on {}", target.label())).open(&mut open).collapsible(false).resizable(true).default_width(460.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            let r = ui.add(egui::TextEdit::multiline(&mut text).desired_rows(4).desired_width(f32::INFINITY).hint_text("what you saw, what to check next…"));
            r.request_focus();
            ui.label(egui::RichText::new(format!("Saved in {}", self.notes.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default())).color(theme::DIM).small());
            ui.horizontal(|ui| {
                if ui.add_enabled(!text.trim().is_empty(), egui::Button::new(theme::semibold("Save note", 13.0).color(theme::ACCENT_INK)).fill(ACCENT).stroke(Stroke::NONE)).clicked() {
                    save = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if save {
            self.notes.add(target, &text);
            if let Err(e) = self.notes.save() {
                self.status = format!("cannot write {}: {}", self.notes.path.display(), e);
            } else {
                self.status = "Note saved".into();
                self.tab = Tab::Notes;
            }
        } else if open && !cancel {
            self.note_draft = Some((target, text));
        }
    }

    fn help_window(&mut self, ctx: &egui::Context) {
        if !self.show_help {
            return;
        }
        let mut open = true;
        egui::Window::new("Mouse and keys").open(&mut open).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            egui::Grid::new("help").num_columns(2).spacing([18.0, 6.0]).show(ui, |ui| {
                for (k, v) in [
                    ("drag a host", "move it; it stays pinned where you drop it (right click: Unpin)"),
                    ("drag the background", "pan"),
                    ("scroll / pinch", "zoom at the pointer"),
                    ("click", "inspect a host or a connection"),
                    ("double-click a host", "open its neighbourhood"),
                    ("right-click", "what you can do with it"),
                    ("Enter in a filter field", "apply"),
                    ("time strip: drag a handle", "narrow the window"),
                    ("time strip: drag elsewhere", "scrub the replay"),
                    ("time strip: double-click", "the whole timeline again"),
                    ("F1", "frame budget"),
                    ("Present: Space / ← → / Home / Esc", "pause, step, restart, leave"),
                ] {
                    ui.label(theme::medium(k, 13.0));
                    ui.label(egui::RichText::new(v).color(theme::MUTED));
                    ui.end_row();
                }
            });
        });
        self.show_help = open;
    }

    fn reload(&mut self) {
        match self.reload_store() {
            Ok(()) => {
                self.requery(false);
                self.status = format!("Timeline read again: {}", self.status);
            }
            Err(e) => self.status = format!("Cannot read the timeline: {}", e),
        }
    }

    // ───────────────────────── UI: details pane ─────────────────────────

    fn legend(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Click a host or a connection. Drag a host to move it (it stays pinned where you drop it), drag the background to pan, scroll to zoom, double-click a host to open its neighbourhood.").color(MUTED));
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
        chip(ui, HOST_FILL, HOST_RING, "workstation (mostly an origin)");
        chip(ui, SERVER_FILL, SERVER_RING, "server (mostly a destination)");
        chip(ui, DC_FILL, DC_RING, "domain controller (Kerberos ticket traffic)");
        chip(ui, EXTERNAL_FILL, EXTERNAL_RING, "address outside the private ranges");
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
            let mine = self.merged_into(&name);
            if !mine.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new("merged by you:").color(theme::DIM).small());
                    let mut undo: Option<String> = None;
                    for m in &mine {
                        if ui.add(egui::Button::new(egui::RichText::new(format!("{}  {}", m, super::icons::X)).small()).frame(true)).on_hover_text("Undo this merge").clicked() {
                            undo = Some(m.clone());
                        }
                    }
                    if let Some(m) = undo {
                        self.unmerge_host(&m);
                    }
                });
            }
        } else if crate::load_neo4j::looks_like_ip(&name) {
            ui.label(egui::RichText::new("an address the hunt could not tie to a host name").color(MUTED));
        }
        let n = &self.graph.nodes[i];
        ui.label(format!("{} events in · {} events out (in this view)", n.inn, n.out));
        let host_notes: Vec<(String, String)> = self.notes.on_host(&name).map(|n| (n.when.clone(), n.text.clone())).collect();
        if !host_notes.is_empty() {
            theme::section(ui, "Notes");
            for (when, text) in host_notes {
                ui.label(egui::RichText::new(format!("{}  {}", &when[..16], text)).color(theme::MUTED).size(12.5));
            }
        }
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
                e.score,
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
                    ui.label(egui::RichText::new(format!("score {} · {}", q as u8, crate::csv_out::score_words(q as u8))).color(MUTED)).on_hover_text("hunt_score: how rare the connection is, 0 to 100 (-10 log10 of its q-value)");
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
        let picked: Vec<(u16, u32)> = self.rows.as_ref().map(|(_, r, _)| r.iter().enumerate().filter(|(k, _)| self.row_pick.get(*k).copied().unwrap_or(false)).map(|(_, r)| (r.file, r.line)).collect()).unwrap_or_default();
        let total_rows = self.graph.edges[i].rows.len();
        ui.horizontal_wrapped(|ui| {
            let v = self.pending_verdict.unwrap_or(verdict);
            if !picked.is_empty() {
                let label = format!("Save on the {} ticked row{}", picked.len(), if picked.len() == 1 { "" } else { "s" });
                if ui.add(egui::Button::new(theme::semibold(label, 13.0).color(theme::ACCENT_INK)).fill(ACCENT).stroke(Stroke::NONE)).on_hover_text("Only the rows ticked below get this verdict and these notes").clicked() {
                    self.mark_rows(i, &picked, v);
                }
            }
            let label = if total_rows == 1 {
                "Save on this row".to_string()
            } else if users_n > 1 {
                format!("Save on all {} rows of these {} accounts", total_rows, users_n)
            } else {
                format!("Save on all {} rows", total_rows)
            };
            let whole = egui::Button::new(theme::semibold(label, 13.0).color(if picked.is_empty() { theme::ACCENT_INK } else { TEXT })).fill(if picked.is_empty() { ACCENT } else { theme::FIELD }).stroke(Stroke::NONE);
            if ui.add(whole).on_hover_text("Every row this edge stands for").clicked() {
                let all: Vec<(u16, u32)> = self.graph.edges[i].rows.iter().map(|&ei| (self.store.edges[ei as usize].file, self.store.edges[ei as usize].line)).collect();
                self.mark_rows(i, &all, v);
            }
        });
        if !self.mark_msg.is_empty() {
            ui.label(egui::RichText::new(&self.mark_msg).color(MUTED).small());
        }
        ui.add_space(10.0);
        if let Some((_, rows, total)) = &self.rows {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("ROWS {}", if *total > rows.len() { format!("(first {} of {})", rows.len(), total) } else { total.to_string() })).small().color(MUTED));
                if rows.len() > 1 {
                    ui.label(egui::RichText::new("· tick the ones to mark:").small().color(theme::DIM));
                    if ui.small_button("all").clicked() {
                        self.row_pick.iter_mut().for_each(|p| *p = true);
                    }
                    if ui.small_button("none").clicked() {
                        self.row_pick.iter_mut().for_each(|p| *p = false);
                    }
                }
            });
            egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                egui::Grid::new("rows").striped(true).min_col_width(40.0).show(ui, |ui| {
                    for h in ["", "time", "event", "type", "account", "source", "subject", "logon id", "detail", "hunt", "verdict", "notes"] {
                        ui.label(egui::RichText::new(h).small().color(MUTED));
                    }
                    ui.end_row();
                    for (k, r) in rows.iter().enumerate() {
                        let f = |k: usize| r.fields.get(k).cloned().unwrap_or_default();
                        if let Some(p) = self.row_pick.get_mut(k) {
                            ui.checkbox(p, "");
                        } else {
                            ui.label("");
                        }
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
                        ui.label(egui::RichText::new(VERDICT_NAMES[r.verdict as usize]).small().color(verdict_color(r.verdict).unwrap_or(MUTED)));
                        let n = &r.notes;
                        ui.label(egui::RichText::new(if n.chars().count() > 40 { format!("{}…", n.chars().take(40).collect::<String>()) } else { n.clone() }).small().color(MUTED)).on_hover_text(n);
                        ui.end_row();
                        let _ = (r.file, r.line);
                    }
                });
            });
        }
    }

    // ───────────────────────── style ─────────────────────────

    fn persist(&self) {
        let vf = ViewsFile { views: self.saved.clone(), last_style: Some(self.style.clone()), merges: self.merges.clone(), subnets: self.subnet_defs.clone() };
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
        egui::Window::new(format!("{}  Save this filter", super::icons::BOOKMARK_SIMPLE)).open(&mut open).collapsible(false).resizable(false).default_width(420.0).anchor(Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.label(egui::RichText::new("The filter as it is now, and the style with it, under a name. It goes in the views file next to the timeline and travels with the case.").color(theme::MUTED));
            theme::section(ui, "Name");
            let r = ui.add(egui::TextEdit::singleline(&mut self.save_name).desired_width(f32::INFINITY).hint_text("RDP from the jump box, last week…"));
            r.request_focus();
            theme::section(ui, "What it keeps");
            let summary = {
                let f = &self.draft;
                let mut parts: Vec<String> = Vec::new();
                match f.view {
                    View::Findings => parts.push("findings only".into()),
                    View::Around => parts.push(format!("around {}", f.around)),
                    View::All => {}
                }
                for (label, v) in [("host", &f.host), ("account", &f.user), ("logon type", &f.logon_type)] {
                    if !v.trim().is_empty() {
                        parts.push(format!("{} {}", label, v.trim()));
                    }
                }
                if f.min_score > 0 {
                    parts.push(format!("score ≥ {}", f.min_score));
                }
                if !f.from.trim().is_empty() || !f.to.trim().is_empty() {
                    parts.push(format!("{} → {}", if f.from.trim().is_empty() { "start" } else { f.from.trim() }, if f.to.trim().is_empty() { "end" } else { f.to.trim() }));
                }
                if parts.is_empty() { "everything".to_string() } else { parts.join("  ·  ") }
            };
            ui.label(egui::RichText::new(summary).color(TEXT).size(12.5));
            ui.label(egui::RichText::new(format!("and the style: colour by {}, {} hosts, {}", self.style.color_by.label(), self.style.node_style.label(), if self.style.motion { "motion on" } else { "still" })).color(theme::DIM).size(11.5));
            ui.add_space(6.0);
            let n_hosts = self.graph.nodes.len();
            ui.checkbox(&mut self.save_places, format!("Keep the arrangement: the {} hosts where they are now", n_hosts))
                .on_hover_text("Picking the filter later puts these hosts back in these places, pinned; hosts the filter did not have then settle around them. Lay out again frees them.");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let name = self.save_name.trim().to_string();
                let exists = self.saved.iter().any(|v| v.name == name);
                if ui.add_enabled(!name.is_empty(), egui::Button::new(theme::semibold(if exists { "Replace" } else { "Save" }, 13.0).color(theme::ACCENT_INK)).fill(ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(90.0, 30.0))).clicked() {
                    self.saved.retain(|v| v.name != name);
                    let places: Vec<(String, f32, f32)> = if self.save_places {
                        self.graph.nodes.iter().enumerate().filter_map(|(i, n)| self.layout.pos.get(i).map(|p| (self.store.hosts.name(n.host).to_string(), p.x, p.y))).collect()
                    } else {
                        Vec::new()
                    };
                    self.saved.push(SavedView { name: name.clone(), filter: self.draft.clone(), style: self.style.clone(), places });
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

    // ───────────────────────── the scene cache ─────────────────────────

    /// Rebuild the per-edge and per-node looks when the graph or the style
    /// changed since they were built.
    fn ensure_scene(&mut self) {
        let fp = serde_json::to_string(&self.style).unwrap_or_default();
        if self.scene.fingerprint == fp && self.scene.edges.len() == self.graph.edges.len() && self.scene.nodes.len() == self.graph.nodes.len() && self.scene.graph_id == self.graph_id {
            return;
        }
        self.rebuild_scene(fp);
    }

    fn rebuild_scene(&mut self, fingerprint: String) {
        let rules = self.compiled_rules();
        let g = &self.graph;
        let mut groups: HashMap<(usize, usize), Vec<usize>> = HashMap::new();
        let mut ab: Vec<(usize, usize)> = Vec::with_capacity(g.edges.len());
        for (k, e) in g.edges.iter().enumerate() {
            let a = g.node_of_host[&e.src];
            let b = g.node_of_host[&e.dst];
            ab.push((a, b));
            groups.entry((a.min(b), a.max(b))).or_default().push(k);
        }
        let mut fan = vec![(0u16, 1u16); g.edges.len()];
        for ks in groups.values() {
            for (i, &k) in ks.iter().enumerate() {
                fan[k] = (i.min(u16::MAX as usize) as u16, ks.len().min(u16::MAX as usize) as u16);
            }
        }
        let max_count = g.edges.iter().map(|e| e.count).max().unwrap_or(1).max(1) as f32;
        let mut node_edges: Vec<Vec<u32>> = vec![Vec::new(); g.nodes.len()];
        let mut edges = Vec::with_capacity(g.edges.len());
        for (k, e) in g.edges.iter().enumerate() {
            let (a, b) = ab[k];
            node_edges[a].push(k as u32);
            if a != b {
                node_edges[b].push(k as u32);
            }
            let base = 0.7 + 1.6 * ((1 + e.count) as f32).ln() / (1.0 + max_count).ln();
            let mut color = self.edge_base_color(e);
            let mut width = if e.hunt == super::store::H_SIGNIFICANT { base * 1.4 } else { base };
            let mut dashed = e.result == R_LOGOFF || e.result == R_CONNECT;
            let mut glow = false;
            let mut hide = false;
            if let Some((ri, _)) = rules.iter().find(|(ri, pats)| self.rule_hits_edge(&self.style.rules[*ri], pats, e)) {
                let r = &self.style.rules[*ri];
                hide = r.hide;
                if let Some(c) = r.color {
                    color = Color32::from_rgb(c[0], c[1], c[2]);
                }
                width *= r.width;
                dashed |= r.dashed;
                glow = r.glow;
            }
            let finding = matches!(e.hunt, super::store::H_SIGNIFICANT | super::store::H_CANDIDATE);
            edges.push(EdgeLook { a: a as u32, b: b as u32, fan: fan[k], color, width, dashed, glow, hide, finding, verdict: verdict_color(e.verdict()) });
        }
        let mut nodes = Vec::with_capacity(g.nodes.len());
        for (i, n) in g.nodes.iter().enumerate() {
            let name = self.store.hosts.name(n.host).to_string();
            let is_ip = crate::load_neo4j::looks_like_ip(&name);
            // the colour says what the host is; an address the hunt could not
            // name stays sand-coloured whatever it does
            let (mut fill, mut ring) = match n.role {
                Role::External => (EXTERNAL_FILL, EXTERNAL_RING),
                _ if is_ip => (IP_FILL, IP_RING),
                Role::DomainController => (DC_FILL, DC_RING),
                Role::Server => (SERVER_FILL, SERVER_RING),
                _ => (HOST_FILL, HOST_RING),
            };
            let mut icon: Option<&'static str> = if self.style.node_style == NodeStyle::Icon { Some(labels::role_icon(n.role, is_ip)) } else { None };
            let mut device: Option<super::devices::Device> = if self.style.node_style.draws_devices() { Some(labels::role_device(n.role, is_ip)) } else { None };
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
            let mut size = 1.0;
            let mut glow = false;
            let mut hide = false;
            let mut label_pos = self.style.label_pos;
            let mut label_size = 1.0;
            let mut label_bg = if self.style.label_bg { Some(Color32::from_rgb(self.style.label_bg_color[0], self.style.label_bg_color[1], self.style.label_bg_color[2])) } else { None };
            if let Some((ri, _)) = rules.iter().filter(|(ri, _)| self.style.rules[*ri].field.on_nodes()).find(|(ri, pats)| self.rule_hits_node(&self.style.rules[*ri], pats, i)) {
                let rule = &self.style.rules[*ri];
                hide = rule.hide;
                if let Some(p) = rule.label_pos {
                    label_pos = p;
                }
                if let Some(s) = rule.label_size {
                    label_size = s;
                }
                if let Some(c) = rule.label_bg {
                    label_bg = Some(Color32::from_rgb(c[0], c[1], c[2]));
                }
                if let Some(key) = rule.icon.as_deref() {
                    match super::devices::Device::from_key(key) {
                        Some(d) if self.style.node_style.draws_devices() => {
                            device = Some(d);
                        }
                        _ => {
                            device = None;
                            icon = labels::icon_glyph(key).or(icon);
                        }
                    }
                }
                if let Some(c) = rule.color {
                    fill = Color32::from_rgb(c[0], c[1], c[2]);
                    ring = Color32::from_rgb((c[0] as f32 * 0.75) as u8, (c[1] as f32 * 0.75) as u8, (c[2] as f32 * 0.75) as u8);
                }
                if let Some(sh) = rule.shape {
                    shape = sh;
                }
                size = rule.size;
                glow = rule.glow;
            }
            nodes.push(NodeLook { name, is_ip, fill, ring, shape, size, glow, hide, edges: std::mem::take(&mut node_edges[i]), label_pos, label_size, label_bg, icon, device });
        }
        let n_ip = nodes.iter().filter(|n| n.is_ip).count();
        self.scene = Scene { fingerprint, graph_id: self.graph_id, edges, nodes, chips: self.legend_chips(), n_ip };
    }

    /// Screen-space start, end (on the rims) and control point of every
    /// edge for this frame; parallel edges between a pair fan out. Also
    /// whether the edge touches the canvas.
    fn compute_geometry(&mut self, canvas: Rect) {
        let n = self.graph.edges.len();
        self.geom.clear();
        self.geom.reserve(n);
        let vis = canvas.expand(80.0);
        let mut on_screen = 0usize;
        for k in 0..n {
            let look = &self.scene.edges[k];
            let (a, b) = (look.a as usize, look.b as usize);
            let pa = self.layout.pos[a];
            let pb = self.layout.pos[b];
            let ra = self.layout.radius[a] * self.style.node_scale * self.scene.nodes[a].size;
            let rb = self.layout.radius[b] * self.style.node_scale * self.scene.nodes[b].size;
            let (start, end, ctrl) = if a == b {
                (pa, pa, pa + V2::new(0.0, -ra * 3.0))
            } else {
                let d = pb - pa;
                let len = d.len().max(1.0);
                let u = d * (1.0 / len);
                let normal = V2::new(-u.y, u.x);
                let side = if a < b { 1.0 } else { -1.0 };
                let (idx, cnt) = look.fan;
                let offset = if self.style.curves || cnt > 1 { (idx as f32 - (cnt as f32 - 1.0) / 2.0) * 34.0 * side } else { 0.0 };
                let mid = pa + d * 0.5 + normal * offset;
                let da = mid - pa;
                let start = pa + da * ((ra + 1.0) / da.len().max(1.0));
                let db = mid - pb;
                let end = pb + db * ((rb + 2.0) / db.len().max(1.0));
                let ctrl = mid * 2.0 - (start + end) * 0.5;
                (start, end, ctrl)
            };
            let sa = self.to_screen(canvas, start);
            let sb = self.to_screen(canvas, end);
            let sc = self.to_screen(canvas, ctrl);
            let shown = vis.intersects(Rect::from_points(&[sa, sb, sc]));
            on_screen += shown as usize;
            self.geom.push(EdgeGeom { a: sa, b: sb, c: sc, on_screen: shown });
        }
        self.edges_on_screen = on_screen;
    }

    fn hit_test(&self, canvas: Rect, p: Pos2) -> Option<Sel> {
        // nodes first, nearest wins
        let mut best: Option<(f32, Sel)> = None;
        for i in 0..self.graph.nodes.len() {
            if self.scene.nodes[i].hide || !self.node_visible(i) {
                continue;
            }
            let c = self.to_screen(canvas, self.layout.pos[i]);
            let r = self.layout.radius[i] * self.zoom * self.style.node_scale * self.scene.nodes[i].size;
            let d = (c - p).length();
            if d <= r + 2.0 && best.map_or(true, |(bd, _)| d < bd) {
                best = Some((d, Sel::Node(i)));
            }
        }
        if best.is_some() {
            return best.map(|(_, s)| s);
        }
        for (k, g) in self.geom.iter().enumerate() {
            if !g.on_screen || self.scene.edges[k].hide || !self.edge_visible(k) {
                continue;
            }
            if !Rect::from_points(&[g.a, g.b, g.c]).expand(8.0).contains(p) {
                continue;
            }
            let mut prev = g.a;
            for s in 1..=12 {
                let q = draw::bez(g.a, g.c, g.b, s as f32 / 12.0);
                let d = dist_to_segment(p, prev, q);
                if d < 6.0 && best.map_or(true, |(bd, _)| d < bd) {
                    best = Some((d, Sel::Edge(k)));
                }
                prev = q;
            }
        }
        best.map(|(_, s)| s)
    }

    fn to_world_at(&self, canvas: Rect, p: Pos2, cam: V2, zoom: f32) -> V2 {
        let c = canvas.center();
        V2::new(cam.x + (p.x - c.x) / zoom, cam.y + (p.y - c.y) / zoom)
    }

    // ───────────────────────── UI: canvas ─────────────────────────

    fn canvas(&mut self, ui: &mut egui::Ui) {
        if self.files.is_empty() {
            self.welcome(ui);
            return;
        }
        let draw_start = std::time::Instant::now();
        let (resp, painter) = ui.allocate_painter(ui.available_size(), Sense::click_and_drag());
        let canvas = resp.rect;
        let now = self.t0.elapsed().as_secs_f32();
        let dt = self.frame_dt;
        self.ensure_scene();
        if self.fit_pending && self.layout.len() > 0 {
            // give the layout a head start so the first picture is settled
            let start = std::time::Instant::now();
            for _ in 0..300 {
                if !self.layout.tick() || start.elapsed() > std::time::Duration::from_millis(350) {
                    break;
                }
            }
            self.fit(canvas, true);
            self.fit_pending = false;
        }
        let t_bg = std::time::Instant::now();
        let arcade_mode = self.style.node_style == NodeStyle::Arcade;
        draw::background(&painter, canvas, BG, BG_CENTRE, (self.cam.x, self.cam.y), self.zoom, draw::BgStyle { grid: self.style.grid, vignette: self.style.vignette, arcade: arcade_mode, t: now, motion: self.style.motion && !self.presenting });
        if self.style.motion && !arcade_mode && !self.presenting {
            draw::dust(&painter, canvas, now);
        }
        self.bg_ms = t_bg.elapsed().as_secs_f32() * 1000.0;
        if self.layout.len() == 0 {
            painter.text(canvas.center(), Align2::CENTER_CENTER, "nothing to draw with these filters", FontId::proportional(16.0), MUTED);
            self.draw_ms = draw_start.elapsed().as_secs_f32() * 1000.0;
            return;
        }
        let t = std::time::Instant::now();
        let big = self.layout.len() > 1500;
        // light mode: a frame drawn by the CPU costs a quarter of a second or more, so the
        // layout does all its ticks now (microseconds each for a lab) rather than two a frame
        // while a host is held, a few ticks a frame so the rest follows it rather than settling anew each frame
        let (budget, max_ticks) = if self.dragging.is_some() { (4, if big { 1 } else { 3 }) } else if self.light_mode { (60, 2000) } else if big { (8, 1) } else { (4, 2) };
        let ticking = self.layout.tick_for(std::time::Duration::from_millis(budget), max_ticks);
        // the centring came back after a host was unpinned: the camera moves with it
        let r = std::mem::take(&mut self.layout.recentred);
        if r.len2() > 0.0 {
            self.cam -= r;
            self.cam_t -= r;
        }
        if ticking {
            ui.ctx().request_repaint();
        } else if self.fill_pending && !self.presenting && self.dragging.is_none() {
            // the layout settled: stretch it to the window, once per query
            self.fill_pending = false;
            self.fill_window(canvas);
            if self.fill_anim.is_none() {
                self.fit(canvas, false);
            }
        }
        if let Some((from, to, started)) = &self.fill_anim {
            let k = if self.light_mode { 1.0 } else { draw::ease_out_cubic((now - started) / 0.55) };
            for i in 0..self.layout.pos.len().min(from.len()) {
                self.layout.pos[i] = from[i] + (to[i] - from[i]) * k;
            }
            if k >= 1.0 {
                self.fill_anim = None;
                self.fit(canvas, false);
            } else {
                ui.ctx().request_repaint();
            }
        }
        self.layout_ms = t.elapsed().as_secs_f32() * 1000.0;

        // ── the camera glides to where it is going ──
        let k = if self.light_mode { 1.0 } else { 1.0 - (-dt * 14.0).exp() };
        if (self.zoom_t - self.zoom).abs() > 1e-4 || (self.cam_t - self.cam).len() > 0.05 {
            self.zoom += (self.zoom_t - self.zoom) * k;
            self.cam += (self.cam_t - self.cam) * k;
            ui.ctx().request_repaint();
        } else {
            self.zoom = self.zoom_t;
            self.cam = self.cam_t;
        }
        let t_geom = std::time::Instant::now();
        self.compute_geometry(canvas);
        self.geom_ms = t_geom.elapsed().as_secs_f32() * 1000.0;

        // ── input: zoom, pan, drag, hover, click ──
        let pointer = resp.hover_pos();
        if let Some(p) = pointer {
            let scroll = ui.input(|i| i.smooth_scroll_delta.y);
            let zd = ui.input(|i| i.zoom_delta());
            let factor = if scroll != 0.0 { (scroll * 0.0025).exp() } else { zd };
            if (factor - 1.0).abs() > 1e-4 {
                let before = self.to_world_at(canvas, p, self.cam_t, self.zoom_t);
                self.zoom_t = (self.zoom_t * factor).clamp(0.03, 6.0);
                let after = self.to_world_at(canvas, p, self.cam_t, self.zoom_t);
                self.cam_t = self.cam_t + (before - after);
                ui.ctx().request_repaint();
            }
        }
        let t_hit = std::time::Instant::now();
        let hit = pointer.and_then(|p| self.hit_test(canvas, p));
        self.hit_ms = t_hit.elapsed().as_secs_f32() * 1000.0;
        self.hovered = hit;
        self.canvas_rect = canvas;
        if resp.secondary_clicked() {
            self.ctx_target = hit;
        }
        if !self.presenting {
            resp.context_menu(|ui| self.context_menu(ui));
        }
        if self.scene.graph_id != self.graph_id {
            // the menu changed the view under us: the looks and the geometry of
            // this frame belong to the old graph, so draw it on the next one
            ui.ctx().request_repaint();
            return;
        }
        if ui.input(|i| i.pointer.any_pressed()) && resp.hovered() {
            let origin = ui.input(|i| i.pointer.press_origin());
            self.press_hit = origin.and_then(|o| self.hit_test(canvas, o));
            if let (Some(Sel::Node(i)), Some(o)) = (self.press_hit, origin) {
                self.drag_grab = self.layout.pos[i] - self.to_world(canvas, o);
            }
        }
        if resp.drag_started() {
            if let Some(Sel::Node(i)) = self.press_hit {
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
                        self.layout.pos[i] = self.to_world(canvas, p) + self.drag_grab;
                        self.layout.reheat(0.2);
                        ui.ctx().request_repaint();
                    }
                }
                None => {
                    let d = resp.drag_delta();
                    self.cam = self.cam - V2::new(d.x / self.zoom, d.y / self.zoom);
                    self.cam_t = self.cam;
                }
            }
        }
        if resp.drag_stopped() {
            // the host stays where it was dropped, pinned (right click, Unpin)
            if self.dragging.take().is_some() {
                self.layout.reheat(0.1);
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
        let target = if focus.is_some() { 1.0 } else { 0.0 };
        if (self.focus_t - target).abs() > 0.001 {
            let step = if self.light_mode { 1.0 } else { dt / 0.16 };
            self.focus_t = (self.focus_t + (target - self.focus_t).clamp(-step, step)).clamp(0.0, 1.0);
            ui.ctx().request_repaint();
        }
        let (lit_nodes, lit_edges): (HashSet<usize>, HashSet<usize>) = match focus {
            None => (HashSet::new(), HashSet::new()),
            Some(Sel::Node(i)) => {
                let mut ns = HashSet::new();
                let mut es = HashSet::new();
                ns.insert(i);
                for &k in &self.scene.nodes[i].edges {
                    es.insert(k as usize);
                    let l = &self.scene.edges[k as usize];
                    ns.insert(l.a as usize);
                    ns.insert(l.b as usize);
                }
                (ns, es)
            }
            Some(Sel::Edge(k)) => {
                let l = &self.scene.edges[k];
                ([l.a as usize, l.b as usize].into_iter().collect(), [k].into_iter().collect())
            }
        };
        let dimmed = self.focus_t;
        let z = self.zoom;
        let motion = self.style.motion;
        let lod = self.edges_on_screen > 2500;
        let fs = self.style.font_scale;
        let (reveal_done, reveal_now) = self.reveal();
        let cur_step = self.current_step();
        let mut keep_moving = false;
        let frame_now = std::time::Instant::now();
        if self.reveal_running(frame_now) {
            keep_moving = true;
        } else if self.hunt_reveal.is_some() {
            self.hunt_reveal = None;
        }
        // the mastiff on the scent while the hunt runs, fading out as the findings light up
        let dog_alpha = if let Some(started) = self.hunt_sweep {
            let t = started.elapsed().as_secs_f32();
            (t * 1.5).min(1.0) * (0.22 + 0.06 * (t * 2.2).sin())
        } else if let Some(started) = self.hunt_reveal {
            (1.0 - started.elapsed().as_secs_f32() / 1.2).clamp(0.0, 1.0) * 0.22
        } else {
            0.0
        };
        if dog_alpha > 0.005 {
            if let Some(t) = &self.logo_dog {
                let w = (canvas.width().min(canvas.height()) * 0.62).clamp(160.0, 520.0);
                let h = w * 280.0 / 448.0;
                let pulse = if motion { 1.0 + 0.02 * (now * 2.2).sin() } else { 1.0 };
                let r = Rect::from_center_size(canvas.center(), Vec2::new(w * pulse, h * pulse));
                painter.circle_filled(canvas.center(), w * 0.55, draw::fade(theme::VIOLET, 0.06 * dog_alpha / 0.22));
                painter.image(t.id(), r, Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)), draw::fade(Color32::WHITE, dog_alpha));
                keep_moving = true;
            }
        }
        // while a hunt runs, a sweep crosses the canvas
        if let Some(started) = self.hunt_sweep {
            let t = started.elapsed().as_secs_f32();
            let x = canvas.left() + ((t * 0.35).fract()) * canvas.width();
            let mut mesh = egui::epaint::Mesh::default();
            let w = 140.0;
            let c = draw::fade(ACCENT, 0.0);
            let m = draw::fade(ACCENT, 0.09);
            let v = |p: Pos2, col: Color32| egui::epaint::Vertex { pos: p, uv: egui::epaint::WHITE_UV, color: col };
            mesh.vertices.extend([v(Pos2::new(x - w, canvas.top()), c), v(Pos2::new(x, canvas.top()), m), v(Pos2::new(x, canvas.bottom()), m), v(Pos2::new(x - w, canvas.bottom()), c), v(Pos2::new(x + 8.0, canvas.top()), c), v(Pos2::new(x + 8.0, canvas.bottom()), c)]);
            mesh.add_triangle(0, 1, 2);
            mesh.add_triangle(0, 2, 3);
            mesh.add_triangle(1, 4, 5);
            mesh.add_triangle(1, 5, 2);
            painter.add(egui::Shape::mesh(mesh));
            painter.line_segment([Pos2::new(x, canvas.top()), Pos2::new(x, canvas.bottom())], Stroke::new(1.5, draw::fade(ACCENT, 0.6)));
            keep_moving = true;
        }
        let t_edges = std::time::Instant::now();

        // ── the subnet regions, behind everything ──
        self.layout.aspect = (canvas.width() / canvas.height().max(1.0)).clamp(0.5, 2.5);
        self.draw_subnets(&painter, canvas, false);

        // ── edges ──
        let mut animated: Vec<usize> = Vec::new();
        let mut edges_drawn = 0usize;
        let mut taken: Vec<Rect> = Vec::new();
        // the plain edges go into one mesh, drawn under everything else
        let plain_slot = painter.add(egui::Shape::Noop);
        let mut plain_mesh = egui::epaint::Mesh::default();
        let crowd = (3000.0 / self.edges_on_screen.max(1) as f32).clamp(0.3, 1.0);
        for k in 0..self.graph.edges.len() {
            let look = &self.scene.edges[k];
            if look.hide || !self.geom[k].on_screen || !self.edge_visible(k) {
                continue;
            }
            let g = self.geom[k];
            let (pa, pb_full, pc_full) = (g.a, g.b, g.c);
            let progress = if self.presenting {
                self.edge_progress(k)
            } else if self.replay_anim > 0.0 {
                let b = self.edge_born.get(k).copied().unwrap_or(f32::NEG_INFINITY);
                if b.is_finite() { draw::ease_out_cubic(((now - b) / self.replay_anim).clamp(0.0, 1.0)) } else { 1.0 }
            } else {
                1.0
            };
            if progress < 1.0 {
                keep_moving = true;
            }
            // while a presentation draws the edge, the curve grows from the origin
            let (pb, pc) = if progress < 1.0 {
                let pm = draw::bez(pa, pc_full, pb_full, progress);
                let cm = Pos2::new(pa.x + (pc_full.x - pa.x) * progress, pa.y + (pc_full.y - pa.y) * progress);
                (pm, cm)
            } else {
                (pb_full, pc_full)
            };
            let lit = !lit_edges.is_empty() && lit_edges.contains(&k);
            let birth = {
                let ba = draw::ease_out_cubic((now - self.born[look.a as usize]) / 0.45);
                let bb = draw::ease_out_cubic((now - self.born[look.b as usize]) / 0.45);
                ba.min(bb)
            };
            let mut alpha = if lit { 1.0 } else { 1.0 - 0.86 * dimmed } * birth;
            let e = &self.graph.edges[k];
            if self.presenting && self.story.fade_old {
                if let (Some(cur), Some(&st)) = (cur_step, self.step_of_event.get(e.first_event)) {
                    if st != usize::MAX && cur > st + 8 {
                        alpha *= 0.3;
                    }
                }
            }
            if alpha <= 0.01 {
                continue;
            }
            let emphasised = self.presenting && self.step_of_event.get(e.first_event).and_then(|&st| self.steps.get(st)).map_or(false, |st| st.emphasis || (st.significant && progress < 1.0));
            let alpha = alpha * self.style.edge_opacity;
            let arcade = self.style.node_style == NodeStyle::Arcade;
            let mut width = look.width * z.sqrt() * self.style.edge_scale;
            let mut color = if arcade { draw::lighten(look.color, 0.15) } else { look.color };
            let mut flash = 0.0f32;
            if let Some((shown, f)) = self.reveal_state(k, frame_now) {
                if !shown {
                    color = EDGE_LOGOFF;
                    width = (width * 0.7).max(1.0);
                } else {
                    flash = f;
                }
            }
            let selected = self.selected == Some(Sel::Edge(k));
            let stroke_color = if selected { ACCENT } else { color };
            let short = (pa - pb).length() < 14.0;
            let plain = lod && !lit && !selected;
            let glow = !plain && (arcade || ((self.style.edge_glow || look.glow) && (look.glow || emphasised || progress < 1.0 || (lit && focus.is_some()) || (look.finding && dimmed < 0.5))));
            if glow {
                painter.add(egui::epaint::QuadraticBezierShape { points: [pa, pc, pb], closed: false, fill: Color32::TRANSPARENT, stroke: egui::epaint::PathStroke::new(width + 6.0 * z.sqrt(), draw::fade(color, if progress < 1.0 { 0.45 } else if arcade { 0.22 } else { 0.16 } * alpha)) });
            }
            if flash > 0.0 {
                painter.add(egui::epaint::QuadraticBezierShape { points: [pa, pc, pb], closed: false, fill: Color32::TRANSPARENT, stroke: egui::epaint::PathStroke::new(width + (6.0 + 26.0 * flash) * z.sqrt(), draw::fade(draw::lighten(color, 0.4), 0.55 * flash * alpha)) });
            }
            if let Some(vc) = look.verdict {
                if !plain {
                    painter.add(egui::epaint::QuadraticBezierShape { points: [pa, pc, pb], closed: false, fill: Color32::TRANSPARENT, stroke: egui::epaint::PathStroke::new(width + 7.0 * z.sqrt(), draw::fade(vc, 0.35 * alpha)) });
                }
            }
            if short || plain {
                if (pa - pb).length() < 1.5 {
                    continue;
                }
                // a finding keeps its colour and most of its presence in the crowd
                let k = if !plain { 1.0 } else if look.finding { 0.9 } else { 0.8 * crowd };
                draw::line_quad(&mut plain_mesh, pa, pb, width, draw::fade(stroke_color, alpha * k));
            } else if look.dashed {
                draw::dashed_curve(&painter, pa, pc, pb, width, draw::fade(stroke_color, alpha), (5.0 * z.sqrt()).clamp(3.0, 9.0));
            } else {
                // a faint halo under the line gives it body without weight
                if !lod && !glow {
                    painter.add(egui::epaint::QuadraticBezierShape { points: [pa, pc, pb], closed: false, fill: Color32::TRANSPARENT, stroke: egui::epaint::PathStroke::new(width * 2.4 + 1.5, draw::fade(stroke_color, 0.09 * alpha)) });
                }
                draw::gradient_curve(&painter, pa, pc, pb, width, draw::fade(stroke_color, alpha * 0.5), draw::fade(stroke_color, alpha));
            }
            edges_drawn += 1;
            if progress < 1.0 {
                continue;
            }
            // arrowhead at the destination's rim
            if self.style.arrows && !short && (!plain || lit) {
                let dir = (pb - draw::bez(pa, pc, pb, 0.9)).normalized();
                let size = (6.0 + width * 1.4).min(15.0) * z.sqrt().max(0.5);
                draw::arrow(&painter, pb, dir, size, draw::fade(stroke_color, alpha));
            }
            if motion && !short && (lit || look.finding || look.glow || emphasised) && animated.len() < if lod { 120 } else { 600 } && (!plain || lit) {
                animated.push(k);
            }
            // the account on the edge, like Neo4j's relationship caption
            if !plain && self.style.caption != Caption::None && (z > 0.6 || lit) && (pa - pb).length() > 90.0 && (!(self.style.caption_hover || self.edges_on_screen > 80) || lit || selected) {
                let caption = self.edge_caption(e);
                if !caption.is_empty() {
                    let mid = draw::bez(pa, pc, pb, 0.5);
                    let font = FontId::proportional((10.0 * z.sqrt() * fs).clamp(7.0, 16.0));
                    let galley = painter.layout_no_wrap(caption, font, draw::fade(TEXT, alpha));
                    let r = Rect::from_center_size(mid, galley.size() + Vec2::new(12.0, 5.0));
                    // a caption that would sit on another is left out, unless its edge is lit
                    if lit || !taken.iter().any(|t| t.intersects(r)) {
                        draw::pill(&painter, mid, galley, draw::fade(CAPTION_BG, alpha), if lit { Some(draw::fade(stroke_color, 0.6 * alpha)) } else { None }, TEXT);
                        taken.push(r);
                    }
                }
            }
        }

        if !plain_mesh.is_empty() {
            painter.set(plain_slot, egui::Shape::mesh(plain_mesh));
        }

        // ── the dots that travel along the edges that matter ──
        if motion && !animated.is_empty() {
            for &k in &animated {
                let g = self.geom[k];
                let look = &self.scene.edges[k];
                let lit = lit_edges.contains(&k);
                let alpha = if lit { 1.0 } else { 1.0 - 0.7 * dimmed };
                let len = (g.a - g.b).length();
                let n = if len > 260.0 { 3 } else if len > 120.0 { 2 } else { 1 };
                let speed = 0.32 / (len / 220.0).clamp(0.6, 2.5);
                let phase = (k as f32 * 0.618).fract();
                let r = (2.2 * z.sqrt()).clamp(1.2, 3.2);
                for j in 0..n {
                    let t = (now * speed + phase + j as f32 / n as f32).fract();
                    if arcade_mode {
                        draw::particle_square(&painter, g.a, g.c, g.b, t, r * 1.1, if lit { draw::lighten(look.color, 0.2) } else { look.color }, alpha);
                    } else {
                        draw::particle(&painter, g.a, g.c, g.b, t, r, if lit { draw::lighten(look.color, 0.2) } else { look.color }, alpha);
                    }
                }
            }
            keep_moving = true;
        }
        let t_nodes = std::time::Instant::now();
        self.edges_ms = (t_nodes - t_edges).as_secs_f32() * 1000.0;

        // ── nodes ──
        let mut nodes_drawn = 0usize;
        let ring_w = (1.6 * z.sqrt()).clamp(1.0, 3.0);
        let node_slot = painter.add(egui::Shape::Noop);
        let mut node_mesh = egui::epaint::Mesh::default();
        let crowd_nodes = lod || self.graph.nodes.len() > 700;
        // pinned hosts carry a pin, unless the whole picture is (a saved arrangement, the hops)
        let show_pins = !self.presenting && self.layout.fixed.iter().any(|&f| !f);
        for i in 0..self.graph.nodes.len() {
            let look = &self.scene.nodes[i];
            if look.hide || !self.node_visible(i) {
                continue;
            }
            let n = &self.graph.nodes[i];
            let p = self.to_screen(canvas, self.layout.pos[i]);
            let mut r = self.layout.radius[i] * z * self.style.node_scale * look.size;
            let age = if self.light_mode { 1.0 } else { (now - self.born[i]) / 0.45 };
            if age < 1.0 {
                r *= draw::ease_out_back(age).max(0.05);
                keep_moving = true;
            }
            if !canvas.expand(r * 2.2).contains(p) {
                continue;
            }
            // a host that has just appeared in a presentation pops a little
            if self.presenting {
                if let Some((a, b, pr)) = reveal_now {
                    if n.first_event >= a && n.first_event < b {
                        r *= 1.0 + 0.35 * (1.0 - ((pr - 0.45) / 0.55).clamp(0.0, 1.0));
                    }
                }
            }
            let _ = reveal_done;
            let lit = lit_nodes.contains(&i);
            let alpha = if lit { 1.0 } else { 1.0 - 0.82 * dimmed };
            let selected = self.selected == Some(Sel::Node(i));
            let hovered = self.hovered == Some(Sel::Node(i));
            let significant = n.hunt_rank == 0;
            let (fill, ring) = (look.fill, if significant { SIGNIFICANT } else { look.ring });
            let node_flash = if self.hunt_reveal.is_some() { look.edges.iter().filter_map(|&k| self.reveal_state(k as usize, frame_now)).filter(|(shown, _)| *shown).map(|(_, f)| f).fold(0.0f32, f32::max) } else { 0.0 };
            if node_flash > 0.0 && r > 2.0 {
                painter.circle_filled(p, r + 4.0 + 22.0 * node_flash, draw::fade(if significant { SIGNIFICANT } else { CANDIDATE }, 0.35 * node_flash));
            }
            let glow_strength = if look.glow {
                1.0
            } else if significant {
                if motion { 0.8 + 0.2 * (now * 2.4 + i as f32).sin() } else { 0.9 }
            } else if n.hunt_rank == 1 && dimmed < 0.5 {
                0.12
            } else if lit && focus.is_some() {
                0.6
            } else {
                0.0
            };
            let small = (r < 10.0 || crowd_nodes) && matches!(look.shape, Shape::Circle) && !selected && !hovered && !lit;
            if glow_strength > 0.0 && r > 4.0 && (significant || lit || look.glow || (r > 7.0 && !lod)) {
                let gc = if significant { SIGNIFICANT } else if n.hunt_rank == 1 { CANDIDATE } else { fill };
                if small {
                    draw::disc(&mut node_mesh, p, r * 1.6 + 2.0, draw::fade(gc, 0.16 * glow_strength * alpha));
                } else {
                    draw::glow(&painter, p, r + 2.0, gc, glow_strength * alpha);
                }
                if significant && motion {
                    keep_moving = true;
                }
            }
            if hovered && !selected {
                let pulse = if motion { 2.5 * (now * 5.0).sin() } else { 0.0 };
                painter.circle_stroke(p, r + 5.0 + pulse, Stroke::new(1.5, draw::fade(Color32::WHITE, 0.45)));
                if motion {
                    keep_moving = true;
                }
            }
            if selected {
                painter.circle_filled(p, r + 7.0, draw::fade(ACCENT, 0.18));
                painter.circle_stroke(p, r + 5.0, Stroke::new(2.0, draw::fade(ACCENT, 0.95)));
            }
            if small {
                draw::disc(&mut node_mesh, p, r, draw::fade(fill, alpha));
                if r >= 5.0 {
                    draw::ring(&mut node_mesh, p, r, ring_w.min(1.5) * if significant { 1.6 } else { 1.0 }, draw::fade(draw::lighten(ring, 0.25), alpha * 0.95));
                }
            } else {
                if let Some(dev) = look.device {
                    if motion {
                        keep_moving = true;
                    }
                    if significant {
                        painter.circle_filled(p, r * 1.3, draw::fade(SIGNIFICANT, 0.12 * alpha));
                    }
                    if self.style.node_style == NodeStyle::Arcade {
                        super::devices::draw_arcade(&painter, dev, p, r, fill, ring, alpha, now + i as f32 * 0.37, motion);
                    } else {
                        super::devices::draw(&painter, dev, p, r, fill, ring, alpha, now + i as f32 * 0.37, motion);
                    }
                } else if let (Some(g), NodeStyle::Icon) = (look.icon, self.style.node_style) {
                    draw::tile(&painter, p, r, fill, ring, alpha, ring_w * if significant { 1.6 } else { 1.0 }, g);
                } else if matches!(look.shape, Shape::Circle) {
                    // the sheen runs on the hosts that matter, and on all of them when few
                    let sheen = if motion && (lit || significant || n.hunt_rank == 1 || self.graph.nodes.len() <= 120) { Some(now * 0.9 + i as f32 * 0.7) } else { None };
                    if sheen.is_some() {
                        keep_moving = true;
                    }
                    draw::glass(&painter, p, r, fill, ring, alpha, ring_w * if significant { 1.6 } else { 1.0 }, look.icon, self.style.node_style == NodeStyle::Minimal, sheen);
                } else {
                    draw::orb(&painter, look.shape, p, r, fill, ring, alpha, ring_w * if significant { 1.6 } else { 1.0 });
                    if let Some(g) = look.icon {
                        painter.text(p, Align2::CENTER_CENTER, g, FontId::proportional((r * 1.0).max(8.0)), draw::fade(Color32::WHITE, 0.94 * alpha));
                    }
                }
            }
            if show_pins && r > 5.0 && self.layout.fixed.get(i).copied().unwrap_or(false) {
                let at = p + Vec2::new(r * 0.78, -r * 0.78);
                let px = (r * 0.62).clamp(10.0, 17.0);
                painter.circle_filled(at, px * 0.62, draw::fade(BG, 0.85 * alpha));
                painter.text(at, Align2::CENTER_CENTER, super::icons::PUSH_PIN, FontId::proportional(px), draw::fade(ACCENT, alpha));
            }
            nodes_drawn += 1;
            let anonym = self.presenting && self.story.anonymise;
            let shown: Cow<str> = if anonym { Cow::Owned(self.anon.host(n.host, look.is_ip)) } else { Cow::Borrowed(look.name.as_str()) };
            let shown_name: &str = &shown;
            if z > 0.3 || lit || look.label_pos != LabelPos::Auto {
                let base_px = (11.0 * z.sqrt() * fs * look.label_size).clamp(6.5, 40.0);
                let pos = if (look.icon.is_some() || look.device.is_some() || self.style.node_style == NodeStyle::Minimal) && matches!(look.label_pos, LabelPos::Auto | LabelPos::Inside) { LabelPos::Below } else { look.label_pos };
                labels::paint_host_label(&painter, shown_name, p, r, pos, base_px, look.label_bg, ring, alpha, lit, crowd_nodes || lod, self.style.node_style == NodeStyle::Arcade);
            }
            if let Some(label) = self.overlay.as_ref().and_then(|o| o.labels.get(&n.host)) {
                let galley = painter.layout_no_wrap(label.clone(), FontId::proportional((10.5 * z.sqrt() * fs).clamp(8.0, 14.0)), ACCENT);
                let h = galley.size().y;
                draw::pill(&painter, Pos2::new(p.x, p.y + r + 10.0 + h / 2.0), galley, draw::fade(CAPTION_BG, alpha), Some(draw::fade(ACCENT, 0.5 * alpha)), ACCENT);
            }
        }

        if !node_mesh.is_empty() {
            painter.set(node_slot, egui::Shape::mesh(node_mesh));
        }
        self.draw_subnets(&painter, canvas, true);
        self.nodes_ms = t_nodes.elapsed().as_secs_f32() * 1000.0;
        if self.style.motion && !self.presenting {
            // the dust and the stars move on their own
            keep_moving = true;
        }
        if keep_moving {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(16));
        }

        if arcade_mode {
            draw::scanlines(&painter, canvas, 0.10);
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
            painter.rect_filled(r, CornerRadius::same(6), Color32::from_rgba_premultiplied(22, 26, 36, 235));
            painter.rect_stroke(r, CornerRadius::same(6), Stroke::new(1.0, BORDER), egui::StrokeKind::Outside);
            painter.galley(r.min + Vec2::new(6.0, 4.0), galley, TEXT);
        }

        if self.presenting {
            self.presentation_overlays(&painter, canvas);
        }
        self.nodes_drawn = nodes_drawn;
        self.edges_drawn = edges_drawn;
        self.draw_ms = draw_start.elapsed().as_secs_f32() * 1000.0;
        if !self.presenting && self.story.logo_always {
            self.brand_overlay(&painter, canvas, 0.0);
        }
        if self.hud {
            let fps = if self.frame_ms > 0.0 { 1000.0 / self.frame_ms } else { 0.0 };
            let text = format!("{} / {} hosts · {} / {} edges · layout {:.1} · bg {:.1} · geom {:.1} · hit {:.1} · edges {:.1} · hosts {:.1} · draw {:.1} ms · frame {:.0} ms (masstin {:.0}, rendering {:.0}) · {:.1} fps{}{} · F1 keeps drawing", nodes_drawn, self.graph.nodes.len(), edges_drawn, self.graph.edges.len(), self.layout_ms, self.bg_ms, self.geom_ms, self.hit_ms, self.edges_ms, self.nodes_ms, self.draw_ms, self.frame_ms, self.inside_ms, self.outside_ms, fps, if lod { " · reduced detail" } else { "" }, if self.light_mode { " · light mode" } else { "" });
            let galley = painter.layout_no_wrap(text, FontId::monospace(11.0), TEXT);
            let r = Rect::from_min_size(Pos2::new(canvas.left() + 10.0, canvas.bottom() - galley.size().y - 16.0), galley.size() + Vec2::new(12.0, 8.0));
            painter.rect_filled(r, CornerRadius::same(6), Color32::from_rgba_premultiplied(22, 26, 36, 225));
            painter.galley(r.min + Vec2::new(6.0, 4.0), galley, TEXT);
            ui.ctx().request_repaint();
        }
    }

    /// The story's logo in its corner. `lift` raises a bottom logo above a
    /// caption. Returns where it went.
    fn brand_overlay(&mut self, painter: &egui::Painter, canvas: Rect, lift: f32) -> Option<Rect> {
        let path = self.story.logo.trim().to_string();
        if path.is_empty() {
            self.brand = None;
            return None;
        }
        if self.brand.as_ref().map_or(true, |(p, _, _)| *p != path) {
            if self.brand_err.as_ref().map_or(false, |(p, _)| *p == path) {
                return None;
            }
            self.brand = None;
            match image::open(&path) {
                Ok(img) => {
                    let mut rgba = img.to_rgba8();
                    if rgba.width() > 1024 {
                        let h = ((rgba.height() as f32) * 1024.0 / rgba.width() as f32).max(1.0) as u32;
                        rgba = image::imageops::resize(&rgba, 1024, h, image::imageops::FilterType::Lanczos3);
                    }
                    let size = [rgba.width() as usize, rgba.height() as usize];
                    let ci = egui::ColorImage::from_rgba_unmultiplied(size, rgba.as_raw());
                    let tex = painter.ctx().load_texture("brand-logo", ci, egui::TextureOptions::LINEAR);
                    self.brand = Some((path.clone(), tex, size));
                    self.brand_err = None;
                }
                Err(e) => {
                    self.brand_err = Some((path, e.to_string()));
                    return None;
                }
            }
        }
        let (_, tex, size) = self.brand.as_ref()?;
        let mut w = canvas.width() * self.story.logo_width.clamp(0.03, 0.6);
        let mut h = w * size[1] as f32 / size[0].max(1) as f32;
        let max_h = canvas.height() * 0.3;
        if h > max_h {
            w *= max_h / h;
            h = max_h;
        }
        let m = 14.0;
        let x = match self.story.logo_pos {
            LogoPos::TopLeft | LogoPos::BottomLeft => canvas.left() + m,
            LogoPos::TopCentre | LogoPos::BottomCentre => canvas.center().x - w / 2.0,
            LogoPos::TopRight | LogoPos::BottomRight => canvas.right() - m - w,
        };
        let y = match self.story.logo_pos {
            LogoPos::TopLeft | LogoPos::TopCentre | LogoPos::TopRight => canvas.top() + m,
            _ => canvas.bottom() - m - h - lift,
        };
        let r = Rect::from_min_size(Pos2::new(x, y), Vec2::new(w, h));
        painter.image(tex.id(), r, Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)), draw::fade(Color32::WHITE, self.story.logo_opacity.clamp(0.05, 1.0)));
        Some(r)
    }

    fn presentation_overlays(&mut self, painter: &egui::Painter, canvas: Rect) {
        let fs = self.style.font_scale;
        let cur = self.current_step();
        // a bottom logo stays above the caption; a top-centre one pushes the title down
        let lift = if self.story.show_caption && cur.is_some() { 64.0 * fs } else { 0.0 };
        let logo = self.brand_overlay(painter, canvas, lift);
        if !self.story.title.is_empty() {
            let top = match logo {
                Some(r) if self.story.logo_pos == LogoPos::TopCentre => r.bottom() + 8.0,
                _ => canvas.top() + 16.0,
            };
            painter.text(Pos2::new(canvas.center().x, top), Align2::CENTER_TOP, &self.story.title, FontId::proportional(22.0 * fs), TEXT);
        }
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
            // a recording is the window itself: nothing drawn that is not the story
            Some(_) => {}
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
                ui.label("Logo").on_hover_text("Your company's logo on the presentation and the recording: PNG (with transparency), JPEG, WebP, BMP or GIF. The path is saved with the story.");
                ui.horizontal(|ui| {
                    changed |= ui.add_sized([188.0, 20.0], egui::TextEdit::singleline(&mut self.story.logo).hint_text("none: pick an image file…")).changed();
                    if ui.button("Choose…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().set_title("Logo for the recording").add_filter("Images", &["png", "jpg", "jpeg", "webp", "bmp", "gif"]).pick_file() {
                            self.story.logo = p.to_string_lossy().to_string();
                            changed = true;
                        }
                    }
                    if !self.story.logo.is_empty() && ui.add(egui::Button::new(egui::RichText::new(super::icons::X).color(theme::DIM)).frame(false)).on_hover_text("No logo").clicked() {
                        self.story.logo.clear();
                        changed = true;
                    }
                });
                ui.label("Place it");
                egui::ComboBox::from_id_salt("logo-pos").selected_text(self.story.logo_pos.label()).show_ui(ui, |ui| {
                    for p in LogoPos::ALL {
                        changed |= ui.selectable_value(&mut self.story.logo_pos, p, p.label()).changed();
                    }
                });
                ui.label("Width % / opacity");
                ui.horizontal(|ui| {
                    let mut pct = self.story.logo_width * 100.0;
                    if ui.add(egui::DragValue::new(&mut pct).range(3.0..=60.0).speed(0.5).fixed_decimals(0).suffix(" %")).on_hover_text("of the window's width; the height follows the image").changed() {
                        self.story.logo_width = pct / 100.0;
                        changed = true;
                    }
                    changed |= ui.add(egui::DragValue::new(&mut self.story.logo_opacity).range(0.05..=1.0).speed(0.02).fixed_decimals(2)).on_hover_text("1: as it is; lower for a watermark").changed();
                    changed |= ui.checkbox(&mut self.story.logo_always, "also on the window").on_hover_text("Show it outside the presentation too").changed();
                });
                ui.end_row();
                if let Some((p, e)) = &self.brand_err {
                    if *p == self.story.logo.trim() {
                        ui.label("");
                        ui.label(egui::RichText::new(format!("cannot read this image: {}", e)).color(SIGNIFICANT).small());
                        ui.end_row();
                    }
                }
            });
            ui.add_space(4.0);
            ui.label(egui::RichText::new("STRETCHES   (a part of the timeline at a speed of its own: the first stretch a step falls in sets its timing; the rest take the global one)").small().color(MUTED));
            let mut remove_stretch: Option<usize> = None;
            egui::Grid::new("stretches").num_columns(7).spacing([8.0, 4.0]).show(ui, |ui| {
                for h in ["from", "to", "timing", "speed", "", "", ""] {
                    ui.label(egui::RichText::new(h).small().color(MUTED));
                }
                ui.end_row();
                let n_str = self.story.stretches.len();
                for i in 0..n_str {
                    let s = &mut self.story.stretches[i];
                    let ok_from = s.from.trim().is_empty() || parse_time(&s.from).is_some();
                    let ok_to = s.to.trim().is_empty() || parse_time(&s.to).is_some();
                    changed |= ui.add_sized([150.0, 20.0], egui::TextEdit::singleline(&mut s.from).hint_text("start").text_color(if ok_from { TEXT } else { SIGNIFICANT })).on_hover_text("YYYY-MM-DD HH:MM; empty: from the start").changed();
                    changed |= ui.add_sized([150.0, 20.0], egui::TextEdit::singleline(&mut s.to).hint_text("end").text_color(if ok_to { TEXT } else { SIGNIFICANT })).on_hover_text("YYYY-MM-DD HH:MM; empty: to the end").changed();
                    egui::ComboBox::from_id_salt(("stretch-timing", i)).selected_text(match s.timing { Timing::Fixed => "same time per step", Timing::Compressed => "by the clock" }).width(150.0).show_ui(ui, |ui| {
                        changed |= ui.selectable_value(&mut s.timing, Timing::Fixed, "same time per step").changed();
                        changed |= ui.selectable_value(&mut s.timing, Timing::Compressed, "by the clock").changed();
                    });
                    match s.timing {
                        Timing::Fixed => {
                            changed |= ui.add(egui::DragValue::new(&mut s.step_secs).range(0.05..=60.0).speed(0.05).fixed_decimals(2).suffix(" s/step")).changed();
                            ui.label(egui::RichText::new("every step this long").small().color(MUTED));
                        }
                        Timing::Compressed => {
                            let mut mins = s.compress / 60.0;
                            if ui.add(egui::DragValue::new(&mut mins).range(0.01..=1_000_000.0).speed(1.0).fixed_decimals(1).suffix(" min/s")).on_hover_text("minutes of the timeline a second; the gap min / max above still clamp each step").changed() {
                                s.compress = mins * 60.0;
                                changed = true;
                            }
                            ui.label(egui::RichText::new(present::clock_label(s.compress)).small().color(MUTED));
                        }
                    }
                    if ui.add(egui::Button::new(egui::RichText::new(super::icons::TRASH).color(theme::DIM)).frame(false)).on_hover_text("Remove this stretch").clicked() {
                        remove_stretch = Some(i);
                    }
                    ui.label("");
                    ui.end_row();
                }
            });
            if let Some(i) = remove_stretch {
                self.story.stretches.remove(i);
                changed = true;
            }
            ui.horizontal(|ui| {
                if ui.button("+  Add a stretch").on_hover_text("A new stretch over the window the filter selects (From / To), at the story's speed; edit it").clicked() {
                    let mut s = present::Stretch::default();
                    s.from = self.filter.from.trim().to_string();
                    s.to = self.filter.to.trim().to_string();
                    s.timing = self.story.timing;
                    s.step_secs = self.story.step_secs;
                    s.compress = self.story.compress;
                    self.story.stretches.push(s);
                    changed = true;
                }
                if !self.story.stretches.is_empty() {
                    ui.label(egui::RichText::new(format!("{} stretch(es); steps outside them take the global timing", self.story.stretches.len())).small().color(MUTED));
                }
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
                for (i, name) in ["this window", "1280 x 720", "1920 x 1080", "1600 x 900"].iter().enumerate() {
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
            3 => Some(Vec2::new(1600.0, 900.0)),
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

    /// Film the window as it is used (Tools › Film the window, or
    /// `MASSTIN_VIEW_AUTO=film=mp4:20:1[:file]`): a frame whenever one is
    /// due at the rate, in real time, until Stop filming, `cut` or `quit`.
    /// MP4 through ffmpeg's standard input; GIF with the encoder of the
    /// story. The file goes next to the timeline, or to the temp dir
    /// when nothing is open.
    pub(super) fn start_film(&mut self, ctx: &egui::Context, format: Format, fps: u32, size: usize, out: Option<std::path::PathBuf>, quiet: bool) {
        if self.film.is_some() {
            return;
        }
        let format = if format == Format::Mp4 && !present::ffmpeg_available() { Format::Gif } else if format == Format::Png { Format::Gif } else { format };
        let out = out.unwrap_or_else(|| {
            let (dir, stem) = match self.files.first() {
                Some(f) => {
                    let p = std::path::Path::new(f);
                    (p.parent().map(|d| d.to_path_buf()).unwrap_or_default(), p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "masstin".into()))
                }
                None => (std::env::temp_dir().join("masstin"), "masstin".to_string()),
            };
            let _ = std::fs::create_dir_all(&dir);
            dir.join(format!("{}-film-{}.{}", stem, chrono::Local::now().format("%Y%m%d-%H%M%S"), if format == Format::Gif { "gif" } else { "mp4" }))
        });
        let fps = fps.clamp(5, 60);
        let restore = match size {
            1 => Some(Vec2::new(1280.0, 720.0)),
            2 => Some(Vec2::new(1920.0, 1080.0)),
            3 => Some(Vec2::new(1600.0, 900.0)),
            _ => None,
        };
        let current = ctx.input(|i| i.viewport().inner_rect.map(|r| r.size()));
        if let Some(s) = restore {
            let ppp = ctx.pixels_per_point();
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(s / ppp));
        }
        let rec = match format {
            Format::Mp4 => present::Recorder::start_stream(fps, out.clone()),
            _ => present::Recorder::start(fps, Format::Gif, out.clone()),
        };
        let (tx, rx) = std::sync::mpsc::channel();
        // a resized window needs a frame or two before it is its new size
        let started = std::time::Instant::now() + std::time::Duration::from_millis(if restore.is_some() { 500 } else { 0 });
        self.film = Some(FilmJob { fps, started, pushed: 0, waiting: false, rx, tx, restore: if restore.is_some() { current } else { None }, rec, quit_after: false });
        // from the menu the status says so; the autopilot's film stays clean
        if !quiet {
            self.status = format!("Filming the window to {} (Tools > Stop filming)", out.display());
        }
        if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
            eprintln!("[view] filming the window to {}", out.display());
        }
    }

    fn stop_film(&mut self, quit_after: bool) {
        if let Some(job) = self.film.as_mut() {
            job.quit_after |= quit_after;
            job.rec.finish();
        }
    }

    /// Drive a film: when a frame is due, ask for a screenshot; when it
    /// comes, push it once per slot that went by.
    fn film_step(&mut self, ctx: &egui::Context) {
        let Some(job) = self.film.as_mut() else { return };
        if let Some(result) = job.rec.result() {
            let (restore, quit) = (job.restore, job.quit_after);
            self.film = None;
            if let Some(size) = restore {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
            }
            self.status = match result {
                Ok(m) => format!("Filmed: {}", m),
                Err(e) => format!("Filming failed: {}", e),
            };
            if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
                eprintln!("[view] {}", self.status);
            }
            if quit {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            return;
        }
        if job.rec.finishing() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
            return;
        }
        let elapsed = std::time::Instant::now().saturating_duration_since(job.started).as_secs_f32();
        if job.waiting {
            if let Ok((_, img)) = job.rx.try_recv() {
                let due = (elapsed * job.fps as f32).floor() as usize;
                // a stall (the window starved by a parser, a slow read-back) is held
                // frozen for as long as it lasted, so the film keeps the clock's time
                let n = due.saturating_sub(job.pushed).clamp(1, 30 * job.fps as usize);
                for _ in 0..n {
                    job.rec.push(img.clone());
                }
                job.pushed += n;
                job.waiting = false;
            }
        }
        if !job.waiting && (elapsed * job.fps as f32) as usize >= job.pushed {
            let tx = job.tx.clone();
            let idx = job.pushed;
            job.waiting = true;
            ctx.request_screenshot(move |img| {
                let _ = tx.send((idx, img));
            });
        }
        ctx.request_repaint();
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
        if let Some(f) = &self.film {
            if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
                eprintln!("[film] t={:.2} {}", std::time::Instant::now().saturating_duration_since(f.started).as_secs_f32(), cmd);
            }
        }
        if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
            let b = self.layout.bounds().map(|(lo, hi)| format!("({:.0},{:.0})-({:.0},{:.0})", lo.x, lo.y, hi.x, hi.y)).unwrap_or_default();
            eprintln!("[view] auto: {}  [cam ({:.0},{:.0}) -> ({:.0},{:.0}) zoom {:.2} -> {:.2} bounds {}]", cmd, self.cam.x, self.cam.y, self.cam_t.x, self.cam_t.y, self.zoom, self.zoom_t, b);
        }
        match cmd.as_str() {
            "present" => self.start_presentation(),
            "story" => self.show_story = true,
            "rules" => self.show_rules = true,
            "fit" => {
                self.fill_pending = true;
                self.layout.stop();
            }
            "questions" => self.show_questions = true,
            "quit" => {
                if self.film.is_some() {
                    self.stop_film(true);
                } else {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
            "cut" => self.stop_film(false),
            "close" => {
                self.ingest.open = false;
                self.show_hunt = false;
                self.hunt_report = None;
                self.show_story = false;
                self.show_table = false;
                self.show_paths = false;
                self.show_questions = false;
                self.show_last_log = false;
                if self.presenting {
                    self.stop_presentation();
                }
                if self.job.as_ref().map_or(false, |j| j.done.is_some()) {
                    let j = self.job.take().unwrap();
                    self.last_log = Some((j.command, j.log));
                }
                if self.overlay.is_some() {
                    self.overlay = None;
                    self.path_found.clear();
                    self.path_msg.clear();
                    self.requery(false);
                }
            }
            "hud" => self.hud = !self.hud,
            "motion" => self.style.motion = !self.style.motion,
            "table" => self.show_table = true,
            "ingest" => self.ingest.open = true,
            "ingest-go" => {
                if self.ingest.output.trim().is_empty() {
                    self.ingest.output = self.ingest.default_output();
                }
                self.run_ingest();
            }
            other if other.starts_with("ingest=") => self.ingest_with(vec![other["ingest=".len()..].to_string()]),
            other if other.starts_with("ingest-step=") => {
                self.ingest.open = true;
                self.ingest.step = other["ingest-step=".len()..].parse::<usize>().unwrap_or(0).min(3);
            }
            other if other.starts_with("size=") => {
                // size=WxH: the window's inner size in points
                if let Some((w, h)) = other["size=".len()..].split_once('x') {
                    if let (Ok(w), Ok(h)) = (w.parse::<f32>(), h.parse::<f32>()) {
                        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(Vec2::new(w, h)));
                    }
                }
            }
            other if other.starts_with("results=") => {
                // results=ok+fail+connect+logoff: the result pills of the filter pane
                let toks: Vec<&str> = other["results=".len()..].split('+').map(|t| t.trim()).collect();
                for (name, k) in [("ok", R_OK), ("fail", R_FAIL), ("connect", R_CONNECT), ("logoff", R_LOGOFF)] {
                    self.draft.results[k as usize] = toks.contains(&name);
                }
                self.requery(false);
            }
            other if other.starts_with("from=") || other.starts_with("to=") || other.starts_with("user=") || other.starts_with("host=") => {
                match other.split_once('=') {
                    Some(("from", v)) => self.draft.from = v.to_string(),
                    Some(("to", v)) => self.draft.to = v.to_string(),
                    Some(("user", v)) => self.draft.user = v.to_string(),
                    Some((_, v)) => self.draft.host = v.to_string(),
                    None => {}
                }
                self.requery(false);
            }
            other if other.starts_with("out=") => self.ingest.output = other["out=".len()..].to_string(),
            other if other.starts_with("drop=") || other.starts_with("drop+=") => {
                // as if the file had been dropped on the window; `drop+=` adds
                let (add, p) = match other.strip_prefix("drop+=") {
                    Some(p) => (true, p),
                    None => (false, &other["drop=".len()..]),
                };
                self.drop_files(vec![std::path::PathBuf::from(p)], add);
            }
            "ingest-stop" => {
                if let Some(j) = self.job.as_mut() {
                    j.cancel();
                }
            }
            other if other.starts_with("hunt=") => {
                self.hunt_form.from = other["hunt=".len()..].to_string();
                self.hunt_form.alpha = format!("{}", self.alpha);
                self.hunt_form.end.clear();
                self.show_hunt = true;
                self.hunt_autorun = true;
            }
            other if other.starts_with("bench=") => {
                // bench=N heats the layout first; bench=N:cold measures it as it is
                let spec = &other["bench=".len()..];
                let (n, cold) = match spec.split_once(':') {
                    Some((n, "cold")) => (n.parse().unwrap_or(120), true),
                    _ => (spec.parse().unwrap_or(120), false),
                };
                if !cold {
                    self.layout.reheat(1.0);
                }
                self.bench = Some((n, Vec::new()));
            }
            other if other.starts_with("shot=") => {
                let path = std::path::PathBuf::from(&other["shot=".len()..]);
                let debug = std::env::var_os("MASSTIN_VIEW_DEBUG").is_some();
                ctx.request_screenshot(move |img| {
                    let rgba = present::to_rgba(&img);
                    match rgba.save(&path) {
                        Ok(()) => {
                            if debug {
                                eprintln!("[view] screenshot {}", path.display());
                            }
                        }
                        Err(e) => eprintln!("masstin: cannot write {}: {}", path.display(), e),
                    }
                });
            }
            other if other.starts_with("all=") => {
                self.draft.view = View::All;
                self.draft.limit = other["all=".len()..].parse().unwrap_or(5000);
                self.draft.from.clear();
                self.draft.to.clear();
                self.requery(true);
            }
            other if other.starts_with("wait=") => {
                let secs: f32 = other["wait=".len()..].parse().unwrap_or(1.0);
                self.auto_next = now + std::time::Duration::from_secs_f32(secs.max(0.0));
            }
            other if other.starts_with("zoom=") => {
                self.zoom_t = other["zoom=".len()..].parse::<f32>().unwrap_or(1.0).clamp(0.03, 6.0);
            }
            other if other.starts_with("select=") => {
                let name = other["select=".len()..].to_ascii_uppercase();
                self.selected = self.graph.nodes.iter().position(|n| self.store.hosts.name(n.host).eq_ignore_ascii_case(&name)).map(Sel::Node);
            }
            other if other.starts_with("pin=") => {
                // pin=HOST:DX:DY: the host moved by (DX, DY) and pinned there, as a drag leaves it
                let mut it = other["pin=".len()..].split(':');
                let name = it.next().unwrap_or("").to_string();
                let dx: f32 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
                let dy: f32 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
                if let Some(i) = self.graph.nodes.iter().position(|n| self.store.hosts.name(n.host).eq_ignore_ascii_case(&name)) {
                    self.layout.pos[i] += V2::new(dx, dy);
                    self.layout.fixed[i] = true;
                    self.layout.reheat(0.1);
                }
            }
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
                if let Some(spec) = other.strip_prefix("film=") {
                    // film=FORMAT:FPS:SIZE[:file]  (mp4 | gif; size 0 window, 1 720p, 2 1080p)
                    let mut parts = spec.splitn(4, ':');
                    let format = match parts.next().unwrap_or("mp4") {
                        "gif" => Format::Gif,
                        _ => Format::Mp4,
                    };
                    let fps = parts.next().and_then(|f| f.parse().ok()).unwrap_or(20);
                    let size = parts.next().and_then(|f| f.parse().ok()).unwrap_or(0);
                    let out = parts.next().filter(|s| !s.is_empty()).map(std::path::PathBuf::from);
                    self.start_film(ctx, format, fps, size, out, true);
                } else if let Some(spec) = other.strip_prefix("record=") {
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

#[cfg(test)]
mod renderer_tests {
    use super::is_software_renderer;

    #[test]
    fn software_renderers_are_told_from_gpus() {
        for s in ["OpenGL · GDI Generic · Microsoft Corporation · 1.1.0", "OpenGL · llvmpipe (LLVM 15.0.7, 256 bits) · Mesa · 4.5", "wgpu · Microsoft Basic Render Driver · Dx12 · Cpu", "OpenGL · SwiftShader · Google · 3.0", "software · masstin's CPU rasteriser · Avx2"] {
            assert!(is_software_renderer(s), "{}", s);
        }
        for s in ["OpenGL · NVIDIA GeForce RTX 3060/PCIe/SSE2 · NVIDIA Corporation · 4.6.0", "wgpu · AMD Radeon RX 6800 · Vulkan · DiscreteGpu", "OpenGL · Intel(R) Iris(R) Xe Graphics · Intel · 4.6.0"] {
            assert!(!is_software_renderer(s), "{}", s);
        }
    }
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
        self.frame(ui);
    }
}

impl super::softwin::SoftApp for Viewer {
    fn frame(&mut self, ui: &mut egui::Ui) {
        Viewer::frame(self, ui);
    }
}

impl Viewer {
    /// One frame of the window, whatever draws it.
    fn frame(&mut self, ui: &mut egui::Ui) {
        let __ui_start = std::time::Instant::now();
        self.ui_inner(ui);
        self.inside_ms = self.inside_ms * 0.8 + __ui_start.elapsed().as_secs_f32() * 1000.0 * 0.2;
        self.ui_end = Some(std::time::Instant::now());
    }
}

impl Viewer {
    fn ui_inner(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let now = std::time::Instant::now();
        let gap = (now - self.last_frame).as_secs_f32();
        if let Some(end) = self.ui_end.take() {
            let o = (now - end).as_secs_f32() * 1000.0;
            if o < 2000.0 {
                self.outside_ms = self.outside_ms * 0.8 + o * 0.2;
            }
        }
        let dt = gap.min(0.25);
        self.last_frame = now;
        self.frame_dt = dt;
        self.frame_gap_ms = gap * 1000.0;
        // the HUD's average: only frames that follow one another (a frame after a pause is not a cost)
        if gap < 2.0 {
            self.frame_ms = self.frame_ms * 0.8 + gap * 1000.0 * 0.2;
        }
        self.fps_count += 1;
        if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
            let since = (now - self.fps_since).as_secs_f32();
            if since >= 2.0 {
                eprintln!("[view] {} frame(s) in {:.1} s ({:.1} a second) · in masstin {:.1} ms · in eframe (tessellate, render, present) {:.1} ms{}", self.fps_count, since, self.fps_count as f32 / since, self.inside_ms, self.outside_ms, if self.light_mode { " · light mode" } else { "" });
                self.fps_count = 0;
                self.fps_since = now;
            }
        }
        self.watch_frame_cost(dt);
        if ctx.input(|i| i.key_pressed(egui::Key::F1)) {
            self.hud = !self.hud;
        }
        if self.playing {
            let before = self.cursor;
            let n_ev = self.graph.events.len();
            match self.rate_secs {
                None => {
                    self.acc += dt * self.rate;
                    let step = self.acc.floor() as usize;
                    if step > 0 {
                        self.acc -= step as f32;
                        self.cursor = (self.cursor + step).min(n_ev);
                    }
                }
                Some(per_sec) => {
                    // the clock advances; the head takes every row up to it
                    self.replay_t += (dt * per_sec) as f64;
                    let t = self.replay_t.floor() as i64;
                    let k = self.graph.events[self.cursor.min(n_ev)..].partition_point(|&ei| self.store.edges[ei as usize].t <= t);
                    self.cursor = (self.cursor + k).min(n_ev);
                }
            }
            if self.cursor >= n_ev {
                self.playing = false;
            }
            if self.cursor > before {
                self.replay_crossed(before, self.cursor);
            }
            ctx.request_repaint();
        }
        self.film_step(&ctx);
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
                // steps wholly drawn at this moment; Right shows one more,
                // Left one fewer (the time a step ends is the next one's
                // start when there is no pause, so counting "the current
                // step" would stick on the same one and never go back)
                let t = self.present_t;
                let done = self.steps.iter().take_while(|s| s.start + s.dur <= t + 1e-4).count();
                let want = if right { (done + 1).min(self.steps.len()) } else { done.saturating_sub(1) };
                self.present_t = match want {
                    0 => 0.0,
                    n => self.steps[n - 1].start + self.steps[n - 1].dur,
                };
                ctx.request_repaint();
            }
        }
        if self.presenting {
            egui::CentralPanel::default().frame(egui::Frame::new().fill(BG)).show(ui, |ui| self.canvas(ui));
            return;
        }
        // files dropped on the window: timelines open, evidence goes to the wizard
        let dropped: Vec<std::path::PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).collect());
        if !dropped.is_empty() {
            let add = ctx.input(|i| i.modifiers.ctrl || i.modifiers.shift);
            self.drop_files(dropped, add);
        }
        let bar = |fill: Color32, m: egui::Margin| egui::Frame::new().fill(fill).inner_margin(m);
        egui::Panel::top("menu").frame(bar(theme::PANEL, egui::Margin::symmetric(6, 3))).show_separator_line(false).show(ui, |ui| self.menu_bar(ui));
        egui::Panel::top("toolbar").frame(bar(theme::PANEL, egui::Margin::symmetric(10, 6))).show_separator_line(false).show(ui, |ui| self.toolbar(ui));
        if self.filters_active() {
            egui::Panel::top("chips").frame(bar(theme::PANEL_2, egui::Margin::symmetric(12, 6))).show_separator_line(false).show(ui, |ui| {
                self.filter_chips(ui);
            });
        }
        egui::Panel::bottom("status").frame(bar(theme::PANEL, egui::Margin::symmetric(12, 4))).show_separator_line(false).show(ui, |ui| self.status_bar(ui));
        egui::Panel::bottom("time").frame(bar(theme::PANEL, egui::Margin::symmetric(10, 8))).show(ui, |ui| self.time_strip(ui));
        if self.show_filters {
            egui::Panel::left("filters").default_size(292.0).resizable(true).frame(bar(theme::PANEL, egui::Margin::symmetric(14, 10))).show(ui, |ui| self.left_panel(ui));
        }
        if self.show_inspector {
            egui::Panel::right("inspector").default_size(400.0).resizable(true).frame(bar(theme::PANEL, egui::Margin::same(14))).show(ui, |ui| self.inspector(ui));
        }
        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG)).show(ui, |ui| self.canvas(ui));
        if self.layout.len() > 0 && !self.ingest.open {
            let r = self.canvas_rect;
            self.legend_overlay(&ctx, r);
            self.limit_banner(&ctx, r);
        }
        self.color_window(&ctx);
        self.mark_window(&ctx);
        self.note_window(&ctx);
        self.help_window(&ctx);
        self.hunt_window(&ctx);
        if let Some(at) = self.hunt_report_at {
            if std::time::Instant::now() >= at {
                self.hunt_report_at = None;
                self.hunt_report = Some(self.build_report());
            } else {
                ctx.request_repaint_after(std::time::Duration::from_millis(200));
            }
        }
        self.report_window(&ctx);
        self.ingest_window(&ctx);
        self.merge_window(&ctx);
        self.poll_job(&ctx);
        self.job_window(&ctx);
        self.last_log_window(&ctx);
        self.table_window(&ctx);
        self.drop_overlay(&ctx);
        self.labels_window(&ctx);
        self.about_window(&ctx);
        self.host_window(&ctx);
        self.edge_window(&ctx);
        self.merge_host_window(&ctx);
        self.merges_window(&ctx);
        self.subnets_window(&ctx);
        self.rules_window(&ctx);
        self.save_popup(&ctx);
        self.confirm_delete_window(&ctx);
        self.story_window(&ctx);
        self.export_window(&ctx);
        self.paths_window(&ctx);
        self.questions_window(&ctx);
        self.bench_step(&ctx, dt);
    }
}

impl Viewer {
    /// `MASSTIN_VIEW_AUTO=bench=N`: the next N frames timed, the figures
    /// on stderr.
    fn bench_step(&mut self, ctx: &egui::Context, dt: f32) {
        let Some((n, mut samples)) = self.bench.take() else { return };
        samples.push((dt * 1000.0, self.layout_ms, self.draw_ms, self.edges_ms, self.nodes_ms, self.bg_ms, self.geom_ms, self.hit_ms));
        if samples.len() < n {
            self.bench = Some((n, samples));
            ctx.request_repaint();
            return;
        }
        let mut frames: Vec<f32> = samples.iter().map(|s| s.0).collect();
        frames.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let avg = |f: &dyn Fn(&(f32, f32, f32, f32, f32, f32, f32, f32)) -> f32| samples.iter().map(f).sum::<f32>() / samples.len() as f32;
        eprintln!(
            "[view] bench: {} frames, {} / {} hosts drawn, {} / {} edges drawn; frame avg {:.1} ms, p95 {:.1} ms, max {:.1} ms; layout avg {:.1} ms; draw avg {:.1} ms (edges {:.1}, hosts {:.1}, background {:.1}, geometry {:.1}, hit test {:.1})",
            samples.len(),
            self.nodes_drawn,
            self.graph.nodes.len(),
            self.edges_drawn,
            self.graph.edges.len(),
            avg(&|s| s.0),
            frames[(frames.len() as f32 * 0.95) as usize - 1],
            frames[frames.len() - 1],
            avg(&|s| s.1),
            avg(&|s| s.2),
            avg(&|s| s.3),
            avg(&|s| s.4),
            avg(&|s| s.5),
            avg(&|s| s.6),
            avg(&|s| s.7)
        );
    }
}
