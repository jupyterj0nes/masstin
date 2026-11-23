//! The window: filter bar on top, the graph in the middle, a details pane
//! on the right, the replay bar at the bottom.
//!
//! The graph is drawn as Neo4j Browser draws one: a host is a filled
//! circle with a darker ring and its name inside, an edge a thin line (a
//! curve when the pair has several) with an arrowhead at the destination
//! and the account written on it; hovering lights up a host and what
//! touches it, selecting opens it in the pane. The force layout runs while
//! warm and the analyst can drag any host.

mod case_ui;
mod chrome;
mod edge_style;
mod labels;
mod merge_hosts;
mod report;
mod subnets;
mod tasks;
mod hunt;
mod remote;
mod studio;
mod ingest;
mod agent;
mod hosts;
mod table;
mod viewers;
mod when;
mod loading;
mod safeguard;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use egui::{Align2, Color32, CornerRadius, FontId, Pos2, Rect, Sense, Stroke, Vec2};

use super::draw;
use super::layout::{Layout, V2};
use super::case::{self, CaseFile};
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
use hunt::HuntForm;
use remote::{CortexForm, DbForm};
use studio::Studio;
use tasks::{Job, MergeForm};
use super::store::{Pattern, Store, HUNT_NAMES, RESULT_NAMES, R_CONNECT, R_FAIL, R_LOGOFF, R_OK, VERDICT_NAMES};
use super::paths::{self, Path, PathQuery};
use super::present::{self, Anonymiser, Format, LogoPos, Quality, Step, StepOverride, Story, Timing};
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
/// the warm trace a reached host keeps in a cinematic presentation
const FOOTPRINT: Color32 = Color32::from_rgb(255, 170, 70);
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
    /// the notes the box was opened with: left as they are, each row of a
    /// block keeps its own
    notes_shown: String,
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
    /// a costly part of the drawing asked for where it may slow the window:
    /// said, with what it may cost, before it is turned on
    confirm_cost: Option<safeguard::Costly>,
    /// the hosts of the last frame drawn as plain discs, and whether the
    /// names were left out for the zoom: what the chip over the graph says
    drawn_reduced: (usize, bool),
    /// the analyst turned a costly part on knowing what it may cost: the
    /// safeguard no longer turns the drawing down by itself in this window
    keep_as_asked: bool,
    /// places to give the hosts on the next query (a saved view picked)
    restore_places: Option<Vec<(String, f32, f32)>>,
    // presentation and recording
    story: Story,
    story_path: std::path::PathBuf,
    /// the case file in use: everything kept goes there, nothing next to the timelines
    case: Option<std::path::PathBuf>,
    steps: Vec<Step>,
    step_of_event: Vec<usize>,
    presenting: bool,
    /// the presentation still has to give every name its room
    room_pending: bool,
    /// where the hosts were before the presentation moved them apart
    before_present: Option<Vec<V2>>,
    present_t: f32,
    present_playing: bool,
    show_story: bool,
    anon: Anonymiser,
    show_export: bool,
    /// the window's title, put back after a recording has shown its progress there
    title: String,
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
    /// a path (or a cone) is marked on the map as it is, instead of being
    /// the only thing drawn
    path_in_map: bool,
    /// the path marked on the map
    trail: Option<Trail>,
    /// per connection drawn: it is part of the trail
    trail_on: Vec<bool>,
    path_results: [bool; 4],
    path_skip_machine: bool,
    /// hops are chained by the session the one before opened (its logon
    /// ID), not by time alone
    path_by_session: bool,
    /// by session: a logon with no logoff is followed for the gap
    path_session_gap: bool,
    /// every hop of a chain is by the same account, whichever it is
    path_same_account: bool,
    /// everything from a host (or into it): the tree last asked for
    path_tree: Option<PathTree>,
    /// the settings of the Paths window are folded away: the boxes, the
    /// buttons and what was found are all it shows
    path_compact: bool,
    /// the search runs over the whole timeline, not over what the filters select
    path_scope_all: bool,
    /// only the logins of these accounts are hops
    path_user: String,
    /// the search's own time window (empty: the bar's, or none)
    path_from: String,
    path_to: String,
    /// the list of names open under a box of the Paths window
    path_suggest: Option<Suggest>,
    /// hosts and accounts by name, for those lists: (key, hosts, accounts)
    path_names: (usize, std::rc::Rc<Vec<String>>, std::rc::Rc<Vec<String>>),
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
    show_cortex: bool,
    cortex_form: CortexForm,
    show_db: bool,
    studio: Studio,
    db_form: DbForm,
    /// "On to agentc00pr": the dialog, while it is open
    agent: Option<agent::AgentDialog>,
    /// Tools › Hosts and addresses: the table, while it is open
    hosts: Option<hosts::HostsDialog>,
    /// the open timelines that already carry a hunt, while the analyst is
    /// asked what to do with them; and that the answer was given
    hunt_ask: Option<Vec<(String, crate::graph_hunt_common::record::Previous)>>,
    hunt_answered: bool,
    /// Timeline mode: the centre of the window is the rows of the CSV, in
    /// the file's own 19 columns, instead of the graph
    show_table: bool,
    table_find: String,
    /// Timeline mode: the filters that add up, each "this column (or any)
    /// contains this" or "does not"
    table_filters: Vec<table::RowFilter>,
    /// what is being typed in a column's filter box: (column, text)
    table_filter_draft: (usize, String),
    /// its tick: the filter being typed is "does not contain"
    table_filter_not: bool,
    /// the box was just opened: the keyboard goes to it
    table_filter_focus: bool,
    /// the filter typed on the bar: its column (None: any) and its tick
    table_find_col: Option<usize>,
    table_find_not: bool,
    /// the cell a right click fell on: (column, its text)
    table_ctx_cell: Option<(usize, String)>,
    /// Timeline mode: the size of its text, the width of each column and
    /// the ones hidden, as the analyst left them (kept between sessions)
    table_look: table::TableLook,
    table_look_dirty: bool,
    /// the width each column needs for what the rows shown hold, at the
    /// size of text it was measured with: ((rows shown, text size), widths)
    table_fit: Option<(((String, usize, usize, u64), u32), [f32; 19])>,
    /// the rows of a connection or a host, when the timeline is narrowed
    /// to them (and a counter that changes with it, for the cache)
    table_scope: Option<table::TableScope>,
    table_scope_gen: u64,
    /// the row picked in the timeline (file, row)
    table_sel: Option<(u16, u32)>,
    /// Timeline mode: the rows picked with Ctrl or Shift, when several are
    table_multi: std::collections::BTreeSet<(u16, u32)>,
    /// "Open in…" opens the whole file, not a copy of the rows shown
    table_open_whole: bool,
    /// the programs a timeline opens in, found on first use
    viewer_apps: Option<Vec<viewers::ViewerApp>>,
    table_raw_rows: Vec<(u16, u32)>,
    table_raw_key: (String, usize, usize, u64),
    table_raw_cache: HashMap<(u16, u32), Vec<String>>,
    /// timelines opened lately, for the welcome and the menu
    recent: Vec<String>,
    show_help: bool,
    quick: String,
    focus_around: bool,
    auto_apply: bool,
    auto_apply_at: Option<std::time::Instant>,
    tab: Tab,
    brush: Option<Brush>,
    /// the From / To fields as typed, until they read as a time
    when_text: [String; 2],
    /// events per day, for the calendar's shading (edge count it was made for)
    when_days: Option<(usize, HashMap<chrono::NaiveDate, u32>)>,
    /// the time window opened from the time strip
    show_when: bool,
    /// autopilot: open the calendar of this field ("pane:0", "strip:1")
    when_open_cal: Option<String>,
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
    /// the report the last hunt was asked to write
    hunt_last_report: Option<String>,
    /// the ingest wizard
    ingest: Ingest,
    merge_form: MergeForm,
    /// a hunt is running: a sweep crosses the canvas
    hunt_sweep: Option<std::time::Instant>,
    /// a hunt just ended: the findings appear one by one
    hunt_reveal: Option<std::time::Instant>,
    /// what was selected at the last frame and when it became so: the ripple of a new selection
    sel_seen: Option<Sel>,
    sel_at: f32,
    /// the timeline a hunt just wrote, being read again away from the window
    hunt_loading: Option<std::sync::mpsc::Receiver<Result<Store, String>>>,
    /// timelines being read away from the window (an opener waiting for them)
    pending_load: Option<loading::PendingLoad>,
    /// ticks of a big graph's layout under way on a worker thread
    layout_work: Option<super::layout::Work>,
    /// `MASSTIN_VIEW_DEBUG`: works of the layout taken and dropped since the last report
    layout_works: (u32, u32),
    /// a big graph's layout ticks on a worker (four cores or more)
    layout_worker: bool,
    /// the meshes the plain lines are drawn in: one per thread of the window's pool, eight at most
    plain_parts: usize,
    /// the drawing reduced because the window was too slow (and the style before)
    safeguard: Option<safeguard::Safeguard>,
    /// since when the frames have been slow
    slow_since: Option<std::time::Instant>,
    /// the view whose reduction the analyst undid: left alone
    safeguard_declined: Option<u64>,
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
    /// timelines the open case names that were not there when it was
    /// opened (a share that is down): kept in the case when it is saved
    pub(super) case_missing: Vec<String>,
    subnet_defs: Vec<(String, String)>,
    subnets: Vec<SubnetGroup>,
    subnet_of: Vec<Option<u16>>,
    show_subnets_window: bool,
    merge_edit: Option<MergeHostsEdit>,
    show_merges: bool,
    merge_add: (String, String),
    last_log: Option<(String, Vec<String>)>,
    /// the file the last run's lines were written to
    last_log_path: Option<std::path::PathBuf>,
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

/// One `--event`: what an event must be to answer to it. An empty field is
/// not asked about.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct EventCond {
    /// unix seconds, UTC
    pub t: Option<i64>,
    /// the digits after the second, when the time was given with them
    pub fraction: String,
    pub user: String,
    pub origin: String,
    pub destination: String,
}

/// `TIME,USER,ORIGIN,DESTINATION`.
pub(crate) fn parse_event(text: &str) -> Result<EventCond, String> {
    let p: Vec<&str> = text.split(',').map(str::trim).collect();
    if p.len() != 4 {
        return Err(format!("--event {}: four fields, TIME,USER,ORIGIN,DESTINATION (an empty one is not asked about)", text));
    }
    let mut c = EventCond { user: p[1].to_uppercase(), origin: p[2].to_uppercase(), destination: p[3].to_uppercase(), ..EventCond::default() };
    if !p[0].is_empty() {
        let t = crate::graph_hunt_common::parse_ts(p[0]).ok_or_else(|| format!("--event {}: `{}` is not a time (YYYY-MM-DD HH:MM:SS, UTC)", text, p[0]))?;
        c.t = Some(t.and_utc().timestamp());
        if let Some(rest) = p[0].get(19..).and_then(|r| r.strip_prefix('.')) {
            c.fraction = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect::<String>().trim_end_matches('0').to_string();
        }
    }
    if c.t.is_none() && c.user.is_empty() && c.origin.is_empty() && c.destination.is_empty() {
        return Err(format!("--event {}: every field is empty", text));
    }
    Ok(c)
}

/// Whether a host answers to a name given: its own name or one merged
/// into it, in any case, short or fully qualified.
pub(crate) fn host_answers(names: &[String], asked: &str) -> bool {
    let short = |s: &str| -> String { if s.parse::<std::net::IpAddr>().is_ok() { s.to_string() } else { s.split('.').next().unwrap_or(s).to_string() } };
    let asked_short = short(asked);
    names.iter().any(|n| {
        let n = n.to_uppercase();
        n == asked || short(&n) == asked_short
    })
}

/// `12,57,2:301`: rows by their line in the file (1 is the header, so the
/// first row is 2), of the first timeline or, with `N:`, of the N-th.
pub(crate) fn parse_rows(text: &str) -> Result<Vec<(u16, u32)>, String> {
    let mut out = Vec::new();
    for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (file, line) = match part.split_once(':') {
            Some((f, l)) => (f.trim().parse::<u16>().ok().filter(|f| *f >= 1), l.trim()),
            None => (Some(1), part),
        };
        match (file, line.parse::<u32>().ok().filter(|l| *l >= 2)) {
            (Some(f), Some(l)) => out.push((f - 1, l - 2)),
            _ => return Err(format!("--rows {}: `{}` is not a line of a timeline (LINE, or FILE:LINE; the header is line 1, the first row 2)", text, part)),
        }
    }
    if out.is_empty() {
        return Err("--rows: no line given".to_string());
    }
    Ok(out)
}

/// What the canvas shows instead of the filter's selection: the edges of
/// a path or a cone, with a word under each host.
/// A path or a cone marked on the map: the map stays as the filters draw
/// it and these connections stand out on it.
/// The list of names open under a box: which box, whether it shows every
/// name (the arrow) or the ones that match what is typed, the row the keys
/// are on.
pub(crate) struct Suggest {
    field: u8,
    all: bool,
    at: Option<usize>,
}

/// The rows a path search may use as hops, its time window, and how many
/// rows that is: `(the rows, or None for all of them, from, to, how many)`.
///
/// Inside the filters (`whole` false) they are the rows the filters select,
/// in the filters' time window unless the search has its own (`from`, `to`:
/// a text that is no date counts as empty). Over the whole timeline the
/// filters and their window are ignored. On top of either, `account` keeps
/// the logins of the accounts it names (the patterns of the filters).
fn path_rows(store: &Store, filter: &Filter, whole: bool, account: &str, from: &str, to: &str) -> (Option<std::rc::Rc<Vec<bool>>>, Option<i64>, Option<i64>, usize) {
    let n = store.edges.len();
    let users = Pattern::parse_list(account);
    let own = |text: &str, bar: &str| -> Option<i64> { parse_time(text).or_else(|| if whole { None } else { parse_time(bar) }) };
    let (t_from, t_to) = (own(from, &filter.from), own(to, &filter.to));
    if whole && users.is_empty() {
        let rows = store.in_window(t_from, t_to).len();
        return (None, t_from, t_to, rows);
    }
    let mut ok = vec![whole; n];
    if !whole {
        let mut f = filter.clone();
        if parse_time(from).is_some() {
            f.from = from.to_string();
        }
        if parse_time(to).is_some() {
            f.to = to.to_string();
        }
        for ei in f.select(store) {
            ok[ei as usize] = true;
        }
    }
    for (i, e) in store.edges.iter().enumerate() {
        if ok[i] && ((!users.is_empty() && !Pattern::any_account(&users, store.users.name(e.user))) || t_from.map_or(false, |f| e.t < f) || t_to.map_or(false, |t| e.t > t)) {
            ok[i] = false;
        }
    }
    let rows = ok.iter().filter(|x| **x).count();
    (Some(std::rc::Rc::new(ok)), t_from, t_to, rows)
}

/// Why a search found no path, when no wider search finds one either: the
/// origin is the source of nothing that counts as a hop, nothing that
/// counts enters the destination, or what the one reaches and what reaches
/// the other never meet.
fn why_no_path(store: &Store, q: &PathQuery) -> String {
    let why = why_no_path_itself(store, q);
    // a machine named in some rows and by its address in others is two hosts
    if store.hosts.names.iter().any(|n| n.parse::<std::net::IpAddr>().is_ok()) {
        format!("{}
Some hosts of this timeline are addresses: a machine that appears by its name in some rows and by its address in others is two hosts, and a path breaks there. Tools › Hosts and addresses says whose each address is and merges the ones the evidence is sure of.", why)
    } else {
        why
    }
}

fn why_no_path_itself(store: &Store, q: &PathQuery) -> String {
    let (o, d) = (store.hosts.name(q.origin), store.hosts.name(q.dest));
    // the logins of a host by result, and how many of them may be a hop
    let tally = |rows: &[u32]| -> ([usize; 4], usize) {
        let mut by = [0usize; 4];
        let mut usable = 0usize;
        for &ei in rows {
            let e = &store.edges[ei as usize];
            by[e.result as usize] += 1;
            if q.results[e.result as usize] && !(q.skip_machine_accounts && super::store::is_machine_account(store.users.name(e.user))) && q.only.as_ref().map_or(true, |only| only[ei as usize]) && q.from.map_or(true, |f| e.t >= f) && q.to.map_or(true, |t| e.t <= t) {
                usable += 1;
            }
        }
        (by, usable)
    };
    let has = |by: &[usize; 4]| -> String { RESULT_NAMES.iter().enumerate().filter(|(i, _)| by[*i] > 0).map(|(i, n)| format!("{} {}", group_digits(by[i]), n)).collect::<Vec<_>>().join(", ") };
    let (out_by, out_ok) = tally(store.out_adj.of(q.origin));
    let (in_by, in_ok) = tally(store.in_adj.of(q.dest));
    let kinds = RESULT_NAMES.iter().enumerate().filter(|(i, _)| q.results[*i]).map(|(_, n)| *n).collect::<Vec<_>>().join(" / ");
    let narrow = "the ones this search counts (see «Hops are», machine accounts, the account, the dates and «Search in»)";
    if out_by.iter().sum::<usize>() == 0 {
        return format!("Nothing in the timeline logs on FROM {}: it is only ever a destination, so no path can start at it.", o);
    }
    if out_ok == 0 {
        return format!("No path can start at {}: none of its logins is among {}. As an origin it has {}; the search counts {}.", o, narrow, has(&out_by), kinds);
    }
    if in_by.iter().sum::<usize>() == 0 {
        return format!("Nothing in the timeline logs on TO {}: it is only ever an origin, so no path can end at it.", d);
    }
    if in_ok == 0 {
        return format!("No path can end at {}: none of the logins into it is among {}. As a destination it has {}; the search counts {}.", d, narrow, has(&in_by), kinds);
    }
    let reach = paths::cone(store, q.origin, q.from.unwrap_or(store.t_min), q, true).0.len().saturating_sub(1);
    let ways = paths::cone(store, q.dest, q.to.unwrap_or(store.t_max), q, false).0.len().saturating_sub(1);
    format!("From {} a chain of these logins reaches {} host(s), and {} host(s) could reach {}, but no chain joins the two within these limits («Reach from origin» and «Ways into destination» draw them). Try more hops, a longer gap, or letting failed logons and connections count as hops.", o, group_digits(reach), group_digits(ways), d)
}

/// `1234567` as `1,234,567`.
/// The most meshes the plain lines are drawn in (one per thread of the
/// window's pool otherwise: a single one on two cores).
const PLAIN_PARTS: usize = 8;

/// A mesh of quads (four vertices, six indices each, as `draw::line_quad`
/// makes them) cut into `parts` meshes of about as many quads, in order.
/// Empty parts are left out.
fn split_mesh(mesh: egui::epaint::Mesh, parts: usize) -> Vec<egui::epaint::Mesh> {
    let quads = mesh.indices.len() / 6;
    if quads == 0 {
        return Vec::new();
    }
    let parts = parts.clamp(1, quads);
    if parts == 1 {
        return vec![mesh];
    }
    let per = quads.div_ceil(parts);
    let mut out = Vec::with_capacity(parts);
    for c in 0..parts {
        let (q0, q1) = (c * per, ((c + 1) * per).min(quads));
        if q0 >= q1 {
            break;
        }
        let mut m = egui::epaint::Mesh::with_texture(mesh.texture_id);
        m.vertices.extend_from_slice(&mesh.vertices[q0 * 4..q1 * 4]);
        let base = (q0 * 4) as u32;
        m.indices.extend(mesh.indices[q0 * 6..q1 * 6].iter().map(|i| i - base));
        out.push(m);
    }
    out
}

fn group_digits(n: usize) -> String {
    let d = n.to_string();
    let mut out = String::with_capacity(d.len() + d.len() / 3);
    for (i, ch) in d.chars().enumerate() {
        if i > 0 && (d.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// The names a box offers for what is typed: the ones that start with it,
/// then the ones that contain it; every one when nothing is typed.
fn suggestions<'a>(names: &'a [String], typed: &str) -> Vec<&'a String> {
    let needle = typed.trim().to_lowercase();
    if needle.is_empty() {
        return names.iter().collect();
    }
    let (mut first, mut rest) = (Vec::new(), Vec::new());
    for n in names {
        let l = n.to_lowercase();
        if l.starts_with(&needle) {
            first.push(n);
        } else if l.contains(&needle) {
            rest.push(n);
        }
    }
    first.extend(rest);
    first
}

/// A text box that offers the names it could mean: as it is typed, the
/// ones that contain the text (click one, or the arrow keys and Enter), and
/// from the arrow next to it, every one. Says whether Enter was pressed
/// with no name picked from the list (the form's own Enter).
fn suggest_box(ui: &mut egui::Ui, me: u8, state: &mut Option<Suggest>, text: &mut String, width: f32, hint: &str, names: &[String]) -> bool {
    let mine = state.as_ref().map_or(false, |s| s.field == me);
    let mut step = 0i32;
    if mine {
        ui.input_mut(|i| {
            if i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                step = 1;
            }
            if i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                step = -1;
            }
        });
    }
    let (edit, arrow) = ui
        .horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            let edit = ui.add(egui::TextEdit::singleline(text).desired_width(width).hint_text(hint));
            let arrow = ui.add(egui::Button::new(egui::RichText::new(super::icons::CARET_DOWN).size(12.0)).min_size(Vec2::new(20.0, 20.0))).on_hover_text(format!("Every one the timeline has ({}), to pick from", group_digits(names.len())));
            (edit, arrow)
        })
        .inner;
    let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
    if arrow.clicked() {
        *state = if mine && state.as_ref().map_or(false, |s| s.all) { None } else { Some(Suggest { field: me, all: true, at: None }) };
    } else if edit.changed() || edit.gained_focus() {
        *state = Some(Suggest { field: me, all: false, at: None });
    } else if mine && ui.input(|i| i.key_pressed(egui::Key::Escape)) {
        *state = None;
    }
    let Some(st) = state.as_mut().filter(|s| s.field == me) else { return enter };
    let list: Vec<&String> = if st.all { names.iter().collect() } else { suggestions(names, text) };
    if step != 0 && !list.is_empty() {
        let n = list.len() as i32;
        st.at = Some(match st.at {
            None => if step > 0 { 0 } else { (n - 1) as usize },
            Some(k) => (k as i32 + step).rem_euclid(n) as usize,
        });
    }
    if enter {
        let picked = st.at.and_then(|k| list.get(k)).map(|n| (*n).clone());
        *state = None;
        return match picked {
            Some(n) => {
                *text = n;
                false
            }
            None => true,
        };
    }
    // the one name there is, already written: nothing to offer
    if !st.all && list.len() == 1 && list[0].eq_ignore_ascii_case(text.trim()) {
        return false;
    }
    let mut chosen: Option<String> = None;
    let at = st.at;
    let shown = egui::Popup::from_response(&edit).open(true).close_behavior(egui::PopupCloseBehavior::IgnoreClicks).show(|ui| {
        ui.set_width(edit.rect.width().max(260.0));
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
        if list.is_empty() {
            ui.label(egui::RichText::new("Nothing in the timeline is called like that.").small().color(theme::MUTED));
            return;
        }
        ui.label(egui::RichText::new(if list.len() == names.len() { format!("{} in the timeline: type to narrow", group_digits(names.len())) } else { format!("{} of {}", group_digits(list.len()), group_digits(names.len())) }).small().color(theme::MUTED));
        let row_h = ui.spacing().interact_size.y;
        let mut area = egui::ScrollArea::vertical().max_height(236.0).auto_shrink([false, true]);
        if let (true, Some(k)) = (step != 0, at) {
            area = area.vertical_scroll_offset((k as f32 * (row_h + ui.spacing().item_spacing.y) - 96.0).max(0.0));
        }
        area.show_rows(ui, row_h, list.len(), |ui, range| {
            for k in range {
                if ui.add(egui::Button::selectable(at == Some(k), list[k].as_str())).clicked() {
                    chosen = Some(list[k].clone());
                }
            }
        });
    });
    if let Some(n) = chosen {
        *text = n;
        *state = None;
        return false;
    }
    // a press anywhere else puts the list away
    let inside = |p: Pos2| edit.rect.contains(p) || arrow.rect.contains(p) || shown.as_ref().map_or(false, |r| r.response.rect.contains(p));
    if ui.input(|i| i.pointer.any_pressed() && i.pointer.interact_pos().map_or(false, |p| !inside(p))) {
        *state = None;
    }
    false
}

/// Everything from a host, or into it: the cone, and its hosts as the
/// rows of a tree (each under the host its first arrival came from).
struct PathTree {
    cone: paths::Cone,
    /// (host, how deep in the tree), in the order they are listed
    rows: Vec<(u32, usize)>,
    title: String,
}

struct Trail {
    title: String,
    edges: std::collections::HashSet<u32>,
    labels: HashMap<u32, String>,
    /// how many of its connections the view does not draw
    missing: usize,
}

/// A length of time as it is said: "48 s", "2 min 05 s", "1 h 12 min".
fn story_length(secs: f32) -> String {
    let s = secs.max(0.0).round() as u64;
    if s < 60 {
        format!("{} s", s)
    } else if s < 3600 {
        format!("{} min {:02} s", s / 60, s % 60)
    } else {
        format!("{} h {:02} min", s / 3600, (s % 3600) / 60)
    }
}

struct Overlay {
    title: String,
    edges: Vec<u32>,
    labels: HashMap<u32, String>,
    hops: HashMap<u32, usize>,
    /// rows picked one by one (a selection of the timeline): drawn
    /// ungrouped, one edge per row, all of them, whatever the filter says
    exact: bool,
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
    /// Esc: the encoder closes the file with the frames it has
    cancelled: bool,
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
        let title = super::window_title(&opts.case, &opts.files);
        let first = opts.files.first().cloned().unwrap_or_else(ingest::scratch_csv);
        // a case (opened by `run`, so it is there) holds what the side files would
        let case_path = opts.case.clone().map(std::path::PathBuf::from);
        let case_file = case_path.as_ref().and_then(|p| CaseFile::load(p).ok());
        let case_path = case_path.filter(|_| case_file.is_some());
        if let Some(p) = &case_path {
            ingest::remember(&[p.to_string_lossy().to_string()]);
        } else if !opts.files.is_empty() {
            ingest::remember(&opts.files);
        }
        let views_path = ViewsFile::path_for(&first);
        let vf = match &case_file {
            Some(c) => c.views.clone(),
            None => ViewsFile::load(&views_path),
        };
        let style = vf.last_style.clone().unwrap_or_default();
        let builtin = builtin_views(store.t_max);
        let story_path = Story::path_for(&first);
        let story = match &case_file {
            Some(c) => c.story.clone(),
            None => Story::load(&story_path),
        };
        let notes = match (&case_file, &case_path) {
            (Some(c), Some(p)) => Notes { path: p.clone(), notes: c.notes.clone() },
            _ => Notes::load(&Notes::path_for(&first)),
        };
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
            notes_shown: String::new(),
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
            confirm_cost: None,
            drawn_reduced: (0, false),
            keep_as_asked: false,
            restore_places: None,
            story,
            story_path,
            case: case_path,
            steps: Vec::new(),
            step_of_event: Vec::new(),
            presenting: false,
            room_pending: false,
            before_present: None,
            present_t: 0.0,
            present_playing: false,
            show_story: false,
            anon: Anonymiser::new(),
            show_export: false,
            title,
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
            path_in_map: false,
            trail: None,
            trail_on: Vec::new(),
            path_results: [true, false, false, false],
            path_skip_machine: true,
            path_by_session: false,
            path_session_gap: false,
            path_same_account: false,
            path_tree: None,
            path_compact: false,
            path_scope_all: false,
            path_user: String::new(),
            path_from: String::new(),
            path_to: String::new(),
            path_suggest: None,
            path_names: (usize::MAX, Default::default(), Default::default()),
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
            show_cortex: false,
            cortex_form: CortexForm::default(),
            show_db: false,
            studio: Studio::default(),
            db_form: DbForm::default(),
            show_table: false,
            agent: None,
            hosts: None,
            hunt_ask: None,
            hunt_answered: false,
            table_find: String::new(),
            table_filters: Vec::new(),
            table_filter_draft: (usize::MAX, String::new()),
            table_filter_not: false,
            table_filter_focus: false,
            table_find_col: None,
            table_find_not: false,
            table_ctx_cell: None,
            table_look: table::TableLook::load(),
            table_look_dirty: false,
            table_fit: None,
            table_scope: None,
            table_scope_gen: 0,
            table_sel: None,
            table_multi: std::collections::BTreeSet::new(),
            table_open_whole: false,
            viewer_apps: None,
            table_raw_rows: Vec::new(),
            table_raw_key: (String::new(), usize::MAX, 0, 0),
            table_raw_cache: HashMap::new(),
            recent: ingest::load_recent(),
            show_help: false,
            quick: String::new(),
            focus_around: false,
            auto_apply: false,
            auto_apply_at: None,
            tab: Tab::Selection,
            brush: None,
            when_text: [String::new(), String::new()],
            when_days: None,
            show_when: false,
            when_open_cal: None,
            canvas_rect: Rect::NOTHING,
            ctx_target: None,
            color_pick: None,
            notes,
            note_draft: None,
            mark_dialog: None,
            row_pick: Vec::new(),
            job: None,
            hunt_form: HuntForm::default(),
            hunt_last_report: None,
            ingest: Ingest::default(),
            merge_form: MergeForm { inputs: Vec::new(), output: String::new(), from: String::new(), to: String::new(), carry: String::new() },
            hunt_sweep: None,
            hunt_reveal: None,
            sel_seen: None,
            sel_at: 0.0,
            hunt_loading: None,
            pending_load: None,
            layout_work: None,
            layout_works: (0, 0),
            layout_worker: super::layout_worker_pays(super::cores()),
            plain_parts: rayon::current_num_threads().clamp(1, PLAIN_PARTS),
            safeguard: None,
            slow_since: None,
            safeguard_declined: None,
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
            case_missing: Vec::new(),
            subnet_defs: vf.subnets.clone(),
            subnets: Vec::new(),
            subnet_of: Vec::new(),
            show_subnets_window: false,
            merge_edit: None,
            show_merges: false,
            merge_add: (String::new(), String::new()),
            last_log: None,
            last_log_path: None,
            show_last_log: false,
        };
        v.requery(true);
        // `--rows`: the window opens on exactly those rows
        if let Some(r) = &opts.rows {
            match parse_rows(r) {
                Ok(rows) => v.rows_to_graph_view(&rows),
                Err(e) => v.status = e,
            }
        }
        // `--event`: the window opens on exactly the events named
        if !opts.events.is_empty() {
            v.events_to_graph_view(&opts.events);
        }
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
            Some(o) if o.exact => GraphView::from_edges(&self.store, &Filter { grouping: super::query::Grouping::PerEvent, limit: o.edges.len().max(1), ..self.filter.clone() }, o.edges.clone()),
            Some(o) => GraphView::from_edges(&self.store, &self.filter, o.edges.clone()),
            None => GraphView::build(&self.store, &self.filter),
        };
        if let Some(t) = self.trail.as_mut() {
            // a trail is marked on what is drawn; what it needs and the
            // filters left out is drawn with it
            let drawn: std::collections::HashSet<u32> = self.graph.edges.iter().flat_map(|e| e.rows.iter().copied()).collect();
            let lacking: Vec<u32> = t.edges.iter().copied().filter(|e| !drawn.contains(e)).collect();
            t.missing = lacking.len();
            if !lacking.is_empty() {
                let mut all: Vec<u32> = drawn.into_iter().collect();
                all.extend(lacking);
                self.graph = GraphView::from_edges(&self.store, &self.filter, all);
            }
        }
        self.trail_on = match &self.trail {
            Some(t) => self.graph.edges.iter().map(|e| e.rows.iter().any(|r| t.edges.contains(r))).collect(),
            None => Vec::new(),
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
        if let Some(t) = &self.trail {
            parts.insert(0, format!("{} marked on the map", t.title));
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
        if let Some(to) = self.fill_target(canvas) {
            let from: Vec<V2> = self.layout.pos.clone();
            self.layout.stop();
            self.fill_anim = Some((from, to, self.t0.elapsed().as_secs_f32()));
        }
    }

    /// Where `fill_window` takes the hosts; None when the picture already
    /// has the window's shape.
    fn fill_target(&self, canvas: Rect) -> Option<Vec<V2>> {
        let n = self.layout.len();
        let (lo, hi) = self.layout.bounds()?;
        if n < 2 {
            return None;
        }
        let gw = (hi.x - lo.x).max(1.0);
        let gh = (hi.y - lo.y).max(1.0);
        let margin = 90.0;
        let inset = if self.presenting { 0.0 } else { self.legend_h + 12.0 };
        let cw = (canvas.width() - margin * 2.0).max(100.0);
        let ch = (canvas.height() - inset - self.caption_room() - margin * 2.0).max(100.0);
        // the zoom the graph would get as it is, and the stretch that makes it
        // fill both axes at that zoom (never shrinking an axis)
        let z = (cw / gw).min(ch / gh).min(2.2);
        let sx = ((cw / z) / gw).clamp(1.0, 2.6);
        let sy = ((ch / z) / gh).clamp(1.0, 2.6);
        if (sx - 1.0).abs() < 0.03 && (sy - 1.0).abs() < 0.03 {
            return None;
        }
        let c = V2::new((lo.x + hi.x) / 2.0, (lo.y + hi.y) / 2.0);
        Some(self.layout.pos.iter().map(|p| V2::new(c.x + (p.x - c.x) * sx, c.y + (p.y - c.y) * sy)).collect())
    }

    /// Where a host's name is drawn: under the picture when the host is a
    /// picture (a machine, an icon) or a bare dot, as its style says otherwise.
    fn drawn_label_pos(&self, look: &NodeLook) -> LabelPos {
        if (look.icon.is_some() || look.device.is_some() || self.style.node_style == NodeStyle::Minimal) && matches!(look.label_pos, LabelPos::Auto | LabelPos::Inside) {
            LabelPos::Below
        } else {
            look.label_pos
        }
    }

    /// Moves `pos` apart so no host covers another's name at the zoom the
    /// picture will be framed at (found again after every pass, since
    /// spreading the hosts lowers it). Only the hosts that are drawn count.
    fn give_names_room(&self, pos: &mut [V2], canvas: Rect, max_zoom: f32, inset: f32) -> usize {
        let n = pos.len().min(self.graph.nodes.len()).min(self.scene.nodes.len());
        if n < 2 || n > 400 {
            return 0;
        }
        let fs = self.style.font_scale;
        let mut moved = 0;
        for _ in 0..4 {
            let shown: Vec<usize> = (0..n).filter(|&i| !self.scene.nodes[i].hide).collect();
            let mut lo = V2::new(f32::MAX, f32::MAX);
            let mut hi = V2::new(f32::MIN, f32::MIN);
            for &i in &shown {
                let r = self.layout.radius.get(i).copied().unwrap_or(20.0);
                lo.x = lo.x.min(pos[i].x - r);
                lo.y = lo.y.min(pos[i].y - r);
                hi.x = hi.x.max(pos[i].x + r);
                hi.y = hi.y.max(pos[i].y + r);
            }
            if shown.len() < 2 {
                return moved;
            }
            let w = (hi.x - lo.x).max(50.0) + 80.0;
            let h = (hi.y - lo.y).max(50.0) + 80.0;
            let z = (canvas.width() / w).min((canvas.height() - inset).max(50.0) / h).clamp(0.05, max_zoom);
            let mut sub: Vec<V2> = shown.iter().map(|&i| pos[i]).collect();
            let room: Vec<super::layout::Room> = shown.iter().map(|&i| {
                let look = &self.scene.nodes[i];
                let r_px = self.layout.radius.get(i).copied().unwrap_or(20.0) * z * self.style.node_scale * look.size;
                let base_px = (11.0 * z.sqrt() * fs * look.label_size).clamp(6.5, 40.0);
                let name = self.host_label(self.graph.nodes[i].host);
                let (hw, up, down) = labels::host_extent(&name, r_px, self.drawn_label_pos(look), base_px);
                super::layout::Room { half_w: hw / z, up: up / z, down: down / z }
            }).collect();
            let held: Vec<bool> = shown.iter().map(|&i| self.layout.fixed.get(i).copied().unwrap_or(false) && !self.presenting).collect();
            let used = super::layout::make_room(&mut sub, &room, &held, 10.0 / z, 200);
            for (k, &i) in shown.iter().enumerate() {
                pos[i] = sub[k];
            }
            if used == 0 {
                break;
            }
            moved += used;
        }
        moved
    }

    /// The strip a presentation keeps clear at the bottom for its caption.
    fn caption_room(&self) -> f32 {
        if self.presenting && self.story.show_caption { 64.0 } else { 0.0 }
    }

    fn fit(&mut self, canvas: Rect, snap: bool) {
        if let Some((lo, hi)) = self.layout.bounds() {
            let w = (hi.x - lo.x).max(50.0) + 80.0;
            let h = (hi.y - lo.y).max(50.0) + 80.0;
            let max_zoom = if self.presenting { 1.8 } else { 2.2 };
            // the legend chips sit over the top of the canvas: keep it clear
            let inset = if self.presenting { 0.0 } else { self.legend_h + 12.0 };
            let bottom = self.caption_room();
            self.zoom_t = (canvas.width() / w).min((canvas.height() - inset - bottom).max(50.0) / h).clamp(0.05, max_zoom);
            self.cam_t = V2::new((lo.x + hi.x) / 2.0, (lo.y + hi.y) / 2.0 - (inset / 2.0) / self.zoom_t + (bottom / 2.0) / self.zoom_t);
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
        if let Some(p) = &self.case {
            if let Err(e) = self.write_case(p) {
                eprintln!("masstin: cannot save {}: {}", p.display(), e);
            }
            return;
        }
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
        // hosts close together cover each other's names: the story gives
        // every one its room, and leaving puts them back
        self.before_present = Some(self.layout.pos.clone());
        self.room_pending = true;
        // the canvas is the whole window now: frame the graph again
        self.fit_pending = true;
    }

    fn stop_presentation(&mut self) {
        self.presenting = false;
        self.present_playing = false;
        self.room_pending = false;
        if let Some(pos) = self.before_present.take() {
            if pos.len() == self.layout.pos.len() {
                self.layout.pos = pos;
                self.fit_pending = true;
            }
        }
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
        self.notes_shown = self.notes_draft.clone();
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
        f.view != View::All || !f.host.trim().is_empty() || !f.user.trim().is_empty() || !f.logon_type.trim().is_empty() || !f.from.trim().is_empty() || !f.to.trim().is_empty() || f.min_score > 0 || f.hunt.iter().any(|h| !h) || f.results.iter().any(|r| !r) || f.verdict.iter().any(|v| !v) || f.grouping != super::query::Grouping::PerAccount
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
                        if ui.small_button("all").on_hover_text("Tick every one").clicked() {
                            d.picked.iter_mut().for_each(|p| *p = true);
                        }
                        if ui.small_button("none").on_hover_text("Untick every one").clicked() {
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
                if ui.button("Cancel").on_hover_text("Close this without doing anything").clicked() {
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
        // a hunt under way is rewriting these same files: a mark written now
        // would be lost when the hunt replaces them, or the other way round
        if self.job.as_ref().map_or(false, |j| j.kind == tasks::JobKind::Hunt && j.done.is_none()) {
            self.mark_msg = "A hunt is writing this timeline: mark it when the hunt ends".to_string();
            self.status = self.mark_msg.clone();
            return;
        }
        // The notes box shows one note for the whole connection. Left as
        // it was opened, every row keeps the note it has (the box showed
        // one of them, or none; the verdict alone is written). Edited, its
        // text goes on every row given. Before, an untouched box was
        // written on all the rows, and an empty one erased their notes.
        let draft = self.notes_draft.trim().to_string();
        let untouched = draft == self.notes_shown.trim();
        let mut groups: Vec<(String, Vec<(u16, u32)>)> = Vec::new();
        if untouched && rows.len() > 1 {
            for &r in rows {
                let own = self.store.notes.get(&r).cloned().unwrap_or_default();
                match groups.iter_mut().find(|(n, _)| *n == own) {
                    Some((_, v)) => v.push(r),
                    None => groups.push((own, vec![r])),
                }
            }
        } else {
            groups.push((draft, rows.to_vec()));
        }
        let mut result: std::io::Result<usize> = Ok(0);
        for (note, group) in &groups {
            match self.store.mark(group, verdict, note) {
                Ok(n) => result = result.map(|k| k + n),
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        match result {
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
                if ui.button("Cancel").on_hover_text("Close this without doing anything").clicked() {
                    cancel = true;
                }
            });
        });
        if save {
            self.notes.add(target, &text);
            if let Err(e) = self.save_notes() {
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
        self.reload_store_then(Box::new(|v: &mut Viewer, r: Result<(), String>| match r {
            Ok(()) => {
                v.requery(false);
                v.status = format!("Timeline read again: {}", v.status);
            }
            Err(e) => v.status = format!("Cannot read the timeline: {}", e),
        }));
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
        // its rows, in sight (the right click on the host gives the same)
        if ui.button(format!("{}  See its rows in the Timeline", super::icons::TABLE)).on_hover_text("Timeline mode, on the rows of the CSV behind every connection of this host that the graph shows").clicked() {
            self.timeline_of_node(i);
            return;
        }
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
                ui.label(egui::RichText::new(format!("{}  {}", when.get(..16).unwrap_or(&when), text)).color(theme::MUTED).size(12.5));
            }
        }
        ui.horizontal(|ui| {
            if ui.button("Expand around").on_hover_text("Add to the canvas the hosts this one talks to, and their connections, keeping what is there").clicked() {
                self.draft.view = View::Around;
                self.draft.around = name.clone();
                self.requery(false);
                return;
            }
            if ui.button("Only this host").on_hover_text("Reduce the canvas to this host and what it talks to directly (its neighbourhood)").clicked() {
                self.draft.view = View::All;
                self.draft.host = name.clone();
                self.requery(false);
            }
        });
        ui.horizontal(|ui| {
            if ui.button("Paths from here").on_hover_text("Open Paths with this host as the origin: where could someone go from it?").clicked() {
                self.path_origin = name.clone();
                self.show_paths = true;
            }
            if ui.button("Paths to here").on_hover_text("Open Paths with this host as the destination: how could someone have got here?").clicked() {
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
                    ui.label(egui::RichText::new(format!("score {} · {}", q as u8, crate::csv_out::score_words(q as u8))).color(MUTED)).on_hover_text("hunt_score: how rare the connection is among the connections of normal days, 0 to 100 (-10 log10 of the share of baseline connections at least as unusual)");
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
        // Where to read the rows of this connection, in sight: the same
        // ways the right click on the connection gives, for whoever does
        // not think of a right click.
        {
            let n = self.graph.edges[i].rows.len();
            // the rows ticked below, when some are: then it is about them alone
            let ticked: Vec<(u16, u32)> = self.rows.as_ref().map(|(_, r, _)| r.iter().enumerate().filter(|(k, _)| self.row_pick.get(*k).copied().unwrap_or(false)).map(|(_, r)| (r.file, r.line)).collect()).unwrap_or_default();
            // 0 the timeline here, 1 agentc00pr, 2 the system's CSV program, 3.. a program of the list
            let mut go: Option<usize> = None;
            let apps = self.viewer_list();
            let title = if ticked.is_empty() { format!("SEE ITS {} ROW{} IN", n, if n == 1 { "" } else { "S" }) } else { format!("SEE THE {} TICKED ROW{} IN", ticked.len(), if ticked.len() == 1 { "" } else { "S" }) };
            ui.label(egui::RichText::new(title).small().color(if ticked.is_empty() { MUTED } else { ACCENT })).on_hover_text("Every row of the connection, or only the ones ticked in the list below when some are");
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = Vec2::new(6.0, 6.0);
                if ui.add(egui::Button::new(theme::semibold(format!("{}  Timeline", super::icons::TABLE), 13.0).color(theme::ACCENT_INK)).fill(ACCENT).stroke(Stroke::NONE)).on_hover_text("Timeline mode, on the rows of the CSV this connection is drawn from: every column, as the file has them").clicked() {
                    go = Some(0);
                }
                if ui.button(format!("{}  agentc00pr", super::icons::APP_WINDOW)).on_hover_text("agentc00pr's viewer on the case this timeline is in, showing only the events of this connection. A timeline that is in no case yet is taken to one first").clicked() {
                    go = Some(1);
                }
                ui.menu_button(format!("{}  Another program", super::icons::CARET_DOWN), |ui| {
                    ui.set_min_width(260.0);
                    ui.label(egui::RichText::new("A copy of these rows, with the timeline's own columns, opened in:").color(MUTED).small());
                    if theme::icon_button(ui, super::icons::APP_WINDOW, "The system's CSV application").clicked() {
                        ui.close();
                        go = Some(2);
                    }
                    for (k, a) in apps.iter().enumerate() {
                        if theme::icon_button(ui, super::icons::APP_WINDOW, &a.name).on_hover_text(a.args.last().unwrap_or(&a.program)).clicked() {
                            ui.close();
                            go = Some(3 + k);
                        }
                    }
                    ui.separator();
                    ui.label(egui::RichText::new("More programs are added in Timeline › Open in…").color(theme::DIM).small());
                });
            });
            ui.add_space(8.0);
            if let Some(g) = go {
                let (label, rows) = if ticked.is_empty() {
                    (self.graph_edge_label(i), self.rows_of_graph_edge(i))
                } else {
                    (format!("{} row{} ticked of {}", ticked.len(), if ticked.len() == 1 { "" } else { "s" }, self.graph_edge_label(i)), ticked.clone())
                };
                match g {
                    0 if !ticked.is_empty() => self.show_rows_in_timeline(label, rows),
                    0 => self.timeline_of_edge(i),
                    1 => self.rows_to_agentc00pr(&rows, &label),
                    2 => self.rows_in_program(&rows, &label, None),
                    k => self.rows_in_program(&rows, &label, Some(k - 3)),
                }
                return;
            }
        }
        if let Some((_, rows, total)) = &self.rows {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("ROWS {}", if *total > rows.len() { format!("(first {} of {})", rows.len(), total) } else { total.to_string() })).small().color(MUTED));
                if rows.len() > 1 {
                    ui.label(egui::RichText::new("· tick the ones to mark:").small().color(theme::DIM));
                    if ui.small_button("all").on_hover_text("Tick every one").clicked() {
                        self.row_pick.iter_mut().for_each(|p| *p = true);
                    }
                    if ui.small_button("none").on_hover_text("Untick every one").clicked() {
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

    fn views_now(&self) -> ViewsFile {
        ViewsFile { views: self.saved.clone(), last_style: Some(self.style_to_save()), merges: self.merges.clone(), subnets: self.subnet_defs.clone() }
    }

    fn persist(&self) {
        if let Some(p) = &self.case {
            if let Err(e) = self.write_case(p) {
                eprintln!("masstin: cannot save {}: {}", p.display(), e);
            }
            return;
        }
        if let Err(e) = self.views_now().save(&self.views_path) {
            eprintln!("masstin: cannot save {}: {}", self.views_path.display(), e);
        }
    }

    /// Everything the case keeps, written to `path`.
    pub(super) fn write_case(&self, path: &std::path::Path) -> std::io::Result<()> {
        // (with the timelines that could not be found when the case was
        // opened: a share that is down today is still part of the case)
        let mut timelines: Vec<String> = self.files.iter().map(|f| case::absolute(f)).collect();
        for m in &self.case_missing {
            if !timelines.contains(m) {
                timelines.push(m.clone());
            }
        }
        let c = CaseFile { masstin_case: 1, timelines, views: self.views_now(), story: self.story.clone(), notes: self.notes.notes.clone() };
        c.save(path)
    }

    /// Where recordings and films go: next to the case file when there is
    /// one, next to the first timeline otherwise.
    pub(super) fn out_dir(&self) -> Option<std::path::PathBuf> {
        match &self.case {
            Some(c) => c.parent().map(|d| d.to_path_buf()),
            None => self.files.first().and_then(|f| std::path::Path::new(f).parent()).map(|d| d.to_path_buf()),
        }
    }

    /// The notes, in the case file when there is one.
    pub(super) fn save_notes(&self) -> std::io::Result<()> {
        match &self.case {
            Some(p) => self.write_case(p),
            None => self.notes.save(),
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
                    self.saved.push(SavedView { name: name.clone(), filter: self.draft.clone(), style: self.style_to_save(), places });
                    self.saved.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
                    self.preset = name;
                    self.persist();
                    done = true;
                }
                if ui.button("Cancel").on_hover_text("Close this without doing anything").clicked() {
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
                        if i > 0 && ui.small_button("up").on_hover_text("Apply this rule before the one above it: when two rules fit the same thing, the later one wins").clicked() {
                            swap = Some((i, i - 1));
                        }
                        if i + 1 < n && ui.small_button("down").on_hover_text("Apply this rule after the one below it").clicked() {
                            swap = Some((i, i + 1));
                        }
                        if ui.small_button("x").on_hover_text("Remove this rule").clicked() {
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
                if ui.button("+ rule").on_hover_text("A new empty rule: say what it matches (a name, an account, a state) and how that is drawn").clicked() {
                    self.style.rules.push(Rule::default());
                    changed = true;
                }
                if ui.button("+ account in colour").on_hover_text("colour every edge of one account").clicked() {
                    self.style.rules.push(Rule { field: Field::User, pattern: "jdoe".into(), color: Some([255, 196, 84]), width: 1.6, ..Default::default() });
                    changed = true;
                }
                if ui.button("+ hide machine accounts").on_hover_text("A ready-made rule: connections of machine accounts (names ending in $) are not drawn").clicked() {
                    self.style.rules.push(Rule { field: Field::User, pattern: "*$".into(), color: None, hide: true, ..Default::default() });
                    changed = true;
                }
                if ui.button("+ fade benign").on_hover_text("A ready-made rule: what the hunt found habitual or baseline is drawn faint, so the findings stand out").clicked() {
                    self.style.rules.push(Rule { field: Field::Verdict, pattern: "benign".into(), color: Some([90, 96, 110]), width: 0.6, ..Default::default() });
                    changed = true;
                }
                if ui.button("+ domain controllers as hexagons").on_hover_text("A ready-made rule: hosts whose name looks like a domain controller are drawn as hexagons").clicked() {
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
            Field::User => e.users.iter().any(|&u| Pattern::any_account(pats, s.users.name(u))),
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
            if self.room_pending && self.presenting {
                self.room_pending = false;
                // the story has the whole window: the hosts settle again for
                // it (a narrowed view keeps the gaps of the hosts it lost),
                // stretch to its shape and make room for every name
                let per_host = (canvas.width() * canvas.height() / self.layout.len().max(1) as f32).sqrt();
                self.layout.link_distance = (per_host * 0.95).clamp(120.0, 330.0);
                self.layout.aspect = (canvas.width() / canvas.height().max(1.0)).clamp(0.5, 2.5);
                self.layout.reheat(0.5);
                let start = std::time::Instant::now();
                for _ in 0..600 {
                    if !self.layout.tick() || start.elapsed() > std::time::Duration::from_millis(400) {
                        break;
                    }
                }
                self.layout.stop();
                if let Some(to) = self.fill_target(canvas) {
                    self.layout.pos = to;
                }
                let mut pos = self.layout.pos.clone();
                let moved = self.give_names_room(&mut pos, canvas, 1.8, self.caption_room());
                if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
                    eprintln!("[view] presentation: names given room in {} sweep(s)", moved);
                }
                self.layout.pos = pos;
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
        let big = self.layout.len() >= super::layout::BIG_GRAPH && self.layout_worker;
        // light mode: a frame drawn by the CPU costs a quarter of a second or more, so the
        // layout does all its ticks now (microseconds each for a lab) rather than two a frame
        // while a host is held, a few ticks a frame so the rest follows it rather than settling anew each frame
        let ticking = if big {
            // A tick of thousands of hosts is tens of milliseconds, and a frame
            // waited for it (two or three a frame: 3 to 4 frames a second over
            // remote desktop for half a minute). A worker ticks now while the
            // window draws, and the hosts move when its ticks are done.
            if let Some(w) = &self.layout_work {
                match self.layout.poll_work(w, self.graph_id) {
                    super::layout::WorkState::Pending => {}
                    s => {
                        if s == super::layout::WorkState::Adopted { self.layout_works.0 += 1 } else { self.layout_works.1 += 1 }
                        self.layout_work = None;
                    }
                }
            }
            if self.layout_work.is_none() && self.layout.is_running() {
                // as long as a frame takes: the worker ticks the whole time the
                // window draws, and its hosts are there for the next frame
                let budget = (self.frame_ms * 0.9).clamp(20.0, 250.0) as u64;
                self.layout_work = Some(self.layout.start_work(std::time::Duration::from_millis(budget), self.graph_id));
            }
            self.layout_work.is_some() || self.layout.is_running()
        } else {
            self.layout_work = None;
            // in the frame (a lab, or a big graph on a machine of fewer than four cores)
            let heavy = self.layout.len() >= super::layout::BIG_GRAPH;
            let (budget, max_ticks) = if self.dragging.is_some() { (4, if heavy { 1 } else { 3 }) } else if self.light_mode { (60, 2000) } else if heavy { (8, 1) } else { (4, 2) };
            self.layout.tick_for(std::time::Duration::from_millis(budget), max_ticks)
        };
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
            if let Some(Sel::Node(i)) = self.press_hit.filter(|h| matches!(h, Sel::Node(i) if *i < self.layout.pos.len() && *i < self.layout.fixed.len())) {
                self.dragging = Some(i);
                self.layout.fixed[i] = true;
            } else {
                self.dragging = None;
            }
        }
        if resp.dragged() {
            // (a job that ends while a host is held redraws the graph with
            // other hosts: the one held may be gone)
            if self.dragging.map_or(false, |i| i >= self.layout.pos.len()) {
                self.dragging = None;
            }
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
        let lod = self.edges_on_screen > 2500 || self.safeguard.is_some();
        let fs = self.style.font_scale;
        let (reveal_done, reveal_now) = self.reveal();
        let cur_step = self.current_step();
        let mut keep_moving = false;
        let frame_now = std::time::Instant::now();
        // ── cinematic: the hop under way is what is lit, the rest dims; rings mark its ends ──
        let mut lit_nodes = lit_nodes;
        let mut lit_edges = lit_edges;
        let mut dimmed = dimmed;
        let mut focus_any = focus.is_some();
        let cine = self.presenting && self.story.cinematic;
        let look_focus = cine && self.story.look.focus;
        let look_footprint = cine && self.story.look.footprint;
        let accent = self.accent();
        let mut hop_src: HashSet<usize> = HashSet::new();
        let mut hop_dst: HashSet<usize> = HashSet::new();
        // when the hop started, when its line arrived, whether it is significant
        let mut hop_times: Option<(f32, f32, bool)> = None;
        if look_focus {
            if let Some(k) = cur_step {
                let st = &self.steps[k];
                let t = self.present_t;
                let arrived = st.start + st.dur;
                hop_times = Some((st.start, arrived, st.significant));
                for e in &self.graph.edges {
                    if e.first_event >= st.from && e.first_event < st.to {
                        if let Some(&a) = self.graph.node_of_host.get(&e.src) {
                            hop_src.insert(a);
                        }
                        if let Some(&b) = self.graph.node_of_host.get(&e.dst) {
                            hop_dst.insert(b);
                        }
                    }
                }
                // the dim holds from one hop to the next when they come close (under
                // a second apart): a picture that dimmed and lit again at every hop
                // would strobe, and a GIF would carry the whole picture every frame
                let held_from_prev = k > 0 && st.start - (self.steps[k - 1].start + self.steps[k - 1].dur) < 0.9;
                let held_to_next = self.steps.get(k + 1).map_or(false, |nx| nx.start - arrived < 0.9);
                let rise = if held_from_prev { 1.0 } else { ((t - st.start) / 0.25).clamp(0.0, 1.0) };
                let fall = if held_to_next { 1.0 } else { 1.0 - ((t - arrived) / 0.7).clamp(0.0, 1.0) };
                let strength = rise.min(fall);
                if strength > 0.01 {
                    lit_edges = self.graph.edges.iter().enumerate().filter(|(_, e)| e.first_event >= st.from && e.first_event < st.to).map(|(k, _)| k).collect();
                    lit_nodes = hop_src.union(&hop_dst).copied().collect();
                    dimmed = dimmed.max(0.8 * draw::ease_out_cubic(strength));
                    focus_any = true;
                    keep_moving = true;
                }
            }
        }
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
            // and a bar says how far the hunt is: its stage, of how many
            let (pos, len, what) = match self.job.as_ref().filter(|j| j.kind == tasks::JobKind::Hunt) {
                Some(j) if j.done.is_some() => (1u64, 1u64, "reading the result".to_string()),
                Some(j) => j.progress.bar.clone().unwrap_or((0, 10, "starting".to_string())),
                None => (1, 1, "reading the result".to_string()),
            };
            // (a stage under way counts as half done, and the bar eases to where it is)
            let target = if len == 0 { 0.0 } else { ((pos as f32 - 0.5) / len as f32).clamp(0.02, 1.0) };
            let shown = ui.ctx().animate_value_with_time(egui::Id::new("hunt-bar"), target, 0.6);
            let w = (canvas.width() * 0.46).clamp(260.0, 560.0);
            let track = Rect::from_center_size(Pos2::new(canvas.center().x, canvas.bottom() - 34.0), Vec2::new(w, 8.0));
            let plate = track.expand2(Vec2::new(16.0, 24.0)).translate(Vec2::new(0.0, -8.0));
            painter.rect_filled(plate, CornerRadius::same(12), Color32::from_rgba_unmultiplied(10, 14, 22, 215));
            painter.rect_stroke(plate, CornerRadius::same(12), Stroke::new(1.0, draw::fade(ACCENT, 0.35)), egui::StrokeKind::Inside);
            painter.rect_filled(track, CornerRadius::same(4), theme::FIELD);
            let fill = Rect::from_min_size(track.min, Vec2::new((track.width() * shown).max(8.0), track.height()));
            let mut bar = egui::epaint::Mesh::default();
            let (c0, c1) = (theme::CYAN, theme::MAGENTA);
            let mix = |f: f32| Color32::from_rgb((c0.r() as f32 + (c1.r() as f32 - c0.r() as f32) * f) as u8, (c0.g() as f32 + (c1.g() as f32 - c0.g() as f32) * f) as u8, (c0.b() as f32 + (c1.b() as f32 - c0.b() as f32) * f) as u8);
            bar.vertices.extend([v(fill.left_top(), c0), v(fill.right_top(), mix(shown)), v(fill.right_bottom(), mix(shown)), v(fill.left_bottom(), c0)]);
            bar.add_triangle(0, 1, 2);
            bar.add_triangle(0, 2, 3);
            painter.with_clip_rect(fill).add(egui::Shape::mesh(bar));
            // a light runs along what is done
            let glint = fill.left() + ((t * 0.9).fract()) * fill.width();
            painter.with_clip_rect(fill).rect_filled(Rect::from_center_size(Pos2::new(glint, fill.center().y), Vec2::new(26.0, fill.height())), CornerRadius::same(4), Color32::from_rgba_unmultiplied(255, 255, 255, 70));
            painter.text(Pos2::new(track.left(), track.top() - 9.0), Align2::LEFT_BOTTOM, format!("Hunting  ·  {}", what), FontId::proportional(12.5), TEXT);
            painter.text(Pos2::new(track.right(), track.top() - 9.0), Align2::RIGHT_BOTTOM, format!("{:.0} %   {:.0} s", shown * 100.0, t), FontId::monospace(11.0), draw::fade(ACCENT, 0.9));
        }
        let t_edges = std::time::Instant::now();

        // ── the subnet regions, behind everything ──
        self.layout.aspect = (canvas.width() / canvas.height().max(1.0)).clamp(0.5, 2.5);
        self.draw_subnets(&painter, canvas, false);

        // a new selection sends a ripple out from what was picked
        if self.sel_seen != self.selected {
            self.sel_seen = self.selected;
            self.sel_at = now;
        }
        let ripple = if motion && self.selected.is_some() { ((now - self.sel_at) / 0.55).clamp(0.0, 1.0) } else { 1.0 };
        if ripple < 1.0 {
            keep_moving = true;
        }
        // ── edges ──
        let mut animated: Vec<usize> = Vec::new();
        let mut edges_drawn = 0usize;
        let mut taken: Vec<Rect> = Vec::new();
        // the plain edges go into one mesh, drawn under everything else
        // the plain lines go in several meshes, each its own primitive (a clip a
        // hundredth of a pixel apart): the CPU rasteriser draws primitives on
        // all the cores, and one mesh of 40,000 lines was one core's work
        let plain_slots: Vec<(egui::Painter, egui::layers::ShapeIdx)> = (0..self.plain_parts)
            .map(|i| {
                let p = painter.with_clip_rect(painter.clip_rect().shrink(i as f32 * 0.01));
                let s = p.add(egui::Shape::Noop);
                (p, s)
            })
            .collect();
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
            let on_trail = self.trail_on.get(k).copied().unwrap_or(false);
            let trailing = !self.trail_on.is_empty();
            let alpha = if trailing && !on_trail && !selected { alpha * 0.22 } else { alpha };
            if on_trail {
                width = width * 1.8 + 2.6 * z.sqrt();
                color = theme::MAGENTA;
            }
            if selected && ripple < 1.0 {
                // the line swells with light as it is picked
                painter.add(egui::epaint::QuadraticBezierShape { points: [pa, pc, pb], closed: false, fill: Color32::TRANSPARENT, stroke: egui::epaint::PathStroke::new(width + 22.0 * (1.0 - ripple) * z.sqrt(), draw::fade(theme::CYAN, 0.30 * (1.0 - ripple))) });
            }
            let stroke_color = if selected { ACCENT } else { color };
            let short = (pa - pb).length() < 14.0;
            let plain = lod && !lit && !selected && !on_trail;
            let glow = !plain && (arcade || ((self.style.edge_glow || look.glow) && (look.glow || emphasised || progress < 1.0 || (lit && focus_any) || (look.finding && dimmed < 0.5))));
            if glow {
                painter.add(egui::epaint::QuadraticBezierShape { points: [pa, pc, pb], closed: false, fill: Color32::TRANSPARENT, stroke: egui::epaint::PathStroke::new(width + 6.0 * z.sqrt(), draw::fade(color, if progress < 1.0 { 0.45 } else if arcade { 0.22 } else { 0.16 } * alpha)) });
            }
            if on_trail && !short {
                // its light: wide and soft under the line, breathing
                let breath = if motion { 0.75 + 0.25 * (now * 2.6 + k as f32 * 0.7).sin() } else { 0.9 };
                painter.add(egui::epaint::QuadraticBezierShape { points: [pa, pc, pb], closed: false, fill: Color32::TRANSPARENT, stroke: egui::epaint::PathStroke::new(width + 14.0 * z.sqrt(), draw::fade(theme::VIOLET, 0.16 * breath * alpha)) });
                painter.add(egui::epaint::QuadraticBezierShape { points: [pa, pc, pb], closed: false, fill: Color32::TRANSPARENT, stroke: egui::epaint::PathStroke::new(width + 6.0 * z.sqrt(), draw::fade(theme::MAGENTA, 0.30 * breath * alpha)) });
                keep_moving |= motion;
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
                if on_trail && !selected {
                    // the logo's own run of colour, from where it leaves to where it lands
                    draw::gradient_curve(&painter, pa, pc, pb, width, draw::fade(theme::CYAN, alpha), draw::fade(theme::MAGENTA, alpha));
                } else {
                    draw::gradient_curve(&painter, pa, pc, pb, width, draw::fade(stroke_color, alpha * 0.5), draw::fade(stroke_color, alpha));
                }
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
            if motion && !short && (lit || look.finding || look.glow || emphasised || on_trail) && animated.len() < if lod { 120 } else { 600 } && (!plain || lit) {
                animated.push(k);
            }
            // the account on the edge, like Neo4j's relationship caption
            // when it is drawn: View › Style › Connections › captions (caption_rule)
            if let Some(keep_clear) = super::views::caption_rule(&self.style, self.edges_on_screen, z, (pa - pb).length(), lit, selected, plain) {
                let caption = self.edge_caption(e);
                if !caption.is_empty() {
                    let mid = draw::bez(pa, pc, pb, 0.5);
                    let font = FontId::proportional((10.0 * z.sqrt() * fs).clamp(7.0, 16.0));
                    let galley = painter.layout_no_wrap(caption, font, draw::fade(TEXT, alpha));
                    let r = Rect::from_center_size(mid, galley.size() + Vec2::new(12.0, 5.0));
                    // a caption that would sit on another is left out, unless its edge is lit
                    if !keep_clear || !taken.iter().any(|t| t.intersects(r)) {
                        draw::pill(&painter, mid, galley, draw::fade(CAPTION_BG, alpha), if lit { Some(draw::fade(stroke_color, 0.6 * alpha)) } else { None }, TEXT);
                        taken.push(r);
                    }
                }
            }
        }

        for (part, (p, slot)) in split_mesh(plain_mesh, self.plain_parts).into_iter().zip(plain_slots) {
            p.set(slot, egui::Shape::mesh(part));
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
        // asked for by the analyst: every host its figure and its name
        let full = self.style.names_always;
        let crowd_nodes = !full && (lod || self.graph.nodes.len() > 700);
        let (mut drawn_plain, mut names_left_out) = (0usize, false);
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
            // a path marked on the map: its hosts keep their light and carry its ring, the others step back
            if selected && ripple < 1.0 && r > 2.0 {
                // two rings leave the host, in the logo's two colours
                let e = draw::ease_out_cubic(ripple);
                painter.circle_stroke(p, r + 6.0 + 46.0 * e, Stroke::new(2.0 * (1.0 - ripple) + 0.5, draw::fade(theme::CYAN, 0.75 * (1.0 - ripple))));
                painter.circle_stroke(p, r + 4.0 + 26.0 * e, Stroke::new(1.5 * (1.0 - ripple) + 0.5, draw::fade(theme::MAGENTA, 0.55 * (1.0 - ripple))));
            }
            let on_trail = !self.trail_on.is_empty() && look.edges.iter().any(|&k| self.trail_on.get(k as usize).copied().unwrap_or(false));
            let alpha = if !self.trail_on.is_empty() && !on_trail && !selected && !hovered { alpha * 0.3 } else { alpha };
            if on_trail && r > 2.0 {
                let breath = if motion { 0.7 + 0.3 * (now * 2.6 + i as f32).sin() } else { 0.85 };
                painter.circle_filled(p, r * 1.45 + 8.0, draw::fade(theme::VIOLET, 0.10 * breath));
                painter.circle_stroke(p, r * 1.18 + 5.0, Stroke::new((2.2 * z.sqrt()).clamp(1.5, 3.5), draw::fade(theme::MAGENTA, 0.85 * breath)));
            }
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
            } else if lit && focus_any {
                0.6
            } else {
                0.0
            };
            let small = (r < if full { 2.5 } else { 10.0 } || crowd_nodes) && matches!(look.shape, Shape::Circle) && !selected && !hovered && !lit;
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
            if look_footprint && r > 4.0 && !significant && !lit && n.hunt_rank != 1 {
                // a host already reached keeps a warm trace: the spread, visible
                draw::glow(&painter, p, r + 1.0, FOOTPRINT, 0.3 * alpha);
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
                drawn_plain += 1;
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
            if let Some((t_start, t_arrived, sig)) = hop_times {
                let t = self.present_t;
                if hop_dst.contains(&i) {
                    // the line arrived: a ring runs out of the destination and it lights up
                    let since = t - t_arrived;
                    if (0.0..0.7).contains(&since) {
                        let k = draw::ease_out_cubic(since / 0.7);
                        let col = if sig { SIGNIFICANT } else { accent };
                        painter.circle_stroke(p, r + 4.0 + 80.0 * z.sqrt().clamp(0.5, 1.4) * k, Stroke::new(0.6 + 3.0 * (1.0 - k), draw::fade(col, 0.9 * (1.0 - k))));
                        draw::glow(&painter, p, r + 2.0, col, 0.9 * (1.0 - k));
                        keep_moving = true;
                    }
                }
                if hop_src.contains(&i) {
                    // the hop leaves: a short ping at the origin
                    let since = t - t_start;
                    if (0.0..0.45).contains(&since) {
                        let k = since / 0.45;
                        painter.circle_stroke(p, r + 3.0 + 34.0 * z.sqrt().clamp(0.5, 1.4) * k, Stroke::new(0.4 + 2.0 * (1.0 - k), draw::fade(accent, 0.75 * (1.0 - k))));
                        keep_moving = true;
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
            self.drawn_reduced = (drawn_plain, names_left_out);
            let anonym = self.presenting && self.story.anonymise;
            let shown: Cow<str> = if anonym { Cow::Owned(self.anon.host(n.host, look.is_ip)) } else { Cow::Borrowed(look.name.as_str()) };
            let shown_name: &str = &shown;
            if !(full || z > 0.3 || lit || look.label_pos != LabelPos::Auto) {
                names_left_out = true;
            }
            if full || z > 0.3 || lit || look.label_pos != LabelPos::Auto {
                // asked for: a name that is read, however far the view is
                let base_px = (11.0 * z.sqrt() * fs * look.label_size).clamp(if full { 9.0 } else { 6.5 }, 40.0);
                let pos = self.drawn_label_pos(look);
                labels::paint_host_label(&painter, shown_name, p, r, pos, base_px, look.label_bg, ring, alpha, lit, crowd_nodes || lod, self.style.node_style == NodeStyle::Arcade);
            }
            if let Some(label) = self.overlay.as_ref().and_then(|o| o.labels.get(&n.host)).or_else(|| self.trail.as_ref().and_then(|t| t.labels.get(&n.host))) {
                let galley = painter.layout_no_wrap(label.clone(), FontId::proportional((10.5 * z.sqrt() * fs).clamp(8.0, 14.0)), ACCENT);
                let h = galley.size().y;
                draw::pill(&painter, Pos2::new(p.x, labels::hop_badge_y(p, r, h, look.label_pos)), galley, draw::fade(CAPTION_BG, alpha), Some(draw::fade(ACCENT, 0.5 * alpha)), ACCENT);
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

    /// The presentation's accent: the client's colour when the cinematic
    /// look names one, masstin's amber otherwise.
    fn accent(&self) -> Color32 {
        match self.story.look.accent {
            Some([r, g, b]) if self.story.cinematic => Color32::from_rgb(r, g, b),
            _ => ACCENT,
        }
    }

    fn font_medium(&self, size: f32) -> FontId {
        FontId::new(size * self.style.font_scale, egui::FontFamily::Name(theme::MEDIUM.into()))
    }

    fn font_semibold(&self, size: f32) -> FontId {
        FontId::new(size * self.style.font_scale, egui::FontFamily::Name(theme::SEMIBOLD.into()))
    }

    /// The analyst's latest note on this connection, by the names it was written under.
    fn note_for_edge(&self, src: u32, dst: u32, user: u32) -> Option<String> {
        let (s, d, u) = (self.store.hosts.name(src), self.store.hosts.name(dst), self.store.users.name(user));
        self.notes.notes.iter().rev().find_map(|n| match &n.target {
            NoteTarget::Edge { src: ns, dst: nd, user: nu } if ns.eq_ignore_ascii_case(s) && nd.eq_ignore_ascii_case(d) && (nu.is_empty() || nu.eq_ignore_ascii_case(u)) => Some(n.text.clone()),
            _ => None,
        })
    }

    fn presentation_overlays(&mut self, painter: &egui::Painter, canvas: Rect) {
        let fs = self.style.font_scale;
        let cine = self.story.cinematic;
        let look = self.story.look.clone();
        let accent = self.accent();
        let t = self.present_t;
        let cur = present::at(&self.steps, t);
        let bar_h = if cine && look.bar { 30.0 } else { 0.0 };
        // a bottom logo stays above the caption and the bar; a top-centre one pushes the title down
        let caption_h = match cur {
            Some(_) if cine && look.lower_third => 84.0 * fs,
            Some(_) if self.story.show_caption => 64.0 * fs,
            _ => 0.0,
        };
        let logo = self.brand_overlay(painter, canvas, caption_h + bar_h);
        if !self.story.title.is_empty() {
            let top = match logo {
                Some(r) if self.story.logo_pos == LogoPos::TopCentre => r.bottom() + 8.0,
                _ => canvas.top() + 16.0,
            };
            let font = if cine { self.font_medium(22.0) } else { FontId::proportional(22.0 * fs) };
            let r = painter.text(Pos2::new(canvas.center().x, top), Align2::CENTER_TOP, &self.story.title, font, TEXT);
            if cine {
                painter.line_segment([Pos2::new(r.center().x - 22.0, r.bottom() + 6.0), Pos2::new(r.center().x + 22.0, r.bottom() + 6.0)], Stroke::new(2.0, draw::fade(accent, 0.9)));
            }
        }
        if let Some((k, p)) = cur {
            let st = self.steps[k].clone();
            let prev = if k > 0 { Some(self.steps[k - 1].clone()) } else { None };
            // the clock rolls from the step before while the line draws: time
            // passing, at the pace the story gives it
            let shown_t = match &prev {
                Some(pv) if cine && look.time && p < 1.0 => pv.t + ((st.t - pv.t) as f64 * draw::ease_out_cubic((p / 0.6).min(1.0)) as f64) as i64,
                _ => st.t,
            };
            if cine && look.time {
                self.clock_card(painter, canvas, &st, prev.as_ref(), shown_t, k, accent);
            } else if self.story.show_clock {
                let galley = painter.layout_no_wrap(fmt_time(st.t), FontId::monospace(20.0 * fs), TEXT);
                let r = Rect::from_min_size(Pos2::new(canvas.right() - galley.size().x - 26.0, canvas.top() + 12.0), galley.size() + Vec2::new(16.0, 8.0));
                painter.rect_filled(r, CornerRadius::same(6), CAPTION_BG);
                painter.galley(r.min + Vec2::new(8.0, 4.0), galley, TEXT);
            }
            if self.story.show_counter && !(cine && look.time) {
                painter.text(Pos2::new(canvas.right() - 12.0, canvas.bottom() - 10.0 - bar_h), Align2::RIGHT_BOTTOM, format!("{} / {}", k + 1, self.steps.len()), FontId::proportional(12.0 * fs), MUTED);
            }
            if cine && look.lower_third {
                self.lower_third(painter, canvas, &st, k, bar_h, accent);
            } else if self.story.show_caption {
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
                let r = Rect::from_center_size(Pos2::new(canvas.center().x, canvas.bottom() - 34.0 - bar_h), galley.size() + Vec2::new(28.0, 14.0));
                painter.rect_filled(r, CornerRadius::same(8), Color32::from_rgba_premultiplied(24, 26, 31, 225));
                if st.significant || st.emphasis {
                    painter.rect_stroke(r, CornerRadius::same(8), Stroke::new(1.5, if st.significant { SIGNIFICANT } else { accent }), egui::StrokeKind::Inside);
                }
                painter.galley(r.min + Vec2::new(14.0, 7.0), galley, TEXT);
            }
            if cine && look.bar {
                self.incident_bar(painter, canvas, shown_t, accent);
            }
        }
        match &self.export {
            None => {
                let hint = if cine { Pos2::new(canvas.center().x, canvas.bottom() - 8.0 - bar_h) } else { Pos2::new(canvas.left() + 12.0, canvas.bottom() - 10.0) };
                painter.text(hint, if cine { Align2::CENTER_BOTTOM } else { Align2::LEFT_BOTTOM }, "Space pause  ·  Left / Right step  ·  Esc leave", FontId::proportional(11.0), MUTED);
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
        // the cards cover everything, the hint too
        if cine && look.cards {
            self.cards(painter, canvas, t, accent);
        }
    }

    /// The clock card, top right: the date, the time (rolling while a line
    /// draws), the pace and whether it just changed, the counter; and a
    /// jump in the timeline named at the top while the line draws.
    fn clock_card(&self, painter: &egui::Painter, canvas: Rect, st: &Step, prev: Option<&Step>, shown_t: i64, k: usize, accent: Color32) {
        let fs = self.style.font_scale;
        let when = chrono::DateTime::from_timestamp(shown_t, 0);
        let date = when.map(|d| d.format("%a %d %b %Y").to_string()).unwrap_or_default();
        let time = when.map(|d| d.format("%H:%M:%S").to_string()).unwrap_or_default();
        let since = self.present_t - st.start;
        let change = prev.and_then(|pv| present::speed_change(pv, st)).filter(|_| since < 2.5);
        let (speed_text, speed_col, pulse) = match change {
            Some(faster) => (format!("{}  {}", if faster { "»  faster" } else { "«  slower" }, present::speed_label(st)), if faster { accent } else { TEXT }, 1.0 + 0.18 * (1.0 - (since / 0.6).min(1.0))),
            None => (present::speed_label(st), draw::fade(accent, 0.9), 1.0),
        };
        let g_date = painter.layout_no_wrap(date, self.font_medium(12.5), MUTED);
        let g_time = painter.layout_no_wrap(time, FontId::monospace(30.0 * fs), TEXT);
        let g_speed = painter.layout_no_wrap(speed_text, self.font_medium(12.5 * pulse), speed_col);
        let g_count = if self.story.show_counter { Some(painter.layout_no_wrap(format!("{} / {}", k + 1, self.steps.len()), self.font_medium(11.0), theme::DIM)) } else { None };
        let w = [g_date.size().x, g_time.size().x, g_speed.size().x].into_iter().fold(0.0f32, f32::max) + 30.0;
        let h = g_date.size().y + g_time.size().y + g_speed.size().y + g_count.as_ref().map_or(0.0, |g| g.size().y + 2.0) + 24.0;
        let r = Rect::from_min_size(Pos2::new(canvas.right() - w - 18.0, canvas.top() + 14.0), Vec2::new(w, h));
        painter.rect_filled(r, CornerRadius::same(10), Color32::from_rgba_premultiplied(18, 21, 28, 228));
        painter.rect_stroke(r, CornerRadius::same(10), Stroke::new(1.0, draw::fade(accent, 0.35)), egui::StrokeKind::Inside);
        painter.rect_filled(Rect::from_min_size(r.min + Vec2::new(0.0, 10.0), Vec2::new(3.0, r.height() - 20.0)), CornerRadius::same(2), draw::fade(accent, 0.9));
        let x = r.right() - 14.0;
        let mut y = r.top() + 11.0;
        let dy = g_date.size().y;
        painter.galley(Pos2::new(x - g_date.size().x, y), g_date, MUTED);
        y += dy + 2.0;
        let ty = g_time.size().y;
        painter.galley(Pos2::new(x - g_time.size().x, y), g_time, TEXT);
        y += ty + 2.0;
        let sy = g_speed.size().y;
        painter.galley(Pos2::new(x - g_speed.size().x, y), g_speed, speed_col);
        y += sy + 2.0;
        if let Some(g) = g_count {
            painter.galley(Pos2::new(x - g.size().x, y), g, theme::DIM);
        }
        // a jump in the timeline, named at the top while the line draws
        if prev.is_some() && st.gap >= present::jump_threshold(&self.steps) {
            let p = (since / st.dur.max(0.05)).clamp(0.0, 1.0);
            if p < 0.85 {
                let a = (p / 0.12).min(1.0) * (1.0 - ((p - 0.65) / 0.2).clamp(0.0, 1.0));
                let g = painter.layout_no_wrap(format!("{}   {}", super::icons::CLOCK, present::jump_label(st.gap)), self.font_medium(15.0), draw::fade(TEXT, a));
                let top = canvas.top() + if self.story.title.is_empty() { 22.0 } else { 58.0 * fs };
                let pr = Rect::from_min_size(Pos2::new(canvas.center().x - g.size().x / 2.0 - 14.0, top), g.size() + Vec2::new(28.0, 12.0));
                painter.rect_filled(pr, CornerRadius::same(8), draw::fade(Color32::from_rgb(18, 21, 28), 0.92 * a));
                painter.rect_stroke(pr, CornerRadius::same(8), Stroke::new(1.0, draw::fade(accent, 0.6 * a)), egui::StrokeKind::Inside);
                painter.galley(pr.min + Vec2::new(14.0, 6.0), g, TEXT);
            }
        }
    }

    /// The caption as a lower third, bottom left: the account in the accent,
    /// origin and destination, the hunt's word or the analyst's verdict as a
    /// tag, the time and the logon under, the analyst's note on the
    /// connection when there is one. It slides in as the step starts and
    /// fades before the next.
    fn lower_third(&self, painter: &egui::Painter, canvas: Rect, st: &Step, k: usize, bar_h: f32, accent: Color32) {
        let t = self.present_t;
        // it slides in once and stays while the hops come close (under a second
        // apart), its words changing with each; it leaves before a long gap
        let held_from_prev = k > 0 && st.start - (self.steps[k - 1].start + self.steps[k - 1].dur) < 0.9;
        let k_in = if held_from_prev { 1.0 } else { draw::ease_out_cubic(((t - st.start) / 0.35).clamp(0.0, 1.0)) };
        let k_out = match self.steps.get(k + 1) {
            Some(next) if next.start - (st.start + st.dur) < 0.9 => 1.0,
            Some(next) => ((next.start - t) / 0.3).clamp(0.0, 1.0),
            None => 1.0,
        };
        let a = k_in * k_out;
        if a <= 0.01 {
            return;
        }
        let ei = self.graph.events[st.from] as usize;
        let e = self.store.edges[ei];
        let n = st.to - st.from;
        let fmt = |font: FontId, color: Color32| egui::text::TextFormat { font_id: font, color, ..Default::default() };
        // the account and the two hosts: the headline, or under the analyst's
        // own caption so the words never hide who went where
        let who = |size: f32| {
            let mut job = egui::text::LayoutJob::default();
            let user = self.user_label(e.user);
            if !user.is_empty() {
                job.append(&user, 0.0, fmt(self.font_semibold(size), draw::fade(accent, a)));
                job.append("    ", 0.0, fmt(self.font_medium(size), TEXT));
            }
            job.append(&self.host_label(e.src), 0.0, fmt(self.font_semibold(size), draw::fade(TEXT, a)));
            job.append("  →  ", 0.0, fmt(self.font_medium(size), draw::fade(MUTED, a)));
            job.append(&self.host_label(e.dst), 0.0, fmt(self.font_semibold(size), draw::fade(TEXT, a)));
            if n > 1 {
                job.append(&format!("    +{} more", n - 1), 0.0, fmt(self.font_medium(size * 0.74), draw::fade(MUTED, a)));
            }
            job
        };
        let (g1, g_who) = match &st.caption {
            Some(c) => {
                let mut job = egui::text::LayoutJob::default();
                job.append(c, 0.0, fmt(self.font_semibold(19.0), draw::fade(TEXT, a)));
                job.wrap.max_width = (canvas.width() * 0.6).max(360.0);
                (painter.layout_job(job), Some(painter.layout_job(who(14.5))))
            }
            None => (painter.layout_job(who(19.0)), None),
        };
        let mut detail = vec![fmt_time(e.t)[11..].to_string()];
        let lt = self.store.logon_types.name(e.logon_type);
        if !lt.is_empty() && lt != "-" {
            detail.push(format!("logon type {}", lt));
        }
        if e.event_id > 0 {
            detail.push(format!("event {}", e.event_id));
        }
        let g2 = painter.layout_no_wrap(detail.join("  ·  "), self.font_medium(12.5), draw::fade(MUTED, a));
        let tag: Option<(&str, Color32)> = if e.verdict != 0 {
            Some((VERDICT_NAMES[e.verdict as usize], match e.verdict { 1 => SUSPICIOUS, 2 => CONFIRMED, _ => MUTED }))
        } else if e.hunt == super::store::H_SIGNIFICANT {
            Some(("significant", SIGNIFICANT))
        } else if e.hunt == super::store::H_CANDIDATE {
            Some(("candidate", CANDIDATE))
        } else {
            None
        };
        let g_tag = tag.map(|(s, c)| (painter.layout_no_wrap(s.to_uppercase(), self.font_medium(10.5), draw::fade(c, a)), c));
        let g3 = self.note_for_edge(e.src, e.dst, e.user).map(|note| {
            let mut job = egui::text::LayoutJob::default();
            job.append(&format!("{}  {}", super::icons::NOTE_PENCIL, note), 0.0, fmt(self.font_medium(13.5), draw::fade(TEXT, 0.92 * a)));
            job.wrap.max_width = (canvas.width() * 0.5).max(320.0);
            painter.layout_job(job)
        });
        let pad = 14.0;
        let w1 = g1.size().x + g_tag.as_ref().map_or(0.0, |(g, _)| g.size().x + 28.0);
        let w = w1.max(g2.size().x).max(g3.as_ref().map_or(0.0, |g| g.size().x)).max(g_who.as_ref().map_or(0.0, |g| g.size().x)) + pad * 2.0 + 8.0;
        let h = g1.size().y + g_who.as_ref().map_or(0.0, |g| g.size().y + 4.0) + g2.size().y + g3.as_ref().map_or(0.0, |g| g.size().y + 6.0) + pad * 1.5;
        let x = canvas.left() + 24.0 - 40.0 * (1.0 - k_in);
        let r = Rect::from_min_size(Pos2::new(x, canvas.bottom() - bar_h - 18.0 - h), Vec2::new(w, h));
        painter.rect_filled(r, CornerRadius::same(8), draw::fade(Color32::from_rgb(18, 21, 28), 0.9 * a));
        painter.rect_filled(Rect::from_min_size(r.min, Vec2::new(4.0, h)), CornerRadius { nw: 8, sw: 8, ne: 0, se: 0 }, draw::fade(if st.significant { SIGNIFICANT } else { accent }, a));
        let x0 = r.left() + pad + 8.0;
        let mut y = r.top() + pad * 0.6;
        let (h1, w1_text) = (g1.size().y, g1.size().x);
        painter.galley(Pos2::new(x0, y), g1, TEXT);
        if let Some((g, c)) = g_tag {
            let tr = Rect::from_min_size(Pos2::new(x0 + w1_text + 14.0, y + (h1 - g.size().y - 6.0) / 2.0), g.size() + Vec2::new(12.0, 6.0));
            painter.rect_stroke(tr, CornerRadius::same(4), Stroke::new(1.0, draw::fade(c, 0.85 * a)), egui::StrokeKind::Inside);
            painter.galley(tr.min + Vec2::new(6.0, 3.0), g, c);
        }
        y += h1 + 3.0;
        if let Some(g) = g_who {
            let hw = g.size().y;
            painter.galley(Pos2::new(x0, y + 1.0), g, TEXT);
            y += hw + 4.0;
        }
        let h2 = g2.size().y;
        painter.galley(Pos2::new(x0, y), g2, MUTED);
        if let Some(g) = g3 {
            y += h2 + 6.0;
            painter.galley(Pos2::new(x0, y), g, TEXT);
        }
    }

    /// The incident's span along the bottom: a track from the first hop to
    /// the last, a tick a day, the significant hops as red dots, the head
    /// where the story is now.
    fn incident_bar(&self, painter: &egui::Painter, canvas: Rect, now_t: i64, accent: Color32) {
        let (Some(first), Some(last)) = (self.steps.first(), self.steps.last()) else { return };
        let (t0, t1) = (first.t, last.t.max(first.t + 1));
        let (x0, x1) = (canvas.left() + 28.0, canvas.right() - 28.0);
        let y = canvas.bottom() - 15.0;
        let xf = |t: i64| x0 + (x1 - x0) * ((t - t0) as f32 / (t1 - t0) as f32).clamp(0.0, 1.0);
        painter.rect_filled(Rect::from_min_max(Pos2::new(canvas.left(), y - 15.0), canvas.max), CornerRadius::ZERO, Color32::from_rgba_premultiplied(0, 0, 0, 120));
        painter.line_segment([Pos2::new(x0, y), Pos2::new(x1, y)], Stroke::new(3.0, Color32::from_rgb(44, 50, 64)));
        let days = (t1 - t0) / 86_400;
        if (1..=120).contains(&days) {
            let mut d = (t0 / 86_400 + 1) * 86_400;
            while d < t1 {
                let x = xf(d);
                painter.line_segment([Pos2::new(x, y - 4.0), Pos2::new(x, y + 4.0)], Stroke::new(1.0, Color32::from_rgb(64, 72, 92)));
                d += 86_400;
            }
        }
        let xn = xf(now_t);
        painter.line_segment([Pos2::new(x0, y), Pos2::new(xn, y)], Stroke::new(3.0, draw::fade(accent, 0.9)));
        for s in &self.steps {
            if s.significant {
                painter.circle_filled(Pos2::new(xf(s.t), y), 3.5, SIGNIFICANT);
            }
        }
        painter.circle_filled(Pos2::new(xn, y), 8.0, draw::fade(accent, 0.25));
        painter.circle_filled(Pos2::new(xn, y), 4.0, accent);
        painter.text(Pos2::new(x0, y - 7.0), Align2::LEFT_BOTTOM, &fmt_time(t0)[..10], self.font_medium(10.5), MUTED);
        painter.text(Pos2::new(x1, y - 7.0), Align2::RIGHT_BOTTOM, &fmt_time(t1)[..10], self.font_medium(10.5), MUTED);
    }

    /// The title card before the story and the summary after it, over the
    /// picture, fading at their edges.
    fn cards(&self, painter: &egui::Painter, canvas: Rect, t: f32, accent: Color32) {
        let total = present::total_secs(&self.steps, &self.story);
        let lead = self.story.lead_in();
        let a_in = if lead > 0.0 && t < lead { 1.0 - ((t - (lead - 0.7)) / 0.7).clamp(0.0, 1.0) } else { 0.0 };
        let out_from = total - self.story.lead_out();
        let a_out = if self.story.lead_out() > 0.0 && t > out_from { ((t - out_from) / 0.7).clamp(0.0, 1.0) } else { 0.0 };
        if a_in <= 0.001 && a_out <= 0.001 {
            return;
        }
        let (Some(first), Some(last)) = (self.steps.first(), self.steps.last()) else { return };
        let a = a_in.max(a_out);
        painter.rect_filled(canvas, CornerRadius::ZERO, draw::fade(BG, a));
        let cx = canvas.center().x;
        let mut y = canvas.top() + canvas.height() * 0.17;
        if let Some((_, tex, size)) = &self.brand {
            let w = (canvas.width() * 0.2).min(340.0);
            let h = w * size[1] as f32 / size[0].max(1) as f32;
            let r = Rect::from_center_size(Pos2::new(cx, y + h / 2.0), Vec2::new(w, h));
            painter.image(tex.id(), r, Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)), draw::fade(Color32::WHITE, a));
            y += h + 30.0;
        }
        let title = if self.story.title.is_empty() { "Lateral movement".to_string() } else { self.story.title.clone() };
        let accounts: HashSet<u32> = self.graph.events.iter().map(|&ei| self.store.edges[ei as usize].user).filter(|&u| !self.store.users.name(u).is_empty()).collect();
        let significant = self.steps.iter().filter(|s| s.significant).count();
        if a_in > 0.001 {
            // each line a little after the one before
            let fade_in = |d: f32| ((t - d) / 0.5).clamp(0.0, 1.0) * a_in;
            let r = painter.text(Pos2::new(cx, y), Align2::CENTER_TOP, &title, self.font_medium(38.0), draw::fade(TEXT, fade_in(0.15)));
            painter.line_segment([Pos2::new(cx - 28.0, r.bottom() + 12.0), Pos2::new(cx + 28.0, r.bottom() + 12.0)], Stroke::new(2.0, draw::fade(accent, fade_in(0.35))));
            let span = format!("{}   →   {}", &fmt_time(first.t)[..16], &fmt_time(last.t)[..16]);
            let r = painter.text(Pos2::new(cx, r.bottom() + 30.0), Align2::CENTER_TOP, span, self.font_medium(17.0), draw::fade(MUTED, fade_in(0.55)));
            let stats = format!("{} connections  ·  {} hosts  ·  {} accounts{}", self.graph.events.len(), self.graph.nodes.len(), accounts.len(), if significant > 0 { format!("  ·  {} significant", significant) } else { String::new() });
            painter.text(Pos2::new(cx, r.bottom() + 8.0), Align2::CENTER_TOP, stats, self.font_medium(15.0), draw::fade(MUTED, fade_in(0.75)));
            painter.text(Pos2::new(cx, canvas.bottom() - 26.0), Align2::CENTER_BOTTOM, "the movement between machines, reconstructed from the logs with masstin", self.font_medium(11.0), draw::fade(theme::DIM, fade_in(0.95)));
        }
        if a_out > 0.001 {
            let r = painter.text(Pos2::new(cx, y), Align2::CENTER_TOP, &title, self.font_medium(28.0), draw::fade(TEXT, a_out));
            painter.text(Pos2::new(cx, r.bottom() + 10.0), Align2::CENTER_TOP, "IN SHORT", self.font_medium(11.0), draw::fade(accent, a_out));
            let days = ((last.t - first.t) as f32 / 86_400.0).max(0.0);
            let span = if days >= 1.5 { format!("{:.0} days", days) } else { format!("{:.0} hours", (last.t - first.t) as f32 / 3600.0) };
            let lines = [
                format!("{} hosts reached  ·  {} accounts used", self.graph.nodes.len(), accounts.len()),
                format!("{} connections{}", self.graph.events.len(), if significant > 0 { format!(", {} of them significant", significant) } else { String::new() }),
                format!("{}  →  {}  ({})", &fmt_time(first.t)[..16], &fmt_time(last.t)[..16], span),
            ];
            let mut yy = r.bottom() + 40.0;
            for l in lines {
                let r = painter.text(Pos2::new(cx, yy), Align2::CENTER_TOP, l, self.font_medium(17.0), draw::fade(TEXT, a_out));
                yy = r.bottom() + 8.0;
            }
            // the significant hops, up to six, in their order
            let sig: Vec<&Step> = self.steps.iter().filter(|s| s.significant).take(6).collect();
            if !sig.is_empty() {
                yy += 16.0;
                let fmt = |font: FontId, color: Color32| egui::text::TextFormat { font_id: font, color, ..Default::default() };
                for s in sig {
                    let ei = self.graph.events[s.from] as usize;
                    let e = self.store.edges[ei];
                    let mut job = egui::text::LayoutJob::default();
                    job.append(&format!("{}    ", &fmt_time(e.t)[5..16]), 0.0, fmt(FontId::monospace(13.5 * self.style.font_scale), draw::fade(MUTED, a_out)));
                    let user = self.user_label(e.user);
                    if !user.is_empty() {
                        job.append(&format!("{}    ", user), 0.0, fmt(self.font_semibold(14.5), draw::fade(accent, a_out)));
                    }
                    job.append(&format!("{}  →  {}", self.host_label(e.src), self.host_label(e.dst)), 0.0, fmt(self.font_medium(14.5), draw::fade(TEXT, a_out)));
                    let g = painter.layout_job(job);
                    let gw = g.size().x;
                    let gh = g.size().y;
                    painter.circle_filled(Pos2::new(cx - gw / 2.0 - 16.0, yy + gh / 2.0), 3.5, draw::fade(SIGNIFICANT, a_out));
                    painter.galley(Pos2::new(cx - gw / 2.0, yy), g, TEXT);
                    yy += gh + 6.0;
                }
            }
            painter.text(Pos2::new(cx, canvas.bottom() - 26.0), Align2::CENTER_BOTTOM, "reconstructed from the logs with masstin", self.font_medium(11.0), draw::fade(theme::DIM, a_out));
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

    /// The filters as one line, for whoever is about to search inside them.
    fn filter_summary(&self) -> String {
        let f = &self.filter;
        let mut v: Vec<String> = vec![match f.view {
            View::Findings => "the hunt's findings only".to_string(),
            View::All => "everything".to_string(),
            View::Around => format!("the neighbourhood of {} ({} hop(s))", if f.around.is_empty() { "?" } else { &f.around }, f.hops),
        }];
        if f.results.iter().any(|r| !r) {
            v.push(RESULT_NAMES.iter().enumerate().filter(|(i, _)| f.results[*i]).map(|(_, n)| *n).collect::<Vec<_>>().join(" + "));
        }
        for (name, text) in [("host", &f.host), ("account", &f.user), ("logon type", &f.logon_type)] {
            if !text.trim().is_empty() {
                v.push(format!("{} {}", name, text.trim()));
            }
        }
        if !f.from.is_empty() || !f.to.is_empty() {
            v.push(format!("{} → {}", if f.from.is_empty() { "start" } else { &f.from }, if f.to.is_empty() { "end" } else { &f.to }));
        }
        if f.min_score > 0 {
            v.push(format!("score ≥ {}", f.min_score));
        }
        if f.view != View::Findings && f.hunt.iter().any(|h| !h) {
            v.push("some hunt states left out".to_string());
        }
        if f.verdict.iter().any(|x| !x) {
            v.push("some marks left out".to_string());
        }
        v.join("  ·  ")
    }

    /// The search as the form has it: (the query, the rows it may use).
    fn path_query(&self, origin: u32, dest: u32) -> (PathQuery, usize) {
        let (only, from, to, rows) = path_rows(&self.store, &self.filter, self.path_scope_all, &self.path_user, &self.path_from, &self.path_to);
        let q = PathQuery {
            origin,
            dest,
            from,
            to,
            max_hops: self.path_hops.max(1),
            max_gap: (self.path_gap_h.max(0.01) * 3600.0) as i64,
            max_paths: self.path_max.max(1),
            results: self.path_results,
            skip_machine_accounts: self.path_skip_machine,
            by_session: self.path_by_session,
            gap_without_session: self.path_session_gap,
            only,
            launched: false,
            same_account: self.path_same_account,
        };
        (q, rows)
    }

    /// What was searched, in words: "by session, in 1,204 of 39,679 rows (what the filters select)".
    fn path_scope_text(&self, q: &PathQuery, rows: usize) -> String {
        let how = if q.by_session { if q.gap_without_session { "by session (the gap where a logon has no logoff)" } else { "by session" } } else { "by time" };
        let whose = format!("{}{}", if self.path_user.trim().is_empty() { String::new() } else { format!(", account {}", self.path_user.trim()) }, if q.same_account { ", the same account all along" } else { "" });
        format!("{}, in {} of {} rows ({}{})", how, group_digits(rows), group_digits(self.store.edges.len()), if self.path_scope_all { "the whole timeline" } else { "what the filters select" }, whose)
    }

    fn run_paths(&mut self) {
        let (Some(o), Some(d)) = (self.host_named(&self.path_origin), self.host_named(&self.path_dest)) else {
            self.path_msg = "Name an origin and a destination the timeline knows (the arrow next to each box lists them).".into();
            return;
        };
        if o == d {
            self.path_msg = "Origin and destination are the same host.".into();
            return;
        }
        let (q, rows) = self.path_query(o, d);
        let scope = self.path_scope_text(&q, rows);
        let (found, cut) = paths::search(&self.store, &q);
        self.path_found = found;
        let cut = if cut { "\nThe search was cut short: there are so many chains to try that not all were walked, so there may be more paths (or shorter ones). Narrow it with an account, dates, fewer hops or a shorter gap." } else { "" };
        if self.path_found.is_empty() {
            // the path of a search before this one is not this one's answer
            if self.overlay.as_ref().map_or(false, |o| !o.exact) || self.trail.is_some() {
                self.overlay = None;
                self.trail = None;
                self.requery(false);
            }
            // why not, as far as a wider search can tell
            let mut hints: Vec<String> = Vec::new();
            let mut wider = q.clone();
            if q.by_session {
                wider.by_session = false;
                let n = paths::find_paths(&self.store, &wider).len();
                if n > 0 {
                    hints.push(format!("By time alone there {}: nothing ties those hops to the session before them. The host in between has no record of the session making the next hop (a 4648 on Windows, an auditd connect record on Linux), and the session's end is not in the timeline (no logoff with its logon ID) or the next hop left after it. Tick «the gap where a logon has no logoff», or chain by time.", if n == 1 { "is 1 path".to_string() } else { format!("are {} paths", n) }));
                }
            }
            if hints.is_empty() && (q.only.is_some() || q.from.is_some() || q.to.is_some()) {
                wider.only = None;
                wider.from = None;
                wider.to = None;
                let n = paths::find_paths(&self.store, &wider).len();
                if n > 0 {
                    let what = if self.path_scope_all { "the account or the dates set here leave out a login the path needs. Empty them to see it.".to_string() } else { format!("the filters{} leave out a login the path needs. Set «Search in» to the whole timeline, or widen the filters.", if self.path_user.trim().is_empty() { "" } else { " or the account" }) };
                    hints.push(format!("In the whole timeline, any account and any date, there {}: {}", if n == 1 { "is 1".to_string() } else { format!("are {}", n) }, what));
                }
            }
            if hints.is_empty() {
                hints.push(why_no_path(&self.store, &q));
            }
            self.path_msg = format!("No path from {} to {} within {} hops{}. Searched {}.\n{}", self.store.hosts.name(o), self.store.hosts.name(d), q.max_hops, if q.by_session && !q.gap_without_session { String::new() } else { format!(" and {:.1} h per hop", self.path_gap_h) }, scope, hints.join("\n")) + cut;
            return;
        }
        self.path_msg = format!("{} path(s), shortest first{}. Searched {}.{}", self.path_found.len(), if self.path_found.len() >= q.max_paths { " (as many as «Max paths» allows: there may be more)" } else { "" }, scope, cut);
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

    /// Everything from the origin (forward) or into the destination: every
    /// host a chain of logins reaches, as a tree. With no host named, from
    /// (or into) every host a chain of the logins searched can start at
    /// (end at): every chain of an account, or of a period.
    fn run_cone(&mut self, forward: bool) {
        let field = if forward { self.path_origin.trim().to_string() } else { self.path_dest.trim().to_string() };
        let (q, rows) = self.path_query(0, 0);
        let scope = self.path_scope_text(&q, rows);
        self.path_found.clear();
        self.path_tree = None;
        let seeds: Vec<u32> = if field.is_empty() {
            paths::chain_ends(&self.store, &q, forward)
        } else {
            match self.host_named(&field) {
                Some(h) => vec![h],
                None => {
                    self.path_msg = format!("No host of the timeline is called {} (the arrow next to the box lists them). Leave the box empty for every chain of the account or the dates set below, wherever it {}.", field, if forward { "starts" } else { "ends" });
                    return;
                }
            }
        };
        if seeds.is_empty() {
            self.path_msg = format!("No login of the ones searched can {} a chain. Searched {}.", if forward { "start" } else { "end" }, scope);
            return;
        }
        let t0 = if forward { q.from.unwrap_or(self.store.t_min) } else { q.to.unwrap_or(self.store.t_max) };
        let cone = paths::cone_from(&self.store, &seeds, t0, &q, forward);
        let reached = cone.reach.len().saturating_sub(seeds.len());
        let whose = if field.is_empty() {
            format!("{} host(s) where a chain {} (no host named: every one the logins searched allow)", group_digits(seeds.len()), if forward { "starts" } else { "ends" })
        } else {
            self.store.hosts.name(seeds[0]).to_string()
        };
        self.path_msg = format!("{} host(s) {} {} within {} hops. Searched {}.", group_digits(reached), if forward { "reachable from" } else { "that could reach" }, whose, q.max_hops, scope);
        if reached == 0 {
            if self.overlay.as_ref().map_or(false, |o| !o.exact) || self.trail.is_some() {
                self.overlay = None;
                self.trail = None;
                self.requery(false);
            }
            return;
        }
        // the tree: each host under the one its first arrival came from
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut roots: Vec<u32> = Vec::new();
        for (host, r) in &cone.reach {
            match r.via {
                Some(ei) => {
                    let e = &self.store.edges[ei as usize];
                    children.entry(if forward { e.src } else { e.dst }).or_default().push(*host);
                }
                None => roots.push(*host),
            }
        }
        // (a seed that reaches nothing is no branch)
        roots.retain(|h| children.contains_key(h));
        roots.sort_by_key(|h| self.store.hosts.name(*h).to_string());
        for v in children.values_mut() {
            v.sort_by_key(|h| (cone.reach[h].t, self.store.hosts.name(*h).to_string()));
            if !forward {
                v.reverse();
            }
        }
        let mut rows: Vec<(u32, usize)> = Vec::new();
        let mut stack: Vec<(u32, usize)> = roots.iter().rev().map(|h| (*h, 0)).collect();
        let mut listed: HashSet<u32> = HashSet::new();
        while let Some((h, depth)) = stack.pop() {
            if !listed.insert(h) {
                continue;
            }
            rows.push((h, depth));
            if let Some(kids) = children.get(&h) {
                for k in kids.iter().rev() {
                    stack.push((*k, depth + 1));
                }
            }
        }
        let title = if field.is_empty() { format!("every chain {} {} host(s)", if forward { "from" } else { "into" }, seeds.len()) } else { format!("{} {}", if forward { "reach of" } else { "ways into" }, self.store.hosts.name(seeds[0])) };
        self.path_tree = Some(PathTree { cone, rows, title });
        self.show_tree();
    }

    /// The whole tree on the canvas.
    fn show_tree(&mut self) {
        let Some(tree) = &self.path_tree else { return };
        let forward = tree.cone.forward;
        let mut edges: Vec<u32> = tree.cone.reach.values().filter_map(|r| r.via).collect();
        edges.extend(tree.cone.support.iter().copied());
        let labels: HashMap<u32, String> = tree.cone.reach.iter().map(|(host, r)| (*host, if r.hop == 0 { (if forward { "origin" } else { "destination" }).to_string() } else { format!("hop {} · {}", r.hop, &fmt_time(r.t)[5..16]) })).collect();
        let hops: HashMap<u32, usize> = tree.cone.reach.iter().map(|(host, r)| (*host, r.hop)).collect();
        let title = tree.title.clone();
        self.set_overlay(title, edges, labels, hops);
    }

    /// One branch of the tree on the canvas: the chain between its seed
    /// and a host.
    fn show_tree_chain(&mut self, host: u32) {
        let Some(tree) = &self.path_tree else { return };
        let chain = tree.cone.chain(host);
        if chain.is_empty() {
            return;
        }
        let forward = tree.cone.forward;
        let n = chain.len();
        let mut labels: HashMap<u32, String> = HashMap::new();
        let mut hops: HashMap<u32, usize> = HashMap::new();
        let first = &self.store.edges[chain[0] as usize];
        labels.insert(first.src, if forward { "origin".to_string() } else { format!("hop {} back", n) });
        hops.insert(first.src, 0);
        for (k, &ei) in chain.iter().enumerate() {
            let e = &self.store.edges[ei as usize];
            labels.insert(e.dst, if !forward && k + 1 == n { "destination".to_string() } else if forward { format!("hop {} · {}", k + 1, &fmt_time(e.t)[11..16]) } else { format!("hop {} back · {}", n - k - 1, &fmt_time(e.t)[11..16]) });
            hops.insert(e.dst, k + 1);
        }
        let title = format!("chain {} {}", if forward { "to" } else { "from" }, self.store.hosts.name(host));
        self.set_overlay(title, chain, labels, hops);
    }

    fn set_overlay(&mut self, title: String, edges: Vec<u32>, labels: HashMap<u32, String>, hops: HashMap<u32, usize>) {
        if self.path_in_map {
            // marked on the map as it is: nothing moves, the path stands out
            self.overlay = None;
            self.trail = Some(Trail { title, edges: edges.into_iter().collect(), labels, missing: 0 });
            self.requery(false);
            return;
        }
        self.trail = None;
        self.overlay = Some(Overlay { title, edges, labels, hops, exact: false });
        self.requery(true);
        self.arrange_by_hops();
    }

    /// The path shown again the other way (alone, or marked on the map).
    fn reshow_path(&mut self) {
        let (title, edges, labels) = match (&self.overlay, &self.trail) {
            (Some(o), _) if !o.exact => (o.title.clone(), o.edges.clone(), o.labels.clone()),
            (_, Some(t)) => (t.title.clone(), t.edges.iter().copied().collect(), t.labels.clone()),
            _ => return,
        };
        let mut hops: HashMap<u32, usize> = HashMap::new();
        for (h, l) in &labels {
            let k = l.strip_prefix("hop ").and_then(|r| r.split(' ').next()).and_then(|n| n.parse().ok()).unwrap_or(0);
            hops.insert(*h, k);
        }
        if let Some(o) = &self.overlay {
            hops = o.hops.clone();
        }
        self.overlay = None;
        self.trail = None;
        self.set_overlay(title, edges, labels, hops);
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

    /// Hosts and accounts by name, for the lists under the boxes.
    fn path_name_lists(&mut self) -> (std::rc::Rc<Vec<String>>, std::rc::Rc<Vec<String>>) {
        let key = self.store.hosts.len().wrapping_mul(31).wrapping_add(self.store.users.len()).wrapping_mul(31).wrapping_add(self.store.edges.len());
        if self.path_names.0 != key {
            let by_name = |v: &[String]| -> Vec<String> {
                let mut v: Vec<String> = v.iter().filter(|n| !n.trim().is_empty()).cloned().collect();
                // names before addresses, each in the order of the alphabet
                v.sort_by_cached_key(|n| (n.parse::<std::net::IpAddr>().is_ok(), n.to_lowercase()));
                v
            };
            self.path_names = (key, std::rc::Rc::new(by_name(&self.store.hosts.names)), std::rc::Rc::new(by_name(&self.store.users.names)));
        }
        (self.path_names.1.clone(), self.path_names.2.clone())
    }

    fn paths_window(&mut self, ctx: &egui::Context) {
        if !self.show_paths {
            self.path_suggest = None;
            return;
        }
        let mut open = true;
        let mut find = false;
        let mut cone: Option<bool> = None;
        let mut pick: Option<usize> = None;
        let mut reshow = false;
        // the tree: a branch picked, every path to a host asked for, the whole of it again
        let mut branch: Option<u32> = None;
        let mut all_paths: Option<u32> = None;
        let mut whole_tree = false;
        let (hosts, accounts) = self.path_name_lists();
        let screen_h = ctx.content_rect().height();
        // sized by what it holds (a fixed width, as tall as its contents, and
        // scrolling when the screen is shorter), so nothing is ever cut
        egui::Window::new(format!("{}  Paths", super::icons::PATH)).id(egui::Id::new("paths-window-2")).open(&mut open).resizable(false).collapsible(true).show(ctx, |ui| {
            ui.set_width(660.0);
            // (a window that is not resized by hand offers its last size as the room there is: say how tall it may get)
            ui.set_max_height((screen_h - 150.0).max(240.0));
            egui::ScrollArea::vertical().max_height((screen_h - 150.0).max(240.0)).auto_shrink([false, true]).show(ui, |ui| {
                ui.add(egui::Label::new(egui::RichText::new("A path is a chain of logins from one host to another, each hop after the one before: how someone could have moved. Ask for the paths between two hosts, or for everything that leaves a host (or arrives at it) as a tree, or for every chain of an account or a period wherever it starts. Hover any ? for what a setting does.").color(MUTED)).wrap());

                theme::section_help(ui, "From where to where", "The host the chain starts at and the one it ends at. Type part of a name or an address and pick from the list that opens, or use the arrow to see every host of the timeline. «Paths from here» and «Paths to here» in a host's right-click menu fill these boxes.\n\nFor «Everything from the origin» only the origin is used, and for «Everything into the destination» only the destination. Leave that box EMPTY and the tree starts at every host a chain can start at (or end at): with an account below, every chain that account made; with dates, every chain of that period.");
                ui.horizontal(|ui| {
                    ui.label("Origin");
                    find |= suggest_box(ui, 0, &mut self.path_suggest, &mut self.path_origin, 200.0, "host or address", &hosts);
                    if ui.button(super::icons::ARROWS_CLOCKWISE).on_hover_text("Swap origin and destination").clicked() {
                        std::mem::swap(&mut self.path_origin, &mut self.path_dest);
                    }
                    ui.label("Destination");
                    find |= suggest_box(ui, 1, &mut self.path_suggest, &mut self.path_dest, 200.0, "host or address", &hosts);
                });
                ui.horizontal(|ui| {
                    let mut shown = !self.path_compact;
                    if ui.toggle_value(&mut shown, format!("{}  settings", super::icons::FUNNEL)).on_hover_text("Show or fold away the settings of the search (how hops are chained, which logins count, how it is shown), to leave room for what was found. Folded, they still apply, and the line next to this says them").changed() {
                        self.path_compact = !shown;
                    }
                    if self.path_compact {
                        let mut said: Vec<String> = vec![if self.path_by_session { "by session".to_string() } else { format!("by time, {:.1} h per hop", self.path_gap_h) }, format!("up to {} hops", self.path_hops), if self.path_scope_all { "the whole timeline".to_string() } else { "inside the filters".to_string() }];
                        if !self.path_user.trim().is_empty() {
                            said.push(format!("account {}", self.path_user.trim()));
                        }
                        if self.path_same_account {
                            said.push("the same account all along".to_string());
                        }
                        if !self.path_from.trim().is_empty() || !self.path_to.trim().is_empty() {
                            said.push(format!("{} → {}", if self.path_from.trim().is_empty() { "start" } else { self.path_from.trim() }, if self.path_to.trim().is_empty() { "end" } else { self.path_to.trim() }));
                        }
                        ui.add(egui::Label::new(egui::RichText::new(said.join("  ·  ")).small().color(MUTED)).truncate());
                    }
                });
                if !self.path_compact {

                theme::section_help(ui, "How one hop leads to the next", "By time: the next hop leaves the host after the one that entered it, and no later than the gap. It is what «could have happened», and it finds the most.\n\nBy session (logon ID): the next hop is tied to the session the hop before opened on that host, by that session's logon ID. Two kinds of evidence do it, and either is enough:\n\n• The host's own record that the session MADE the hop: on Windows a 4648 (a process of the session used credentials for another machine), on Linux an auditd connect record (it needs an audit rule on connect). Each carries the session's ID. It is the strongest: such a hop is drawn =(account time)-> in the list of paths.\n\n• The hop leaves while the session is still open, between its logon and its end, which the timeline pairs by their logon ID (on Linux, the process id of the sshd of the connection). It needs the end of the session in the timeline: where it is not, the logon cannot be followed this way (or is followed for the gap, if you tick that).");
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.path_by_session, false, format!("{}  by time", super::icons::CLOCK)).on_hover_text("Coherent in time: each hop after the one before and within the gap. Finds every chain that could have happened");
                    ui.selectable_value(&mut self.path_by_session, true, format!("{}  by session (logon ID)", super::icons::KEY)).on_hover_text("Each hop is tied to the session the hop before opened, by its logon ID: the host has its own record of that session making the hop (4648, auditd connect), or the hop leaves while the session is still open (its logon and its end share the logon ID)");
                });
                ui.add(egui::Label::new(egui::RichText::new(format!("{} of {} logons have their session  ·  {} record(s) of what a session made", group_digits(self.store.sessions_known), group_digits(self.store.logons), group_digits(self.store.launches))).small().color(if self.path_by_session && self.store.sessions_known == 0 && self.store.launches == 0 { CANDIDATE } else { MUTED })).wrap()).on_hover_text("What a search by session has to work with in this timeline. Successful logons whose end is in it too (same host, same logon ID): a hop can be told to have left while they were open. And the rows written from the origin of a connection with the logon ID of the session that made it (4648, auditd connect): a hop can be told to have been made by a session");
                if self.path_by_session {
                    ui.checkbox(&mut self.path_session_gap, "the gap where a logon has no logoff").on_hover_text("A logon whose logoff is not in the timeline is followed for the gap below instead of not at all: sessions where the timeline has them, time where it does not");
                }
                ui.horizontal(|ui| {
                    theme::label_help(ui, "Max gap per hop (h)", "The longest a hop may wait after the one before it, in hours. By session it only counts for logons with no logoff, when that box is ticked: a session lasts what it lasts.");
                    ui.add_enabled(!self.path_by_session || self.path_session_gap, egui::DragValue::new(&mut self.path_gap_h).range(0.05..=24.0 * 90.0).speed(0.5).fixed_decimals(1));
                    ui.add_space(10.0);
                    theme::label_help(ui, "Max hops", "The longest chain looked for: 3 is origin → A → B → destination.");
                    ui.add(egui::DragValue::new(&mut self.path_hops).range(1..=12));
                    ui.add_space(10.0);
                    theme::label_help(ui, "Max paths", "How many paths are listed, shortest first.");
                    ui.add(egui::DragValue::new(&mut self.path_max).range(1..=2000).speed(1));
                });

                theme::section_help(ui, "Which logins can be a hop", "The search does not look at every row unless you ask. By default it runs inside what the filters on the left select (the same rows the canvas draws from): with «Findings» on, only the hunt's findings can be hops, and a path through an ordinary login is not found. Choose the whole timeline to ignore the filters. On top of either, the account and the dates here narrow it further.");
                ui.horizontal(|ui| {
                    ui.label("Search in");
                    ui.selectable_value(&mut self.path_scope_all, false, format!("{}  what the filters select", super::icons::FUNNEL)).on_hover_text("Only the rows the filters on the left let through can be hops: the view, the results, hosts, accounts, time window, hunt states and marks");
                    ui.selectable_value(&mut self.path_scope_all, true, "the whole timeline").on_hover_text("Every row of the timeline can be a hop, whatever the filters say (the bar's time window included)");
                });
                if !self.path_scope_all {
                    ui.add(egui::Label::new(egui::RichText::new(format!("The filters now: {}", self.filter_summary())).small().color(MUTED)).wrap());
                }
                ui.horizontal(|ui| {
                    theme::label_help(ui, "Account", "Only logins of this account are hops: the chain one account made. Part of a name is enough; * is a wildcard, ! in front leaves an account out, a comma separates several. Empty: any account.");
                    find |= suggest_box(ui, 2, &mut self.path_suggest, &mut self.path_user, 170.0, "any account", &accounts);
                    ui.add_space(6.0);
                    theme::label_help(ui, "From", "The first hop is at or after this moment and the last one at or before «To», in the timeline's time (UTC): 2026-11-03 or 2026-11-03 14:30. Empty: the time window of the filters, or the whole timeline when the search ignores them.");
                    let bar = |t: &str, none: &str| if self.path_scope_all || t.is_empty() { none.to_string() } else { t.to_string() };
                    let (hint_from, hint_to) = (bar(&self.filter.from, "the start"), bar(&self.filter.to, "the end"));
                    for (k, (text, hint)) in [(&mut self.path_from, hint_from), (&mut self.path_to, hint_to)].into_iter().enumerate() {
                        let bad = !text.trim().is_empty() && parse_time(text).is_none();
                        let r = ui.add(egui::TextEdit::singleline(text).desired_width(128.0).hint_text(hint).text_color_opt(bad.then_some(SIGNIFICANT)));
                        if bad {
                            r.on_hover_text("Not a date: write it as 2026-11-03 or 2026-11-03 14:30");
                        }
                        if k == 0 {
                            ui.label("To");
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.path_same_account, "the same account all along").on_hover_text("Every hop of a chain is by the same account, whichever it is: the chains one account made, for every account at once. The domain or the machine after the name does not count (ana@CORP and ana@WS01 are one). With an account written above, this adds nothing");
                    theme::help(ui, "Without it a chain may change accounts from hop to hop, as an intruder does when new credentials are found on the way: A enters B as ana, then B enters C as admin. With it, a chain is one account moving: fewer chains, and each of them the trace of one identity. Use it to follow what a single account did without naming it.");
                });
                ui.horizontal_wrapped(|ui| {
                    theme::label_help(ui, "Hops are", "Which events count as a hop. A logon that succeeded is a movement; a failed one or a connection is an attempt, worth adding when looking for what someone tried. Machine accounts (NAME$) log on to each other all day and are left out unless asked.");
                    for (i, name) in RESULT_NAMES.iter().enumerate() {
                        if ui.add(egui::Button::selectable(self.path_results[i], *name)).clicked() {
                            self.path_results[i] = !self.path_results[i];
                        }
                    }
                    ui.checkbox(&mut self.path_skip_machine, "no machine accounts");
                });

                theme::section_help(ui, "Show it", "Two ways to look at the same path. Alone: the canvas is reduced to the path's hosts, laid out hop by hop. Marked on the map: nothing is taken away or moved, the path's connections are drawn thick and bright over the rest, which is dimmed. Change it at any time: the path found is shown again the other way.");
                ui.horizontal(|ui| {
                    let was = self.path_in_map;
                    ui.selectable_value(&mut self.path_in_map, false, format!("{}  alone", super::icons::PATH)).on_hover_text("Only the hosts and connections of the path are drawn, in columns by hop, so it reads left to right. Everything else leaves the canvas until you go back to the view");
                    ui.selectable_value(&mut self.path_in_map, true, format!("{}  marked on the map", super::icons::CROSSHAIR)).on_hover_text("The map stays as it is, with every host where it was, and the path stands out on it: thicker, in the logo's colours, with the rest dimmed. For seeing where the path runs among everything else");
                    if was != self.path_in_map {
                        reshow = true;
                    }
                });
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(egui::RichText::new("Find paths").strong().color(Color32::from_rgb(30, 24, 8))).fill(ACCENT)).on_hover_text("Every chain of logins from the origin to the destination, as set above. Enter in a box does the same").clicked() {
                        find = true;
                    }
                    if ui.button(format!("{}  Everything from the origin", super::icons::GRAPH)).on_hover_text("The tree of every host a chain of logins reaches from the origin, branch by branch, with the account and the moment of each arrival (the destination is not used). With the origin box empty: from every host a chain can start at, for the account and the dates set above").clicked() {
                        cone = Some(true);
                    }
                    if ui.button(format!("{}  Everything into the destination", super::icons::GRAPH)).on_hover_text("The tree of every host from which a chain of logins reaches the destination, walking back in time (the origin is not used). With the destination box empty: into every host a chain can end at").clicked() {
                        cone = Some(false);
                    }
                    if (self.overlay.is_some() || self.trail.is_some()) && ui.button("Back to the view").on_hover_text("Leave the path or the cone and draw again what the filters select").clicked() {
                        self.overlay = None;
                        self.trail = None;
                        self.path_found.clear();
                        self.path_tree = None;
                        self.path_msg.clear();
                        self.requery(false);
                    }
                });
                if !self.path_msg.is_empty() {
                    ui.add_space(2.0);
                    ui.add(egui::Label::new(egui::RichText::new(&self.path_msg).color(if self.path_msg.starts_with("No ") || self.path_msg.starts_with("Name ") || self.path_msg.starts_with("Origin and") { CANDIDATE } else { TEXT })).wrap());
                }
                if !self.path_found.is_empty() {
                    ui.separator();
                    egui::ScrollArea::vertical().id_salt("paths-found").max_height((screen_h * 0.3).clamp(110.0, 320.0)).auto_shrink([false, true]).show(ui, |ui| {
                        for (i, p) in self.path_found.iter().enumerate() {
                            let mut text = String::new();
                            if let Some(&first) = p.edges.first() {
                                text.push_str(self.store.hosts.name(self.store.edges[first as usize].src));
                            }
                            let mut made = 0usize;
                            for (k, &ei) in p.edges.iter().enumerate() {
                                let e = &self.store.edges[ei as usize];
                                let u = self.store.users.name(e.user);
                                // made by the session the hop before opened, by the record of the host in between
                                let by_session = k > 0 && self.store.launched_by(p.edges[k - 1], ei);
                                made += by_session as usize;
                                text.push_str(&format!("  {}({}{})->  {}", if by_session { "=" } else { "-" }, if u.is_empty() { "?" } else { u }, &fmt_time(e.t)[10..16].replace(' ', " "), self.store.hosts.name(e.dst)));
                            }
                            if made > 0 {
                                text.push_str(&format!("   [= {} hop(s) the session before is recorded to have made]", made));
                            }
                            let span = p.span(&self.store);
                            let label = format!("{}.  {} hop(s) · {}  ·  {}", i + 1, p.hops(), if span >= 3600 { format!("{:.1} h", span as f32 / 3600.0) } else { format!("{} min", span / 60) }, text);
                            if ui.add(egui::Button::new(egui::RichText::new(label).small()).frame(false).wrap()).on_hover_text("Show this path alone (or marked on the map)").clicked() {
                                pick = Some(i);
                            }
                        }
                    });
                }
                if let Some(tree) = &self.path_tree {
                    let forward = tree.cone.forward;
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label(theme::semibold(&tree.title, 12.5).color(TEXT));
                        theme::help(ui, "Every host the chains reach, each under the host its first arrival came from, with the account and the moment of that arrival. Click a host for its branch alone: the chain of logins between the start and it. The magnifier asks for every path between the two, not only the first. A host is listed once, where it was first reached; other ways into it are what the magnifier finds.");
                        if ui.small_button("the whole tree").on_hover_text("Draw the whole tree again, after looking at one branch").clicked() {
                            whole_tree = true;
                        }
                        if tree.rows.len() > 3000 {
                            ui.label(egui::RichText::new(format!("the first 3,000 of {} hosts", group_digits(tree.rows.len()))).small().color(MUTED));
                        }
                    });
                    egui::ScrollArea::vertical().id_salt("paths-tree").max_height(if self.path_compact { (screen_h * 0.62).clamp(160.0, 900.0) } else { (screen_h * 0.34).clamp(120.0, 380.0) }).auto_shrink([false, true]).show(ui, |ui| {
                        for &(host, depth) in tree.rows.iter().take(3000) {
                            let r = tree.cone.reach[&host];
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                ui.add_space(depth as f32 * 16.0);
                                let name = self.store.hosts.name(host);
                                match r.via {
                                    None => {
                                        ui.label(theme::semibold(name, 12.0).color(ACCENT));
                                        ui.label(egui::RichText::new(if forward { "start" } else { "end" }).small().color(MUTED));
                                    }
                                    Some(ei) => {
                                        let e = &self.store.edges[ei as usize];
                                        let u = self.store.users.name(e.user);
                                        let label = format!("{} {}", if forward { "→" } else { "←" }, name);
                                        if ui.add(egui::Button::new(egui::RichText::new(label).size(12.0)).frame(false)).on_hover_text("Show this branch alone: the chain of logins between the start and this host").clicked() {
                                            branch = Some(host);
                                        }
                                        ui.label(egui::RichText::new(format!("{} · {} · hop {}", if u.is_empty() { "?" } else { u }, &fmt_time(e.t)[5..16], r.hop)).small().color(MUTED));
                                        if ui.add(egui::Button::new(egui::RichText::new(super::icons::MAGNIFYING_GLASS).size(11.0)).frame(false)).on_hover_text("Every path between the start of this branch and this host, not only the first one").clicked() {
                                            all_paths = Some(host);
                                        }
                                    }
                                }
                            });
                        }
                    });
                }
                ui.add_space(4.0);
            });
        });
        if let Some(h) = branch {
            self.show_tree_chain(h);
        }
        if whole_tree {
            self.show_tree();
        }
        if let Some(h) = all_paths {
            // between the seed of its branch and the host
            let ends = self.path_tree.as_ref().map(|t| (t.cone.forward, t.cone.chain(h)));
            if let Some((forward, chain)) = ends.filter(|(_, c)| !c.is_empty()) {
                let (a, b) = (self.store.edges[chain[0] as usize].src, self.store.edges[*chain.last().unwrap() as usize].dst);
                let _ = forward;
                self.path_origin = self.store.hosts.name(a).to_string();
                self.path_dest = self.store.hosts.name(b).to_string();
                find = true;
            }
        }
        if find {
            self.run_paths();
        } else if reshow {
            self.reshow_path();
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

    /// Set the pace so the animation lasts about `target` seconds: rows
    /// close in time are grouped until the steps are few enough to be seen
    /// (a quarter of a second each at least), then every step takes the same
    /// time. Nothing leaves the picture.
    fn fit_story(&mut self, target: f32) {
        self.story.timing = Timing::Fixed;
        self.story.stretches.clear();
        self.story.hold_end = if target <= 30.0 { 2.0 } else { 3.0 };
        self.story.pause_significant = if target <= 60.0 { 0.4 } else { 1.0 };
        let most = ((target - self.story.hold_end) / 0.25).max(1.0) as usize;
        for group in [0.0f32, 2.0, 10.0, 60.0, 300.0, 1800.0, 7200.0, 43200.0, 172800.0, 604800.0] {
            self.story.group_secs = group;
            self.rebuild_steps();
            if self.steps.len() <= most {
                break;
            }
        }
        let n = self.steps.len().max(1) as f32;
        let findings = self.steps.iter().filter(|s| s.significant).count() as f32;
        let room = (target - self.story.hold_end - findings * self.story.pause_significant).max(target * 0.4);
        self.story.step_secs = (room / n).clamp(0.02, 20.0);
        self.rebuild_steps();
        self.status = format!("Animation fitted to about {}: {} steps, {:.2} s each, rows within {:.0} s together", story_length(present::total_secs(&self.steps, &self.story)), self.steps.len(), self.story.step_secs, self.story.group_secs);
    }

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
        let mut fit: Option<f32> = None;
        egui::Window::new(format!("{}  Animation · the story of this view", super::icons::FILM_STRIP)).id(egui::Id::new("story-window")).open(&mut open).default_width(820.0).default_height(560.0).resizable(true).show(ctx, |ui| {
            let total = present::total_secs(&self.steps, &self.story);
            let (n_now, n_rows) = (self.steps.len(), self.graph.events.len());
            // what an animation is and how long this one is, before any knob
            egui::Frame::new().fill(theme::FIELD).stroke(Stroke::new(1.0, theme::BORDER_2)).corner_radius(egui::CornerRadius::same(8)).inner_margin(egui::Margin::symmetric(10, 8)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(theme::semibold(format!("{}  How an animation is made", super::icons::FILM_STRIP), 13.0).color(theme::CYAN));
                ui.add(egui::Label::new(egui::RichText::new("1 · The graph on the canvas is what is animated, connection by connection in time order: narrow it first with the filters (a time window, the findings, one host's neighbourhood).\n2 · Here you set its pace and what is written on the picture.\n3 · Present plays it full screen (Esc ends it). Record… writes it as a GIF or a video.\nEverything is saved with the timeline as you change it.").color(TEXT).size(12.5)).wrap());
                ui.add_space(2.0);
                ui.horizontal_wrapped(|ui| {
                    let (verdict, colour) = if n_now == 0 {
                        ("nothing to animate: the view is empty", CANDIDATE)
                    } else if total > 300.0 {
                        ("long for a video: fit it to a length here, or narrow the view", CANDIDATE)
                    } else if total < 8.0 {
                        ("very short: slow it down, or widen the view", CANDIDATE)
                    } else {
                        ("a good length", theme::CYAN)
                    };
                    ui.label(egui::RichText::new(format!("Now: {} steps from {} rows, {}", n_now, n_rows, story_length(total))).color(TEXT));
                    ui.label(egui::RichText::new(verdict).color(colour));
                });
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Fit it to").color(MUTED));
                    for (label, secs) in [("30 s", 30.0f32), ("1 min", 60.0), ("2 min", 120.0), ("5 min", 300.0)] {
                        if ui.add_enabled(n_now > 0, egui::Button::new(label)).on_hover_text(format!("Set the pace so the whole animation lasts about {}: rows close in time are shown together and every step takes the same time. The knobs below show what it set, and can be changed after", label)).clicked() {
                            fit = Some(secs);
                        }
                    }
                    theme::help(ui, "The quick way: say how long the animation should be and masstin sets the pace for you. It groups rows that are close in time into one step until there are few enough, then gives every step the same time. Nothing is removed from the picture: only how fast it is drawn. For a talk, 1 to 2 minutes is usually right; for a GIF in a report, 30 seconds.");
                });
            });
            ui.add_space(4.0);
            theme::section(ui, "Pace");
            egui::Grid::new("story-pace").num_columns(4).spacing([10.0, 6.0]).show(ui, |ui| {
                theme::label_help(ui, "Timing", "How long each step stays. «same time per step»: every step lasts the same, whatever the real time between them: the simplest, and right for most videos. «real gaps, compressed»: a step waits in proportion to the real time that passed before it, so a burst plays fast and a quiet night is felt as a pause: right when the rhythm of the attack is the point.");
                ui.horizontal(|ui| {
                    changed |= ui.selectable_value(&mut self.story.timing, Timing::Fixed, "same time per step").on_hover_text("Every step lasts «Seconds per step»").changed();
                    changed |= ui.selectable_value(&mut self.story.timing, Timing::Compressed, "real gaps, compressed").on_hover_text("A step waits the real time before it, divided by «Compress by», kept between the two gaps").changed();
                });
                theme::label_help(ui, "Group rows within", "Rows of the timeline this close in time (in seconds) are drawn together as one step. 0: one step per row, which is slow when there are thousands. Raise it to shorten the animation without losing anything from the picture: a logon and its ten repeats in the same minute become one step.");
                changed |= ui.add(egui::DragValue::new(&mut self.story.group_secs).range(0.0..=604800.0).speed(0.5).fixed_decimals(1).suffix(" s")).on_hover_text("rows this close in time appear together as one step").changed();
                ui.end_row();
                if self.story.timing == Timing::Fixed {
                    theme::label_help(ui, "Seconds per step", "How long each step takes to draw and stay before the next. 0.8 reads well when someone is explaining; 0.2 to 0.4 for an overview. The length above is the number of steps times this, plus the pauses.");
                    changed |= ui.add(egui::DragValue::new(&mut self.story.step_secs).range(0.02..=20.0).speed(0.05).fixed_decimals(2).suffix(" s")).changed();
                } else {
                    theme::label_help(ui, "Compress by", "Real seconds between two steps are divided by this to get the wait on screen. 600 means ten minutes of the incident pass in one second. The wait is never shorter than the first gap nor longer than the second, so a week of silence does not freeze the picture.");
                    ui.horizontal(|ui| {
                        changed |= ui.add(egui::DragValue::new(&mut self.story.compress).range(1.0..=100000.0).speed(10.0)).on_hover_text("real seconds between rows divided by this").changed();
                        ui.label(egui::RichText::new("wait between").color(MUTED));
                        changed |= ui.add(egui::DragValue::new(&mut self.story.min_gap).range(0.05..=10.0).speed(0.05).fixed_decimals(2).suffix(" s")).on_hover_text("the shortest a step waits").changed();
                        ui.label(egui::RichText::new("and").color(MUTED));
                        changed |= ui.add(egui::DragValue::new(&mut self.story.max_gap).range(0.1..=60.0).speed(0.1).fixed_decimals(1).suffix(" s")).on_hover_text("the longest a step waits").changed();
                    });
                }
                theme::label_help(ui, "Pause on a finding", "Extra seconds the picture holds after a step the hunt marked significant, so the eye has time to land on it. 0: no pause.");
                changed |= ui.add(egui::DragValue::new(&mut self.story.pause_significant).range(0.0..=30.0).speed(0.1).fixed_decimals(1).suffix(" s")).changed();
                ui.end_row();
                theme::label_help(ui, "Hold the end", "Seconds the finished picture stays before the animation ends (and before a GIF loops): time to read the whole graph.");
                changed |= ui.add(egui::DragValue::new(&mut self.story.hold_end).range(0.0..=60.0).speed(0.1).fixed_decimals(1).suffix(" s")).changed();
                ui.end_row();
            });
            ui.add_space(4.0);
            theme::section(ui, "On the picture");
            egui::Grid::new("story-screen").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                theme::label_help(ui, "Title", "A line at the top of the picture for the whole animation: the case, the client, the date. Empty: none.");
                changed |= ui.add_sized([360.0, 20.0], egui::TextEdit::singleline(&mut self.story.title).hint_text("shown at the top, for instance: Incident 2026-11 · lateral movement")).changed();
                ui.end_row();
                theme::label_help(ui, "Show", "What is written over the graph while it plays. Hover each one for what it is.");
                ui.horizontal_wrapped(|ui| {
                    changed |= ui.checkbox(&mut self.story.show_clock, "clock").on_hover_text("The date and time of the step being drawn, in a corner: when it happened").changed();
                    changed |= ui.checkbox(&mut self.story.show_caption, "caption").on_hover_text("A line at the bottom saying what the step is: origin, destination and account. A step's own caption (in the list below) replaces it").changed();
                    changed |= ui.checkbox(&mut self.story.show_counter, "counter").on_hover_text("«12 / 80»: which step this is, of how many").changed();
                    changed |= ui.checkbox(&mut self.story.fade_old, "fade older").on_hover_text("Connections drawn several steps ago dim, so the newest stand out and the picture does not fill up").changed();
                    changed |= ui.checkbox(&mut self.story.anonymise, "anonymise").on_hover_text("Real names never appear: HOST-01, user-02, 10.x.x.3 stand in for them, the same stand-in every time. For a talk or anything that leaves the case").changed();
                    changed |= ui.checkbox(&mut self.story.cinematic, "cinematic").on_hover_text("The look for a client: the hop under way lit, a clock at the story's pace, a lower third, the incident's bar, a title card and a summary. Its pieces and the colour are in Record…").changed();
                });
                ui.end_row();
                theme::label_help(ui, "Logo", "Your company's logo on the presentation and the recording: PNG (with transparency), JPEG, WebP, BMP or GIF. Where it goes, how wide it is (a share of the window's width) and how opaque (1 as it is, lower for a watermark). The path is saved with the story.");
                ui.horizontal(|ui| {
                    changed |= ui.add_sized([188.0, 20.0], egui::TextEdit::singleline(&mut self.story.logo).hint_text("none: pick an image file…")).changed();
                    if ui.button("Choose…").on_hover_text("Pick the image file").clicked() {
                        if let Some(p) = rfd::FileDialog::new().set_title("Logo for the recording").add_filter("Images", &["png", "jpg", "jpeg", "webp", "bmp", "gif"]).pick_file() {
                            self.story.logo = p.to_string_lossy().to_string();
                            changed = true;
                        }
                    }
                    if !self.story.logo.is_empty() && ui.add(egui::Button::new(egui::RichText::new(super::icons::X).color(theme::DIM)).frame(false)).on_hover_text("No logo").clicked() {
                        self.story.logo.clear();
                        changed = true;
                    }
                    egui::ComboBox::from_id_salt("logo-pos").selected_text(self.story.logo_pos.label()).show_ui(ui, |ui| {
                        for p in LogoPos::ALL {
                            changed |= ui.selectable_value(&mut self.story.logo_pos, p, p.label()).changed();
                        }
                    }).response.on_hover_text("The corner it sits in");
                    let mut pct = self.story.logo_width * 100.0;
                    if ui.add(egui::DragValue::new(&mut pct).range(3.0..=60.0).speed(0.5).fixed_decimals(0).suffix(" % wide")).on_hover_text("of the window's width; the height follows the image").changed() {
                        self.story.logo_width = pct / 100.0;
                        changed = true;
                    }
                    changed |= ui.add(egui::DragValue::new(&mut self.story.logo_opacity).range(0.05..=1.0).speed(0.02).fixed_decimals(2).prefix("opacity ")).on_hover_text("1: as it is; lower for a watermark").changed();
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
            ui.horizontal(|ui| {
                theme::section(ui, "Stretches");
                theme::help(ui, "Optional. A stretch is a part of the timeline (from a time to a time) played at a speed of its own: slow down the hour the attacker moved, race through the quiet days around it. A step takes the timing of the first stretch it falls in; steps outside every stretch take the pace above. «Add a stretch» starts one over the time window the filters select.");
            });
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
                if ui.add(egui::Button::new(egui::RichText::new(format!("{}  Present", super::icons::PRESENTATION)).strong().color(Color32::from_rgb(30, 24, 8))).fill(ACCENT)).on_hover_text("Play the animation now, full screen, as it is set here. Esc ends it; the space bar pauses; the arrows go a step back or forward").clicked() {
                    start = true;
                }
                if ui.button(format!("{}  Record…", super::icons::VIDEO_CAMERA)).on_hover_text("Write the animation to a file: a GIF, an MP4 (needs ffmpeg) or PNG frames. Opens the choices of format, size and quality").clicked() {
                    self.show_export = true;
                }
                ui.label(egui::RichText::new(format!("{} steps · {} rows · {:.0} s", self.steps.len(), self.graph.events.len(), total)).color(MUTED));
                ui.label(egui::RichText::new(self.case.as_ref().unwrap_or(&self.story_path).to_string_lossy()).small().color(MUTED));
            });
            ui.separator();
            ui.horizontal(|ui| {
                theme::section(ui, "Steps");
                theme::help(ui, "Every step of the animation, in order. Click its number to see the graph as it is at that moment. Each step can have its own time (s: 0 means the pace above), a pause after it, a caption of your own instead of the automatic one, be skipped (it is drawn with the next, without a stop) or be emphasised (drawn brighter and thicker). A step in red is one the hunt marked significant.");
                ui.label(egui::RichText::new("click a number to see the graph at that moment").small().color(MUTED));
            });
            let n_steps = self.steps.len();
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                egui::Grid::new("steps").striped(true).num_columns(9).spacing([8.0, 4.0]).show(ui, |ui| {
                    for (h, tip) in [("#", "The step. Click it to see the graph at that moment"), ("time", "When its first row happened"), ("what", "Origin, destination and account of its first row; (+N) more rows drawn with it"), ("s", "Its own duration in seconds. 0: the pace set above"), ("pause", "Extra seconds the picture holds after it"), ("caption", "Your own line for this step, instead of the automatic one"), ("skip", "Do not stop on it: it is drawn together with the next step"), ("emph", "Emphasise it: brighter and thicker while it is drawn"), ("", "")] {
                        ui.label(egui::RichText::new(h).small().color(MUTED)).on_hover_text(tip);
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
        if let Some(secs) = fit {
            self.fit_story(secs);
            self.save_story();
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
        let mut changed = false;
        let total = present::total_secs(&self.steps, &self.story);
        let ppp = ctx.pixels_per_point();
        let window_px = ctx.input(|i| i.viewport().inner_rect.map(|r| r.size() * ppp)).unwrap_or(Vec2::new(1460.0, 900.0));
        let out = self.export_target();
        egui::Window::new("Record the story").open(&mut open).collapsible(false).resizable(false).default_width(620.0).anchor(Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.label(egui::RichText::new("The story as it plays, frame by frame, into a file: what you see is what is recorded, so leave the window alone meanwhile. Esc stops a recording and keeps what was recorded.").color(MUTED));
            ui.add_space(8.0);
            theme::section(ui, "On the picture");
            egui::Grid::new("rec-picture").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                theme::label_help(ui, "Title", "A line at the top of every frame: the case, the client, the date. The same as in the story's settings.");
                changed |= ui.add_sized([460.0, 20.0], egui::TextEdit::singleline(&mut self.story.title).hint_text("a line at the top: the case, the date… (none)")).changed();
                ui.end_row();
                ui.label("Logo").on_hover_text("Your logo on the frames and on the presentation: PNG with transparency, JPEG, WebP, BMP or GIF");
                ui.horizontal(|ui| {
                    let logo = self.story.logo.trim().to_string();
                    if logo.is_empty() {
                        ui.label(egui::RichText::new("none").color(theme::DIM));
                    } else {
                        let name = std::path::Path::new(&logo).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| logo.clone());
                        ui.label(egui::RichText::new(name).color(TEXT)).on_hover_text(&logo);
                    }
                    if ui.button("Choose…").on_hover_text("Pick the image file").clicked() {
                        if let Some(p) = rfd::FileDialog::new().set_title("Logo for the recording").add_filter("Images", &["png", "jpg", "jpeg", "webp", "bmp", "gif"]).pick_file() {
                            self.story.logo = p.to_string_lossy().to_string();
                            changed = true;
                        }
                    }
                    if !logo.is_empty() && ui.button("None").on_hover_text("No logo").clicked() {
                        self.story.logo.clear();
                        changed = true;
                    }
                });
                ui.end_row();
                if !self.story.logo.trim().is_empty() {
                    ui.label("");
                    ui.horizontal(|ui| {
                        egui::ComboBox::from_id_salt("rec-logo-pos").selected_text(self.story.logo_pos.label()).show_ui(ui, |ui| {
                            for p in LogoPos::ALL {
                                changed |= ui.selectable_value(&mut self.story.logo_pos, p, p.label()).changed();
                            }
                        });
                        ui.label(egui::RichText::new("width").color(MUTED));
                        let mut pct = self.story.logo_width * 100.0;
                        if ui.add(egui::DragValue::new(&mut pct).range(3.0..=60.0).speed(0.5).fixed_decimals(0).suffix(" %")).on_hover_text("of the picture's width; the height follows the image").changed() {
                            self.story.logo_width = pct / 100.0;
                            changed = true;
                        }
                        ui.label(egui::RichText::new("opacity").color(MUTED));
                        let mut op = self.story.logo_opacity * 100.0;
                        if ui.add(egui::DragValue::new(&mut op).range(5.0..=100.0).speed(1.0).fixed_decimals(0).suffix(" %")).on_hover_text("lower for a watermark").changed() {
                            self.story.logo_opacity = op / 100.0;
                            changed = true;
                        }
                    });
                    ui.end_row();
                }
            });
            ui.add_space(8.0);
            theme::section(ui, "The look");
            egui::Grid::new("rec-look").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                theme::label_help(ui, "Cinematic", "The look made for a client or a talk: the hop being drawn is lit and the rest steps back, a clock runs at the story's pace, a lower third names each step, and a title card opens and a summary closes the video. Each piece can be turned off below, and its colour set to the client's.");
                ui.horizontal(|ui| {
                    changed |= ui.checkbox(&mut self.story.cinematic, "on").on_hover_text("The hop under way lit and the rest dimmed, a clock that rolls at the story's pace and says when it changes, a lower third with the hunt's word, the incident's bar, a title card and a summary. Present shows the same.").changed();
                    if self.story.cinematic {
                        let look = &mut self.story.look;
                        for (flag, name, hint) in [
                            (&mut look.focus, "focus", "The rest dims while a hop draws; a ring runs out of the destination as the line arrives"),
                            (&mut look.footprint, "footprint", "The hosts already reached keep a warm trace"),
                            (&mut look.time, "clock", "Date, time rolling at the story's pace, the speed and when it changes, a jump in time named"),
                            (&mut look.lower_third, "lower third", "The caption bottom left: account, hosts, the hunt's word or your verdict, your note on the connection"),
                            (&mut look.bar, "bar", "The incident's span along the bottom, the significant hops marked"),
                            (&mut look.cards, "cards", "A title card before the story (3.5 s) and a summary after it (7 s)"),
                        ] {
                            changed |= ui.checkbox(flag, name).on_hover_text(hint).changed();
                        }
                    }
                });
                ui.end_row();
                if self.story.cinematic {
                    theme::label_help(ui, "Colour", "The colour of the cinematic pieces (the lit hop, the bar, the cards). masstin's own, or the client's brand colour.");
                    ui.horizontal(|ui| {
                        let mut own = self.story.look.accent.is_some();
                        if ui.checkbox(&mut own, "the client's").on_hover_text("The overlays, the focus and the cards in this colour instead of masstin's amber").changed() {
                            self.story.look.accent = if own { Some([ACCENT.r(), ACCENT.g(), ACCENT.b()]) } else { None };
                            changed = true;
                        }
                        if let Some(c) = self.story.look.accent.as_mut() {
                            if egui::color_picker::color_edit_button_srgb(ui, c).changed() {
                                changed = true;
                            }
                            for (name, rgb) in [("navy", [52, 98, 196]), ("teal", [20, 170, 160]), ("green", [60, 170, 90]), ("red", [220, 60, 70]), ("violet", [138, 96, 240]), ("orange", [240, 130, 40])] {
                                let (r, p) = ui.allocate_painter(Vec2::new(16.0, 16.0), Sense::click());
                                p.circle_filled(r.rect.center(), 7.0, Color32::from_rgb(rgb[0], rgb[1], rgb[2]));
                                if r.on_hover_text(name).clicked() {
                                    *c = rgb;
                                    changed = true;
                                }
                            }
                        }
                    });
                    ui.end_row();
                }
            });
            ui.add_space(8.0);
            theme::section(ui, "The file");
            let rec = &mut self.story.recording;
            egui::Grid::new("rec-file").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                theme::label_help(ui, "Format", "GIF: plays anywhere (a report, a chat, a slide) with no player, but large and limited to 256 colours. MP4: small and sharp, for video; it needs ffmpeg installed on this computer. PNG frames: one image per frame, for editing in a video editor.");
                ui.horizontal(|ui| {
                    for (f, hint) in [
                        (Format::Gif, "Plays wherever a picture does. 256 colours a frame; only what changes is stored, still big for a long story."),
                        (Format::Mp4, "H.264: small and sharp. Plays in PowerPoint, Keynote and browsers."),
                        (Format::Png, "One PNG a frame, in a folder, to encode yourself."),
                    ] {
                        let enabled = f != Format::Mp4 || ffmpeg;
                        let r = ui.add_enabled(enabled, egui::Button::selectable(rec.format == f, f.label())).on_hover_text(hint).on_disabled_hover_text("ffmpeg was not found on the PATH: install it, or record PNG frames and encode them yourself");
                        if r.clicked() && rec.format != f {
                            rec.format = f;
                            rec.fps = present::nearest_fps(f, rec.fps);
                            changed = true;
                        }
                    }
                });
                ui.end_row();
                theme::label_help(ui, "Quality", "How much the file is squeezed. Small file: fewer colours or stronger compression, for sending. Balanced: the usual. Best: the largest file and the cleanest picture.");
                ui.horizontal(|ui| {
                    for q in Quality::ALL {
                        if ui.add(egui::Button::selectable(rec.quality == q, q.label())).on_hover_text(q.hint()).clicked() {
                            rec.quality = q;
                            changed = true;
                        }
                    }
                });
                ui.end_row();
                theme::label_help(ui, "Size", "The size of the picture in pixels. «this window» records exactly what you see. The fixed sizes resize the window while it records and put it back after: 1280 x 720 for a report or a chat, 1920 x 1080 for a screen or a talk.");
                ui.horizontal(|ui| {
                    for (i, name) in [(0usize, "this window"), (1, "1280 x 720"), (3, "1600 x 900"), (2, "1920 x 1080")] {
                        if ui.add(egui::Button::selectable(rec.size == i, name)).on_hover_text("The window is resized for the recording and put back after").clicked() {
                            rec.size = i;
                            changed = true;
                        }
                    }
                });
                ui.end_row();
                theme::label_help(ui, "Frames a second", "How smooth the motion is. 20 to 25 is enough for a graph; more makes a bigger file. A GIF can only keep time at the values offered here.");
                ui.horizontal(|ui| {
                    for f in present::fps_choices(rec.format) {
                        if ui.add(egui::Button::selectable(rec.fps == *f, f.to_string())).clicked() {
                            rec.fps = *f;
                            changed = true;
                        }
                    }
                    if rec.format == Format::Gif {
                        ui.label(egui::RichText::new("a GIF's clock ticks in hundredths: these keep time").small().color(theme::DIM));
                    }
                });
                ui.end_row();
                theme::label_help(ui, "Save as", "Where the recording is written. The name proposed is the timeline's with -story.");
                ui.horizontal(|ui| {
                    let shown = out.to_string_lossy().to_string();
                    let n = shown.chars().count();
                    let short = if n > 60 { format!("…{}", shown.chars().skip(n - 59).collect::<String>()) } else { shown.clone() };
                    ui.label(egui::RichText::new(short).color(TEXT)).on_hover_text(&shown);
                    if ui.button("Change…").on_hover_text("Choose where the file is written and its name").clicked() {
                        let picked = match rec.format {
                            Format::Png => rfd::FileDialog::new().set_title("Folder for the frames").pick_folder(),
                            f => {
                                let ext = if f == Format::Gif { "gif" } else { "mp4" };
                                let mut d = rfd::FileDialog::new().set_title("Record the story as").add_filter(ext.to_uppercase(), &[ext]);
                                if let Some(dir) = out.parent() {
                                    d = d.set_directory(dir);
                                }
                                if let Some(name) = out.file_name() {
                                    d = d.set_file_name(name.to_string_lossy());
                                }
                                d.save_file()
                            }
                        };
                        if let Some(p) = picked {
                            rec.file = p.to_string_lossy().to_string();
                            changed = true;
                        }
                    }
                    if !rec.file.is_empty() && ui.add(egui::Button::new(egui::RichText::new(super::icons::X).color(theme::DIM)).frame(false)).on_hover_text("Back to the default: next to the case, or the timeline").clicked() {
                        rec.file.clear();
                        changed = true;
                    }
                });
                ui.end_row();
            });
            ui.add_space(8.0);
            let (w, h) = match rec.size {
                1 => (1280.0, 720.0),
                2 => (1920.0, 1080.0),
                3 => (1600.0, 900.0),
                _ => (window_px.x, window_px.y),
            };
            let frames = (total * rec.fps as f32).ceil() as usize;
            let (lo, hi) = present::estimate_bytes(rec.format, rec.quality, w, h, rec.fps, total);
            ui.label(egui::RichText::new(format!("{:.0} s · {} frames at {} x {} · about {} to {} (what moves decides)", total, frames, w as u32, h as u32, present::human_bytes(lo), present::human_bytes(hi))).color(MUTED));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(!self.steps.is_empty(), egui::Button::new(egui::RichText::new("Record").strong().color(Color32::from_rgb(30, 24, 8))).fill(ACCENT)).clicked() {
                    start = true;
                }
                if ui.button("Cancel").on_hover_text("Close this without doing anything").clicked() {
                    self.show_export = false;
                }
            });
        });
        if changed {
            // the cards make room before and after the steps
            self.rebuild_steps();
            self.save_story();
        }
        if !open {
            self.show_export = false;
        }
        if start {
            self.start_export(ctx);
        }
    }

    /// Where the recording goes: the file chosen, or `<stem>-story.<ext>`
    /// next to the case (or the timeline).
    fn export_target(&self) -> std::path::PathBuf {
        let rec = &self.story.recording;
        let ext = match rec.format {
            Format::Gif => "gif",
            Format::Mp4 => "mp4",
            Format::Png => "",
        };
        let chosen = rec.file.trim();
        if !chosen.is_empty() {
            let mut p = std::path::PathBuf::from(chosen);
            if rec.format != Format::Png && p.extension().map_or(true, |e| !e.eq_ignore_ascii_case(ext)) {
                p.set_extension(ext);
            }
            return p;
        }
        let stem = self.files.first().and_then(|f| std::path::Path::new(f).file_stem()).map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "timeline".into());
        let dir = self.out_dir().unwrap_or_default();
        if rec.format == Format::Png {
            dir.join(format!("{}-story", stem))
        } else {
            dir.join(format!("{}-story.{}", stem, ext))
        }
    }

    /// Begin recording the story with the Record dialog's settings.
    fn start_export(&mut self, ctx: &egui::Context) {
        self.show_export = false;
        self.show_story = false;
        self.rebuild_steps();
        let rec = self.story.recording.clone();
        let out = self.export_target();
        if let Some(dir) = if rec.format == Format::Png { Some(out.as_path()) } else { out.parent() } {
            let _ = std::fs::create_dir_all(dir);
        }
        let total = present::total_secs(&self.steps, &self.story);
        let frames = ((total * rec.fps as f32).ceil() as usize).max(1);
        let (tx, rx) = std::sync::mpsc::channel();
        let restore = match rec.size {
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
            eprintln!("[view] recording {} frames at {} fps, {:?}, {:?}, to {}", frames, rec.fps, rec.format, rec.quality, out.display());
        }
        let recorder = present::Recorder::start(rec.fps, rec.format, rec.quality, out.clone());
        self.export = Some(ExportJob { fps: rec.fps, out, total: frames, next: 0, waiting: false, rx, tx, restore: if restore.is_some() { current } else { None }, rec: recorder, cancelled: false });
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
                Some(f) => (self.out_dir().unwrap_or_default(), std::path::Path::new(f).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "masstin".into())),
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
            Format::Mp4 => present::Recorder::start_stream(fps, Quality::Balanced, out.clone()),
            _ => present::Recorder::start(fps, Format::Gif, Quality::Balanced, out.clone()),
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
        // a timeline being read: the next action waits for it, as a hand would
        if now < self.auto_next || self.loading() {
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
            "record-dialog" => self.show_export = true,
            "cinematic" => {
                self.story.cinematic = !self.story.cinematic;
                self.rebuild_steps();
            }
            other if other.starts_with("seek=") => {
                // the presentation at this second, still
                self.present_t = other["seek=".len()..].parse().unwrap_or(0.0);
                self.present_playing = false;
                ctx.request_repaint();
            }
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
            // for tests: another timeline opened the way every opener
            // does, and the side files written as a change of style does
            other if other.starts_with("open=") => {
                self.open_files(vec![other["open=".len()..].to_string()]);
            }
            "persist" => self.persist(),
            other if other.starts_with("open-case=") => {
                self.open_case(std::path::PathBuf::from(&other["open-case=".len()..]));
            }
            // the rows of a connection (the n-th edge of the view), a text
            // typed into its notes box, and "Save on all rows" with a verdict
            other if other.starts_with("rows=") => {
                let i: usize = other["rows=".len()..].parse().unwrap_or(0);
                if i < self.graph.edges.len() {
                    self.load_rows(i);
                }
            }
            other if other.starts_with("note=") => self.notes_draft = other["note=".len()..].to_string(),
            other if other.starts_with("mark-all=") => {
                if let Some(i) = self.rows.as_ref().map(|(e, _, _)| *e) {
                    let v = super::store::verdict_code(&other["mark-all=".len()..]);
                    let all: Vec<(u16, u32)> = self.graph.edges[i].rows.iter().map(|&ei| (self.store.edges[ei as usize].file, self.store.edges[ei as usize].line)).collect();
                    self.mark_rows(i, &all, v);
                    if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
                        eprintln!("[view] mark: {}", self.mark_msg);
                    }
                }
            }
            other if other.starts_with("save-view=") => {
                let name = other["save-view=".len()..].to_string();
                self.saved.retain(|v| v.name != name);
                self.saved.push(SavedView { name, filter: self.draft.clone(), style: self.style_to_save(), places: Vec::new() });
                self.persist();
            }
            // a saved view picked as the Filters menu picks it: its filter,
            // its style and the places it keeps
            other if other.starts_with("view=") => {
                let name = &other["view=".len()..];
                if let Some(v) = self.saved.iter().find(|v| v.name == name).cloned() {
                    self.preset = v.name.clone();
                    self.draft = v.filter.clone();
                    self.style = v.style.clone();
                    if !v.places.is_empty() {
                        self.restore_places = Some(v.places.clone());
                    }
                    self.requery(false);
                } else {
                    eprintln!("masstin: no saved view named {}", name);
                }
            }
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
                    self.last_log_path = j.log_path.clone();
                    self.last_log = Some((j.command, j.full));
                }
                if self.overlay.is_some() {
                    self.overlay = None;
                    self.path_found.clear();
                    self.path_tree = None;
                    self.path_msg.clear();
                    self.requery(false);
                }
            }
            "hud" => self.hud = !self.hud,
            "motion" => {
                self.style.motion = !self.style.motion;
                self.persist();
            }
            other if other.starts_with("note=") => {
                self.notes.add(NoteTarget::Free, &other["note=".len()..]);
                if let Err(e) = self.save_notes() {
                    eprintln!("masstin: cannot write {}: {}", self.notes.path.display(), e);
                }
            }
            // on to agentc00pr: the dialog, a new case of that name in that folder, go
            // how rows become edges: `grouping=hosts|connection|event`
            other if other.starts_with("grouping=") => {
                self.draft.grouping = match &other["grouping=".len()..] {
                    "hosts" => super::query::Grouping::PerPair,
                    "event" => super::query::Grouping::PerEvent,
                    _ => super::query::Grouping::PerAccount,
                };
                self.requery(false);
            }
            // exactly the events named, as `--event`; several with `;` between
            other if other.starts_with("events=") => {
                let conds: Vec<String> = other["events=".len()..].split(';').map(|c| c.replace('|', ",")).collect();
                self.events_to_graph_view(&conds);
            }
            // exactly these rows in the graph, ungrouped: `rows=12,57` (lines
            // of the first timeline), `rows=2:12` (of the second)
            other if other.starts_with("rows=") => match parse_rows(&other["rows=".len()..]) {
                Ok(rows) => self.rows_to_graph_view(&rows),
                Err(e) => self.status = e,
            },
            // hosts and addresses: the table, a level, merge what it allows
            "hosts" => self.open_hosts(),
            other if other.starts_with("hosts-level=") => {
                if let (Some(d), Some(l)) = (self.hosts.as_mut(), crate::graph_hunt_common::hostmap::Level::parse(&other["hosts-level=".len()..])) {
                    d.level = l;
                }
            }
            "hosts-merge" => {
                let todo = match self.hosts.as_ref() {
                    Some(hosts::HostsDialog { table: Ok(t), level, .. }) => Some((hosts::pending(t, *level, &self.merges), level.name())),
                    _ => None,
                };
                if let Some((pairs, level)) = todo {
                    self.merge_many(&pairs, &format!("the evidence of the timelines, level {}", level));
                }
            }
            // the hunt's form on one of its four steps (0 to 3), not run
            other if other.starts_with("hunt-step=") => {
                self.show_hunt = true;
                self.hunt_form.step = other["hunt-step=".len()..].parse::<usize>().unwrap_or(0).min(3);
            }
            // the hunt's tick box: `hunt-hosts=standard`, `hunt-hosts=off`
            other if other.starts_with("hunt-hosts=") => {
                self.hunt_form.merge_hosts = crate::graph_hunt_common::hostmap::Level::parse(&other["hunt-hosts=".len()..]);
            }
            "agent" => self.open_agentc00pr(),
            // the events of the N-th connection drawn, in agentc00pr's viewer
            other if other.starts_with("agent-edge=") => {
                let k: usize = other["agent-edge=".len()..].parse().unwrap_or(0);
                if k < self.graph.edges.len() {
                    let (label, rows) = (self.graph_edge_label(k), self.rows_of_graph_edge(k));
                    self.rows_to_agentc00pr(&rows, &label);
                }
            }
            other if other.starts_with("agent-new=") => {
                if let (Some(d), Some((name, parent))) = (self.agent.as_mut(), other["agent-new=".len()..].split_once('|')) {
                    d.new_case = true;
                    d.name = name.to_string();
                    d.parent = parent.to_string();
                }
            }
            // one of agentc00pr's cases, by its folder
            other if other.starts_with("agent-case=") => {
                if let Some(d) = self.agent.as_mut() {
                    let folder = other["agent-case=".len()..].to_string();
                    d.pick = match d.cases.iter().position(|(_, f)| f.replace(92 as char, "/").eq_ignore_ascii_case(&folder.replace(92 as char, "/"))) {
                        Some(i) => i,
                        None => {
                            d.cases.insert(0, (folder.clone(), folder));
                            0
                        }
                    };
                    d.new_case = false;
                }
            }
            "agent-go" => self.agent_go(),
            // the answer to "already hunted": overwrite, keep or new
            other if other.starts_with("hunt-answer=") => {
                if let Some(x) = crate::graph_hunt_common::record::IfHunted::parse(&other["hunt-answer=".len()..]) {
                    self.answer_hunted(x);
                }
            }
            // the two modes, and what moves between them
            "table" | "table-csv" | "timeline" => self.show_table = true,
            "graph" => self.show_table = false,
            other if other.starts_with("timeline-edge=") => {
                let i: usize = other["timeline-edge=".len()..].parse().unwrap_or(0);
                self.timeline_of_edge(i);
            }
            other if other.starts_with("timeline-node=") => {
                let i: usize = other["timeline-node=".len()..].parse().unwrap_or(0);
                self.timeline_of_node(i);
            }
            // (a text looked for in any column is a filter like the others)
            other if other.starts_with("timeline-find=") => {
                if let Some(f) = table::RowFilter::parse(&format!("+{}", &other["timeline-find=".len()..])) {
                    self.add_table_filter(f);
                }
            }
            // the look of the timeline: `timeline-font=14`, `timeline-hide=COLUMN`
            // (again shows it), `timeline-width=COLUMN:PIXELS`
            other if other.starts_with("timeline-font=") => self.table_look.set_font(other["timeline-font=".len()..].parse().unwrap_or(12.0)),
            other if other.starts_with("timeline-hide=") => {
                if let Some(ci) = table::column_named(&other["timeline-hide=".len()..]) {
                    self.table_look.hidden[ci] = !self.table_look.hidden[ci];
                }
            }
            other if other.starts_with("timeline-width=") => {
                if let Some((c, w)) = other["timeline-width=".len()..].split_once(':') {
                    if let (Some(ci), Ok(w)) = (table::column_named(c), w.parse::<f32>()) {
                        self.table_look.set_width(ci, w);
                        self.table_look.fixed[ci] = true;
                    }
                }
            }
            // a filter of the timeline, added to the ones there: `+user:alice`,
            // `-event_type:logoff`, `+10.0.0.5` (any column); `timeline-filter=` clears them
            other if other.starts_with("timeline-filter=") => match table::RowFilter::parse(&other["timeline-filter=".len()..]) {
                Some(f) => self.add_table_filter(f),
                None => {
                    self.table_filters.clear();
                    self.table_scope_gen += 1;
                }
            },
            // the n-th row of the file: picked, and to its connection in the graph
            other if other.starts_with("timeline-row=") => {
                let i: u32 = other["timeline-row=".len()..].parse().unwrap_or(0);
                self.pick_row((0, i));
            }
            other if other.starts_with("timeline-to-graph=") => {
                let i: u32 = other["timeline-to-graph=".len()..].parse().unwrap_or(0);
                self.row_to_graph((0, i));
            }
            // "Open in…" with the program of this name (or the system's)
            other if other.starts_with("timeline-open=") => {
                let name = other["timeline-open=".len()..].to_string();
                let apps = viewers::all();
                eprintln!("masstin: programs found: {}", apps.iter().map(|a| a.name.as_str()).collect::<Vec<_>>().join(", "));
                let i = apps.iter().position(|a| a.name.eq_ignore_ascii_case(&name));
                self.open_rows_in(i, false);
                eprintln!("masstin: {}", self.status);
            }
            // the copy "Open in…" hands to a program, written and named on stderr
            "timeline-copy" => {
                let rows: Vec<(u16, u32)> = match &self.table_scope {
                    Some(sc) => sc.rows.clone(),
                    None => Vec::new(),
                };
                let label = self.table_scope.as_ref().map(|s| s.label.clone()).unwrap_or_default();
                match self.write_rows_copy(&rows, &label) {
                    Ok(p) => eprintln!("masstin: rows copy {}", p),
                    Err(e) => eprintln!("masstin: cannot write the rows copy: {}", e),
                }
            }
            // rows of the first file to the system clipboard, as "Copy the row" does (copy-rows=0+1)
            other if other.starts_with("copy-rows=") => {
                let rows: Vec<(u16, u32)> = other["copy-rows=".len()..].split('+').filter_map(|s| s.trim().parse().ok()).map(|l| (0u16, l)).collect();
                match self.rows_text(&rows) {
                    Ok(t) => {
                        ctx.copy_text(t);
                        eprintln!("masstin: copied {} row(s) to the clipboard", rows.len());
                    }
                    Err(e) => eprintln!("masstin: cannot copy the rows: {}", e),
                }
            }
            "style" => self.show_labels = true,
            "when" => self.show_when = true,
            other if other.starts_with("when-cal=") => self.when_open_cal = Some(other["when-cal=".len()..].to_string()),
            "ingest" => self.ingest.open = true,
            // for tests: the log window, and the wizard's --debug
            "log-window" => self.show_last_log = true,
            "names-always" => self.ask_costly(safeguard::Costly::Names),
            "names-always-yes" => self.turn_on(safeguard::Costly::Names),
            "motion-ask" => self.ask_costly(safeguard::Costly::Motion),
            "ingest-debug" => self.ingest.debug = true,
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
            // the new evidence in a timeline of its own, not added to the one open
            "ingest-own" => {
                self.ingest.append_offered = true;
                self.ingest.append_to.clear();
            }
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
            other if other.starts_with("captions=") => {
                self.style.caption_hover = false;
                self.style.caption_show = match &other["captions=".len()..] {
                    "always" => super::views::CaptionShow::Always,
                    "hover" => super::views::CaptionShow::Hover,
                    _ => super::views::CaptionShow::Auto,
                };
            }
            other if other.starts_with("captions-limit=") => {
                self.style.caption_crowd = other["captions-limit=".len()..].parse().unwrap_or(80);
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
            other if other.starts_with("story-fit=") => {
                if let Ok(secs) = other["story-fit=".len()..].parse::<f32>() {
                    self.fit_story(secs);
                }
            }
            other if other.starts_with("studio=") => {
                self.studio.open = true;
                self.studio.load(&other["studio=".len()..]);
            }
            other if other.starts_with("studio-do=") => self.studio.auto(&other["studio-do=".len()..]),
            "paths-map" => self.path_in_map = true,
            "paths-alone" => self.path_in_map = false,
            "paths-reshow" => self.reshow_path(),
            // the Cortex wizard, for tests: open it, fill it, move through it
            "cortex" => self.show_cortex = true,
            "cortex-check" => {
                self.cortex_form.go_on = false;
                self.cortex_check_start();
            }
            "cortex-shown-ok" => {
                // (the look of an accepted connection, with no tenant asked)
                self.cortex_form.check = remote::CortexCheck::Accepted(vec!["Key: Advanced (signed with a nonce and the time)".into(), "Quota: 1.25 of 100 compute units used today".into()]);
                self.cortex_form.checked = self.cortex_form.tenant_digest();
            }
            other if other.starts_with("cortex-url=") => self.cortex_form.url = other["cortex-url=".len()..].to_string(),
            other if other.starts_with("cortex-id=") => self.cortex_form.key_id = other["cortex-id=".len()..].to_string(),
            other if other.starts_with("cortex-key=") => self.cortex_form.key = other["cortex-key=".len()..].to_string(),
            other if other.starts_with("cortex-step=") => self.cortex_form.step = other["cortex-step=".len()..].parse().unwrap_or(0),
            "paths-open" => self.show_paths = true,
            other if other.starts_with("merge=") => {
                // merge=FROM>INTO: the analyst's merge of two hosts that are one
                if let Some((from, into)) = other["merge=".len()..].split_once('>') {
                    self.merge_hosts(from, into);
                }
            }
            "paths-find" => {
                let t = std::time::Instant::now();
                self.run_paths();
                println!("PATHS| ({} took {:.2} s)", "paths-find", t.elapsed().as_secs_f32());
            }
            "cone-fwd" => {
                let t = std::time::Instant::now();
                self.run_cone(true);
                println!("PATHS| ({} took {:.2} s)", "cone-fwd", t.elapsed().as_secs_f32());
            }
            "cone-back" => {
                let t = std::time::Instant::now();
                self.run_cone(false);
                println!("PATHS| ({} took {:.2} s)", "cone-back", t.elapsed().as_secs_f32());
            }
            "paths-back" => {
                self.overlay = None;
                self.trail = None;
                self.path_found.clear();
                self.path_tree = None;
                self.path_msg.clear();
                self.requery(false);
            }
            "paths-compact" => self.path_compact = true,
            "paths-full" => self.path_compact = false,
            "paths-same-account" => self.path_same_account = true,
            "paths-any-account" => self.path_same_account = false,
            "tree-say" => {
                // the tree as the window lists it, for a test to read
                if let Some(tree) = &self.path_tree {
                    println!("TREE| {} ({} rows)", tree.title, tree.rows.len());
                    for &(host, depth) in tree.rows.iter().take(60) {
                        let r = tree.cone.reach[&host];
                        let by = r.via.map(|ei| { let e = &self.store.edges[ei as usize]; format!("  {} {}  hop {}", self.store.users.name(e.user), fmt_time(e.t), r.hop) }).unwrap_or_default();
                        println!("TREE| {}{}{}", "    ".repeat(depth), self.store.hosts.name(host), by);
                    }
                } else {
                    println!("TREE| none");
                }
            }
            other if other.starts_with("tree-pick=") => {
                if let Some(h) = self.host_named(&other["tree-pick=".len()..]) {
                    self.show_tree_chain(h);
                }
            }
            "paths-say" => {
                // what the window says and what is drawn, for a test to read
                println!("PATHS| {}", self.path_msg.replace('\n', " / "));
                for p in &self.path_found {
                    let mut t = self.store.hosts.name(self.store.edges[p.edges[0] as usize].src).to_string();
                    for &ei in &p.edges {
                        let e = &self.store.edges[ei as usize];
                        let made = p.edges.iter().position(|&x| x == ei).filter(|k| *k > 0).map_or(false, |k| self.store.launched_by(p.edges[k - 1], ei));
                        t.push_str(&format!(" {}({} {})-> {}", if made { "=" } else { "-" }, self.store.users.name(e.user), fmt_time(e.t), self.store.hosts.name(e.dst)));
                    }
                    println!("PATHS|   {}", t);
                }
                println!("PATHS|   drawn: {} hosts, {} connections; overlay {:?}; trail {:?} ({} marked)", self.graph.nodes.len(), self.graph.edges.len(), self.overlay.as_ref().map(|o| o.title.clone()), self.trail.as_ref().map(|t| t.title.clone()), self.trail_on.iter().filter(|x| **x).count());
                let mut labels: Vec<String> = self.overlay.as_ref().map(|o| &o.labels).or(self.trail.as_ref().map(|t| &t.labels)).map(|l| l.iter().map(|(h, t)| format!("{}={}", self.store.hosts.name(*h), t)).collect()).unwrap_or_default();
                labels.sort();
                println!("PATHS|   labels: {}", labels.join("; "));
            }
            other if other.starts_with("paths-origin=") => self.path_origin = other["paths-origin=".len()..].to_string(),
            other if other.starts_with("paths-dest=") => self.path_dest = other["paths-dest=".len()..].to_string(),
            other if other.starts_with("paths-hops=") => self.path_hops = other["paths-hops=".len()..].parse().unwrap_or(6),
            other if other.starts_with("paths-max=") => self.path_max = other["paths-max=".len()..].parse().unwrap_or(50),
            other if other.starts_with("paths-gap=") => self.path_gap_h = other["paths-gap=".len()..].parse().unwrap_or(24.0),
            other if other.starts_with("paths-results=") => {
                for (i, ch) in other["paths-results=".len()..].chars().take(4).enumerate() {
                    self.path_results[i] = ch == '1';
                }
            }
            other if other.starts_with("paths-machine=") => self.path_skip_machine = &other["paths-machine=".len()..] != "1",
            other if other.starts_with("paths-pick=") => self.show_one_path(other["paths-pick=".len()..].parse().unwrap_or(0)),
            "paths-session-only" => {
                self.path_by_session = true;
                self.path_session_gap = false;
            }
            "paths-session" => self.path_by_session = true,
            "paths-session-gap" => {
                self.path_by_session = true;
                self.path_session_gap = true;
            }
            "paths-time" => self.path_by_session = false,
            "paths-all" => self.path_scope_all = true,
            "paths-filtered" => self.path_scope_all = false,
            other if other.starts_with("paths-user=") => self.path_user = other["paths-user=".len()..].to_string(),
            other if other.starts_with("paths-from=") => self.path_from = other["paths-from=".len()..].to_string(),
            other if other.starts_with("paths-to=") => self.path_to = other["paths-to=".len()..].to_string(),
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
                    // record=FORMAT:FPS:SIZE[:QUALITY[:FILE]]
                    let parts: Vec<&str> = spec.split(':').collect();
                    let rec = &mut self.story.recording;
                    rec.format = match parts.first().copied().unwrap_or("gif") {
                        "png" => Format::Png,
                        "mp4" => Format::Mp4,
                        _ => Format::Gif,
                    };
                    rec.fps = parts.get(1).and_then(|f| f.parse().ok()).unwrap_or(15);
                    rec.size = parts.get(2).and_then(|f| f.parse().ok()).unwrap_or(0);
                    if let Some(q) = parts.get(3) {
                        rec.quality = match *q {
                            "small" => Quality::Small,
                            "best" => Quality::Best,
                            _ => Quality::Balanced,
                        };
                    }
                    if parts.len() > 4 {
                        rec.file = parts[4..].join(":");
                    }
                    self.start_export(ctx);
                } else {
                    eprintln!("masstin: unknown MASSTIN_VIEW_AUTO action '{}'", other);
                }
            }
        }
        ctx.request_repaint();
    }

    /// Drive a recording: one frame per repaint, screenshot taken after
    /// the frame is drawn, encoded as it comes; the progress in the window's
    /// title, since the frames are the window itself.
    fn export_step(&mut self, ctx: &egui::Context) {
        let title = self.title.clone();
        let Some(job) = self.export.as_mut() else { return };
        if let Some(result) = job.rec.result() {
            let (restore, cancelled, done, total) = (job.restore, job.cancelled, job.next, job.total);
            self.export = None;
            self.stop_presentation();
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(title));
            if let Some(size) = restore {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
            }
            self.status = match (result, cancelled) {
                (Ok(m), false) => format!("Recorded: {}", m),
                (Ok(m), true) => format!("Recording stopped after {} of {} frames, kept: {}", done, total, m),
                (Err(e), _) => format!("Recording failed: {}", e),
            };
            if std::env::var_os("MASSTIN_VIEW_DEBUG").is_some() {
                eprintln!("[view] {}", self.status);
            }
            return;
        }
        if job.waiting {
            if let Ok((i, img)) = job.rx.try_recv() {
                if i == job.next {
                    job.rec.push(img);
                    job.next += 1;
                    job.waiting = false;
                }
            }
        }
        if job.rec.finishing() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
            return;
        }
        if !job.waiting {
            if job.next >= job.total {
                job.rec.finish();
                ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!("{} — finishing the recording…", title)));
            } else {
                // the frame about to be drawn
                self.present_t = job.next as f32 / job.fps as f32;
                if job.next % 10 == 0 {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!("{} — recording {} / {} · Esc stops", title, job.next + 1, job.total)));
                }
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

    /// Esc while recording: no more frames, the encoder closes the file
    /// with the ones it has.
    fn cancel_export(&mut self) {
        if let Some(job) = self.export.as_mut() {
            if !job.rec.finishing() {
                job.cancelled = true;
                job.rec.finish();
            }
        }
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
mod rows_option_tests {
    use super::{host_answers, parse_event, parse_rows};

    /// The rows a path search may use: what the filters select or the
    /// whole timeline, the account, the search's own dates over the bar's.
    #[test]
    fn a_path_search_uses_the_rows_it_says() {
        use super::super::query::{parse_time, Filter, View};
        use super::super::store::Store;
        let path = std::env::temp_dir().join(format!("masstin-pathrows-{}.csv", std::process::id()));
        let row = |day: u32, src: &str, dst: &str, user: &str, et: &str, hunt: &str| format!("2026-01-{:02}T10:00:00Z,{},{},4624,3,{},CORP,,{},,,0x{}{},,Security.evtx,{},,,,", day, dst, et, user, src, day, src.len(), hunt);
        let body = [
            crate::csv_out::HEADER.to_string(),
            row(1, "10.0.0.1", "B", "ana", "SUCCESSFUL_LOGON", "significant"),
            row(2, "B", "C", "ana", "SUCCESSFUL_LOGON", "habitual"),
            row(3, "C", "D", "bob", "SUCCESSFUL_LOGON", "candidate"),
            row(4, "C", "D", "ana", "FAILED_LOGON", "baseline"),
            row(5, "D", "E", "anabel", "SUCCESSFUL_LOGON", "not_evaluated"),
            row(6, "D", "E", "bob", "LOGOFF", "baseline"),
        ]
        .join("\n");
        std::fs::write(&path, format!("{}\n", body)).unwrap();
        let s = Store::load(&[path.to_string_lossy().to_string()], 0.05).unwrap();
        assert_eq!(s.edges.len(), 6);
        let days = |only: &Option<std::rc::Rc<Vec<bool>>>| -> Vec<i64> { s.edges.iter().enumerate().filter(|(i, _)| only.as_ref().map_or(true, |o| o[*i])).map(|(_, e)| (e.t - s.t_min) / 86_400 + 1).collect() };
        let findings = Filter::default();
        assert_eq!(findings.view, View::Findings);
        let all = Filter { view: View::All, ..Filter::default() };
        // inside the filters: the findings alone, or everything they let through (no logoff by default)
        let (only, from, to, rows) = super::path_rows(&s, &findings, false, "", "", "");
        assert_eq!((days(&only), from, to, rows), (vec![1, 3], None, None, 2));
        let (only, _, _, rows) = super::path_rows(&s, &all, false, "", "", "");
        assert_eq!((days(&only), rows), (vec![1, 2, 3, 4, 5], 5));
        // the whole timeline: every row, whatever the filters and their window say
        let barred = Filter { from: "2026-01-03".into(), to: "2026-01-04 23:00".into(), ..all.clone() };
        let (only, from, to, rows) = super::path_rows(&s, &barred, true, "", "", "");
        assert!(only.is_none());
        assert_eq!((from, to, rows), (None, None, 6));
        // inside the filters, the bar's window is the search's
        let (only, from, to, rows) = super::path_rows(&s, &barred, false, "", "", "");
        assert_eq!((days(&only), rows), (vec![3, 4], 2));
        assert_eq!((from, to), (parse_time("2026-01-03"), parse_time("2026-01-04 23:00")));
        // the search's own dates go over the bar's, one end or both
        let (only, from, _, _) = super::path_rows(&s, &barred, false, "", "2026-01-02", "");
        assert_eq!((days(&only), from), (vec![2, 3, 4], parse_time("2026-01-02")));
        let (only, _, to, rows) = super::path_rows(&s, &barred, false, "", "2026-01-01", "2026-01-02 12:00");
        assert_eq!((days(&only), to, rows), (vec![1, 2], parse_time("2026-01-02 12:00"), 2));
        // and they bound the whole timeline too
        let (only, from, to, rows) = super::path_rows(&s, &all, true, "", "2026-01-02", "2026-01-05 12:00");
        assert!(only.is_none());
        assert_eq!((from, to, rows), (parse_time("2026-01-02"), parse_time("2026-01-05 12:00"), 4));
        // a text that is no date is as if empty
        let (only, from, _, _) = super::path_rows(&s, &barred, false, "", "yesterday", "");
        assert_eq!((days(&only), from), (vec![3, 4], parse_time("2026-01-03")));
        // the account: part of a name, a wildcard, one left out, several
        let acct = |a: &str, whole: bool| days(&super::path_rows(&s, &all, whole, a, "", "").0);
        assert_eq!(acct("ana", true), vec![1, 2, 4, 5]);
        assert_eq!(acct("ana", false), vec![1, 2, 4, 5]);
        assert_eq!(acct("bob", true), vec![3, 6]);
        assert_eq!(acct("bob", false), vec![3]);
        assert_eq!(acct("anab*", true), vec![5]);
        assert_eq!(acct("!bob", true), vec![1, 2, 4, 5]);
        assert_eq!(acct("bob, anabel", true), vec![3, 5, 6]);
        assert_eq!(acct("nobody", true), Vec::<i64>::new());
        // account and dates and filters together
        let (only, _, _, rows) = super::path_rows(&s, &findings, false, "bob", "2026-01-02", "");
        assert_eq!((days(&only), rows), (vec![3], 1));
        let _ = std::fs::remove_file(path);
    }

    /// Why there is no path, said from what the origin and the destination
    /// have: nothing out of the one, nothing into the other, or two cones
    /// that never meet.
    #[test]
    fn no_path_says_why() {
        use super::super::paths::PathQuery;
        use super::super::store::Store;
        let path = std::env::temp_dir().join(format!("masstin-why-{}.csv", std::process::id()));
        let row = |hour: u32, src: &str, dst: &str, user: &str, et: &str| format!("2026-01-05T{:02}:00:00Z,{},{},4624,3,{},CORP,,{},,,0x{},,Security.evtx,,,,,", hour, dst, et, user, src, hour);
        let body = [
            crate::csv_out::HEADER.to_string(),
            row(1, "10.0.0.9", "B", "ana", "FAILED_LOGON"),
            row(2, "10.0.0.9", "B", "ana", "FAILED_LOGON"),
            row(3, "B", "C", "ana", "SUCCESSFUL_LOGON"),
            row(4, "C", "D", "D$", "SUCCESSFUL_LOGON"),
            // E enters F before anything enters E
            row(5, "E", "F", "ana", "SUCCESSFUL_LOGON"),
            row(9, "C", "E", "ana", "SUCCESSFUL_LOGON"),
        ]
        .join("\n");
        std::fs::write(&path, format!("{}\n", body)).unwrap();
        let s = Store::load(&[path.to_string_lossy().to_string()], 0.05).unwrap();
        let h = |n: &str| s.hosts.get(n).unwrap();
        let q = |o: &str, d: &str| PathQuery { origin: h(o), dest: h(d), ..Default::default() };
        // the address only fails: nothing of what counts leaves it
        let why = super::why_no_path(&s, &q("10.0.0.9", "C"));
        assert!(why.starts_with("No path can start at 10.0.0.9") && why.contains("2 logon FAILED") && why.contains("counts logon OK"), "{}", why);
        // (and with failures counted there is one)
        assert_eq!(super::paths::find_paths(&s, &PathQuery { results: [true, true, false, false], ..q("10.0.0.9", "C") }).len(), 1);
        // F is never an origin, the address never a destination
        assert!(super::why_no_path(&s, &q("F", "B")).starts_with("Nothing in the timeline logs on FROM F"));
        assert!(super::why_no_path(&s, &q("B", "10.0.0.9")).starts_with("Nothing in the timeline logs on TO 10.0.0.9"));
        // D is entered by a machine account alone
        let why = super::why_no_path(&s, &q("B", "D"));
        assert!(why.starts_with("No path can end at D") && why.contains("1 logon OK"), "{}", why);
        // B reaches C and E; E could reach F; but E was left before it was entered
        let why = super::why_no_path(&s, &q("B", "F"));
        assert!(why.starts_with("From B a chain of these logins reaches 2 host(s), and 1 host(s) could reach F"), "{}", why);
        assert!(super::paths::find_paths(&s, &q("B", "F")).is_empty());
        let _ = std::fs::remove_file(path);
    }

    /// The names a box offers: the ones that start with what is typed
    /// first, then the ones that contain it, in any case; all when empty.
    #[test]
    fn a_box_offers_the_names_that_match() {
        let names: Vec<String> = ["10.0.0.5", "DC01", "SRV-DC02", "WS01"].iter().map(|s| s.to_string()).collect();
        let got = |t: &str| -> Vec<String> { super::suggestions(&names, t).into_iter().cloned().collect() };
        assert_eq!(got("dc"), ["DC01", "SRV-DC02"]);
        assert_eq!(got(" 01 "), ["DC01", "WS01"]);
        assert_eq!(got("").len(), 4);
        assert!(got("zz").is_empty());
        assert_eq!((super::group_digits(0), super::group_digits(999), super::group_digits(1000), super::group_digits(5034507)), ("0".to_string(), "999".to_string(), "1,000".to_string(), "5,034,507".to_string()));
    }

    #[test]
    fn an_event_is_named_by_what_it_is() {
        let c = parse_event("2026-11-03 11:12:56, alice ,ws01,SRV01.corp.test").unwrap();
        assert_eq!((c.t, c.fraction.as_str(), c.user.as_str(), c.origin.as_str(), c.destination.as_str()), (Some(1_793_704_376), "", "ALICE", "WS01", "SRV01.CORP.TEST"));
        // the fraction, as an event log or a case tool writes it
        assert_eq!(parse_event("2026-11-03T11:12:56.143498Z,,,").unwrap().fraction, "143498");
        assert_eq!(parse_event("2026-11-03 11:12:56.500000,,,").unwrap().fraction, "5");
        // an empty field is not asked about; all of them empty asks nothing
        let c = parse_event(",alice,,SRV01").unwrap();
        assert_eq!((c.t, c.origin.as_str()), (None, ""));
        for bad in ["", ",,,", "alice,SRV01", "yesterday,alice,WS01,SRV01", "a,b,c,d,e"] {
            assert!(parse_event(bad).is_err(), "{bad}");
        }
        // a host answers by its name or one merged into it, short or qualified, and an address whole
        let names = vec!["DEV-DC01".to_string(), "10.10.0.37".to_string(), "dev-dc01.dev.corp.test".to_string()];
        for asked in ["DEV-DC01", "DEV-DC01.DEV.CORP.TEST", "DEV-DC01.OTHER", "10.10.0.37"] {
            assert!(host_answers(&names, asked), "{asked}");
        }
        for asked in ["DEV-DC02", "10.10.0.3", "10"] {
            assert!(!host_answers(&names, asked), "{asked}");
        }
    }

    /// `--rows` takes the lines an editor shows: the header is 1.
    #[test]
    fn rows_are_given_by_their_line_in_the_file() {
        assert_eq!(parse_rows("2").unwrap(), vec![(0, 0)]);
        assert_eq!(parse_rows("12, 57,301").unwrap(), vec![(0, 10), (0, 55), (0, 299)]);
        assert_eq!(parse_rows("1:12,2:40").unwrap(), vec![(0, 10), (1, 38)]);
        for bad in ["", "1", "0:5", "x", "3:1", "2:"] {
            assert!(parse_rows(bad).is_err(), "{bad}");
        }
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
                eprintln!("[view] {} frame(s) in {:.1} s ({:.1} a second) · in masstin {:.1} ms · in eframe (tessellate, render, present) {:.1} ms{} · layout {} ({} works taken, {} dropped){}", self.fps_count, since, self.fps_count as f32 / since, self.inside_ms, self.outside_ms, if self.light_mode { " · light mode" } else { "" }, if self.layout.is_running() { "running" } else { "still" }, self.layout_works.0, self.layout_works.1, if self.safeguard.is_some() { " · drawing reduced" } else { "" });
                self.layout_works = (0, 0);
                self.fps_count = 0;
                self.fps_since = now;
            }
        }
        self.watch_frame_cost(dt);
        self.watch_safeguard();
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
            // Esc stops a recording and keeps what was recorded, as the
            // window says: the key was only read when nothing was recording
            if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
                self.cancel_export();
            }
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
            if esc {
                if self.export.is_some() {
                    self.cancel_export();
                } else {
                    self.stop_presentation();
                }
            }
            // a recording sets its own time: the keys that move it wait
            if space && self.export.is_none() {
                self.present_playing = !self.present_playing;
            }
            if home && self.export.is_none() {
                self.present_t = 0.0;
            }
            if (right || left) && self.export.is_none() {
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
        // Timeline mode: the rows of the CSV take the centre; what belongs
        // to the picture (its filters, the time strip, the legend) waits
        if self.show_table {
            egui::Panel::bottom("status").frame(bar(theme::PANEL, egui::Margin::symmetric(12, 4))).show_separator_line(false).show(ui, |ui| self.status_bar(ui));
            if self.show_inspector && self.table_sel.is_some() {
                egui::Panel::right("inspector").default_size(400.0).resizable(true).frame(bar(theme::PANEL, egui::Margin::same(14))).show(ui, |ui| self.inspector(ui));
            }
            egui::CentralPanel::default().frame(egui::Frame::new().fill(BG)).show(ui, |ui| self.timeline_view(ui));
        } else {
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
        self.cortex_window(&ctx);
        self.db_window(&ctx);
        self.studio_window(&ctx);
        self.poll_job(&ctx);
        self.poll_hunt_loaded(&ctx);
        self.poll_pending_load(&ctx);
        self.loading_overlay(&ctx);
        self.job_window(&ctx);
        self.last_log_window(&ctx);
        self.drop_overlay(&ctx);
        self.labels_window(&ctx);
        self.when_window(&ctx);
        self.about_window(&ctx);
        self.agent_window(&ctx);
        self.hosts_window(&ctx);
        self.host_window(&ctx);
        self.edge_window(&ctx);
        self.merge_host_window(&ctx);
        self.merges_window(&ctx);
        self.subnets_window(&ctx);
        self.rules_window(&ctx);
        self.save_popup(&ctx);
        self.confirm_delete_window(&ctx);
        self.confirm_cost_window(&ctx);
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

impl Drop for Viewer {
    /// The window is closing: a parse or a hunt started from it does not
    /// go on alone, with nobody to see it end.
    fn drop(&mut self) {
        if let Some(j) = self.job.as_mut() {
            if j.done.is_none() {
                j.cancel();
            }
        }
    }
}

#[cfg(test)]
mod split_mesh_tests {
    use super::*;

    fn quads(n: usize) -> egui::epaint::Mesh {
        let mut m = egui::epaint::Mesh::default();
        for i in 0..n {
            let y = i as f32 * 3.0;
            draw::line_quad(&mut m, Pos2::new(0.0, y), Pos2::new(100.0, y + 1.0), 1.5, Color32::from_rgb((i % 250) as u8, 10, 20));
        }
        m
    }

    /// The parts hold every quad once, in order, each part a mesh of its
    /// own whose indices point into it; the triangles are the same.
    #[test]
    fn the_parts_hold_every_line_once() {
        let whole = quads(1003);
        let parts = split_mesh(whole.clone(), PLAIN_PARTS);
        assert_eq!(parts.len(), PLAIN_PARTS);
        assert_eq!(parts.iter().map(|p| p.indices.len()).sum::<usize>(), whole.indices.len());
        let mut tris = Vec::new();
        for p in &parts {
            assert!(p.is_valid(), "indices inside the part");
            for t in p.indices.chunks(3) {
                tris.push(t.iter().map(|&i| (p.vertices[i as usize].pos, p.vertices[i as usize].color)).collect::<Vec<_>>());
            }
        }
        let want: Vec<_> = whole.indices.chunks(3).map(|t| t.iter().map(|&i| (whole.vertices[i as usize].pos, whole.vertices[i as usize].color)).collect::<Vec<_>>()).collect();
        assert_eq!(tris, want, "the same triangles, in the same order");
    }

    /// Few lines, or none: as many parts as there are lines, never an empty one.
    #[test]
    fn few_lines_make_few_parts() {
        assert!(split_mesh(egui::epaint::Mesh::default(), PLAIN_PARTS).is_empty());
        assert_eq!(split_mesh(quads(3), PLAIN_PARTS).len(), 3);
        assert_eq!(split_mesh(quads(1), 1).len(), 1);
        assert!(split_mesh(quads(17), PLAIN_PARTS).iter().all(|p| !p.indices.is_empty()));
    }
}
