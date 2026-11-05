//! Evidence into the window. A drop on the canvas, the toolbar's button or
//! Evidence › Ingest evidence… opens a wizard: it looks at what was given,
//! says what it is and which parser takes it (and asks when it cannot
//! tell), takes the timeline to write, and runs the parser as a child
//! masstin with the console's own phases and bars mirrored here. The
//! result opens in the window, as a plain table, or in the system's CSV
//! application.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};

use super::tasks::{Job, JobKind};
use super::*;
use crate::view::icons as ic;
use crate::view::theme;

/// A parser the wizard can run.
pub(super) struct Parser {
    pub action: &'static str,
    pub icon: &'static str,
    pub title: &'static str,
    pub desc: &'static str,
}

pub(super) const PARSERS: [Parser; 6] = [
    Parser { action: "parse-windows", icon: ic::DESKTOP, title: "Windows", desc: "EVTX files, triage packages (KAPE, Velociraptor, Cortex XDR) and User Access Logging databases (.mdb), loose or zipped" },
    Parser { action: "parse-linux", icon: ic::TERMINAL_WINDOW, title: "Linux", desc: "auth.log / secure, wtmp, btmp, lastlog, audit.log, journal files, a UAC archive" },
    Parser { action: "parse-mac", icon: ic::LAPTOP, title: "macOS", desc: "a .logarchive bundle (the Unified Log) or a `log show` JSON export" },
    Parser { action: "parse-image", icon: ic::HARD_DRIVES, title: "Disk image", desc: "E01, dd / raw, VMDK, VHD / VHDX: the logs are read from the file system inside, shadow copies included" },
    Parser { action: "parse-massive", icon: ic::CIRCLES_THREE_PLUS, title: "Everything", desc: "A whole evidence folder: images, triage packages and loose EVTX, in one pass, with no mercy" },
    Parser { action: "parser-elastic", icon: ic::CLOUD, title: "Winlogbeat JSON", desc: "Windows events exported from Elasticsearch as Winlogbeat JSON" },
];

const P_WINDOWS: usize = 0;
const P_LINUX: usize = 1;
const P_MAC: usize = 2;
const P_IMAGE: usize = 3;
const P_MASSIVE: usize = 4;
const P_ELASTIC: usize = 5;

/// What a look at the evidence found.
#[derive(Default, Clone)]
pub(super) struct Scan {
    pub evtx: usize,
    pub mdb: usize,
    /// archive name and the kind of triage it is
    pub triages: Vec<(String, &'static str)>,
    /// archives of no known layout
    pub archives: usize,
    /// first segments of disk images
    pub images: Vec<String>,
    /// Linux log family -> files
    pub linux: BTreeMap<&'static str, usize>,
    pub uac: usize,
    pub logarchives: usize,
    pub mac_json: usize,
    pub elastic_json: usize,
    pub timelines: Vec<String>,
    pub files: usize,
    pub dirs: usize,
    /// the walk stopped early (too much, or too slow)
    pub truncated: bool,
    pub secs: f32,
}

impl Scan {
    fn windows(&self) -> usize {
        self.evtx + self.mdb + self.triages.iter().filter(|(_, k)| *k != "UAC").count()
    }
    fn linux_total(&self) -> usize {
        self.linux.values().sum::<usize>() + self.uac + self.triages.iter().filter(|(_, k)| *k == "UAC").count()
    }
    fn mac(&self) -> usize {
        self.logarchives + self.mac_json
    }
}

/// What the look concluded: which parser, how sure, and why.
#[derive(Clone)]
pub(super) struct Verdict {
    /// index into PARSERS; None when the sources are timelines to open as they are
    pub parser: Option<usize>,
    pub sure: bool,
    pub title: String,
    pub why: String,
}

pub(super) fn judge(s: &Scan) -> Verdict {
    let (win, lin, mac, img, ela, tl) = (s.windows(), s.linux_total(), s.mac(), s.images.len(), s.elastic_json, s.timelines.len());
    let n = |k: usize, one: &str, many: &str| if k == 1 { format!("1 {}", one) } else { format!("{} {}", k, many) };
    if win == 0 && lin == 0 && mac == 0 && img == 0 && ela == 0 && tl > 0 {
        return Verdict { parser: None, sure: true, title: "Timelines of masstin".into(), why: format!("{}: already parsed, they open as they are.", n(tl, "timeline CSV", "timeline CSVs")) };
    }
    if img > 0 && win == 0 && lin == 0 && mac == 0 && ela == 0 {
        return Verdict { parser: Some(P_IMAGE), sure: true, title: if img == 1 { "A disk image".into() } else { format!("{} disk images", img) }, why: "The file system inside is read directly: Windows event logs, UAL and shadow copies, or Linux logs, whichever it holds.".into() };
    }
    if img > 0 {
        return Verdict { parser: Some(P_MASSIVE), sure: true, title: "An evidence folder".into(), why: format!("{} with other evidence beside: the massive pass takes the images, the triage packages and the loose EVTX together.", n(img, "disk image", "disk images")) };
    }
    if win > 0 && lin == 0 && mac == 0 && ela == 0 {
        let mut parts = Vec::new();
        if s.evtx > 0 {
            parts.push(n(s.evtx, "EVTX file", "EVTX files"));
        }
        if s.mdb > 0 {
            parts.push(n(s.mdb, "UAL database", "UAL databases"));
        }
        let t = s.triages.len();
        if t > 0 {
            parts.push(n(t, "triage package", "triage packages"));
        }
        return Verdict { parser: Some(P_WINDOWS), sure: true, title: "Windows evidence".into(), why: format!("{}.", parts.join(", ")) };
    }
    if lin > 0 && win == 0 && mac == 0 && ela == 0 {
        let fams: Vec<String> = s.linux.iter().map(|(k, v)| format!("{} {}", v, k)).collect();
        let mut why = fams.join(", ");
        if s.uac > 0 {
            if !why.is_empty() {
                why.push_str(", ");
            }
            why.push_str(&n(s.uac, "UAC archive", "UAC archives"));
        }
        return Verdict { parser: Some(P_LINUX), sure: true, title: "Linux logs".into(), why: format!("{}.", why) };
    }
    if mac > 0 && win == 0 && lin == 0 && ela == 0 {
        return Verdict { parser: Some(P_MAC), sure: true, title: "macOS logs".into(), why: format!("{}{}.", n(s.logarchives, "logarchive bundle", "logarchive bundles"), if s.mac_json > 0 { format!(", {}", n(s.mac_json, "log show export", "log show exports")) } else { String::new() }) };
    }
    if ela > 0 && win == 0 && lin == 0 && mac == 0 {
        return Verdict { parser: Some(P_ELASTIC), sure: true, title: "Winlogbeat JSON".into(), why: format!("{} exported from Elasticsearch.", n(ela, "JSON file", "JSON files")) };
    }
    if win > 0 && lin > 0 {
        return Verdict { parser: Some(P_MASSIVE), sure: false, title: "Windows and Linux together".into(), why: "The massive pass takes the triage packages and the EVTX; loose Linux logs are parse-linux's and need a run of their own. Pick the parser, or split the folder.".into() };
    }
    if win + lin + mac + ela > 0 {
        return Verdict { parser: Some(P_MASSIVE), sure: false, title: "A mix of platforms".into(), why: "Several kinds of evidence side by side. The massive pass is the safe default; one run per platform is cleaner.".into() };
    }
    if s.archives > 0 {
        return Verdict { parser: Some(P_MASSIVE), sure: false, title: "Archives of no known layout".into(), why: format!("{} that is not a triage package masstin recognises. The massive pass looks inside for images; a triage package is better unpacked first.", n(s.archives, "archive", "archives")) };
    }
    Verdict { parser: None, sure: false, title: "Nothing masstin knows how to read".into(), why: "No event logs, triage packages, images or timelines were found here. Pick a parser anyway if the evidence is deeper than the look went, or choose another folder.".into() }
}

/// Walk the sources (bounded: depth, count, time) and count what is there.
fn scan(sources: &[String]) -> Scan {
    let start = std::time::Instant::now();
    let mut s = Scan::default();
    let mut budget = 60_000usize;
    for src in sources {
        let p = Path::new(src);
        if p.is_dir() {
            walk(p, 0, &mut s, &mut budget, &start);
        } else {
            look_at(p, &mut s);
        }
    }
    s.secs = start.elapsed().as_secs_f32();
    s
}

fn walk(dir: &Path, depth: usize, s: &mut Scan, budget: &mut usize, start: &std::time::Instant) {
    if depth > 12 || *budget == 0 || start.elapsed().as_secs_f32() > 8.0 {
        s.truncated = true;
        return;
    }
    let name = dir.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    if name.ends_with(".logarchive") {
        s.logarchives += 1;
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    s.dirs += 1;
    for e in rd.flatten() {
        if *budget == 0 {
            s.truncated = true;
            return;
        }
        *budget -= 1;
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            walk(&p, depth + 1, s, budget, start);
        } else if ft.is_file() {
            look_at(&p, s);
        }
    }
}

fn look_at(p: &Path, s: &mut Scan) {
    s.files += 1;
    let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".evtx") {
        s.evtx += 1;
    } else if lower.ends_with(".mdb") {
        s.mdb += 1;
    } else if lower.ends_with(".zip") {
        let kind = crate::parse::read_zip_top_entries(p).and_then(|entries| crate::parse::detect_triage_type(&p.to_string_lossy(), &entries));
        match kind {
            Some(k) => s.triages.push((name.clone(), k.short_label())),
            None => s.archives += 1,
        }
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") || lower.ends_with(".tar") {
        if lower.starts_with("uac-") {
            s.uac += 1;
        } else {
            s.archives += 1;
        }
    } else if crate::parse_image_windows::is_first_image_segment(p) {
        s.images.push(p.to_string_lossy().to_string());
    } else if lower.ends_with(".json") || lower.ends_with(".ndjson") {
        let head = head_of(p, 4096);
        if head.contains("\"winlog\"") || head.contains("\"event_id\"") && head.contains("\"@timestamp\"") {
            s.elastic_json += 1;
        } else if head.contains("\"eventMessage\"") || head.contains("\"processImagePath\"") || head.contains("\"subsystem\"") {
            s.mac_json += 1;
        }
    } else if lower.ends_with(".csv") {
        let head = head_of(p, 2048);
        let first = head.lines().next().unwrap_or("");
        if crate::csv_out::Layout::of(first).is_some() {
            s.timelines.push(p.to_string_lossy().to_string());
        }
    } else {
        let fam = crate::parse_linux::log_family(&name);
        if fam != "other" && fam != "evtx" {
            *s.linux.entry(fam).or_insert(0) += 1;
        }
    }
}

fn head_of(p: &Path, n: usize) -> String {
    use std::io::Read;
    let mut buf = vec![0u8; n];
    let Ok(mut f) = std::fs::File::open(p) else { return String::new() };
    let got = f.read(&mut buf).unwrap_or(0);
    String::from_utf8_lossy(&buf[..got]).to_string()
}

/// Whether a file is a masstin timeline (by its header).
pub(super) fn is_timeline(p: &Path) -> bool {
    let head = head_of(p, 2048);
    crate::csv_out::Layout::of(head.lines().next().unwrap_or("")).is_some()
}

// ───────────────────────── the wizard's state ─────────────────────────

pub(super) struct Ingest {
    pub open: bool,
    /// 0 evidence, 1 parser, 2 timeline, 3 running / done
    pub step: usize,
    pub sources: Vec<String>,
    scan_rx: Option<Receiver<Scan>>,
    pub scan: Option<Scan>,
    pub verdict: Option<Verdict>,
    pub parser: usize,
    pub output: String,
    pub add: bool,
    pub open_here: bool,
    pub open_table: bool,
    pub open_external: bool,
    pub log_open: bool,
}

impl Default for Ingest {
    fn default() -> Self {
        Ingest { open: false, step: 0, sources: Vec::new(), scan_rx: None, scan: None, verdict: None, parser: P_MASSIVE, output: String::new(), add: false, open_here: true, open_table: false, open_external: false, log_open: false }
    }
}

impl Ingest {
    pub fn command(&self) -> Vec<String> {
        let mut args = vec!["-a".to_string(), PARSERS[self.parser].action.to_string()];
        for s in &self.sources {
            args.push(if Path::new(s).is_dir() { "-d" } else { "-f" }.into());
            args.push(s.clone());
        }
        args.push("-o".into());
        args.push(self.output.trim().to_string());
        args.push("--overwrite".into());
        args
    }

    pub fn command_line(&self) -> String {
        format!("masstin {}", self.command().iter().map(|a| if a.contains(' ') { format!("\"{}\"", a) } else { a.clone() }).collect::<Vec<_>>().join(" "))
    }

    /// A timeline name next to the evidence: `<folder>.csv` or `<file>.csv`.
    pub fn default_output(&self) -> String {
        let Some(first) = self.sources.first() else { return String::new() };
        let p = Path::new(first.trim_end_matches(['\\', '/']));
        let stem = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "timeline".into());
        let dir = if p.is_dir() { p.parent().unwrap_or(p) } else { p.parent().unwrap_or(p) };
        let name = if self.sources.len() > 1 { format!("{}-and-{}-more.csv", stem, self.sources.len() - 1) } else { format!("{}.csv", stem) };
        dir.join(name).to_string_lossy().to_string()
    }
}

impl Viewer {
    /// Open the wizard on these sources (a drop, the menu's pick).
    pub(super) fn ingest_with(&mut self, paths: Vec<String>) {
        let mut sources: Vec<String> = Vec::new();
        for p in paths {
            let p = p.trim().to_string();
            if !p.is_empty() && !sources.contains(&p) {
                sources.push(p);
            }
        }
        self.ingest.sources = sources;
        self.ingest.open = true;
        self.ingest.step = 0;
        self.ingest.scan = None;
        self.ingest.verdict = None;
        self.ingest.output.clear();
        self.start_scan();
    }

    fn start_scan(&mut self) {
        if self.ingest.sources.is_empty() {
            self.ingest.scan = None;
            self.ingest.verdict = None;
            return;
        }
        let (tx, rx) = channel();
        let sources = self.ingest.sources.clone();
        std::thread::spawn(move || {
            let _ = tx.send(scan(&sources));
        });
        self.ingest.scan_rx = Some(rx);
        self.ingest.scan = None;
        self.ingest.verdict = None;
    }

    pub(super) fn poll_scan(&mut self, ctx: &egui::Context) {
        let Some(rx) = self.ingest.scan_rx.as_ref() else { return };
        match rx.try_recv() {
            Ok(s) => {
                let v = judge(&s);
                if let Some(p) = v.parser {
                    self.ingest.parser = p;
                }
                self.ingest.scan = Some(s);
                self.ingest.verdict = Some(v);
                self.ingest.scan_rx = None;
                if self.ingest.output.trim().is_empty() {
                    self.ingest.output = self.ingest.default_output();
                }
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => self.ingest.scan_rx = None,
            Err(_) => ctx.request_repaint_after(std::time::Duration::from_millis(100)),
        }
    }

    /// Files dropped on the window: timelines open (Ctrl or Shift adds them
    /// to the view), anything else goes to the wizard.
    pub(super) fn drop_files(&mut self, paths: Vec<PathBuf>, add: bool) {
        if paths.is_empty() {
            return;
        }
        let all_timelines = paths.iter().all(|p| p.is_file() && p.extension().map_or(false, |e| e.eq_ignore_ascii_case("csv")) && is_timeline(p));
        let names: Vec<String> = paths.iter().map(|p| p.to_string_lossy().to_string()).collect();
        if all_timelines {
            let mut files: Vec<String> = if add { self.files.clone() } else { Vec::new() };
            for n in names {
                if !files.contains(&n) {
                    files.push(n);
                }
            }
            self.open_files(files);
        } else {
            self.ingest_with(names);
        }
    }

    /// Read these timelines into the window (the one way every opener uses).
    pub(super) fn open_files(&mut self, files: Vec<String>) -> bool {
        if files.is_empty() {
            return false;
        }
        let merges = ViewsFile::load(&ViewsFile::path_for(&files[0])).merges;
        match Store::load_with(&files, self.alpha, &merges) {
            Ok(s) => {
                self.store = s;
                self.files = files;
                self.merges = merges;
                self.views_path = ViewsFile::path_for(&self.files[0]);
                self.story_path = Story::path_for(&self.files[0]);
                self.notes = Notes::load(&Notes::path_for(&self.files[0]));
                self.remembered.clear();
                if self.draft.view == View::Findings && !self.store.edges.iter().any(|e| e.hunt != 0) {
                    self.draft.view = View::All;
                }
                self.fit_pending = true;
                self.requery(true);
                self.status = format!("Opened: {}", self.status);
                remember(&self.files);
                self.recent = load_recent();
                true
            }
            Err(e) => {
                self.status = format!("Cannot read: {}", e);
                false
            }
        }
    }

    pub(super) fn run_ingest(&mut self) {
        let args = self.ingest.command();
        let out = self.ingest.output.trim().to_string();
        let title = format!("Parsing with {}", PARSERS[self.ingest.parser].action);
        self.start_job(JobKind::Ingest, title, args, vec![out], self.ingest.add);
        self.ingest.step = 3;
        self.ingest.log_open = false;
    }

    /// The parse ended well: open the timeline the way the wizard was told.
    pub(super) fn finish_ingest(&mut self, out: Vec<String>, add: bool) {
        let mut files: Vec<String> = if add { self.files.clone() } else { Vec::new() };
        for f in &out {
            if !files.contains(f) {
                files.push(f.clone());
            }
        }
        if self.ingest.open_here || self.ingest.open_table {
            self.open_files(files);
        }
        if self.ingest.open_table {
            self.show_table = true;
        }
        if self.ingest.open_external {
            for f in &out {
                if let Err(e) = open_external(f) {
                    self.status = format!("Cannot open {} with the system: {}", f, e);
                }
            }
        }
    }

    // ───────────────────────── the window ─────────────────────────

    pub(super) fn ingest_window(&mut self, ctx: &egui::Context) {
        if !self.ingest.open {
            return;
        }
        self.poll_scan(ctx);
        let mut open = true;
        let mut action: Option<&str> = None;
        let running = self.job.as_ref().map_or(false, |j| j.kind == JobKind::Ingest);
        let title = match self.ingest.step {
            3 if running => format!("{}  Ingest evidence", ic::DOWNLOAD_SIMPLE),
            _ => format!("{}  Ingest evidence", ic::DOWNLOAD_SIMPLE),
        };
        let tall = (ctx.content_rect().height() - 250.0).clamp(320.0, 640.0);
        egui::Window::new(title).id(egui::Id::unique("ingest-wizard")).open(&mut open).collapsible(false).resizable(false).default_width(720.0).max_width(740.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.set_width(700.0);
            ui.set_max_width(700.0);
            stepper(ui, self.ingest.step, &["Evidence", "Parser", "Timeline", "Run"]);
            ui.add_space(6.0);
            egui::ScrollArea::vertical().max_height(tall).auto_shrink([false, true]).show(ui, |ui| match self.ingest.step {
                0 => self.ingest_step_sources(ui, &mut action),
                1 => self.ingest_step_parser(ui),
                2 => self.ingest_step_output(ui),
                _ => self.ingest_step_run(ui, &mut action),
            });
            ui.add_space(8.0);
            theme::hairline(ui);
            // the buttons: Back, the command line, Next / Parse
            ui.horizontal(|ui| {
                if self.ingest.step > 0 && self.ingest.step < 3 {
                    if ui.add(egui::Button::new(format!("{}  Back", ic::ARROW_LEFT)).min_size(Vec2::new(0.0, 30.0))).clicked() {
                        self.ingest.step -= 1;
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let primary = |ui: &mut egui::Ui, text: String, on: bool| ui.add_enabled(on, egui::Button::new(theme::semibold(text, 13.5).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 30.0)).corner_radius(CornerRadius::same(7)));
                    match self.ingest.step {
                        0 => {
                            let timelines_only = self.ingest.verdict.as_ref().map_or(false, |v| v.parser.is_none() && v.sure);
                            if timelines_only {
                                if primary(ui, format!("{}  Open them", ic::FOLDER_OPEN), true).clicked() {
                                    action = Some("open-timelines");
                                }
                            } else {
                                let ready = !self.ingest.sources.is_empty() && self.ingest.scan_rx.is_none();
                                if primary(ui, format!("Next  {}", ic::ARROW_RIGHT), ready).clicked() {
                                    self.ingest.step = 1;
                                }
                            }
                        }
                        1 => {
                            if primary(ui, format!("Next  {}", ic::ARROW_RIGHT), true).clicked() {
                                if self.ingest.output.trim().is_empty() {
                                    self.ingest.output = self.ingest.default_output();
                                }
                                self.ingest.step = 2;
                            }
                        }
                        2 => {
                            let ok = !self.ingest.output.trim().is_empty() && self.job.is_none();
                            if primary(ui, format!("{}  Parse", ic::LIGHTNING), ok).on_hover_text(if self.job.is_some() { "Something is running already" } else { "Start masstin on the evidence" }).clicked() {
                                action = Some("run");
                            }
                        }
                        _ => {
                            let done = self.job.as_ref().map_or(true, |j| j.done.is_some());
                            if done {
                                if ui.add(egui::Button::new("Close").min_size(Vec2::new(0.0, 30.0))).clicked() {
                                    action = Some("close");
                                }
                                if ui.add(egui::Button::new(format!("{}  Parse more", ic::PLUS)).min_size(Vec2::new(0.0, 30.0))).clicked() {
                                    action = Some("more");
                                }
                            } else if ui.add(egui::Button::new(egui::RichText::new(format!("{}  Stop", ic::X)).color(SIGNIFICANT)).min_size(Vec2::new(0.0, 30.0))).clicked() {
                                action = Some("stop");
                            }
                        }
                    }
                    if self.ingest.step < 3 && !self.ingest.sources.is_empty() {
                        ui.add(egui::Label::new(egui::RichText::new(self.ingest.command_line()).monospace().size(10.5).color(theme::DIM)).truncate());
                    }
                });
            });
        });
        match action {
            Some("run") => self.run_ingest(),
            Some("open-timelines") => {
                let files = self.ingest.scan.as_ref().map(|s| s.timelines.clone()).unwrap_or_default();
                if self.open_files(files) {
                    self.ingest.open = false;
                }
            }
            Some("stop") => {
                if let Some(j) = self.job.as_mut() {
                    j.cancel();
                }
            }
            Some("close") => {
                if self.job.as_ref().map_or(false, |j| j.kind == JobKind::Ingest && j.done.is_some()) {
                    let j = self.job.take().unwrap();
                    self.last_log = Some((j.command, j.log));
                }
                self.ingest.open = false;
            }
            Some("more") => {
                if self.job.as_ref().map_or(false, |j| j.kind == JobKind::Ingest && j.done.is_some()) {
                    let j = self.job.take().unwrap();
                    self.last_log = Some((j.command, j.log));
                }
                self.ingest.sources.clear();
                self.ingest.scan = None;
                self.ingest.verdict = None;
                self.ingest.output.clear();
                self.ingest.step = 0;
            }
            _ => {}
        }
        if !open {
            self.ingest.open = false;
        }
    }

    fn ingest_step_sources(&mut self, ui: &mut egui::Ui, action: &mut Option<&str>) {
        let _ = action;
        ui.label(egui::RichText::new("Give masstin the evidence: a folder (a triage, an export of event logs, a whole case), disk images, EVTX files, Linux or macOS logs, or timelines already parsed. It looks at what is there and says which parser takes it.").color(theme::MUTED));
        ui.add_space(8.0);
        // the drop zone
        let hovering = ui.ctx().input(|i| !i.raw.hovered_files.is_empty());
        let (r, p) = ui.allocate_painter(Vec2::new(ui.available_width(), 92.0), Sense::hover());
        let zone = r.rect;
        let stroke = Stroke::new(1.2, if hovering { theme::ACCENT } else { theme::BORDER_2 });
        p.rect_filled(zone, CornerRadius::same(10), if hovering { Color32::from_rgba_unmultiplied(38, 228, 226, 18) } else { theme::PANEL_2 });
        dashed_rect(&p, zone.shrink(1.0), stroke, 10.0);
        p.text(Pos2::new(zone.center().x, zone.top() + 22.0), Align2::CENTER_CENTER, format!("{}  Drop a folder, images, EVTX, logs or a triage here", ic::DOWNLOAD_SIMPLE), FontId::proportional(14.0), if hovering { theme::ACCENT } else { TEXT });
        p.text(Pos2::new(zone.center().x, zone.top() + 42.0), Align2::CENTER_CENTER, "or pick it", FontId::proportional(12.0), theme::DIM);
        let row = Rect::from_center_size(Pos2::new(zone.center().x, zone.bottom() - 20.0), Vec2::new(300.0, 26.0));
        ui.scope_builder(egui::UiBuilder::new().max_rect(row).layout(egui::Layout::left_to_right(egui::Align::Center)), |ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            ui.add_space(30.0);
            if ui.add(egui::Button::new(format!("{}  Folder…", ic::FOLDER_OPEN)).min_size(Vec2::new(0.0, 26.0))).clicked() {
                if let Some(p) = rfd::FileDialog::new().set_title("Evidence folder").pick_folder() {
                    self.add_source(p.to_string_lossy().to_string());
                }
            }
            if ui.add(egui::Button::new(format!("{}  Files…", ic::ARCHIVE)).min_size(Vec2::new(0.0, 26.0))).clicked() {
                if let Some(ps) = rfd::FileDialog::new().set_title("Evidence files (images, EVTX, logs, archives, timelines)").pick_files() {
                    for p in ps {
                        self.add_source(p.to_string_lossy().to_string());
                    }
                }
            }
        });
        if !self.ingest.sources.is_empty() {
            theme::section(ui, "Given");
            let mut remove: Option<usize> = None;
            for (i, s) in self.ingest.sources.iter().enumerate() {
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(egui::RichText::new(ic::X).color(theme::DIM)).frame(false)).on_hover_text("Leave this one out").clicked() {
                        remove = Some(i);
                    }
                    let icon = if Path::new(s).is_dir() { ic::FOLDER_OPEN } else { ic::ARCHIVE };
                    ui.label(egui::RichText::new(format!("{}  {}", icon, s)).size(12.5));
                });
            }
            if let Some(i) = remove {
                self.ingest.sources.remove(i);
                self.ingest.output.clear();
                self.start_scan();
            }
            theme::section(ui, "What masstin found");
            if self.ingest.scan_rx.is_some() {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(14.0).color(theme::ACCENT));
                    ui.label(egui::RichText::new("Looking at what this is…").color(theme::MUTED));
                });
            } else if let (Some(s), Some(v)) = (self.ingest.scan.clone(), self.ingest.verdict.clone()) {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = Vec2::new(6.0, 6.0);
                    count_chip(ui, ic::DESKTOP, s.evtx, "EVTX", theme::CYAN);
                    count_chip(ui, ic::DATABASE, s.mdb, "UAL", theme::CYAN);
                    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
                    for (_, k) in &s.triages {
                        *kinds.entry(k).or_insert(0) += 1;
                    }
                    for (k, n) in kinds {
                        count_chip(ui, ic::ARCHIVE, n, k, theme::VIOLET);
                    }
                    count_chip(ui, ic::HARD_DRIVES, s.images.len(), "disk images", theme::MAGENTA);
                    for (fam, n) in &s.linux {
                        count_chip(ui, ic::TERMINAL_WINDOW, *n, fam, EDGE_OK);
                    }
                    count_chip(ui, ic::ARCHIVE, s.uac, "UAC", EDGE_OK);
                    count_chip(ui, ic::LAPTOP, s.logarchives, "logarchive", CANDIDATE);
                    count_chip(ui, ic::LAPTOP, s.mac_json, "log show JSON", CANDIDATE);
                    count_chip(ui, ic::CLOUD, s.elastic_json, "Winlogbeat JSON", theme::VIOLET);
                    count_chip(ui, ic::TABLE, s.timelines.len(), "timelines", theme::CYAN);
                    count_chip(ui, ic::ARCHIVE, s.archives, "other archives", theme::DIM);
                });
                ui.add_space(4.0);
                ui.label(egui::RichText::new(format!("{} files in {} folders looked at in {:.1} s{}", s.files, s.dirs, s.secs, if s.truncated { "; the look stopped early, the parser goes all the way" } else { "" })).color(theme::DIM).small());
                ui.add_space(6.0);
                let (icon, color) = match (v.parser, v.sure) {
                    (None, true) => (ic::TABLE, theme::CYAN),
                    (Some(p), true) => (PARSERS[p].icon, theme::CYAN),
                    (Some(p), false) => (PARSERS[p].icon, CANDIDATE),
                    (None, false) => (ic::QUESTION, CANDIDATE),
                };
                egui::Frame::new().fill(Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 16)).stroke(Stroke::new(1.0, draw::fade(color, 0.6))).corner_radius(CornerRadius::same(9)).inner_margin(egui::Margin::symmetric(12, 10)).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(icon).size(28.0).color(color));
                        ui.add_space(6.0);
                        ui.vertical(|ui| {
                            ui.label(theme::semibold(&v.title, 15.0).color(TEXT));
                            ui.label(egui::RichText::new(&v.why).color(theme::MUTED).size(12.5));
                            match (v.parser, v.sure) {
                                (Some(p), true) => {
                                    ui.label(egui::RichText::new(format!("{}  {} takes it", ic::CHECK_CIRCLE, PARSERS[p].action)).color(color).size(12.5));
                                }
                                (Some(p), false) => {
                                    ui.label(egui::RichText::new(format!("{}  not sure: {} is offered, the next step lets you choose", ic::WARNING, PARSERS[p].action)).color(color).size(12.5));
                                }
                                (None, false) => {
                                    ui.label(egui::RichText::new(format!("{}  the next step asks you which parser", ic::WARNING)).color(color).size(12.5));
                                }
                                (None, true) => {}
                            }
                        });
                    });
                });
            }
        }
    }

    fn add_source(&mut self, s: String) {
        if !self.ingest.sources.contains(&s) {
            self.ingest.sources.push(s);
            self.ingest.output.clear();
            self.start_scan();
        }
    }

    fn ingest_step_parser(&mut self, ui: &mut egui::Ui) {
        let rec = self.ingest.verdict.as_ref().and_then(|v| v.parser);
        let sure = self.ingest.verdict.as_ref().map_or(false, |v| v.sure);
        ui.label(egui::RichText::new(if sure { "The parser masstin picked, and the others in case you know better." } else { "masstin is not sure which parser this is for. Pick one." }).color(theme::MUTED));
        ui.add_space(6.0);
        for (i, p) in PARSERS.iter().enumerate() {
            let on = self.ingest.parser == i;
            let r = theme::card(ui, on, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(p.icon).size(22.0).color(if on { theme::ACCENT } else { theme::MUTED }));
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(theme::semibold(p.title, 13.5).color(TEXT));
                            ui.label(egui::RichText::new(p.action).monospace().size(11.0).color(theme::DIM));
                            if rec == Some(i) {
                                egui::Frame::new().fill(Color32::from_rgba_unmultiplied(38, 228, 226, 34)).stroke(Stroke::new(1.0, theme::CYAN)).corner_radius(CornerRadius::same(10)).inner_margin(egui::Margin::symmetric(7, 1)).show(ui, |ui| {
                                    ui.label(egui::RichText::new(if sure { "recommended" } else { "offered" }).size(10.5).color(theme::CYAN));
                                });
                            }
                        });
                        ui.label(egui::RichText::new(p.desc).color(theme::MUTED).size(12.0));
                    });
                });
            });
            if r.clicked() {
                self.ingest.parser = i;
            }
        }
    }

    fn ingest_step_output(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("The timeline CSV the parser writes, and what to do with it when it is done.").color(theme::MUTED));
        theme::section(ui, "Timeline to write");
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.ingest.output).desired_width(520.0).hint_text("…\\case.csv"));
            if ui.button(format!("{}  Save as…", ic::FLOPPY_DISK)).clicked() {
                let name = Path::new(&self.ingest.output).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "timeline.csv".into());
                if let Some(p) = rfd::FileDialog::new().set_title("Timeline CSV to write").add_filter("CSV", &["csv"]).set_file_name(name).save_file() {
                    self.ingest.output = p.to_string_lossy().to_string();
                }
            }
        });
        let out = self.ingest.output.trim();
        if !out.is_empty() && Path::new(out).exists() {
            ui.label(egui::RichText::new(format!("{}  this file exists and will be written over", ic::WARNING)).color(CANDIDATE).small());
        } else if let Some(parent) = Path::new(out).parent() {
            if !out.is_empty() && !parent.as_os_str().is_empty() && !parent.exists() {
                ui.label(egui::RichText::new(format!("{}  the folder does not exist; the parser will fail", ic::WARNING)).color(SIGNIFICANT).small());
            }
        }
        theme::section(ui, "When it is done");
        ui.checkbox(&mut self.ingest.open_here, "Open it in this window");
        if self.ingest.open_here && !self.files.is_empty() {
            ui.indent("ingest-add", |ui| {
                ui.radio_value(&mut self.ingest.add, false, "instead of the timelines open now");
                ui.radio_value(&mut self.ingest.add, true, "added to the timelines open now");
            });
        }
        ui.checkbox(&mut self.ingest.open_table, "Show its rows as a table");
        ui.checkbox(&mut self.ingest.open_external, "Open it with the system's CSV application").on_hover_text("Whatever opens .csv files on this machine: a spreadsheet, an editor");
        theme::section(ui, "The command");
        ui.add(egui::Label::new(egui::RichText::new(self.ingest.command_line()).monospace().size(11.5).color(theme::MUTED)).wrap());
        ui.label(egui::RichText::new("The same line works in a terminal or a script.").color(theme::DIM).small());
    }

    fn ingest_step_run(&mut self, ui: &mut egui::Ui, action: &mut Option<&str>) {
        let Some(job) = self.job.as_ref().filter(|j| j.kind == JobKind::Ingest) else {
            ui.label(egui::RichText::new("Nothing is running.").color(theme::MUTED));
            return;
        };
        ui.add(egui::Label::new(egui::RichText::new(&job.command).monospace().size(10.5).color(theme::DIM)).truncate()).on_hover_text(&job.command);
        ui.add_space(6.0);
        progress_ui(ui, job);
        if let Some(Err(e)) = &job.done {
            ui.add_space(4.0);
            if job.stopped {
                egui::Frame::new().fill(Color32::from_rgba_unmultiplied(240, 170, 60, 20)).stroke(Stroke::new(1.0, draw::fade(CANDIDATE, 0.7))).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::symmetric(10, 8)).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(egui::RichText::new(format!("{}  Stopped. Nothing was written; what the parser had extracted under the temp folder goes on its next run.", ic::PROHIBIT)).color(CANDIDATE));
                });
            } else {
                egui::Frame::new().fill(Color32::from_rgba_unmultiplied(236, 72, 96, 22)).stroke(Stroke::new(1.0, draw::fade(SIGNIFICANT, 0.7))).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::symmetric(10, 8)).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(egui::RichText::new(format!("{}  {}", ic::WARNING, e)).color(SIGNIFICANT));
                    let said: Vec<&String> = job.log.iter().filter(|l| l.contains("Error") || l.contains("error") || l.contains("ERROR")).take(3).collect();
                    for l in said {
                        ui.add(egui::Label::new(egui::RichText::new(l).color(TEXT).size(12.5)).wrap());
                    }
                    ui.label(egui::RichText::new("The log below says what the parser saw.").color(theme::MUTED).small());
                });
            }
        }
        if let Some(Ok(())) = &job.done {
            ui.add_space(4.0);
            let outs: Vec<String> = job.open.clone();
            egui::Frame::new().fill(Color32::from_rgba_unmultiplied(38, 228, 226, 14)).stroke(Stroke::new(1.0, draw::fade(theme::CYAN, 0.6))).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::symmetric(12, 10)).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(ic::CHECK_CIRCLE).size(26.0).color(theme::CYAN));
                    ui.vertical(|ui| {
                        ui.label(theme::semibold("The timeline is written", 15.0).color(TEXT));
                        for (k, v) in &job.progress.summary {
                            if k == "Output" {
                                continue;
                            }
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(format!("{}:", k)).color(theme::MUTED).size(12.5));
                                ui.add(egui::Label::new(egui::RichText::new(v).color(TEXT).size(12.5)).truncate());
                            });
                        }
                        for o in &outs {
                            ui.add(egui::Label::new(egui::RichText::new(o).monospace().size(11.0).color(theme::MUTED)).wrap());
                        }
                    });
                });
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    if ui.button(format!("{}  Open here", ic::GRAPH)).clicked() {
                        *action = Some("open-here");
                    }
                    if ui.button(format!("{}  As a table", ic::TABLE)).clicked() {
                        *action = Some("open-table");
                    }
                    if ui.button(format!("{}  System's CSV app", ic::APP_WINDOW)).clicked() {
                        *action = Some("open-external");
                    }
                    if ui.button(format!("{}  Show in folder", ic::FOLDER_OPEN)).clicked() {
                        *action = Some("reveal");
                    }
                });
            });
        }
        ui.add_space(6.0);
        let n = job.log.len();
        egui::CollapsingHeader::new(egui::RichText::new(format!("{}  The parser's log ({} lines)", ic::TERMINAL_WINDOW, n)).color(theme::MUTED)).id_salt("ingest-log").default_open(false).show(ui, |ui| {
            egui::ScrollArea::vertical().stick_to_bottom(true).max_height(200.0).auto_shrink([false, true]).show(ui, |ui| {
                for l in &job.log {
                    ui.add(egui::Label::new(egui::RichText::new(l).monospace().size(11.0)).wrap());
                }
            });
        });
        // the buttons of the done card act after the borrow of the job ends
        let outs = job.open.clone();
        let add = job.add;
        match action.take() {
            Some("open-here") => {
                let mut files: Vec<String> = if add { self.files.clone() } else { Vec::new() };
                for f in &outs {
                    if !files.contains(f) {
                        files.push(f.clone());
                    }
                }
                self.open_files(files);
            }
            Some("open-table") => {
                if !outs.iter().all(|o| self.files.contains(o)) {
                    self.open_files(outs.clone());
                }
                self.show_table = true;
            }
            Some("open-external") => {
                for f in &outs {
                    if let Err(e) = open_external(f) {
                        self.status = format!("Cannot open {} with the system: {}", f, e);
                    }
                }
            }
            Some("reveal") => {
                if let Some(f) = outs.first() {
                    if let Err(e) = reveal_in_folder(f) {
                        self.status = format!("Cannot show {}: {}", f, e);
                    }
                }
            }
            other => *action = other,
        }
    }

    // ───────────────────────── the welcome, when nothing is open ─────────────────────────

    /// The canvas when no timeline is open: the dog, a drop zone, the ways in.
    pub(super) fn welcome(&mut self, ui: &mut egui::Ui) {
        let (resp, painter) = ui.allocate_painter(ui.available_size(), Sense::hover());
        let canvas = resp.rect;
        self.canvas_rect = canvas;
        let now = self.t0.elapsed().as_secs_f32();
        let arcade = self.style.node_style == NodeStyle::Arcade;
        draw::background(&painter, canvas, BG, BG_CENTRE, (0.0, 0.0), 1.0, draw::BgStyle { grid: self.style.grid, vignette: self.style.vignette, arcade, t: now, motion: self.style.motion });
        if self.style.motion && !arcade {
            draw::dust(&painter, canvas, now);
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(33));
        }
        let hovering = ui.ctx().input(|i| !i.raw.hovered_files.is_empty());
        let w = 560.0f32.min(canvas.width() - 40.0);
        let top = canvas.top() + (canvas.height() * 0.12).max(16.0);
        let mut y = top;
        if let Some(t) = &self.logo_dog {
            let r = Rect::from_center_size(Pos2::new(canvas.center().x, y + 60.0), Vec2::new(192.0, 120.0));
            painter.image(t.id(), r, Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)), Color32::WHITE);
            y += 128.0;
        }
        let title_rect = Rect::from_center_size(Pos2::new(canvas.center().x, y + 16.0), Vec2::new(w, 36.0));
        ui.scope_builder(egui::UiBuilder::new().max_rect(title_rect).layout(egui::Layout::top_down(egui::Align::Center)), |ui| {
            theme::wordmark(ui, 30.0);
        });
        y += 40.0;
        painter.text(Pos2::new(canvas.center().x, y + 6.0), Align2::CENTER_TOP, "lateral movement tracker for anything", FontId::proportional(13.0), theme::MUTED);
        y += 40.0;
        // the drop zone
        let zone = Rect::from_min_size(Pos2::new(canvas.center().x - w / 2.0, y), Vec2::new(w, 150.0));
        let pulse = if hovering { 1.0 } else { 0.5 + 0.5 * (now * 1.6).sin() * 0.3 };
        painter.rect_filled(zone, CornerRadius::same(14), if hovering { Color32::from_rgba_unmultiplied(38, 228, 226, 22) } else { draw::fade(theme::PANEL_2, 0.85) });
        dashed_rect(&painter, zone.shrink(1.0), Stroke::new(1.3, draw::fade(theme::CYAN, if hovering { 1.0 } else { 0.35 + 0.25 * pulse })), 12.0);
        painter.text(Pos2::new(zone.center().x, zone.top() + 30.0), Align2::CENTER_CENTER, ic::DOWNLOAD_SIMPLE, FontId::proportional(30.0), if hovering { theme::CYAN } else { draw::fade(theme::CYAN, 0.8) });
        painter.text(Pos2::new(zone.center().x, zone.top() + 62.0), Align2::CENTER_CENTER, if hovering { "Drop it" } else { "Drop evidence or a timeline here" }, FontId::proportional(17.0), TEXT);
        painter.text(Pos2::new(zone.center().x, zone.top() + 84.0), Align2::CENTER_CENTER, "a folder of event logs, a triage package, a disk image, a .logarchive, Linux logs, a timeline CSV", FontId::proportional(11.5), theme::MUTED);
        let row = Rect::from_center_size(Pos2::new(zone.center().x, zone.bottom() - 28.0), Vec2::new(w - 40.0, 32.0));
        let mut open_pick = false;
        let mut ingest_pick = false;
        let mut ingest_files = false;
        ui.scope_builder(egui::UiBuilder::new().max_rect(row).layout(egui::Layout::left_to_right(egui::Align::Center)), |ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            let total = 3.0 * 160.0 + 2.0 * 8.0;
            ui.add_space(((row.width() - total) / 2.0).max(0.0));
            let b = |text: String| egui::Button::new(theme::semibold(text, 13.0).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(160.0, 30.0)).corner_radius(CornerRadius::same(8));
            if ui.add(b(format!("{}  Open a timeline", ic::FOLDER_OPEN))).on_hover_text("A CSV masstin wrote").clicked() {
                open_pick = true;
            }
            let b2 = |text: String| egui::Button::new(theme::semibold(text, 13.0).color(TEXT)).fill(theme::FIELD).stroke(Stroke::new(1.0, theme::BORDER_2)).min_size(Vec2::new(160.0, 30.0)).corner_radius(CornerRadius::same(8));
            if ui.add(b2(format!("{}  Ingest a folder", ic::DOWNLOAD_SIMPLE))).on_hover_text("Evidence masstin parses into a timeline").clicked() {
                ingest_pick = true;
            }
            if ui.add(b2(format!("{}  Ingest files", ic::ARCHIVE))).on_hover_text("Images, EVTX, logs, archives").clicked() {
                ingest_files = true;
            }
        });
        y = zone.bottom() + 22.0;
        // recent timelines
        let recent: Vec<String> = self.recent.iter().filter(|f| Path::new(f).is_file()).take(6).cloned().collect();
        if !recent.is_empty() {
            painter.text(Pos2::new(canvas.center().x - w / 2.0, y), Align2::LEFT_TOP, "RECENT", FontId::proportional(10.5), theme::MUTED);
            y += 18.0;
            let list = Rect::from_min_size(Pos2::new(canvas.center().x - w / 2.0, y), Vec2::new(w, (recent.len() as f32) * 40.0 + 4.0));
            let mut pick: Option<String> = None;
            ui.scope_builder(egui::UiBuilder::new().max_rect(list).layout(egui::Layout::top_down(egui::Align::Min)), |ui| {
                ui.spacing_mut().item_spacing.y = 4.0;
                for f in &recent {
                    let name = Path::new(f).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| f.clone());
                    let dir = Path::new(f).parent().map(|d| d.to_string_lossy().to_string()).unwrap_or_default();
                    let r = theme::card(ui, false, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(ic::TABLE).size(16.0).color(theme::CYAN));
                            ui.vertical(|ui| {
                                ui.label(theme::medium(name.clone(), 13.0).color(TEXT));
                                ui.label(egui::RichText::new(dir).size(11.0).color(theme::DIM));
                            });
                        });
                    });
                    if r.clicked() {
                        pick = Some(f.clone());
                    }
                }
            });
            if let Some(f) = pick {
                self.open_files(vec![f]);
            }
        }
        painter.text(Pos2::new(canvas.center().x, canvas.bottom() - 14.0), Align2::CENTER_BOTTOM, "Evidence › Open timeline… and Ingest evidence… do the same from the menu", FontId::proportional(11.0), theme::DIM);
        if open_pick {
            self.open_timelines(false);
        }
        if ingest_pick {
            if let Some(p) = rfd::FileDialog::new().set_title("Evidence folder").pick_folder() {
                self.ingest_with(vec![p.to_string_lossy().to_string()]);
            }
        }
        if ingest_files {
            if let Some(ps) = rfd::FileDialog::new().set_title("Evidence files (images, EVTX, logs, archives, timelines)").pick_files() {
                self.ingest_with(ps.iter().map(|p| p.to_string_lossy().to_string()).collect());
            }
        }
    }

    /// Files held over the window: a sheet that says what a drop will do.
    pub(super) fn drop_overlay(&mut self, ctx: &egui::Context) {
        let hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());
        if !hovering || self.files.is_empty() {
            return;
        }
        let r = self.canvas_rect;
        if r == Rect::NOTHING {
            return;
        }
        egui::Area::new(egui::Id::unique("drop-overlay")).order(egui::Order::Foreground).fixed_pos(r.min).interactable(false).show(ctx, |ui| {
            let p = ui.painter();
            p.rect_filled(r, CornerRadius::ZERO, Color32::from_rgba_unmultiplied(6, 10, 18, 170));
            let zone = Rect::from_center_size(r.center(), Vec2::new(520.0_f32.min(r.width() - 40.0), 150.0));
            p.rect_filled(zone, CornerRadius::same(14), Color32::from_rgba_unmultiplied(38, 228, 226, 22));
            dashed_rect(p, zone.shrink(1.0), Stroke::new(1.4, theme::CYAN), 12.0);
            p.text(Pos2::new(zone.center().x, zone.top() + 36.0), Align2::CENTER_CENTER, ic::DOWNLOAD_SIMPLE, FontId::proportional(32.0), theme::CYAN);
            p.text(Pos2::new(zone.center().x, zone.top() + 76.0), Align2::CENTER_CENTER, "Drop to open a timeline or ingest evidence", FontId::proportional(17.0), TEXT);
            p.text(Pos2::new(zone.center().x, zone.top() + 100.0), Align2::CENTER_CENTER, "a timeline CSV opens here (Ctrl adds it to the view); anything else goes to the ingest wizard", FontId::proportional(11.5), theme::MUTED);
        });
    }
}

// ───────────────────────── widgets ─────────────────────────

/// The steps of the wizard as numbered dots joined by a line.
fn stepper(ui: &mut egui::Ui, step: usize, labels: &[&str]) {
    let (r, p) = ui.allocate_painter(Vec2::new(ui.available_width(), 46.0), Sense::hover());
    let n = labels.len();
    let pad = 40.0;
    let span = r.rect.width() - 2.0 * pad;
    let xs: Vec<f32> = (0..n).map(|i| r.rect.left() + pad + span * i as f32 / (n - 1).max(1) as f32).collect();
    let y = r.rect.top() + 13.0;
    for i in 0..n.saturating_sub(1) {
        let c = if i < step { theme::CYAN } else { theme::BORDER_2 };
        p.line_segment([Pos2::new(xs[i] + 12.0, y), Pos2::new(xs[i + 1] - 12.0, y)], Stroke::new(1.5, c));
    }
    for (i, l) in labels.iter().enumerate() {
        let c = Pos2::new(xs[i], y);
        let (fill, ring, ink) = if i < step {
            (theme::CYAN, theme::CYAN, theme::ACCENT_INK)
        } else if i == step {
            (Color32::from_rgb(16, 48, 52), theme::CYAN, theme::CYAN)
        } else {
            (theme::PANEL_2, theme::BORDER_2, theme::DIM)
        };
        p.circle_filled(c, 11.0, fill);
        p.circle_stroke(c, 11.0, Stroke::new(1.5, ring));
        let glyph = if i < step { ic::CHECK.to_string() } else { format!("{}", i + 1) };
        p.text(c, Align2::CENTER_CENTER, glyph, FontId::proportional(11.5), ink);
        p.text(Pos2::new(xs[i], y + 18.0), Align2::CENTER_TOP, *l, FontId::proportional(11.0), if i == step { TEXT } else { theme::MUTED });
    }
}

fn dashed_rect(p: &egui::Painter, r: Rect, stroke: Stroke, corner: f32) {
    let c = corner.min(r.width() / 2.0).min(r.height() / 2.0);
    let mut pts: Vec<Pos2> = Vec::new();
    let arc = |pts: &mut Vec<Pos2>, cx: f32, cy: f32, a0: f32, a1: f32| {
        for k in 0..=6 {
            let a = a0 + (a1 - a0) * k as f32 / 6.0;
            pts.push(Pos2::new(cx + c * a.cos(), cy + c * a.sin()));
        }
    };
    use std::f32::consts::PI;
    arc(&mut pts, r.left() + c, r.top() + c, PI, 1.5 * PI);
    arc(&mut pts, r.right() - c, r.top() + c, 1.5 * PI, 2.0 * PI);
    arc(&mut pts, r.right() - c, r.bottom() - c, 0.0, 0.5 * PI);
    arc(&mut pts, r.left() + c, r.bottom() - c, 0.5 * PI, PI);
    pts.push(pts[0]);
    p.add(egui::Shape::dashed_line(&pts, stroke, 7.0, 5.0));
}

/// `icon n what` in a pill of the category's colour: one widget, so a
/// wrapped row moves it whole.
fn count_chip(ui: &mut egui::Ui, icon: &str, n: usize, what: &str, color: Color32) {
    if n == 0 {
        return;
    }
    let mut job = egui::text::LayoutJob::default();
    let plain = |c: Color32| egui::TextFormat { font_id: FontId::proportional(12.5), color: c, ..Default::default() };
    job.append(icon, 0.0, plain(color));
    job.append(&format!(" {}", n), 0.0, egui::TextFormat { font_id: FontId::new(12.5, egui::FontFamily::Name(theme::SEMIBOLD.into())), color: TEXT, ..Default::default() });
    job.append(&format!(" {}", what), 0.0, plain(TEXT));
    let b = egui::Button::new(job).fill(Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 26)).stroke(Stroke::new(1.0, Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 140))).corner_radius(CornerRadius::same(12)).min_size(Vec2::new(0.0, 22.0)).sense(Sense::hover()).wrap_mode(egui::TextWrapMode::Extend);
    ui.add(b);
}

/// The console's phases and bars, as the window draws them.
pub(super) fn progress_ui(ui: &mut egui::Ui, job: &Job) {
    let pr = &job.progress;
    let elapsed = job.elapsed();
    let done_ok = matches!(job.done, Some(Ok(())));
    let failed = matches!(job.done, Some(Err(_)));
    ui.horizontal(|ui| {
        if job.done.is_none() {
            ui.add(egui::Spinner::new().size(14.0).color(theme::ACCENT));
            ui.label(theme::medium(format!("{}  {:.0} s", job.title, elapsed), 13.0).color(TEXT));
        } else if job.stopped {
            ui.label(egui::RichText::new(ic::PROHIBIT).color(CANDIDATE).size(15.0));
            ui.label(theme::medium(format!("Stopped after {:.1} s", elapsed), 13.0).color(TEXT));
        } else if done_ok {
            ui.label(egui::RichText::new(ic::CHECK_CIRCLE).color(theme::CYAN).size(15.0));
            ui.label(theme::medium(format!("Done in {:.1} s", elapsed), 13.0).color(TEXT));
        } else {
            ui.label(egui::RichText::new(ic::WARNING).color(SIGNIFICANT).size(15.0));
            ui.label(theme::medium(format!("Failed after {:.1} s", elapsed), 13.0).color(TEXT));
        }
    });
    ui.add_space(4.0);
    if pr.phases.is_empty() && job.done.is_none() {
        ui.horizontal(|ui| {
            ui.add_space(22.0);
            ui.label(egui::RichText::new("Starting…").color(theme::MUTED));
        });
    }
    let last = pr.phases.len().saturating_sub(1);
    for (i, (tag, text)) in pr.phases.iter().enumerate() {
        let current = i == last && job.done.is_none();
        let finished = i < last || done_ok;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            let (glyph, c) = if finished {
                (ic::CHECK_CIRCLE, theme::CYAN)
            } else if current {
                (ic::RADIO_BUTTON, theme::CYAN)
            } else if failed {
                (ic::WARNING, SIGNIFICANT)
            } else {
                (ic::CIRCLE, theme::DIM)
            };
            ui.label(egui::RichText::new(glyph).color(c).size(14.0));
            ui.label(egui::RichText::new(tag).monospace().size(11.0).color(theme::DIM));
            ui.add(egui::Label::new(if current { theme::medium(text, 13.0).color(TEXT) } else { egui::RichText::new(text).size(13.0).color(if finished { TEXT } else { theme::MUTED }) }).truncate());
        });
        if i == last {
            // the bar and the spinner belong to the phase under way
            if let Some((pos, len, msg)) = &pr.bar {
                ui.horizontal(|ui| {
                    ui.add_space(22.0);
                    ui.vertical(|ui| {
                        bar_ui(ui, *pos, *len, msg, done_ok);
                    });
                });
            }
            if let Some(msg) = &pr.spinner {
                if job.done.is_none() {
                    ui.horizontal(|ui| {
                        ui.add_space(22.0);
                        ui.add(egui::Spinner::new().size(11.0).color(theme::MUTED));
                        ui.label(egui::RichText::new(msg).color(theme::MUTED).size(12.0));
                    });
                }
            }
        }
    }
    if !pr.notes.is_empty() {
        ui.add_space(2.0);
        let from = pr.notes.len().saturating_sub(8);
        for n in &pr.notes[from..] {
            ui.horizontal(|ui| {
                ui.add_space(22.0);
                ui.add(egui::Label::new(egui::RichText::new(format!("{}  {}", ic::CARET_RIGHT, n)).color(EDGE_OK).size(12.0)).truncate());
            });
        }
    }
}

/// A bar like the console's `[=====>----] 12/120 Security.evtx`, drawn.
fn bar_ui(ui: &mut egui::Ui, pos: u64, len: u64, msg: &str, done: bool) {
    let w = ui.available_width().min(560.0);
    let (r, p) = ui.allocate_painter(Vec2::new(w, 12.0), Sense::hover());
    let track = r.rect.shrink2(Vec2::new(0.0, 2.0));
    p.rect_filled(track, CornerRadius::same(4), theme::FIELD);
    let f = if done { 1.0 } else if len == 0 { 0.0 } else { (pos as f32 / len as f32).clamp(0.0, 1.0) };
    if f > 0.0 {
        let fill = Rect::from_min_size(track.min, Vec2::new((track.width() * f).max(6.0), track.height()));
        let mut mesh = egui::epaint::Mesh::default();
        let v = |x: f32, y: f32, c: Color32| egui::epaint::Vertex { pos: Pos2::new(x, y), uv: egui::epaint::WHITE_UV, color: c };
        let (a, b) = (theme::CYAN, theme::VIOLET);
        mesh.vertices.extend([v(fill.left(), fill.top(), a), v(fill.right(), fill.top(), b), v(fill.right(), fill.bottom(), b), v(fill.left(), fill.bottom(), a)]);
        mesh.add_triangle(0, 1, 2);
        mesh.add_triangle(0, 2, 3);
        p.with_clip_rect(fill).add(egui::Shape::mesh(mesh));
        p.rect_stroke(fill, CornerRadius::same(4), Stroke::new(1.0, draw::fade(theme::CYAN, 0.5)), egui::StrokeKind::Inside);
    }
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        ui.label(egui::RichText::new(format!("{} / {}", pos, len)).monospace().size(11.0).color(theme::CYAN));
        ui.label(egui::RichText::new(format!("{:.0} %", f * 100.0)).monospace().size(11.0).color(theme::DIM));
        if !msg.is_empty() {
            ui.add(egui::Label::new(egui::RichText::new(msg).size(11.5).color(theme::MUTED)).truncate());
        }
    });
}

// ───────────────────────── the system, recent files ─────────────────────────

/// Open a file with whatever the system opens it with.
pub(super) fn open_external(path: &str) -> Result<(), String> {
    let mut cmd;
    #[cfg(windows)]
    {
        cmd = std::process::Command::new("cmd");
        cmd.args(["/C", "start", "", path]);
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    #[cfg(target_os = "macos")]
    {
        cmd = std::process::Command::new("open");
        cmd.arg(path);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        cmd = std::process::Command::new("xdg-open");
        cmd.arg(path);
    }
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    cmd.spawn().map(|_| ()).map_err(|e| e.to_string())
}

/// Show a file in the system's file manager.
pub(super) fn reveal_in_folder(path: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        let mut cmd = std::process::Command::new("explorer");
        cmd.arg(format!("/select,{}", path));
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
        return cmd.spawn().map(|_| ()).map_err(|e| e.to_string());
    }
    #[allow(unreachable_code)]
    {
        let dir = Path::new(path).parent().map(|d| d.to_string_lossy().to_string()).unwrap_or_else(|| ".".into());
        open_external(&dir)
    }
}

fn recent_path() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    }?;
    Some(base.join("masstin").join("recent.json"))
}

pub(super) fn load_recent() -> Vec<String> {
    let Some(p) = recent_path() else { return Vec::new() };
    let Ok(s) = std::fs::read_to_string(&p) else { return Vec::new() };
    serde_json::from_str::<Vec<String>>(&s).unwrap_or_default()
}

/// Put these files at the top of the recent list (ten kept).
pub(super) fn remember(files: &[String]) {
    let Some(p) = recent_path() else { return };
    let mut list = load_recent();
    for f in files.iter().rev() {
        list.retain(|x| x != f);
        list.insert(0, f.clone());
    }
    list.truncate(10);
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(s) = serde_json::to_string_pretty(&list) {
        let _ = std::fs::write(&p, s);
    }
}

/// A path the viewer uses for its side files when no timeline is open:
/// under the temp folder, so the style survives the welcome screen.
pub(super) fn scratch_csv() -> String {
    std::env::temp_dir().join("masstin").join("welcome.csv").to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_of_evtx_is_windows() {
        let mut s = Scan::default();
        s.evtx = 12;
        let v = judge(&s);
        assert_eq!(v.parser, Some(P_WINDOWS));
        assert!(v.sure);
    }

    #[test]
    fn images_beside_evtx_are_massive_and_alone_an_image() {
        let mut s = Scan::default();
        s.images.push("a.E01".into());
        assert_eq!(judge(&s).parser, Some(P_IMAGE));
        s.evtx = 1;
        assert_eq!(judge(&s).parser, Some(P_MASSIVE));
    }

    #[test]
    fn linux_and_windows_together_are_not_sure() {
        let mut s = Scan::default();
        s.evtx = 1;
        s.linux.insert("secure", 2);
        let v = judge(&s);
        assert_eq!(v.parser, Some(P_MASSIVE));
        assert!(!v.sure);
    }

    #[test]
    fn timelines_alone_open_and_nothing_asks() {
        let mut s = Scan::default();
        s.timelines.push("t.csv".into());
        let v = judge(&s);
        assert_eq!(v.parser, None);
        assert!(v.sure);
        let v = judge(&Scan::default());
        assert_eq!(v.parser, None);
        assert!(!v.sure);
    }

    #[test]
    fn a_uac_archive_is_linux_and_a_logarchive_mac() {
        let mut s = Scan::default();
        s.uac = 1;
        assert_eq!(judge(&s).parser, Some(P_LINUX));
        let mut s = Scan::default();
        s.logarchives = 1;
        assert_eq!(judge(&s).parser, Some(P_MAC));
    }

    #[test]
    fn the_command_line_names_folders_and_files() {
        let dir = std::env::temp_dir();
        let mut i = Ingest::default();
        i.parser = P_WINDOWS;
        i.sources = vec![dir.to_string_lossy().to_string(), "C:\\no such\\file.evtx".into()];
        i.output = "out.csv".into();
        let c = i.command();
        assert_eq!(&c[..2], &["-a", "parse-windows"]);
        assert_eq!(c[2], "-d");
        assert_eq!(c[4], "-f");
        assert_eq!(&c[6..], &["-o", "out.csv", "--overwrite"]);
    }
}
