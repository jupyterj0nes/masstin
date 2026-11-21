//! Evidence into the window. A drop on the canvas, the toolbar's button or
//! Evidence › Ingest evidence… opens a wizard: it looks at what was given,
//! says what it is and which parser takes it (and asks when it cannot
//! tell), takes the timeline to write, and runs the parser as a child
//! masstin with the console's own phases and bars mirrored here. The
//! result opens in the window, as a plain table, or in the system's CSV
//! application.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;

use super::tasks::{Job, JobKind};
use super::*;
use crate::view::icons as ic;
use crate::view::theme;
use crate::detect::{self, is_timeline, judge, Limits, Scan, Verdict};

/// A parser the wizard can run.
pub(super) struct Parser {
    pub action: &'static str,
    pub icon: &'static str,
    pub title: &'static str,
    pub desc: &'static str,
}

pub(super) const PARSERS: [Parser; 6] = [
    Parser { action: "parse-windows", icon: ic::DESKTOP, title: "Windows", desc: "EVTX files, triage packages (KAPE, Velociraptor, a Cortex XDR offline collector) and User Access Logging databases (.mdb), loose or zipped" },
    Parser { action: "parse-linux", icon: ic::TERMINAL_WINDOW, title: "Linux", desc: "auth.log / secure, wtmp, btmp, lastlog, audit.log, journal files, a UAC archive" },
    Parser { action: "parse-mac", icon: ic::LAPTOP, title: "macOS", desc: "a .logarchive bundle (the Unified Log) or a `log show` JSON export" },
    Parser { action: "parse-image", icon: ic::HARD_DRIVES, title: "Disk image", desc: "E01, dd / raw, VMDK, VHD / VHDX: the logs are read from the file system inside, shadow copies included" },
    Parser { action: "parse-massive", icon: ic::CIRCLES_THREE_PLUS, title: "Everything", desc: "A whole evidence folder: disk images, Windows and Linux triages, loose EVTX and Linux logs, read together into one timeline" },
    Parser { action: "parser-elastic", icon: ic::CLOUD, title: "Windows events as JSON", desc: "Windows events exported as JSON: Winlogbeat, evtx_dump, Velociraptor, or flat (NXLog, Sentinel)" },
];

const P_WINDOWS: usize = 0;
const P_LINUX: usize = 1;
const P_MAC: usize = 2;
const P_IMAGE: usize = 3;
const P_MASSIVE: usize = 4;
const P_ELASTIC: usize = 5;

/// The wizard's card for a parser the detector named.
fn pidx(action: &str) -> usize {
    PARSERS.iter().position(|p| p.action == action).unwrap_or(P_MASSIVE)
}

// ───────────────────────── the wizard's state ─────────────────────────

pub(super) struct Ingest {
    pub open: bool,
    /// 0 evidence, 1 parser, 2 timeline, 3 running / done
    pub step: usize,
    pub sources: Vec<String>,
    /// what the look found so far, and whether it is done
    scan_rx: Option<Receiver<(Scan, bool)>>,
    /// stops the look under way (other evidence given, or the parse started)
    scan_cancel: Option<Arc<AtomicBool>>,
    pub scan: Option<Scan>,
    pub verdict: Option<Verdict>,
    pub parser: usize,
    pub output: String,
    pub add: bool,
    /// The timeline open in the window that the new evidence is appended to
    /// (its rows added, sorted, duplicates dropped; the rows it has keep their
    /// marks and their hunt). Empty: the parse writes a timeline of its own.
    pub append_to: String,
    /// the append was proposed once for this evidence (the analyst's choice stays)
    pub append_offered: bool,
    pub open_here: bool,
    pub open_table: bool,
    pub open_external: bool,
    pub log_open: bool,
    /// `--carve`: the disk images are also carved for the EVTX records of
    /// deleted or overwritten logs (offered when the evidence holds images)
    pub carve: bool,
    /// `--rules`: a YAML rule file or folder for the logs masstin does not
    /// know (a VPN, a firewall, a proxy)
    pub rules: String,
    /// noise left out of the timeline: `--ignore-local`, `--exclude-users`,
    /// `--exclude-hosts`, `--exclude-ips`
    pub ignore_local: bool,
    pub exclude_users: String,
    pub exclude_hosts: String,
    pub exclude_ips: String,
    /// only the carving (`carve-image`): the images' file systems not read
    pub carve_only: bool,
    /// advanced: `--threads`, `--parallel-images`, `--skip-offsets`, `--debug`
    pub threads: String,
    pub parallel_images: String,
    pub skip_offsets: String,
    pub debug: bool,
}

impl Default for Ingest {
    fn default() -> Self {
        Ingest { open: false, step: 0, sources: Vec::new(), scan_rx: None, scan_cancel: None, scan: None, verdict: None, parser: P_MASSIVE, output: String::new(), add: false, append_to: String::new(), append_offered: false, open_here: true, open_table: false, open_external: false, log_open: false, carve: false, rules: String::new(), ignore_local: false, exclude_users: String::new(), exclude_hosts: String::new(), exclude_ips: String::new(), carve_only: false, threads: String::new(), parallel_images: String::new(), skip_offsets: String::new(), debug: false }
    }
}

impl Ingest {
    /// What the look found so far: the verdict follows it, and so does the
    /// parser while it is still the one masstin picked (a parser chosen by
    /// hand stays).
    pub fn take_scan(&mut self, s: Scan) {
        let v = judge(&s);
        // (a verdict of no parser, timelines so far, left the choice open)
        let picked = self.verdict.as_ref().map_or(true, |old| old.parser.map_or(true, |p| pidx(p) == self.parser));
        if picked {
            if let Some(p) = v.parser {
                self.parser = pidx(p);
            }
        }
        self.scan = Some(s);
        self.verdict = Some(v);
        if self.output.trim().is_empty() {
            self.output = self.default_output();
        }
    }

    /// Whether the parser is the one masstin picked for sure: then the
    /// command is `masstin -a parse`, which makes the same choice.
    pub fn is_auto(&self) -> bool {
        self.verdict.as_ref().map_or(false, |v| v.sure && v.parser.map(pidx) == Some(self.parser))
    }

    /// Whether the evidence holds disk images (what carving reads).
    pub fn has_images(&self) -> bool {
        self.scan.as_ref().map_or(false, |s| !s.images.is_empty())
    }

    /// Carving asked for, on evidence that has images to carve (or may: a
    /// look that stopped early may not have reached them).
    pub fn carve_on(&self) -> bool {
        self.carve && (self.has_images() || self.scan.as_ref().map_or(false, |s| s.truncated))
    }

    /// Rules given for the logs masstin does not know.
    pub fn rules_on(&self) -> bool {
        !self.rules.trim().is_empty()
    }

    /// Whether the command is `masstin -a parse`: the parser masstin picked,
    /// or an option only `parse` has (carving, rules), which then reads what
    /// it knows by itself and the rest with the rules.
    /// The new evidence goes into the timeline open in the window: `parse`
    /// reads that timeline with the evidence and writes over it.
    pub fn append_on(&self) -> bool {
        !self.append_to.trim().is_empty() && self.uses_parse() && !self.carve_only_on()
    }

    /// The timeline the run writes.
    pub fn target(&self) -> String {
        if self.append_on() { self.append_to.trim().to_string() } else { self.output.trim().to_string() }
    }

    pub fn uses_parse(&self) -> bool {
        self.is_auto() || self.carve_on() || self.rules_on()
    }

    /// Only the carving can be asked for: every source is a file and the
    /// look found images among them.
    pub fn carve_only_possible(&self) -> bool {
        self.has_images() && self.sources.iter().all(|s| !Path::new(s).is_dir())
    }

    /// The run is `carve-image`: carving alone, the file systems not read.
    pub fn carve_only_on(&self) -> bool {
        self.carve_on() && self.carve_only && self.carve_only_possible()
    }

    pub fn command(&self) -> Vec<String> {
        if self.carve_only_on() {
            let mut args = vec!["-a".to_string(), "carve-image".to_string()];
            for s in &self.sources {
                args.push("-f".into());
                args.push(s.clone());
            }
            if !self.skip_offsets.trim().is_empty() {
                args.push("--skip-offsets".into());
                args.push(self.skip_offsets.trim().to_string());
            }
            self.push_advanced(&mut args);
            args.push("-o".into());
            args.push(self.output.trim().to_string());
            args.push("--overwrite".into());
            return args;
        }
        let action = if self.uses_parse() { "parse" } else { PARSERS[self.parser].action };
        let mut args = vec!["-a".to_string(), action.to_string()];
        for s in &self.sources {
            args.push(if Path::new(s).is_dir() { "-d" } else { "-f" }.into());
            args.push(s.clone());
        }
        if self.append_on() {
            args.push("-f".into());
            args.push(self.append_to.trim().to_string());
        }
        if self.rules_on() {
            args.push("--rules".into());
            args.push(self.rules.trim().to_string());
        }
        if self.carve_on() {
            args.push("--carve".into());
        }
        if self.ignore_local {
            args.push("--ignore-local".into());
        }
        for (flag, v) in [("--exclude-users", &self.exclude_users), ("--exclude-hosts", &self.exclude_hosts), ("--exclude-ips", &self.exclude_ips)] {
            if !v.trim().is_empty() {
                args.push(flag.into());
                args.push(v.trim().to_string());
            }
        }
        if self.carve_on() && !self.skip_offsets.trim().is_empty() {
            args.push("--skip-offsets".into());
            args.push(self.skip_offsets.trim().to_string());
        }
        self.push_advanced(&mut args);
        args.push("-o".into());
        args.push(self.target());
        args.push("--overwrite".into());
        args
    }

    /// `--threads`, `--parallel-images`, `--debug`, when set.
    fn push_advanced(&self, args: &mut Vec<String>) {
        if let Ok(n) = self.threads.trim().parse::<usize>() {
            if n > 0 {
                args.push("--threads".into());
                args.push(n.to_string());
            }
        }
        if self.has_images() {
            if let Ok(n) = self.parallel_images.trim().parse::<usize>() {
                if n > 0 {
                    args.push("--parallel-images".into());
                    args.push(n.to_string());
                }
            }
        }
        if self.debug {
            args.push("--debug".into());
        }
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
        // never the evidence itself: a log called `fw.csv` gave `fw.csv`,
        // and the run wrote the timeline over it
        let same = |a: &Path, b: &str| a.to_string_lossy().replace('\\', "/").eq_ignore_ascii_case(&b.trim_end_matches(['\\', '/']).replace('\\', "/"));
        let mut out = dir.join(&name);
        if self.sources.iter().any(|s| same(&out, s)) {
            out = dir.join(format!("{}-timeline.csv", stem));
        }
        out.to_string_lossy().to_string()
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
            self.ingest.append_offered = false;
        self.ingest.carve = false;
        self.ingest.rules.clear();
        self.ingest.ignore_local = false;
        self.ingest.exclude_users.clear();
        self.ingest.exclude_hosts.clear();
        self.ingest.exclude_ips.clear();
        self.ingest.carve_only = false;
        self.ingest.threads.clear();
        self.ingest.parallel_images.clear();
        self.ingest.skip_offsets.clear();
        self.ingest.debug = false;
        self.start_scan();
    }

    /// The look at the evidence, in the background: what it finds is shown
    /// as it comes (level by level, so an image beside a deep folder shows
    /// up early) and the wizard goes on meanwhile; it goes as far as the
    /// parser does (`Limits::WINDOW`).
    fn start_scan(&mut self) {
        self.stop_scan();
        if self.ingest.sources.is_empty() {
            self.ingest.scan = None;
            self.ingest.verdict = None;
            return;
        }
        let (tx, rx) = channel();
        let sources = self.ingest.sources.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        std::thread::spawn(move || {
            let s = detect::scan_with(&sources, Limits::WINDOW, &stop, |s| {
                let _ = tx.send((s.clone(), false));
            });
            let _ = tx.send((s, true));
        });
        self.ingest.scan_rx = Some(rx);
        self.ingest.scan_cancel = Some(cancel);
        self.ingest.scan = None;
        self.ingest.verdict = None;
    }

    /// Stops the look under way, if any: what it found stays.
    pub(super) fn stop_scan(&mut self) {
        if let Some(c) = self.ingest.scan_cancel.take() {
            c.store(true, Ordering::Relaxed);
        }
        self.ingest.scan_rx = None;
    }

    pub(super) fn poll_scan(&mut self, ctx: &egui::Context) {
        if self.ingest.scan_rx.is_some() && !self.ingest.open {
            // the wizard was closed: nobody is waiting for the look
            self.stop_scan();
            return;
        }
        let Some(rx) = self.ingest.scan_rx.as_ref() else { return };
        // the latest of what came since the last frame
        let mut latest: Option<(Scan, bool)> = None;
        let mut gone = false;
        loop {
            match rx.try_recv() {
                Ok(m) => latest = Some(m),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    gone = true;
                    break;
                }
            }
        }
        if let Some((s, done)) = latest {
            self.ingest.take_scan(s);
            if done {
                self.ingest.scan_rx = None;
                self.ingest.scan_cancel = None;
                return;
            }
        }
        if gone {
            self.ingest.scan_rx = None;
            self.ingest.scan_cancel = None;
            return;
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(250));
    }

    /// Files dropped on the window: timelines open (Ctrl or Shift adds them
    /// to the view), anything else goes to the wizard.
    pub(super) fn drop_files(&mut self, paths: Vec<PathBuf>, add: bool) {
        if paths.is_empty() {
            return;
        }
        if let Some(c) = paths.iter().find(|p| p.is_file() && case::is_case(&p.to_string_lossy())) {
            self.open_case(c.clone());
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
        // timelines added to the open case stay in it; others leave it
        let in_case = self.case.is_some() && self.files.iter().all(|f| files.contains(f));
        // Another timeline is another set of side files: its saved views,
        // its subnets and its merges are read from ITS views file. Only the
        // merges were, so the next change of style wrote the views of the
        // timeline open before (or none) over the ones this timeline had.
        // A timeline with its masstin file next to it (the parsers and the
        // hunt make it) is opened as that case: what is kept goes there,
        // not into more files next to the timeline.
        let own_case = if in_case { None } else { case::of_timeline(&files) };
        let own = if in_case || own_case.is_some() { None } else { Some(ViewsFile::load(&ViewsFile::path_for(&files[0]))) };
        let merges = match (&own_case, &own) {
            (Some((_, c)), _) => c.views.merges.clone(),
            (None, Some(vf)) => vf.merges.clone(),
            (None, None) => self.merges.clone(),
        };
        let what = if files.len() == 1 { std::path::Path::new(&files[0]).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| files[0].clone()) } else { format!("{} timelines", files.len()) };
        self.load_then(
            files.clone(),
            merges.clone(),
            what,
            Box::new(move |v: &mut Viewer, r: Result<Store, String>| match r {
                Ok(s) => {
                    v.table_raw_cache.clear();
                    v.store = s;
                    v.files = files;
                    v.merges = merges;
                    if let Some(vf) = own {
                        v.saved = vf.views;
                        v.subnet_defs = vf.subnets;
                        if let Some(st) = vf.last_style {
                            v.style = st;
                        }
                        v.case_missing.clear();
                    }
                    if let Some((_, c)) = &own_case {
                        v.saved = c.views.views.clone();
                        v.subnet_defs = c.views.subnets.clone();
                        if let Some(st) = c.views.last_style.clone() {
                            v.style = st;
                        }
                        v.case_missing.clear();
                    }
                    // what was typed for the timeline open before is not this
                    // one's: the hunt's dates, seeds and files, the merge's list
                    v.hunt_form = super::hunt::HuntForm::default();
                    v.merge_form = super::tasks::MergeForm { inputs: Vec::new(), output: String::new(), from: String::new(), to: String::new(), carry: String::new() };
                    v.builtin = super::super::views::builtin_views(v.store.t_max);
                    v.views_path = ViewsFile::path_for(&v.files[0]);
                    v.story_path = Story::path_for(&v.files[0]);
                    if !in_case {
                        match own_case {
                            Some((p, c)) => {
                                v.story = c.story;
                                v.notes = Notes { path: p.clone(), notes: c.notes };
                                v.case = Some(p);
                            }
                            None => {
                                v.case = None;
                                v.story = Story::load(&v.story_path);
                                v.notes = Notes::load(&Notes::path_for(&v.files[0]));
                            }
                        }
                    }
                    v.remembered.clear();
                    if v.draft.view == View::Findings && !v.store.edges.iter().any(|e| e.hunt != 0) {
                        v.draft.view = View::All;
                    }
                    v.fit_pending = true;
                    v.requery(true);
                    v.status = format!("Opened: {}", v.status);
                    match v.case.clone() {
                        Some(p) => {
                            if let Err(e) = v.write_case(&p) {
                                v.status = format!("cannot write the case {}: {}", p.display(), e);
                            }
                            remember(&[p.to_string_lossy().to_string()]);
                        }
                        None => remember(&v.files),
                    }
                    v.recent = load_recent();
                }
                Err(e) => v.status = format!("Cannot read: {}", e),
            }),
        );
        true
    }

    pub(super) fn run_ingest(&mut self) {
        // the parse looks at everything again: the look would only compete with it for the disk
        self.stop_scan();
        let args = self.ingest.command();
        let out = self.ingest.target();
        let appending = self.ingest.append_on();
        let title = if self.ingest.carve_only_on() { "Carving".to_string() } else if self.ingest.uses_parse() { "Parsing".to_string() } else { format!("Parsing with {}", PARSERS[self.ingest.parser].action) };
        self.start_job(JobKind::Ingest, title, args, vec![out], self.ingest.add && !appending);
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
                                let ready = !self.ingest.sources.is_empty() && self.ingest.scan.is_some();
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
            Some("cortex") => {
                // the same question, answered by a tenant instead of a folder
                open = false;
                self.show_cortex = true;
            }
            Some("open-timelines") => {
                let files = self.ingest.scan.as_ref().map(|s| s.timelines.clone()).unwrap_or_default();
                if self.open_files(files) {
                    self.ingest.open = false;
                }
            }
            Some("stop") => {
                // (the parse of this wizard: a hunt under way is not its to stop)
                if let Some(j) = self.job.as_mut().filter(|j| j.kind == JobKind::Ingest) {
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
            self.ingest.append_offered = false;
                self.ingest.carve = false;
                self.ingest.carve_only = false;
                self.ingest.rules.clear();
                // the next evidence starts clean: the rows left out, the
                // threads and the debug of this run were its own
                self.ingest.ignore_local = false;
                self.ingest.exclude_users.clear();
                self.ingest.exclude_hosts.clear();
                self.ingest.exclude_ips.clear();
                self.ingest.threads.clear();
                self.ingest.parallel_images.clear();
                self.ingest.skip_offsets.clear();
                self.ingest.debug = false;
                self.ingest.step = 0;
            }
            _ => {}
        }
        if !open {
            self.ingest.open = false;
        }
    }

    fn ingest_step_sources(&mut self, ui: &mut egui::Ui, action: &mut Option<&str>) {
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
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Nothing on disk?").color(theme::MUTED).size(12.5));
            if ui.add(egui::Button::new(format!("{}  Read it from a Cortex XDR tenant…", ic::CLOUD)).min_size(Vec2::new(0.0, 26.0))).on_hover_text("Lateral movement straight from a Cortex XDR tenant through its API: network connections, the event logs the agents send and the ones the forensics add-on collected, into one timeline. A wizard checks the connection first").clicked() {
                *action = Some("cortex");
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
            self.ingest.append_offered = false;
                self.start_scan();
            }
            theme::section(ui, "What masstin found");
            if self.ingest.scan_rx.is_some() && self.ingest.scan.is_none() {
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
                    count_chip(ui, ic::HARD_DRIVES, s.images.len(), plural(s.images.len(), "disk image", "disk images"), theme::MAGENTA);
                    for (fam, n) in &s.linux {
                        count_chip(ui, ic::TERMINAL_WINDOW, *n, fam, EDGE_OK);
                    }
                    count_chip(ui, ic::ARCHIVE, s.uac, plural(s.uac, "UAC triage", "UAC triages"), EDGE_OK);
                    count_chip(ui, ic::TERMINAL_WINDOW, s.linux_tars, plural(s.linux_tars, "Linux triage", "Linux triages"), EDGE_OK);
                    count_chip(ui, ic::LAPTOP, s.logarchives, "logarchive", CANDIDATE);
                    count_chip(ui, ic::LAPTOP, s.mac_json, "log show JSON", CANDIDATE);
                    count_chip(ui, ic::CLOUD, s.elastic_json, "Windows JSON", theme::VIOLET);
                    count_chip(ui, ic::TABLE, s.timelines.len(), plural(s.timelines.len(), "timeline", "timelines"), theme::CYAN);
                    count_chip(ui, ic::ARCHIVE, s.archives, plural(s.archives, "other archive", "other archives"), theme::DIM);
                });
                ui.add_space(4.0);
                if self.ingest.scan_rx.is_some() {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().size(12.0).color(theme::ACCENT));
                        ui.label(egui::RichText::new(look_note(&s, true)).color(theme::MUTED).size(12.0));
                    });
                } else if s.truncated {
                    ui.label(egui::RichText::new(format!("{}  {}", ic::WARNING, look_note(&s, false))).color(CANDIDATE).size(12.5));
                } else {
                    ui.label(egui::RichText::new(look_note(&s, false)).color(theme::DIM).small());
                }
                ui.add_space(6.0);
                let (icon, color) = match (v.parser, v.sure) {
                    (None, true) => (ic::TABLE, theme::CYAN),
                    (Some(p), true) => (PARSERS[pidx(p)].icon, theme::CYAN),
                    (Some(p), false) => (PARSERS[pidx(p)].icon, CANDIDATE),
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
                                (Some(_), true) => {
                                    ui.label(egui::RichText::new(format!("{}  masstin -a parse reads it", ic::CHECK_CIRCLE)).color(color).size(12.5));
                                }
                                (Some(p), false) => {
                                    ui.label(egui::RichText::new(format!("{}  not sure: {} is offered, the next step lets you choose", ic::WARNING, p)).color(color).size(12.5));
                                }
                                (None, false) => {
                                    ui.label(egui::RichText::new(format!("{}  the next step asks which parser, or the rules to read it with", ic::WARNING)).color(color).size(12.5));
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
            self.ingest.append_offered = false;
            self.start_scan();
        }
    }

    fn ingest_step_parser(&mut self, ui: &mut egui::Ui) {
        let rec = self.ingest.verdict.as_ref().and_then(|v| v.parser).map(pidx);
        let sure = self.ingest.verdict.as_ref().map_or(false, |v| v.sure);
        ui.label(egui::RichText::new(if sure { "The parser masstin picked (masstin -a parse picks the same by itself), and the others in case you know better." } else { "masstin is not sure which parser this is for. Pick one." }).color(theme::MUTED));
        // carving or rules make it `masstin -a parse`, whatever card is lit
        let overridden = self.ingest.uses_parse() && !self.ingest.is_auto();
        if overridden {
            let note = if self.ingest.carve_only_on() { "Only the carving runs (masstin -a carve-image): the cards do not apply." } else { "With carving or rules below, masstin -a parse runs: it reads what it knows by itself, and the rest with the rules. The cards do not apply." };
            ui.label(egui::RichText::new(format!("{}  {}", ic::INFO, note)).color(theme::CYAN).size(12.5));
        }
        ui.add_space(6.0);
        for (i, p) in PARSERS.iter().enumerate() {
            let on = self.ingest.parser == i && !overridden;
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
        // what only `masstin -a parse` does: carve the images, read the rest with rules
        if self.ingest.has_images() || self.ingest.scan.as_ref().map_or(false, |s| s.truncated) {
            theme::section(ui, "Deleted logs");
            ui.checkbox(&mut self.ingest.carve, "Carve the disk images for the records of deleted or overwritten logs");
            if self.ingest.carve && self.ingest.carve_only_possible() {
                ui.indent("carve-only", |ui| {
                    ui.radio_value(&mut self.ingest.carve_only, false, "as well as the logs on the file system (the usual)");
                    ui.radio_value(&mut self.ingest.carve_only, true, "only the carving: the file system is not read (carve-image)");
                });
            }
            ui.label(egui::RichText::new("Every byte of every image is read, unallocated space included, for event log records. What the live logs already hold is dropped; what they lost joins the same timeline (--carve). Slow: minutes per image.").color(theme::MUTED).size(12.0));
        }
        theme::section(ui, "Logs masstin does not know");
        let unknown = self.ingest.sources.iter().find(|s| Path::new(s.as_str()).is_file()).cloned();
        if let Some(log) = unknown.filter(|_| !self.ingest.verdict.as_ref().map_or(false, |v| v.sure)) {
            if ui.button(format!("{}  Build a rule for it in the rule studio…", ic::TERMINAL_WINDOW)).on_hover_text("The log's lines on one side, the rule on the other, the rows it writes underneath; saved, it comes back here as --rules").clicked() {
                self.studio.load(&log);
                self.studio.open = true;
            }
        }
        ui.label(egui::RichText::new("A VPN, a firewall, a proxy: YAML rules say how to read them, and their rows join the same timeline (--rules). masstin's rules folder has rules for several products.").color(theme::MUTED).size(12.0));
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.ingest.rules).desired_width(400.0).hint_text("a rule file (.yaml) or a folder of rules"));
            if ui.button(format!("{}  Rule file…", ic::ARCHIVE)).on_hover_text("A YAML rule (made in the rule studio, or from masstin's library) that reads the logs masstin does not know").clicked() {
                if let Some(p) = rfd::FileDialog::new().set_title("Rule file").add_filter("YAML rules", &["yaml", "yml"]).pick_file() {
                    self.ingest.rules = p.to_string_lossy().to_string();
                }
            }
            if ui.button(format!("{}  Folder…", ic::FOLDER_OPEN)).on_hover_text("Pick a folder: everything in it is used").clicked() {
                if let Some(p) = rfd::FileDialog::new().set_title("Folder of rules").pick_folder() {
                    self.ingest.rules = p.to_string_lossy().to_string();
                }
            }
            if self.ingest.rules_on() && ui.add(egui::Button::new(egui::RichText::new(ic::X).color(theme::DIM)).frame(false)).on_hover_text("No rules").clicked() {
                self.ingest.rules.clear();
            }
        });
        if self.ingest.rules_on() && !Path::new(self.ingest.rules.trim()).exists() {
            ui.label(egui::RichText::new(format!("{}  no such file or folder; the parser will fail", ic::WARNING)).color(SIGNIFICANT).small());
        }
    }

    fn ingest_step_output(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("The timeline CSV the parser writes, and what to do with it when it is done.").color(theme::MUTED));
        // one timeline open and the parser that can read a timeline with the
        // evidence: propose to add the new rows to it, once
        let can_append = self.files.len() == 1 && self.ingest.uses_parse() && !self.ingest.carve_only_on() && !Path::new(&self.files[0]).starts_with(std::env::temp_dir());
        if can_append && !self.ingest.append_offered {
            self.ingest.append_offered = true;
            self.ingest.append_to = self.files[0].clone();
        }
        if !can_append {
            self.ingest.append_to.clear();
        }
        if self.ingest.append_on() {
            theme::section(ui, "Timeline it is added to");
            ui.label(egui::RichText::new(self.ingest.append_to.trim()).monospace().size(12.0));
            ui.label(egui::RichText::new("The rows of the new evidence are added to the timeline open here, sorted, a row it already has not written twice. The rows it has keep your marks, your notes and their hunt; run the hunt again to judge the new ones.").color(theme::MUTED).size(12.0));
            ui.horizontal(|ui| {
                if ui.button("Write a timeline of its own instead").on_hover_text("The new evidence gets its own timeline CSV, and the one open is left as it is").clicked() {
                    self.ingest.append_to.clear();
                }
            });
            self.ingest_step_done_options(ui, true);
            return;
        }
        if can_append {
            ui.horizontal(|ui| {
                if ui.button(format!("{}  Add it to the timeline open here", ic::PLUS)).on_hover_text("One timeline for the case: the new rows are added to the one open, sorted and without duplicates, and its marks are kept").clicked() {
                    self.ingest.append_to = self.files[0].clone();
                }
            });
        }
        theme::section(ui, "Timeline to write");
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.ingest.output).desired_width(520.0).hint_text("…\\case.csv"));
            if ui.button(format!("{}  Save as…", ic::FLOPPY_DISK)).on_hover_text("Choose where the file is written and its name").clicked() {
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
        self.ingest_step_done_options(ui, false);
    }

    /// What to do with the timeline when the run ends, the noise filters,
    /// the advanced options and the command. `appending`: the timeline is
    /// the one open, read again when it is done.
    fn ingest_step_done_options(&mut self, ui: &mut egui::Ui, appending: bool) {
        theme::section(ui, "When it is done");
        if appending {
            self.ingest.open_here = true;
            let mut on = true;
            ui.add_enabled(false, egui::Checkbox::new(&mut on, "Read it again in this window")).on_disabled_hover_text("It is the timeline open here: the window shows it with the new rows");
        } else if self.ingest.open_table {
            // the table shows the timeline open in the window: asking for it opens it here
            let mut on = true;
            ui.add_enabled(false, egui::Checkbox::new(&mut on, "Open it in this window")).on_disabled_hover_text("The table shows the timeline open in this window, so it is opened here too");
        } else {
            ui.checkbox(&mut self.ingest.open_here, "Open it in this window");
        }
        if !appending && (self.ingest.open_here || self.ingest.open_table) && !self.files.is_empty() {
            ui.indent("ingest-add", |ui| {
                ui.radio_value(&mut self.ingest.add, false, "instead of the timelines open now");
                ui.radio_value(&mut self.ingest.add, true, "added to the timelines open now");
            });
        }
        ui.checkbox(&mut self.ingest.open_table, "Show its rows as a table");
        ui.checkbox(&mut self.ingest.open_external, "Open it with the system's CSV application").on_hover_text("Whatever opens .csv files on this machine: a spreadsheet, an editor");
        let leaving = self.ingest.ignore_local || !(self.ingest.exclude_users.trim().is_empty() && self.ingest.exclude_hosts.trim().is_empty() && self.ingest.exclude_ips.trim().is_empty());
        egui::CollapsingHeader::new(theme::semibold(if leaving { "Leave out the noise (on)" } else { "Leave out the noise (optional)" }, 12.5)).id_salt("ingest-noise").default_open(leaving).show(ui, |ui| {
            ui.label(egui::RichText::new("Rows dropped before they are written: the timeline holds the rest. Leave it all empty to keep everything.").color(theme::MUTED).size(12.0));
            ui.checkbox(&mut self.ingest.ignore_local, "Logons with no real origin: loopback, LOCAL, empty or placeholder sources (--ignore-local)");
            let field = |ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str, flag: &str| {
                ui.horizontal(|ui| {
                    ui.add_sized([120.0, 20.0], egui::Label::new(egui::RichText::new(label).color(TEXT)));
                    ui.add(egui::TextEdit::singleline(value).desired_width(420.0).hint_text(hint)).on_hover_text(flag);
                });
            };
            field(ui, "Accounts", &mut self.ingest.exclude_users, "svc_backup, *$ (machine accounts), *admin*, @accounts.txt", "--exclude-users: the subject and the target account, any case; * wildcards; @file reads one per line");
            field(ui, "Hosts", &mut self.ingest.exclude_hosts, "JUMP01, *-MON, @jumpboxes.txt", "--exclude-hosts: origin and destination names; * wildcards; @file reads one per line");
            field(ui, "Addresses", &mut self.ingest.exclude_ips, "10.0.0.5, 10.0.0.0/24, fe80::/10, @scanners.txt", "--exclude-ips: the origin address; single addresses or CIDR ranges; @file reads one per line");
            ui.label(egui::RichText::new("Commas between entries; * matches anything; @file.txt reads a list from a file, one entry a line. The console says how many rows each rule dropped.").color(theme::DIM).small());
        });
        let advanced = self.ingest.debug || !(self.ingest.threads.trim().is_empty() && self.ingest.parallel_images.trim().is_empty() && self.ingest.skip_offsets.trim().is_empty());
        egui::CollapsingHeader::new(theme::semibold(if advanced { "Advanced (on)" } else { "Advanced (optional)" }, 12.5)).id_salt("ingest-advanced").default_open(advanced).show(ui, |ui| {
            ui.label(egui::RichText::new("Left empty, masstin decides by itself; these are for a slow disk, a busy machine or an image that hangs.").color(theme::MUTED).size(12.0));
            ui.horizontal(|ui| {
                ui.add_sized([150.0, 20.0], egui::Label::new(egui::RichText::new("Threads").color(TEXT)));
                ui.add(egui::TextEdit::singleline(&mut self.ingest.threads).desired_width(60.0).hint_text("auto"));
                ui.label(egui::RichText::new("from this window: all cores but two by default, the window and a remote session keep theirs; 1 runs serial (--threads)").color(theme::DIM).small());
            });
            if self.ingest.has_images() {
                ui.horizontal(|ui| {
                    ui.add_sized([150.0, 20.0], egui::Label::new(egui::RichText::new("Images at once").color(TEXT)));
                    ui.add(egui::TextEdit::singleline(&mut self.ingest.parallel_images).desired_width(60.0).hint_text("auto"));
                    ui.label(egui::RichText::new("1 for a spinning disk or a network share; measured by default (--parallel-images)").color(theme::DIM).small());
                });
            }
            if self.ingest.carve_on() {
                ui.horizontal(|ui| {
                    ui.add_sized([150.0, 20.0], egui::Label::new(egui::RichText::new("Skip these offsets").color(TEXT)));
                    ui.add(egui::TextEdit::singleline(&mut self.ingest.skip_offsets).desired_width(300.0).hint_text("0x6478b6000, 0x7a0000000"));
                });
                ui.label(egui::RichText::new("For a damaged E01 whose carving hangs: each offset (hex) skips 32 MB there (--skip-offsets).").color(theme::DIM).small());
            }
            ui.checkbox(&mut self.ingest.debug, "Say more in the parser's log (--debug)");
            if !self.ingest.threads.trim().is_empty() && self.ingest.threads.trim().parse::<usize>().map_or(true, |n| n == 0) {
                ui.label(egui::RichText::new(format!("{}  threads is a whole number, 1 or more; it is left out", ic::WARNING)).color(CANDIDATE).small());
            }
        });
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
                    if ui.button(format!("{}  Open here", ic::GRAPH)).on_hover_text("Open the timeline just written in this window, as a graph").clicked() {
                        *action = Some("open-here");
                    }
                    if ui.button(format!("{}  As a table", ic::TABLE)).on_hover_text("Open the timeline just written in the Timeline: its rows as a table").clicked() {
                        *action = Some("open-table");
                    }
                    if ui.button(format!("{}  System's CSV app", ic::APP_WINDOW)).on_hover_text("Open the CSV with the program this computer uses for CSV files").clicked() {
                        *action = Some("open-external");
                    }
                    if ui.button(format!("{}  Show in folder", ic::FOLDER_OPEN)).on_hover_text("Open the folder the timeline is in, with the file selected").clicked() {
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
                            ui.label(egui::RichText::new(if case::is_case(f) { ic::ARCHIVE } else { ic::TABLE }).size(16.0).color(theme::CYAN));
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
                if case::is_case(&f) {
                    self.open_case(f.into());
                } else {
                    self.open_files(vec![f]);
                }
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
pub(super) fn stepper(ui: &mut egui::Ui, step: usize, labels: &[&str]) {
    let (r, p) = ui.allocate_painter(Vec2::new(ui.available_width(), 46.0), Sense::hover());
    let n = labels.len();
    let pad = 40.0;
    let span = r.rect.width() - 2.0 * pad;
    let xs: Vec<f32> = (0..n).map(|i| r.rect.left() + pad + span * i as f32 / (n - 1).max(1) as f32).collect();
    let y = r.rect.top() + 13.0;
    // how far along the steps, eased: the line fills in as a step is passed
    let along = ui.ctx().animate_value_with_time(r.id.with("along"), step as f32, 0.3);
    for i in 0..n.saturating_sub(1) {
        let (a, b) = (Pos2::new(xs[i] + 12.0, y), Pos2::new(xs[i + 1] - 12.0, y));
        p.line_segment([a, b], Stroke::new(1.5, theme::BORDER_2));
        let part = (along - i as f32).clamp(0.0, 1.0);
        if part > 0.0 {
            p.line_segment([a, Pos2::new(a.x + (b.x - a.x) * part, y)], Stroke::new(1.8, theme::CYAN));
        }
    }
    // the step under way breathes
    if step < n {
        let t = ui.input(|i| i.time) as f32;
        let beat = (t * 2.2).sin() * 0.5 + 0.5;
        p.circle_stroke(Pos2::new(xs[step], y), 13.5 + 3.0 * beat, Stroke::new(1.2, draw::fade(theme::CYAN, 0.35 * (1.0 - beat))));
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(40));
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
/// The name of a count in the singular for one, in the plural otherwise.

/// The line under what the look found: how far it went, and what that
/// means for the evidence not counted yet.
fn look_note(s: &Scan, looking: bool) -> String {
    let what = format!("{} files in {} folders", group_digits(s.files), group_digits(s.dirs));
    if looking {
        format!("Still looking: {} so far ({:.0} s). What is found is added here as it comes; you can go on meanwhile, the parse looks at everything again.", what, s.secs)
    } else if s.truncated {
        format!("The look stopped after {} ({:.0} s): there may be more evidence than shown here, disk images too. The parse looks at everything.", what, s.secs)
    } else {
        format!("{} looked at in {:.1} s", what, s.secs)
    }
}
fn plural<'a>(n: usize, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 {
        one
    } else {
        many
    }
}

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
        // Every line the run reported (each source read, each count), not the last
        // few: nineteen packages are nineteen lines. Eight show at a time and the
        // rest scroll; while the run goes on the list stays at its newest line.
        const SHOWN: usize = 8;
        let total = pr.notes.len();
        if total > SHOWN {
            ui.horizontal(|ui| {
                ui.add_space(22.0);
                ui.label(egui::RichText::new(format!("{} lines, {} shown at a time: scroll to see them all", total, SHOWN)).color(theme::DIM).small());
            });
        }
        let row_h = ui.text_style_height(&egui::TextStyle::Body).max(14.0) + ui.spacing().item_spacing.y + 2.0;
        egui::ScrollArea::vertical().id_salt("progress-notes").max_height(row_h * SHOWN as f32).auto_shrink([false, true]).stick_to_bottom(true).show(ui, |ui| {
            for n in &pr.notes {
                ui.horizontal(|ui| {
                    ui.add_space(22.0);
                    // cut to the width of the window; the whole line on hover
                    ui.add(egui::Label::new(egui::RichText::new(format!("{}  {}", ic::CARET_RIGHT, n)).color(EDGE_OK).size(12.0)).truncate()).on_hover_text(n);
                });
            }
        });
    }
}

/// A bar like the console's `[=====>----] 12/120 Security.evtx`, drawn:
/// the logo's run from cyan to magenta, a light moving along what is done,
/// and the fill easing to where the work is instead of jumping.
fn bar_ui(ui: &mut egui::Ui, pos: u64, len: u64, msg: &str, done: bool) {
    let w = ui.available_width().min(560.0);
    let (r, p) = ui.allocate_painter(Vec2::new(w, 14.0), Sense::hover());
    let track = r.rect.shrink2(Vec2::new(0.0, 3.0));
    p.rect_filled(track, CornerRadius::same(4), theme::FIELD);
    let target = if done { 1.0 } else if len == 0 { 0.0 } else { (pos as f32 / len as f32).clamp(0.0, 1.0) };
    let f = ui.ctx().animate_value_with_time(r.id.with("fill"), target, 0.35);
    if f > 0.0 {
        let fill = Rect::from_min_size(track.min, Vec2::new((track.width() * f).max(6.0), track.height()));
        let mut mesh = egui::epaint::Mesh::default();
        let v = |x: f32, y: f32, c: Color32| egui::epaint::Vertex { pos: Pos2::new(x, y), uv: egui::epaint::WHITE_UV, color: c };
        let (a, z) = (theme::CYAN, theme::MAGENTA);
        // the colour at the end of the fill: as far along the run as the work is
        let b = Color32::from_rgb((a.r() as f32 + (z.r() as f32 - a.r() as f32) * f) as u8, (a.g() as f32 + (z.g() as f32 - a.g() as f32) * f) as u8, (a.b() as f32 + (z.b() as f32 - a.b() as f32) * f) as u8);
        mesh.vertices.extend([v(fill.left(), fill.top(), a), v(fill.right(), fill.top(), b), v(fill.right(), fill.bottom(), b), v(fill.left(), fill.bottom(), a)]);
        mesh.add_triangle(0, 1, 2);
        mesh.add_triangle(0, 2, 3);
        p.with_clip_rect(fill).add(egui::Shape::mesh(mesh));
        if !done {
            let t = ui.input(|i| i.time) as f32;
            let x = fill.left() + (t * 0.8).fract() * fill.width();
            p.with_clip_rect(fill).rect_filled(Rect::from_center_size(Pos2::new(x, fill.center().y), Vec2::new(24.0, fill.height())), CornerRadius::same(4), Color32::from_rgba_unmultiplied(255, 255, 255, 64));
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(33));
        }
        // a glow under the bar
        p.rect_stroke(fill.expand(1.5), CornerRadius::same(5), Stroke::new(1.0, draw::fade(b, 0.28)), egui::StrokeKind::Outside);
    }
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        // (a bar out of a hundred is a share: the percentage says it all)
        if len != 100 {
            ui.label(egui::RichText::new(format!("{} / {}", pos, len)).monospace().size(11.0).color(theme::CYAN));
        }
        ui.label(egui::RichText::new(format!("{:.0} %", target * 100.0)).monospace().size(11.0).color(if len == 100 { theme::CYAN } else { theme::DIM }));
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
        // not through `cmd /C start`: the shell read the path again, and a
        // name with `&` in it (`a&calc.csv`) ran its second half as a command
        cmd = std::process::Command::new("rundll32.exe");
        cmd.args(["url.dll,FileProtocolHandler", path]);
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

/// Two spellings of one file (slashes either way; case too on Windows).
pub(super) fn same_file(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        let s = s.replace('\\', "/");
        if cfg!(windows) { s.to_lowercase() } else { s }
    };
    norm(a) == norm(b)
}

fn recent_path() -> Option<PathBuf> {
    config_file("recent.json")
}

/// A file of the window's own settings (the user's configuration folder).
pub(super) fn config_file(name: &str) -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    }?;
    Some(base.join("masstin").join(name))
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
    /// The look reports as it goes: the parser follows what is found while
    /// it is masstin's pick, and stays once chosen by hand; the note under
    /// the chips says whether the look is still going or stopped early.
    #[test]
    fn the_parser_follows_the_look_until_chosen_by_hand() {
        use super::*;
        let mut i = Ingest::default();
        i.sources = vec!["D:/case".into()];
        let mut s = Scan::default();
        s.timelines.push("t.csv".into());
        i.take_scan(s.clone());
        assert_eq!(i.verdict.as_ref().unwrap().parser, None);
        s.linux.insert("secure", 3);
        i.take_scan(s.clone());
        assert_eq!(i.parser, P_LINUX, "timelines first left the choice open");
        s.images.push("D:/case/images/srv.vmdk".into());
        i.take_scan(s.clone());
        assert_eq!(i.parser, P_MASSIVE, "an image found later moves the pick");
        assert!(i.is_auto());
        i.parser = P_WINDOWS;
        s.evtx = 4;
        i.take_scan(s.clone());
        assert_eq!(i.parser, P_WINDOWS, "a parser chosen by hand stays");
        s.files = 13_045;
        s.dirs = 2_079;
        s.secs = 29.4;
        assert!(look_note(&s, true).starts_with("Still looking: 13,045 files in 2,079 folders"), "{}", look_note(&s, true));
        s.truncated = true;
        assert!(look_note(&s, false).contains("disk images too"));
        s.truncated = false;
        assert!(look_note(&s, false).ends_with("looked at in 29.4 s"));
    }

    use super::*;

    #[test]
    fn one_of_a_kind_is_named_in_the_singular() {
        assert_eq!(plural(1, "disk image", "disk images"), "disk image");
        assert_eq!(plural(2, "disk image", "disk images"), "disk images");
        assert_eq!(plural(0, "Linux triage", "Linux triages"), "Linux triages");
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

    #[test]
    fn the_parser_masstin_picked_is_a_plain_parse() {
        let mut i = Ingest::default();
        i.sources = vec!["D:/case".into()];
        i.output = "out.csv".into();
        i.verdict = Some(Verdict { parser: Some(detect::PARSE_MASSIVE), sure: true, title: String::new(), why: String::new() });
        i.parser = P_MASSIVE;
        assert_eq!(&i.command()[..2], &["-a", "parse"]);
        // another parser picked by hand: named with -a
        i.parser = P_WINDOWS;
        assert_eq!(&i.command()[..2], &["-a", "parse-windows"]);
        // not sure: named too
        i.parser = P_MASSIVE;
        i.verdict.as_mut().unwrap().sure = false;
        assert_eq!(&i.command()[..2], &["-a", "parse-massive"]);
    }

    fn with_scan(images: usize, verdict: Option<Verdict>) -> Ingest {
        let mut i = Ingest::default();
        i.sources = vec!["D:/case".into()];
        i.output = "out.csv".into();
        let mut s = Scan::default();
        s.images = (0..images).map(|k| format!("D:/case/disk{}.vmdk", k)).collect();
        i.scan = Some(s);
        i.verdict = verdict;
        i
    }

    #[test]
    fn carving_is_parse_with_carve_and_only_with_images() {
        let mut i = with_scan(1, Some(Verdict { parser: Some(detect::PARSE_IMAGE), sure: true, title: String::new(), why: String::new() }));
        i.parser = P_IMAGE;
        assert!(!i.command().contains(&"--carve".to_string()));
        i.carve = true;
        let c = i.command();
        assert_eq!(&c[..2], &["-a", "parse"]);
        assert!(c.contains(&"--carve".to_string()));
        assert_eq!(&c[c.len() - 3..], &["-o", "out.csv", "--overwrite"]);
        // no image among the evidence: nothing to carve, no flag
        let mut j = with_scan(0, Some(Verdict { parser: Some(detect::PARSE_WINDOWS), sure: true, title: String::new(), why: String::new() }));
        j.parser = P_WINDOWS;
        j.carve = true;
        assert!(!j.carve_on());
        assert!(!j.command().contains(&"--carve".to_string()));
    }

    #[test]
    fn carving_turns_a_parser_picked_by_hand_into_parse() {
        let mut i = with_scan(1, Some(Verdict { parser: Some(detect::PARSE_IMAGE), sure: true, title: String::new(), why: String::new() }));
        i.parser = P_MASSIVE;
        assert_eq!(&i.command()[..2], &["-a", "parse-massive"]);
        i.carve = true;
        assert!(i.uses_parse() && !i.is_auto());
        assert_eq!(&i.command()[..2], &["-a", "parse"]);
    }

    #[test]
    fn rules_read_what_masstin_does_not_know_with_parse() {
        // a firewall log: nothing masstin knows, so it is not sure
        let mut i = with_scan(0, Some(Verdict { parser: None, sure: false, title: String::new(), why: String::new() }));
        i.sources = vec!["D:/logs/FGT.log".into()];
        assert_eq!(&i.command()[..2], &["-a", "parse-massive"]);
        i.rules = "  D:/rules/fortinet-ssl-vpn.yaml ".into();
        let c = i.command();
        assert_eq!(&c[..2], &["-a", "parse"]);
        assert_eq!(&c[2..4], &["-f", "D:/logs/FGT.log"]);
        assert_eq!(&c[4..6], &["--rules", "D:/rules/fortinet-ssl-vpn.yaml"]);
        assert_eq!(&c[6..], &["-o", "out.csv", "--overwrite"]);
        // blank rules are no rules
        i.rules = "   ".into();
        assert!(!i.rules_on());
        assert!(!i.command().contains(&"--rules".to_string()));
    }

    #[test]
    fn rules_and_carving_together_on_the_command_line() {
        let mut i = with_scan(2, Some(Verdict { parser: Some(detect::PARSE_MASSIVE), sure: true, title: String::new(), why: String::new() }));
        i.parser = P_MASSIVE;
        i.carve = true;
        i.rules = "D:/my rules".into();
        assert_eq!(i.command_line(), "masstin -a parse -f D:/case --rules \"D:/my rules\" --carve -o out.csv --overwrite");
    }

    #[test]
    fn the_new_evidence_is_added_to_the_timeline_open() {
        // the timeline open is read with the evidence and written over: one timeline
        // (rules given: the run is `parse`, the one that reads a timeline with the evidence)
        let mut i = Ingest { sources: vec!["D:/no-such-evidence".into()], output: "own.csv".into(), rules: "D:/rules".into(), ..Default::default() };
        assert!(i.uses_parse());
        assert!(!i.append_on());
        assert_eq!(i.target(), "own.csv");
        i.append_to = "D:/case/open.csv".into();
        assert!(i.append_on());
        assert_eq!(i.target(), "D:/case/open.csv");
        let c = i.command();
        assert_eq!(&c[..2], &["-a", "parse"]);
        assert!(c.windows(2).any(|w| w[0] == "-f" && w[1] == "D:/case/open.csv"), "{:?}", c);
        assert_eq!(&c[c.len() - 3..], &["-o", "D:/case/open.csv", "--overwrite"]);
        // a timeline of its own again
        i.append_to.clear();
        let c = i.command();
        assert!(!c.iter().any(|a| a == "D:/case/open.csv"));
        assert_eq!(&c[c.len() - 3..], &["-o", "own.csv", "--overwrite"]);
    }
    #[test]
    fn the_noise_filters_go_on_the_command_line_trimmed() {
        let mut i = Ingest::default();
        i.parser = P_WINDOWS;
        i.sources = vec!["no-such-file.evtx".into()];
        i.output = "out.csv".into();
        assert!(!i.command().iter().any(|a| a.starts_with("--exclude") || a == "--ignore-local"));
        i.ignore_local = true;
        i.exclude_users = " svc_*, *$ ".into();
        i.exclude_ips = "10.0.0.0/8".into();
        let c = i.command();
        let s = c.join(" ");
        assert!(s.contains("--ignore-local --exclude-users svc_*, *$ --exclude-ips 10.0.0.0/8 -o out.csv"));
        assert!(!s.contains("--exclude-hosts"));
    }
    #[test]
    fn carving_alone_is_carve_image_on_image_files() {
        let mut i = with_scan(1, Some(Verdict { parser: Some(detect::PARSE_IMAGE), sure: true, title: String::new(), why: String::new() }));
        i.sources = vec!["no-such-disk.vmdk".into()];
        i.parser = P_IMAGE;
        i.carve = true;
        i.carve_only = true;
        i.skip_offsets = " 0x6478b6000 ".into();
        assert_eq!(i.command(), vec!["-a", "carve-image", "-f", "no-such-disk.vmdk", "--skip-offsets", "0x6478b6000", "-o", "out.csv", "--overwrite"]);
        // a folder among the sources: carving alone is not offered, parse --carve runs
        i.sources = vec![std::env::temp_dir().to_string_lossy().to_string()];
        assert!(!i.carve_only_possible());
        assert_eq!(&i.command()[..2], &["-a", "parse"]);
    }

    /// The timeline proposed is never the evidence: a log that is itself a
    /// `.csv` gets another name.
    #[test]
    fn the_output_proposed_is_not_the_evidence() {
        let mut i = Ingest::default();
        i.sources = vec!["D:/case/fw.csv".to_string()];
        assert_eq!(i.default_output().replace(char::from(92u8), "/"), "D:/case/fw-timeline.csv");
        i.sources = vec!["D:/case/FW.CSV".to_string()];
        assert_eq!(i.default_output().replace(char::from(92u8), "/"), "D:/case/FW-timeline.csv");
        i.sources = vec!["D:/case/auth.log".to_string()];
        assert_eq!(i.default_output().replace(char::from(92u8), "/"), "D:/case/auth.csv");
        i.sources = vec!["D:/case/auth.log".to_string(), "D:/case/auth.csv".to_string()];
        assert_eq!(i.default_output().replace(char::from(92u8), "/"), "D:/case/auth-and-1-more.csv");
        i.sources = vec!["D:/case/a.csv".to_string(), "D:/case/a-and-1-more.csv".to_string()];
        assert_eq!(i.default_output().replace(char::from(92u8), "/"), "D:/case/a-timeline.csv");
    }

    #[test]
    fn the_advanced_knobs_only_when_set_and_valid() {
        let mut i = with_scan(1, Some(Verdict { parser: Some(detect::PARSE_IMAGE), sure: true, title: String::new(), why: String::new() }));
        i.parser = P_IMAGE;
        let plain = i.command();
        i.threads = "0".into();
        i.parallel_images = "x".into();
        assert_eq!(i.command(), plain);
        i.threads = " 4 ".into();
        i.parallel_images = "1".into();
        i.debug = true;
        i.skip_offsets = "0x10".into(); // no carving: no skip list
        let s = i.command().join(" ");
        assert!(s.contains("--threads 4 --parallel-images 1 --debug -o out.csv"));
        assert!(!s.contains("--skip-offsets"));
    }
}
