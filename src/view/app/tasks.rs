//! Work the viewer starts and watches: the hunt on the open timeline, the
//! ingestion of evidence, a merge. Each runs masstin itself as a child
//! process (the same command line the analyst would type), its output
//! streamed into a log window; when it ends the timeline is read again
//! and, for the hunt, the findings light up one after another.

use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};

use super::*;
use crate::view::icons as ic;
use crate::view::theme;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum JobKind {
    Hunt,
    Ingest,
    Merge,
    /// the Cortex XDR API and the graph databases: what it wrote, if anything, opens
    Remote,
}

/// The cores a run started from the window leaves to the window and the
/// session (`MASSTIN_RESERVE_CORES`).
pub(super) const WINDOW_RESERVE_CORES: usize = 2;

pub(super) enum JobMsg {
    Line(String),
    Done(Result<(), String>),
}

/// The console's phases, bars and summary, read from the child's lines.
#[derive(Default)]
pub(super) struct Progress {
    /// `[1/3]` and what the phase is
    pub phases: Vec<(String, String)>,
    /// position, length, what is being done
    pub bar: Option<(u64, u64, String)>,
    pub spinner: Option<String>,
    /// the `=>` lines: what was found or made
    pub notes: Vec<String>,
    /// the closing summary: `Events collected`, `Completed in`…
    pub summary: Vec<(String, String)>,
    /// the run waits for room on its temporary disk (what it said), until
    /// it says there is room again
    pub waiting: Option<String>,
}

impl Progress {
    /// Read one line; true when it was a bar or a spinner (not for the log).
    pub fn absorb(&mut self, line: &str) -> bool {
        let line = strip_ansi(line);
        if let Some(rest) = line.strip_prefix("@@pb") {
            let rest = rest.trim();
            if rest.is_empty() {
                self.spinner = None;
                return true;
            }
            // a bar: `[=====>----] 12/120 | Security.evtx`
            if let (Some(a), Some(b)) = (rest.find('['), rest.find(']')) {
                if a < b {
                    let after = rest[b + 1..].trim();
                    let mut it = after.splitn(2, char::is_whitespace);
                    if let Some((pos, len)) = it.next().and_then(|x| x.split_once('/')) {
                        if let (Ok(pos), Ok(len)) = (pos.parse::<u64>(), len.parse::<u64>()) {
                            let msg = it.next().unwrap_or("").trim();
                            let msg = msg.trim_start_matches(['|', '/', '-', '\\']).trim();
                            self.bar = Some((pos, len, msg.to_string()));
                            self.spinner = None;
                            return true;
                        }
                    }
                }
            }
            // a spinner: `| Scanning for forensic images...`
            let msg = rest.trim_start_matches(['|', '/', '-', '\\']).trim();
            self.spinner = Some(msg.to_string());
            return true;
        }
        let t = line.trim();
        // the temporary disk: a wait for room, its end, what was left out
        if t.starts_with("Waiting for room on disk") {
            self.waiting = Some(t.to_string());
            return false;
        }
        if t.starts_with("Room on disk") {
            self.waiting = None;
            self.notes.push(t.to_string());
            return false;
        }
        if t.contains("left out for lack of room") || (t.starts_with("Could not write") && t.contains("missing from the timeline")) {
            self.waiting = None;
            self.notes.push(t.to_string());
            return false;
        }
        if t.starts_with('[') {
            if let Some(end) = t.find(']') {
                let tag = &t[..=end];
                let inner = &tag[1..tag.len() - 1];
                if let Some((a, b)) = inner.split_once('/') {
                    if a.chars().all(|c| c.is_ascii_digit()) && b.chars().all(|c| c.is_ascii_digit()) && !a.is_empty() {
                        self.phases.push((tag.to_string(), t[end + 1..].trim().to_string()));
                        self.bar = None;
                        self.spinner = None;
                        return false;
                    }
                }
            }
        }
        if let Some(rest) = t.strip_prefix("=>") {
            self.notes.push(rest.trim().to_string());
            return false;
        }
        if is_fact(t) {
            self.notes.push(t.to_string());
            return false;
        }
        // the count of the whole timeline, said after the halves' own: it is
        // the run's, and what the halves said goes
        if let Some(v) = t.strip_prefix("Events in the timeline:") {
            self.summary.clear();
            self.summary.push(("Events in the timeline".to_string(), v.trim().to_string()));
            return false;
        }
        for key in ["Artifacts parsed", "Events collected", "Skipped", "Output", "Completed in", "Connections loaded", "Rows written", "Rows"] {
            if let Some(rest) = t.strip_prefix(key) {
                if let Some(v) = rest.strip_prefix(':') {
                    self.summary.push((key.to_string(), v.trim().to_string()));
                    return false;
                }
            }
        }
        false
    }
}

/// The console's plain lines worth a note in the window: what the image
/// parser found in the volumes (partitions, shadow copies, what came out of
/// them, the duplicates between the live volume and the copies) and the
/// parts of a `parse`.
fn is_fact(t: &str) -> bool {
    t.starts_with("Temporary files:")
        || t.starts_with("Partitions:")
        || t.starts_with("Extracted:")
        || t.starts_with("Extracting EVTX from VSS store")
        || t.contains("duplicate events removed")
        || (t.starts_with("Part ") && t.contains(" of ") && t.contains(':'))
        || t.starts_with("Merging the ")
}

/// Without the terminal's colour codes, should any slip through.
fn strip_ansi(s: &str) -> String {
    if !s.contains('\u{1b}') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// A child masstin running, with its log.
pub(super) struct Job {
    pub kind: JobKind,
    pub title: String,
    pub command: String,
    pub started: std::time::Instant,
    /// when it ended, so the clock stops
    pub ended: Option<std::time::Instant>,
    pub log: Vec<String>,
    /// every line the run wrote, the ones the progress shows as phases and
    /// notes too: what *Copy all*, *Save as* and the log window give
    pub full: Vec<String>,
    /// the lines of a very long run no longer in `full` (all are in the file)
    pub full_dropped: usize,
    /// the file the lines go to as they come, in the window's own folder
    pub log_path: Option<std::path::PathBuf>,
    log_file: Option<std::io::BufWriter<std::fs::File>>,
    pub rx: Receiver<JobMsg>,
    pub done: Option<Result<(), String>>,
    pub progress: Progress,
    /// the child, to stop it
    child: Arc<Mutex<Option<std::process::Child>>>,
    /// timelines to open (or add) when it ends well
    pub open: Vec<String>,
    pub add: bool,
    /// the banner's art is over (the log starts at the separator line)
    pub past_banner: bool,
    /// what came before the banner: kept only if the banner never comes
    /// (masstin refused the command line before printing it)
    prelude: Vec<String>,
    /// the analyst pressed Stop
    pub stopped: bool,
    /// a hunt that ended well closes its window by itself, the log kept
    pub autoclose_at: Option<std::time::Instant>,
}

pub(super) struct MergeForm {
    pub inputs: Vec<String>,
    pub output: String,
    /// only the events in this window (`--start-time` / `--end-time`)
    pub from: String,
    pub to: String,
    /// an earlier timeline whose verdicts and notes are copied over (`--carry-marks`)
    pub carry: String,
}

impl MergeForm {
    pub fn command(&self) -> Vec<String> {
        let mut args = vec!["-a".to_string(), "merge".to_string()];
        for f in &self.inputs {
            args.push("-f".into());
            args.push(f.clone());
        }
        for (flag, v) in [("--start-time", &self.from), ("--end-time", &self.to), ("--carry-marks", &self.carry)] {
            if !v.trim().is_empty() {
                args.push(flag.into());
                args.push(v.trim().to_string());
            }
        }
        args.push("-o".into());
        args.push(self.output.trim().to_string());
        args.push("--overwrite".into());
        args
    }

    /// What stops the merge, said for the analyst.
    pub fn problem(&self) -> Option<&'static str> {
        if self.inputs.len() < 2 {
            return Some("two timelines at least");
        }
        if self.output.trim().is_empty() {
            return Some("the merged timeline needs a file");
        }
        for t in [&self.from, &self.to] {
            if !t.trim().is_empty() && parse_time(t).is_none() {
                return Some("the times are full dates and times: YYYY-MM-DD HH:MM:SS");
            }
        }
        None
    }
}

impl Job {
    /// Seconds it has run, or ran.
    pub fn elapsed(&self) -> f32 {
        self.ended.unwrap_or_else(std::time::Instant::now).duration_since(self.started).as_secs_f32()
    }

    /// Stop the child; the job ends as failed ("stopped").
    pub fn cancel(&mut self) {
        self.stopped = true;
        if let Ok(mut c) = self.child.lock() {
            if let Some(child) = c.as_mut() {
                let pid = child.id();
                let _ = child.kill();
                // what it unpacked goes with it (it cannot clean up after a kill)
                let _ = child.wait();
                let freed = crate::space::clean_run(pid);
                if freed > 0 {
                    self.log.push(format!("Stopped: {} of its temporary files deleted", crate::space::human(freed)));
                }
            }
        }
    }
}

impl Viewer {
    pub(super) fn masstin_exe() -> std::path::PathBuf {
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("masstin"))
    }

    /// Start a child masstin with these arguments; its lines come through the channel.
    pub(super) fn start_job(&mut self, kind: JobKind, title: String, args: Vec<String>, open: Vec<String>, add: bool) {
        self.start_job_env(kind, title, args, open, add, Vec::new());
    }

    /// The same, with environment variables for the child: a secret (an API
    /// key, a password) goes there, never on the command line or in its log.
    pub(super) fn start_job_env(&mut self, kind: JobKind, title: String, args: Vec<String>, open: Vec<String>, add: bool, env: Vec<(String, String)>) {
        let exe = Self::masstin_exe();
        let command = format!("masstin {}", args.iter().map(|a| if a.contains(' ') { format!("\"{}\"", a) } else { a.clone() }).collect::<Vec<_>>().join(" "));
        let (tx, rx) = channel::<JobMsg>();
        let handle: Arc<Mutex<Option<std::process::Child>>> = Arc::new(Mutex::new(None));
        let handle2 = handle.clone();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut cmd = std::process::Command::new(&exe);
            cmd.envs(env).args(&args).env("MASSTIN_PROGRESS_PIPE", "1").stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).stdin(std::process::Stdio::null());
            // a run started from the window leaves two cores to the window and,
            // over remote desktop, to the session that carries it (one is what a
            // run leaves by itself); a figure set in the environment stands
            if std::env::var_os("MASSTIN_RESERVE_CORES").is_none() {
                cmd.env("MASSTIN_RESERVE_CORES", WINDOW_RESERVE_CORES.to_string());
            }
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                // CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS: the parser takes every core it is given; the window stays fluid
                cmd.creation_flags(0x0800_0000 | 0x0000_4000);
            }
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(JobMsg::Done(Err(format!("cannot start {}: {}", exe.display(), e))));
                    return;
                }
            };
            let out = child.stdout.take();
            let err = child.stderr.take();
            *handle2.lock().unwrap() = Some(child);
            let tx2 = tx.clone();
            let t_err = std::thread::spawn(move || {
                if let Some(err) = err {
                    for line in lossy_lines(err) {
                        let _ = tx2.send(JobMsg::Line(line));
                    }
                }
            });
            if let Some(out) = out {
                for line in lossy_lines(out) {
                    let _ = tx.send(JobMsg::Line(line));
                }
            }
            let _ = t_err.join();
            // the pipes are closed: the child is ending (or was stopped)
            let status = loop {
                let waited = handle2.lock().unwrap().as_mut().map(|c| c.try_wait());
                match waited {
                    Some(Ok(Some(s))) => break Ok(s),
                    Some(Ok(None)) => std::thread::sleep(std::time::Duration::from_millis(50)),
                    Some(Err(e)) => break Err(e),
                    None => break Err(std::io::Error::other("the child went missing")),
                }
            };
            *handle2.lock().unwrap() = None;
            let _ = tx.send(JobMsg::Done(match status {
                Ok(s) if s.success() => Ok(()),
                Ok(s) => Err(format!("masstin ended with {}", s)),
                Err(e) => Err(e.to_string()),
            }));
        });
        let (log_path, log_file) = open_run_log(&command);
        self.job = Some(Job { kind, title, command, started: std::time::Instant::now(), ended: None, log: Vec::new(), full: Vec::new(), full_dropped: 0, log_path, log_file, rx, done: None, progress: Progress::default(), child: handle, open, add, past_banner: false, prelude: Vec::new(), stopped: false, autoclose_at: None });
    }

    /// Drain the running job's output; on its end, read the timeline again.
    pub(super) fn poll_job(&mut self, ctx: &egui::Context) {
        let Some(job) = self.job.as_mut() else { return };
        if job.done.is_some() {
            return;
        }
        // what came since the last look is on disk before anything else can go wrong
        if let Some(f) = job.log_file.as_mut() {
            use std::io::Write;
            let _ = f.flush();
        }
        while let Ok(m) = job.rx.try_recv() {
            match m {
                JobMsg::Line(l) => {
                    // the banner's carriage-return progress lines: keep the last state
                    let l = l.trim_end().to_string();
                    if l.is_empty() {
                        continue;
                    }
                    // everything but the bars' own ticks is kept, and written
                    if !l.starts_with("@@pb") {
                        if let Some(f) = job.log_file.as_mut() {
                            use std::io::Write;
                            let _ = writeln!(f, "{:8.1}  {}", job.started.elapsed().as_secs_f32(), l);
                        }
                        job.full.push(l.clone());
                        if job.full.len() > FULL_LOG_MOST {
                            job.full.drain(..FULL_LOG_MOST / 10);
                            job.full_dropped += FULL_LOG_MOST / 10;
                        }
                    }
                    if !job.past_banner {
                        if l.contains('─') {
                            job.past_banner = true;
                        } else if !l.starts_with("@@pb") {
                            job.prelude.push(l);
                        }
                        continue;
                    }
                    if job.progress.absorb(&l) {
                        continue;
                    }
                    if let Some(last) = job.log.last() {
                        let head: String = l.chars().take(12).collect();
                        if last.starts_with(&head) && l.contains('%') {
                            job.log.pop();
                        }
                    }
                    job.log.push(l);
                    if job.log.len() > 2000 {
                        job.log.drain(..500);
                    }
                }
                JobMsg::Done(r) => {
                    let r = if job.stopped { Err("stopped".to_string()) } else { r };
                    if !job.past_banner && job.log.is_empty() {
                        // the command line was refused before the banner: that is the log
                        job.log = std::mem::take(&mut job.prelude);
                    }
                    if r.is_ok() && job.kind == JobKind::Hunt {
                        job.autoclose_at = Some(std::time::Instant::now() + std::time::Duration::from_millis(1800));
                    }
                    if let Some(mut f) = job.log_file.take() {
                        use std::io::Write;
                        let _ = writeln!(f, "{:8.1}  -- {}", job.started.elapsed().as_secs_f32(), match &r { Ok(()) => "ended well".to_string(), Err(e) => format!("ended badly: {}", e) });
                        let _ = f.flush();
                    }
                    job.done = Some(r);
                    job.ended = Some(std::time::Instant::now());
                }
            }
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
        let finished = job.done.clone();
        let (kind, open, add) = (job.kind, job.open.clone(), job.add);
        // a hunt that wrote new timelines (`--if-hunted new`) names them:
        // "New timeline: OLD -> NEW"
        let renamed: Vec<(String, String)> = job.log.iter().filter_map(|l| l.split_once("New timeline: ").and_then(|(_, r)| r.split_once(" -> ")).map(|(a, b)| (a.trim().to_string(), b.trim().to_string()))).collect();
        if let Some(Ok(())) = finished {
            match kind {
                JobKind::Hunt => {
                    // the window goes on with the new timelines; the ones
                    // it had keep the hunt they had
                    for (old, new) in &renamed {
                        if let Some(f) = self.files.iter_mut().find(|f| super::ingest::same_file(f, old)) {
                            *f = new.clone();
                        }
                    }
                    if !renamed.is_empty() {
                        super::ingest::remember(&self.files);
                    }
                    self.hunt_form.if_hunted = Default::default();
                    // The timeline is read again away from the window, so the
                    // sweep goes on until its findings are there to light up
                    // (read here, the window froze for as long as it took).
                    let (files, alpha, merges) = (self.files.clone(), self.alpha, self.merges.clone());
                    let (tx, rx) = std::sync::mpsc::channel();
                    let ctx2 = ctx.clone();
                    std::thread::spawn(move || {
                        let _ = tx.send(Store::load_with(&files, alpha, &merges).map_err(|e| e.to_string()));
                        ctx2.request_repaint();
                    });
                    self.hunt_loading = Some(rx);
                    self.status = "Hunt done: reading its findings…".to_string();
                }
                JobKind::Ingest => {
                    if !open.is_empty() {
                        self.finish_ingest(open, add);
                    }
                }
                JobKind::Merge | JobKind::Remote => {
                    if !open.is_empty() {
                        let mut files: Vec<String> = if add { self.files.clone() } else { Vec::new() };
                        for f in open {
                            if !files.contains(&f) {
                                files.push(f);
                            }
                        }
                        self.draft.view = View::All;
                        self.open_files(files);
                    }
                }
            }
        }
    }

    /// The timeline a hunt wrote, read again in the background: when it is
    /// there, the window shows its findings.
    pub(super) fn poll_hunt_loaded(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.hunt_loading else { return };
        match rx.try_recv() {
            Ok(Ok(store)) => {
                self.hunt_loading = None;
                self.store = store;
                self.remembered.clear();
                self.draft.view = View::Findings;
                self.requery(false);
                self.begin_reveal();
                self.status = format!("Hunt done: {}", self.status);
            }
            Ok(Err(e)) => {
                self.hunt_loading = None;
                self.hunt_sweep = None;
                self.status = format!("Hunt done, but the timeline cannot be read again: {}", e);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => ctx.request_repaint_after(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.hunt_loading = None;
                self.hunt_sweep = None;
                self.status = "Hunt done, but the timeline could not be read again".to_string();
            }
        }
    }

    /// After a hunt: the findings of the view appear one after another, in
    /// time order, each with a flash.
    fn begin_reveal(&mut self) {
        let mut findings: Vec<(i64, usize)> = self.graph.edges.iter().enumerate().filter(|(_, e)| matches!(e.hunt, super::super::store::H_SIGNIFICANT | super::super::store::H_CANDIDATE)).map(|(k, e)| (e.first, k)).collect();
        findings.sort();
        let n = findings.len().max(1) as f32;
        self.reveal_rank = vec![-1.0; self.graph.edges.len()];
        for (i, (_, k)) in findings.into_iter().enumerate() {
            self.reveal_rank[k] = i as f32 / n;
        }
        self.hunt_reveal = Some(std::time::Instant::now());
        self.hunt_sweep = None;
        self.hunt_report = None;
        self.hunt_report_at = Some(std::time::Instant::now() + std::time::Duration::from_secs_f32(REVEAL_SECS + 0.8));
    }

    /// Where an edge is in the reveal: None when no reveal runs or it is not
    /// a finding; else (visible yet, flash 0..1).
    pub(super) fn reveal_state(&self, k: usize, now: std::time::Instant) -> Option<(bool, f32)> {
        let start = self.hunt_reveal?;
        let rank = *self.reveal_rank.get(k)?;
        if rank < 0.0 {
            return None;
        }
        let age = now.duration_since(start).as_secs_f32();
        let at = 0.05 + rank * REVEAL_SECS;
        if age < at {
            Some((false, 0.0))
        } else {
            Some((true, (1.0 - (age - at) / 0.8).clamp(0.0, 1.0)))
        }
    }

    pub(super) fn reveal_running(&self, now: std::time::Instant) -> bool {
        self.hunt_reveal.map_or(false, |s| now.duration_since(s).as_secs_f32() < REVEAL_SECS + 1.5)
    }

    // ───────────────────────── ingest and merge ─────────────────────────

    pub(super) fn merge_window(&mut self, ctx: &egui::Context) {
        if !self.show_merge {
            return;
        }
        if self.merge_form.inputs.is_empty() {
            self.merge_form.inputs = self.files.clone();
        }
        let mut open = true;
        let mut run = false;
        egui::Window::new(format!("{}  Merge timelines", ic::STACK)).open(&mut open).collapsible(false).resizable(false).default_width(600.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.label(egui::RichText::new("Several timelines into one chronological file (the hunt columns kept where a row has them). The result opens here.").color(theme::MUTED));
            theme::section(ui, "Timelines");
            let mut remove: Option<usize> = None;
            for (i, f) in self.merge_form.inputs.iter().enumerate() {
                ui.horizontal(|ui| {
                    if ui.add(egui::Button::new(egui::RichText::new(ic::X).color(theme::DIM)).frame(false)).clicked() {
                        remove = Some(i);
                    }
                    ui.label(egui::RichText::new(f).size(12.5));
                });
            }
            if let Some(i) = remove {
                self.merge_form.inputs.remove(i);
            }
            if ui.button(format!("{}  Add timelines…", ic::PLUS)).on_hover_text("Pick the timeline CSVs to join into one").clicked() {
                if let Some(ps) = rfd::FileDialog::new().set_title("Timelines to merge").add_filter("CSV", &["csv"]).pick_files() {
                    for p in ps {
                        let s = p.to_string_lossy().to_string();
                        if !self.merge_form.inputs.contains(&s) {
                            self.merge_form.inputs.push(s);
                        }
                    }
                }
            }
            theme::section(ui, "Result");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.merge_form.output).desired_width(380.0).hint_text("…\\case.csv"));
                if ui.button(format!("{}  Save as…", ic::FLOPPY_DISK)).on_hover_text("Choose where the file is written and its name").clicked() {
                    if let Some(p) = rfd::FileDialog::new().set_title("Merged timeline to write").add_filter("CSV", &["csv"]).set_file_name("merged.csv").save_file() {
                        self.merge_form.output = p.to_string_lossy().to_string();
                    }
                }
            });
            let out = self.merge_form.output.trim();
            if !out.is_empty() && std::path::Path::new(out).exists() {
                ui.label(egui::RichText::new(format!("{}  this file exists and will be written over", ic::WARNING)).color(CANDIDATE).small());
            }
            egui::CollapsingHeader::new(theme::semibold("Only a time window, marks from an earlier timeline (optional)", 12.5)).id_salt("merge-more").default_open(!(self.merge_form.from.is_empty() && self.merge_form.to.is_empty() && self.merge_form.carry.is_empty())).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Events from").color(theme::MUTED));
                    ui.add(egui::TextEdit::singleline(&mut self.merge_form.from).desired_width(160.0).hint_text("the first"));
                    ui.label(egui::RichText::new("to").color(theme::MUTED));
                    ui.add(egui::TextEdit::singleline(&mut self.merge_form.to).desired_width(160.0).hint_text("the last"));
                    if ui.small_button("the window's").on_hover_text("The time window of the view").clicked() {
                        self.merge_form.from = self.filter.from.clone();
                        self.merge_form.to = self.filter.to.clone();
                    }
                });
                ui.label(egui::RichText::new("YYYY-MM-DD HH:MM:SS, UTC; empty keeps every event (--start-time, --end-time).").color(theme::DIM).small());
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Marks from").color(theme::MUTED));
                    ui.add(egui::TextEdit::singleline(&mut self.merge_form.carry).desired_width(380.0).hint_text("an earlier timeline of the same evidence"));
                    if ui.button(format!("{}  File…", ic::ARCHIVE)).on_hover_text("Pick a file").clicked() {
                        if let Some(p) = rfd::FileDialog::new().add_filter("CSV", &["csv"]).pick_file() {
                            self.merge_form.carry = p.to_string_lossy().to_string();
                        }
                    }
                });
                ui.label(egui::RichText::new("Its verdicts and notes are copied onto the same rows of the result (--carry-marks).").color(theme::DIM).small());
            });
            ui.add_space(6.0);
            let problem = self.merge_form.problem();
            ui.horizontal(|ui| {
                if ui.add_enabled(problem.is_none() && self.job.is_none(), egui::Button::new(theme::semibold(format!("{}  Merge", ic::STACK), 13.5).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 30.0))).clicked() {
                    run = true;
                }
                if let Some(p) = problem {
                    ui.label(egui::RichText::new(p).color(CANDIDATE).small());
                }
            });
            let line = self.merge_form.command();
            ui.add(egui::Label::new(egui::RichText::new(format!("masstin {}", line.iter().map(|a| if a.contains(' ') { format!("\"{}\"", a) } else { a.clone() }).collect::<Vec<_>>().join(" "))).monospace().size(10.5).color(theme::DIM)).wrap());
        });
        if run {
            let out = self.merge_form.output.trim().to_string();
            let args = self.merge_form.command();
            self.start_job(JobKind::Merge, "Merging".into(), args, vec![out], false);
            self.show_merge = false;
        } else {
            self.show_merge = open;
        }
    }

    /// The running (or just finished) job: its log, its time, its command.
    pub(super) fn job_window(&mut self, ctx: &egui::Context) {
        // an ingest shows in its wizard while that is open
        if self.ingest.open && self.job.as_ref().map_or(false, |j| j.kind == JobKind::Ingest) {
            return;
        }
        // and a reading from Cortex in its own
        if self.show_cortex && self.cortex_form.step == 4 && self.job.as_ref().map_or(false, |j| j.kind == JobKind::Remote) {
            return;
        }
        if let Some(job) = self.job.as_ref() {
            if job.autoclose_at.map_or(false, |t| std::time::Instant::now() >= t) {
                let j = self.job.take().unwrap();
                self.last_log_path = j.log_path.clone();
                    self.last_log = Some((j.command, j.full));
                return;
            }
        }
        let Some(job) = self.job.as_ref() else { return };
        let mut open = true;
        let mut close = false;
        let title = match &job.done {
            None => format!("{}  {}…", ic::ARROWS_CLOCKWISE, job.title),
            Some(Ok(())) => format!("{}  {} — done", ic::CHECK_CIRCLE, job.title),
            Some(Err(_)) => format!("{}  {} — failed", ic::WARNING, job.title),
        };
        let elapsed = job.elapsed();
        // the hunt's log stays folded while it runs (the canvas is the show); a
        // parse or a merge shows its log, there is nothing else to watch
        let folded = job.kind == JobKind::Hunt;
        let title = if folded && job.done.is_none() { format!("{}  Hunting…  {:.0} s", ic::ARROWS_CLOCKWISE, elapsed) } else { title };
        egui::Window::new(title).id(egui::Id::unique("job-window")).open(&mut open).collapsible(true).default_open(!folded).resizable(true).default_width(if folded { 420.0 } else { 720.0 }).max_width(900.0).max_height(400.0).anchor(egui::Align2::RIGHT_BOTTOM, Vec2::new(-14.0, -104.0)).show(ctx, |ui| {
            ui.set_max_width(880.0);
            ui.horizontal(|ui| {
                if job.done.is_none() {
                    ui.add(egui::Spinner::new().size(16.0).color(theme::ACCENT));
                }
                ui.label(egui::RichText::new(format!("{:.0} s", elapsed)).color(theme::DIM).small());
            });
            ui.add(egui::Label::new(egui::RichText::new(&job.command).monospace().size(11.0).color(theme::MUTED)).wrap());
            if let Some(Err(e)) = &job.done {
                ui.label(egui::RichText::new(e).color(SIGNIFICANT));
            }
            if !job.progress.phases.is_empty() {
                theme::hairline(ui);
                super::ingest::progress_ui(ui, job);
            }
            theme::hairline(ui);
            egui::ScrollArea::vertical().stick_to_bottom(true).max_height(230.0).auto_shrink([false, true]).show(ui, |ui| {
                for l in &job.log {
                    ui.add(egui::Label::new(egui::RichText::new(l).monospace().size(11.0)).wrap());
                }
            });
            if job.done.is_some() {
                ui.add_space(4.0);
                if ui.button("Close").on_hover_text("Close this window").clicked() {
                    close = true;
                }
            }
        });
        if (!open || close) && self.job.as_ref().map_or(false, |j| j.done.is_some()) {
            let j = self.job.take().unwrap();
            self.last_log_path = j.log_path.clone();
                    self.last_log = Some((j.command, j.full));
        }
    }

    /// The log of the run under way, or of the last one: every line it
    /// wrote, in a window that moves and takes the size it is given.
    pub(super) fn last_log_window(&mut self, ctx: &egui::Context) {
        if !self.show_last_log {
            return;
        }
        let mut open = true;
        let running = self.job.as_ref().map_or(false, |j| j.done.is_none());
        let title = if running { "The run's log" } else { "Log of the last run" };
        egui::Window::new(format!("{}  {}", ic::TERMINAL_WINDOW, title)).id(egui::Id::new("run-log-window")).open(&mut open).collapsible(true).resizable(true).default_size([920.0, 560.0]).min_width(420.0).min_height(220.0).show(ctx, |ui| {
            let shown: Option<(&str, &[String], usize, Option<&std::path::Path>)> = match (&self.job, &self.last_log) {
                (Some(j), _) => Some((j.command.as_str(), j.full.as_slice(), j.full_dropped, j.log_path.as_deref())),
                (None, Some((command, log))) => Some((command.as_str(), log.as_slice(), 0, self.last_log_path.as_deref())),
                (None, None) => None,
            };
            match shown {
                None => {
                    ui.label(egui::RichText::new("Nothing has run from this window yet.").color(theme::MUTED));
                }
                Some((command, lines, dropped, path)) => {
                    ui.add(egui::Label::new(egui::RichText::new(command).monospace().size(11.0).color(theme::MUTED)).wrap());
                    theme::hairline(ui);
                    log_box(ui, "run-log-window-box", lines, dropped, path, 0.0);
                }
            }
        });
        self.show_last_log = open;
    }
}

/// The lines of a very long run kept in memory (the file has them all).
const FULL_LOG_MOST: usize = 200_000;
/// The last lines drawn in the box (all are copied and saved).
const LOG_BOX_SHOWN: usize = 3000;
/// The run logs kept in the window's folder.
const RUN_LOGS_KEPT: usize = 30;

/// The lines of a pipe, each as it is: one that is not UTF-8 is read with
/// its odd bytes replaced, not taken for the end of the output.
fn lossy_lines<R: std::io::Read>(r: R) -> impl Iterator<Item = String> {
    let mut r = std::io::BufReader::new(r);
    std::iter::from_fn(move || {
        let mut b = Vec::new();
        match std::io::BufRead::read_until(&mut r, b'\n', &mut b) {
            Ok(0) | Err(_) => None,
            Ok(_) => {
                while matches!(b.last(), Some(b'\n') | Some(b'\r')) {
                    b.pop();
                }
                Some(String::from_utf8_lossy(&b).into_owned())
            }
        }
    })
}

/// The file a run's lines go to as they come: `logs/run-<date>-<time>.log`
/// in the window's own folder, its command line first. It is there
/// whatever becomes of the run or of the window; the oldest go once there
/// are thirty.
fn open_run_log(command: &str) -> (Option<std::path::PathBuf>, Option<std::io::BufWriter<std::fs::File>>) {
    use std::io::Write;
    let Some(dir) = super::ingest::config_file("logs") else { return (None, None) };
    if std::fs::create_dir_all(&dir).is_err() {
        return (None, None);
    }
    if let Ok(rd) = std::fs::read_dir(&dir) {
        let mut old: Vec<std::path::PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.file_name().and_then(|n| n.to_str()).map_or(false, |n| n.starts_with("run-") && n.ends_with(".log"))).collect();
        old.sort();
        while old.len() >= RUN_LOGS_KEPT {
            let _ = std::fs::remove_file(old.remove(0));
        }
    }
    let path = dir.join(format!("run-{}.log", chrono::Local::now().format("%Y%m%d-%H%M%S")));
    match std::fs::File::create(&path) {
        Ok(f) => {
            let mut w = std::io::BufWriter::new(f);
            let _ = writeln!(w, "masstin {}  {}", env!("CARGO_PKG_VERSION"), chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
            let _ = writeln!(w, "{}", command);
            let _ = writeln!(w, "(seconds since the start, then each line the run wrote)");
            let _ = w.flush();
            (Some(path), Some(w))
        }
        Err(_) => (None, None),
    }
}

/// A run's lines as text that is selected and copied like any text, with
/// *Copy all*, *Save as* and the file they are kept in. `height` 0 takes
/// the room there is (a window).
pub(super) fn log_box(ui: &mut egui::Ui, salt: &str, lines: &[String], dropped: usize, path: Option<&std::path::Path>, height: f32) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        if ui.button("Copy all").on_hover_text("Every line of the run to the clipboard, not only the ones shown").clicked() {
            ui.ctx().copy_text(lines.join("\n"));
        }
        if ui.button(format!("{}  Save as…", ic::FLOPPY_DISK)).on_hover_text("Every line of the run to a text file").clicked() {
            if let Some(p) = rfd::FileDialog::new().set_title("Save the run's log").set_file_name("masstin-run.log").save_file() {
                let _ = std::fs::write(p, lines.join("\n"));
            }
        }
        if let Some(p) = path {
            if ui.button(format!("{}  Show the log file", ic::FOLDER_OPEN)).on_hover_text(format!("{}\nWritten as the run goes, so it is there whatever becomes of the run: each line with the seconds since the start", p.display())).clicked() {
                let _ = super::ingest::reveal_in_folder(&p.display().to_string());
            }
        }
        let n = lines.len() + dropped;
        let note = if lines.len() > LOG_BOX_SHOWN { format!("{} lines, the last {} shown; Copy all and Save as give them all", n, LOG_BOX_SHOWN) } else { format!("{} lines", n) };
        ui.label(egui::RichText::new(note).color(theme::DIM).small());
    });
    let from = lines.len().saturating_sub(LOG_BOX_SHOWN);
    // the text is put together when a line comes, not at each frame
    let id = ui.id().with(salt);
    let cached: Option<(usize, usize, Arc<String>)> = ui.data(|d| d.get_temp(id));
    let text = match cached {
        Some((n, f, s)) if n == lines.len() && f == from => s,
        _ => {
            let s = Arc::new(lines[from..].join("\n"));
            ui.data_mut(|d| d.insert_temp(id, (lines.len(), from, Arc::clone(&s))));
            s
        }
    };
    let h = if height > 0.0 { height } else { ui.available_height().max(120.0) };
    egui::ScrollArea::both().id_salt(salt).stick_to_bottom(true).max_height(h).auto_shrink([false, height > 0.0]).show(ui, |ui| {
        let mut shown: &str = text.as_str();
        ui.add(egui::TextEdit::multiline(&mut shown).font(egui::FontId::monospace(11.0)).desired_width(f32::INFINITY).frame(egui::Frame::NONE));
    });
}

/// Seconds the reveal takes to go through every finding of the view.
pub(super) const REVEAL_SECS: f32 = 3.0;

#[cfg(test)]
mod tests {

    #[test]
    fn the_merge_command_carries_its_window_and_marks() {
        let mut m = MergeForm { inputs: vec!["a.csv".into(), "b.csv".into()], output: "m.csv".into(), from: String::new(), to: String::new(), carry: String::new() };
        assert_eq!(m.command(), vec!["-a", "merge", "-f", "a.csv", "-f", "b.csv", "-o", "m.csv", "--overwrite"]);
        assert_eq!(m.problem(), None);
        m.from = "2026-11-10 00:00:00".into();
        m.carry = " old.csv ".into();
        assert_eq!(m.command().join(" "), "-a merge -f a.csv -f b.csv --start-time 2026-11-10 00:00:00 --carry-marks old.csv -o m.csv --overwrite");
        m.to = "later".into();
        assert!(m.problem().is_some());
        m.inputs.pop();
        assert_eq!(m.problem(), Some("two timelines at least"));
    }
    use super::*;

    fn read(lines: &[&str]) -> Progress {
        let mut p = Progress::default();
        for l in lines {
            p.absorb(l);
        }
        p
    }

    #[test]
    fn the_shadow_copies_and_the_carving_are_notes_in_the_window() {
        let p = read(&[
            "[1/3] Searching for artifacts...",
            "          Partitions: 1 NTFS, 1 VSS",
            "          Extracted: 664 EVTX + 2 UAL",
            "        Extracting EVTX from VSS store 0...",
            "        14441 duplicate events removed (live + VSS overlap)",
            "        => Carving: 13755 event(s), 13753 already in the live logs, 2 recovered",
        ]);
        assert_eq!(p.phases.len(), 1);
        assert_eq!(
            p.notes,
            vec![
                "Partitions: 1 NTFS, 1 VSS",
                "Extracted: 664 EVTX + 2 UAL",
                "Extracting EVTX from VSS store 0...",
                "14441 duplicate events removed (live + VSS overlap)",
                "Carving: 13755 event(s), 13753 already in the live logs, 2 recovered",
            ]
        );
    }

    #[test]
    fn a_wait_for_room_is_shown_until_there_is_room() {
        let mut p = read(&["        Temporary files: C:\\Temp (the system's; --temp chooses another, 23.5 GB free, 5.0 GB kept free)"]);
        assert_eq!(p.notes.len(), 1);
        p.absorb("        Waiting for room on disk C: (8 KB to write, 4.9 GB free, 5.0 GB kept free for the system). Free some space there");
        assert!(p.waiting.as_deref().unwrap().starts_with("Waiting for room on disk C:"));
        p.absorb("        Room on disk C: again (6.1 GB free): going on");
        assert!(p.waiting.is_none());
        p.absorb("        Waiting for room on disk C: (8 KB to write)");
        p.absorb("        3 file(s) left out for lack of room on the temporary disk; their events are missing from the timeline.");
        assert!(p.waiting.is_none());
        assert_eq!(p.notes.len(), 3);
        p.absorb("        Waiting for room on disk C: (2 KB to write)");
        p.absorb("        Could not write rows to the temporary folder (no room on disk C: (2 KB to write)): they are missing from the timeline, and so are the next ones");
        assert!(p.waiting.is_none(), "the wait is over: the rows are left out");
    }

    #[test]
    fn the_parts_of_a_parse_are_notes_and_other_plain_lines_are_not() {
        let p = read(&[
            "        Part 1 of 2: disk images",
            "        Part 2 of 2: carving the disk images",
            "        Merging the 2 part(s) into one timeline",
            "        Disk images: --carve also carves the EVTX records of deleted or overwritten logs out of them",
            "        some other line of the parser",
        ]);
        assert_eq!(p.notes, vec!["Part 1 of 2: disk images", "Part 2 of 2: carving the disk images", "Merging the 2 part(s) into one timeline"]);
    }
}
