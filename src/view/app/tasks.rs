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
}

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

pub(super) struct HuntForm {
    pub from: String,
    pub end: String,
    pub alpha: String,
}

pub(super) struct MergeForm {
    pub inputs: Vec<String>,
    pub output: String,
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
                let _ = child.kill();
            }
        }
    }
}

impl Viewer {
    fn masstin_exe() -> std::path::PathBuf {
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("masstin"))
    }

    /// Start a child masstin with these arguments; its lines come through the channel.
    pub(super) fn start_job(&mut self, kind: JobKind, title: String, args: Vec<String>, open: Vec<String>, add: bool) {
        let exe = Self::masstin_exe();
        let command = format!("masstin {}", args.iter().map(|a| if a.contains(' ') { format!("\"{}\"", a) } else { a.clone() }).collect::<Vec<_>>().join(" "));
        let (tx, rx) = channel::<JobMsg>();
        let handle: Arc<Mutex<Option<std::process::Child>>> = Arc::new(Mutex::new(None));
        let handle2 = handle.clone();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut cmd = std::process::Command::new(&exe);
            cmd.args(&args).env("MASSTIN_PROGRESS_PIPE", "1").stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).stdin(std::process::Stdio::null());
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
                    for line in std::io::BufReader::new(err).lines().map_while(Result::ok) {
                        let _ = tx2.send(JobMsg::Line(line));
                    }
                }
            });
            if let Some(out) = out {
                for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
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
        self.job = Some(Job { kind, title, command, started: std::time::Instant::now(), ended: None, log: Vec::new(), rx, done: None, progress: Progress::default(), child: handle, open, add, past_banner: false, prelude: Vec::new(), stopped: false, autoclose_at: None });
    }

    /// Drain the running job's output; on its end, read the timeline again.
    pub(super) fn poll_job(&mut self, ctx: &egui::Context) {
        let Some(job) = self.job.as_mut() else { return };
        if job.done.is_some() {
            return;
        }
        while let Ok(m) = job.rx.try_recv() {
            match m {
                JobMsg::Line(l) => {
                    // the banner's carriage-return progress lines: keep the last state
                    let l = l.trim_end().to_string();
                    if l.is_empty() {
                        continue;
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
                    job.done = Some(r);
                    job.ended = Some(std::time::Instant::now());
                }
            }
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
        let finished = job.done.clone();
        let (kind, open, add) = (job.kind, job.open.clone(), job.add);
        if let Some(Ok(())) = finished {
            match kind {
                JobKind::Hunt => {
                    match self.reload_store() {
                        Ok(()) => {
                            self.remembered.clear();
                            self.draft.view = View::Findings;
                            self.requery(false);
                            self.begin_reveal();
                            self.status = format!("Hunt done: {}", self.status);
                        }
                        Err(e) => self.status = format!("Hunt done, but the timeline cannot be read again: {}", e),
                    }
                }
                JobKind::Ingest => {
                    if !open.is_empty() {
                        self.finish_ingest(open, add);
                    }
                }
                JobKind::Merge => {
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

    // ───────────────────────── the hunt ─────────────────────────

    pub(super) fn hunt_window(&mut self, ctx: &egui::Context) {
        if !self.show_hunt {
            return;
        }
        if self.hunt_form.from.is_empty() {
            // a sensible start: the window's From, or the last third of the timeline
            self.hunt_form.from = if !self.filter.from.trim().is_empty() { self.filter.from.clone() } else { fmt_time(self.store.t_min + (self.store.t_max - self.store.t_min) * 2 / 3) };
            self.hunt_form.alpha = format!("{}", self.alpha);
        }
        let mut open = true;
        let mut run = std::mem::take(&mut self.hunt_autorun);
        egui::Window::new(format!("{}  Hunt", ic::DETECTIVE)).open(&mut open).collapsible(false).resizable(false).default_width(520.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.label(egui::RichText::new("The statistical hunt of graph-hunt-csv, on the timeline(s) open here: every new connection after the start of the investigation is tested against what the network did before it, and each row gets its state, score and explanation in the hunt columns.").color(theme::MUTED));
            ui.add_space(8.0);
            egui::Grid::new("hunt-form").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                ui.label("Investigation from");
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.hunt_form.from).desired_width(170.0).hint_text("YYYY-MM-DD HH:MM:SS"));
                    if ui.small_button("window's From").on_hover_text("Take the time strip's left handle").clicked() {
                        self.hunt_form.from = if self.filter.from.trim().is_empty() { fmt_time(self.store.t_min) } else { self.filter.from.clone() };
                    }
                });
                ui.end_row();
                ui.label("Until (optional)");
                ui.add(egui::TextEdit::singleline(&mut self.hunt_form.end).desired_width(170.0).hint_text("YYYY-MM-DD HH:MM:SS"));
                ui.end_row();
                ui.label("Alpha (false discovery rate)");
                ui.add(egui::TextEdit::singleline(&mut self.hunt_form.alpha).desired_width(80.0));
                ui.end_row();
            });
            ui.add_space(4.0);
            let baseline_days = parse_time(&self.hunt_form.from).map(|t| ((t - self.store.t_min) as f64 / 86400.0).max(0.0)).unwrap_or(0.0);
            ui.label(egui::RichText::new(format!("Baseline before that start: {:.1} day(s). The verdicts and notes already written are kept.", baseline_days)).color(theme::DIM).small());
            ui.add_space(8.0);
            let ok = parse_time(&self.hunt_form.from).is_some() && self.hunt_form.alpha.parse::<f64>().map_or(false, |a| a > 0.0 && a < 1.0) && (self.hunt_form.end.trim().is_empty() || parse_time(&self.hunt_form.end).is_some());
            ui.horizontal(|ui| {
                if ui.add_enabled(ok && self.job.is_none(), egui::Button::new(theme::semibold(format!("{}  Run the hunt", ic::DETECTIVE), 13.5).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 30.0))).clicked() {
                    run = true;
                }
                if !ok {
                    ui.label(egui::RichText::new("the start needs a full date and time; alpha is between 0 and 1").color(CANDIDATE).small());
                }
            });
        });
        if run {
            let mut args = vec!["-a".to_string(), "graph-hunt-csv".to_string()];
            for f in &self.files {
                args.push("-f".into());
                args.push(f.clone());
            }
            args.push("--investigation-from".into());
            args.push(self.hunt_form.from.trim().to_string());
            if !self.hunt_form.end.trim().is_empty() {
                args.push("--end-time".into());
                args.push(self.hunt_form.end.trim().to_string());
            }
            args.push("--alpha".into());
            args.push(self.hunt_form.alpha.trim().to_string());
            self.start_job(JobKind::Hunt, "Hunting".into(), args, Vec::new(), false);
            self.show_hunt = false;
            self.hunt_sweep = Some(std::time::Instant::now());
        } else {
            self.show_hunt = open;
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
        let at = 0.3 + rank * REVEAL_SECS;
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
            if ui.button(format!("{}  Add timelines…", ic::PLUS)).clicked() {
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
                if ui.button(format!("{}  Save as…", ic::FLOPPY_DISK)).clicked() {
                    if let Some(p) = rfd::FileDialog::new().set_title("Merged timeline to write").add_filter("CSV", &["csv"]).set_file_name("merged.csv").save_file() {
                        self.merge_form.output = p.to_string_lossy().to_string();
                    }
                }
            });
            ui.add_space(6.0);
            let ok = self.merge_form.inputs.len() >= 2 && !self.merge_form.output.trim().is_empty();
            if ui.add_enabled(ok && self.job.is_none(), egui::Button::new(theme::semibold(format!("{}  Merge", ic::STACK), 13.5).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 30.0))).clicked() {
                run = true;
            }
        });
        if run {
            let out = self.merge_form.output.trim().to_string();
            let mut args = vec!["-a".to_string(), "merge".to_string()];
            for f in &self.merge_form.inputs {
                args.push("-f".into());
                args.push(f.clone());
            }
            args.push("-o".into());
            args.push(out.clone());
            args.push("--overwrite".into());
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
        if let Some(job) = self.job.as_ref() {
            if job.autoclose_at.map_or(false, |t| std::time::Instant::now() >= t) {
                let j = self.job.take().unwrap();
                self.last_log = Some((j.command, j.log));
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
                if ui.button("Close").clicked() {
                    close = true;
                }
            }
        });
        if (!open || close) && self.job.as_ref().map_or(false, |j| j.done.is_some()) {
            let j = self.job.take().unwrap();
            self.last_log = Some((j.command, j.log));
        }
    }

    /// The log of the last run, reopened from the Tools menu.
    pub(super) fn last_log_window(&mut self, ctx: &egui::Context) {
        if !self.show_last_log {
            return;
        }
        let mut open = true;
        egui::Window::new(format!("{}  Last run", ic::TERMINAL_WINDOW)).open(&mut open).collapsible(true).resizable(true).default_width(720.0).max_width(900.0).max_height(420.0).anchor(egui::Align2::RIGHT_BOTTOM, Vec2::new(-14.0, -104.0)).show(ctx, |ui| {
            ui.set_max_width(880.0);
            match &self.last_log {
                None => {
                    ui.label(egui::RichText::new("Nothing has run from this window yet.").color(theme::MUTED));
                }
                Some((command, log)) => {
                    ui.add(egui::Label::new(egui::RichText::new(command).monospace().size(11.0).color(theme::MUTED)).wrap());
                    theme::hairline(ui);
                    egui::ScrollArea::vertical().max_height(300.0).auto_shrink([false, true]).show(ui, |ui| {
                        for l in log {
                            ui.add(egui::Label::new(egui::RichText::new(l).monospace().size(11.0)).wrap());
                        }
                    });
                }
            }
        });
        self.show_last_log = open;
    }
}

/// Seconds the reveal takes to go through every finding of the view.
pub(super) const REVEAL_SECS: f32 = 3.0;
