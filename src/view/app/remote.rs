//! What masstin reads from, or writes to, a server: the Cortex XDR API
//! (Evidence › Cortex XDR API…) and the graph databases, Neo4j and Memgraph
//! (Evidence › Graph databases ›). Each is a window that builds the command a
//! terminal would run and runs it as a child masstin; the secret (the API
//! key, the database password) goes to the child in its environment
//! (`CORTEX_API_KEY` / `CORTEX_API_KEY_ID`, `NEO4J_PASSWORD`), never on the
//! command line, in the log or on disk, and is forgotten once it is passed.

use std::path::Path;

use super::tasks::JobKind;
use super::*;
use crate::view::icons as ic;
use crate::view::theme;

// ───────────────────────── Cortex XDR ─────────────────────────

pub(super) struct CortexForm {
    /// the tenant's sources to read (`--cortex-sources`): the endpoints'
    /// network connections, the event logs every agent sends, the event logs
    /// the forensics add-on collected
    pub network: bool,
    pub eventlog: bool,
    pub forensics: bool,
    pub url: String,
    pub key_id: String,
    pub key: String,
    pub from: String,
    pub to: String,
    pub filter_ip: String,
    pub admin_ports: bool,
    /// `--ignore-local`: link-local and placeholder origins left out too
    pub ignore_local: bool,
    pub event_ids: String,
    pub min_window: String,
    pub max_passes: String,
    pub output: String,
    /// the step of the wizard: the tenant, what to read, which events,
    /// the timeline, the run
    pub step: usize,
    /// whether the tenant accepted the URL, the key and its ID
    pub check: CortexCheck,
    /// what was checked (a digest of the three), so a change asks again
    pub checked: u64,
    /// go on to the next step when the check comes back well
    pub go_on: bool,
}

/// The answer of the tenant to "do this URL, this key and this ID work?".
#[derive(Default)]
pub(super) enum CortexCheck {
    #[default]
    NotAsked,
    Asking(std::sync::mpsc::Receiver<Result<Vec<String>, String>>, std::time::Instant),
    /// accepted: what it said (the kind of key, the quota used today)
    Accepted(Vec<String>),
    Refused(String),
}

impl Default for CortexForm {
    fn default() -> Self {
        CortexForm { network: true, eventlog: true, forensics: true, url: String::new(), key_id: String::new(), key: String::new(), from: String::new(), to: String::new(), filter_ip: String::new(), admin_ports: false, ignore_local: true, event_ids: String::new(), min_window: "300".into(), max_passes: "200".into(), output: String::new(), step: 0, check: CortexCheck::NotAsked, checked: 0, go_on: false }
    }
}

impl CortexForm {
    pub fn problem(&self) -> Option<&'static str> {
        if !self.url.trim().starts_with("https://api-") {
            return Some("the API URL starts with https://api- (Cortex › Settings › Configurations › API Keys › Copy API URL)");
        }
        if self.key_id.trim().parse::<u32>().is_err() {
            return Some("the key's ID is a number");
        }
        if self.key.trim().is_empty() {
            return Some("the API key is missing");
        }
        for t in [&self.from, &self.to] {
            if !t.trim().is_empty() && parse_time(t).is_none() {
                return Some("the times are full dates and times: YYYY-MM-DD HH:MM:SS");
            }
        }
        for n in [&self.min_window, &self.max_passes] {
            if n.trim().parse::<u64>().map_or(true, |v| v == 0) {
                return Some("the paging figures are whole numbers, 1 or more");
            }
        }
        if self.output.trim().is_empty() {
            return Some("the timeline needs a file");
        }
        if !(self.network || self.eventlog || self.forensics) {
            return Some("tick at least one source to read");
        }
        None
    }

    /// `--cortex-sources`' value; None when the three are read (the default).
    pub fn sources(&self) -> Option<String> {
        if self.network && self.eventlog && self.forensics {
            return None;
        }
        let names: Vec<&str> = [(self.network, "network"), (self.eventlog, "eventlog"), (self.forensics, "forensics")].iter().filter(|(on, _)| *on).map(|(_, n)| *n).collect();
        Some(names.join(","))
    }

    /// The command line: no secret in it.
    pub fn command(&self) -> Vec<String> {
        let mut args = vec!["-a".to_string(), "parse-cortex".to_string(), "--cortex-url".into(), self.url.trim().trim_end_matches('/').to_string()];
        if let Some(s) = self.sources() {
            args.push("--cortex-sources".into());
            args.push(s);
        }
        for (flag, v) in [("--start-time", &self.from), ("--end-time", &self.to)] {
            if !v.trim().is_empty() {
                args.push(flag.into());
                args.push(v.trim().to_string());
            }
        }
        if self.network && !self.filter_ip.trim().is_empty() {
            args.push("--filter-cortex-ip".into());
            args.push(self.filter_ip.trim().to_string());
        }
        if self.network && self.admin_ports {
            args.push("--admin-ports".into());
        }
        if self.ignore_local {
            args.push("--ignore-local".into());
        }
        if self.forensics && !self.event_ids.trim().is_empty() {
            args.push("--cortex-event-ids".into());
            args.push(self.event_ids.trim().to_string());
        }
        if self.min_window.trim() != "300" {
            args.push("--cortex-min-window-secs".into());
            args.push(self.min_window.trim().to_string());
        }
        if self.max_passes.trim() != "200" {
            args.push("--cortex-max-passes".into());
            args.push(self.max_passes.trim().to_string());
        }
        args.push("-o".into());
        args.push(self.output.trim().to_string());
        args.push("--overwrite".into());
        args
    }

    /// What stops the check of the connection: only the tenant's three values.
    pub fn tenant_problem(&self) -> Option<&'static str> {
        if !self.url.trim().starts_with("https://api-") {
            return Some("the API URL starts with https://api- (use Copy API URL in Cortex)");
        }
        if self.key_id.trim().parse::<u32>().is_err() {
            return Some("the key's ID is a number (the ID column of the key)");
        }
        if self.key.trim().is_empty() {
            return Some("the API key is missing");
        }
        None
    }

    /// A digest of the three values a check is about.
    pub fn tenant_digest(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        (self.url.trim().trim_end_matches('/'), self.key_id.trim(), self.key.trim()).hash(&mut h);
        h.finish() | 1
    }

    /// The tenant accepted these very values.
    pub fn connected(&self) -> bool {
        matches!(self.check, CortexCheck::Accepted(_)) && self.checked == self.tenant_digest()
    }

    /// The time window as the last hours up to now (UTC).
    pub fn last_hours(&mut self, hours: i64) {
        let now = chrono::Utc::now();
        self.from = (now - chrono::Duration::hours(hours)).format("%Y-%m-%d %H:%M:%S").to_string();
        self.to = now.format("%Y-%m-%d %H:%M:%S").to_string();
    }

    /// The secret, for the child's environment.
    pub fn env(&self) -> Vec<(String, String)> {
        vec![("CORTEX_API_KEY_ID".into(), self.key_id.trim().to_string()), ("CORTEX_API_KEY".into(), self.key.trim().to_string())]
    }
}

// ───────────────────────── graph databases ─────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum DbOp {
    Load,
    MergeNodes,
    Hunt,
}

pub(super) struct DbForm {
    pub memgraph: bool,
    pub op: DbOp,
    pub url: String,
    pub user: String,
    pub password: String,
    pub db: String,
    pub ungrouped: bool,
    pub from: String,
    pub to: String,
    pub old_node: String,
    pub new_node: String,
    pub hunt_from: String,
    pub alpha: String,
    pub report: String,
}

impl Default for DbForm {
    fn default() -> Self {
        DbForm { memgraph: false, op: DbOp::Load, url: "localhost:7687".into(), user: "neo4j".into(), password: String::new(), db: String::new(), ungrouped: false, from: String::new(), to: String::new(), old_node: String::new(), new_node: String::new(), hunt_from: String::new(), alpha: "0.05".into(), report: String::new() }
    }
}

impl DbForm {
    pub fn action(&self) -> &'static str {
        match (self.op, self.memgraph) {
            (DbOp::Load, false) => "load-neo4j",
            (DbOp::Load, true) => "load-memgraph",
            (DbOp::MergeNodes, false) => "merge-neo4j-nodes",
            (DbOp::MergeNodes, true) => "merge-memgraph-nodes",
            (DbOp::Hunt, false) => "graph-hunt-neo4j",
            (DbOp::Hunt, true) => "graph-hunt",
        }
    }

    pub fn problem(&self, files: &[String]) -> Option<&'static str> {
        if self.url.trim().is_empty() {
            return Some("the database's address is missing (host:port)");
        }
        if !self.memgraph && self.user.trim().is_empty() && self.op != DbOp::Hunt {
            return Some("Neo4j needs a user");
        }
        match self.op {
            DbOp::Load => {
                if files.is_empty() {
                    return Some("open a timeline first: it is what is loaded");
                }
                for t in [&self.from, &self.to] {
                    if !t.trim().is_empty() && parse_time(t).is_none() {
                        return Some("the times are full dates and times: YYYY-MM-DD HH:MM:SS");
                    }
                }
            }
            DbOp::MergeNodes => {
                if self.old_node.trim().is_empty() || self.new_node.trim().is_empty() {
                    return Some("both hosts are needed: the one that goes and the one that stays");
                }
            }
            DbOp::Hunt => {
                if parse_time(&self.hunt_from).is_none() {
                    return Some("the investigation needs a start: a full date and time");
                }
                if !self.alpha.trim().parse::<f64>().map_or(false, |a| a > 0.0 && a < 1.0) {
                    return Some("the false discovery rate is a number between 0 and 1");
                }
            }
        }
        None
    }

    pub fn command(&self, files: &[String]) -> Vec<String> {
        let mut args = vec!["-a".to_string(), self.action().to_string()];
        if self.op == DbOp::Load {
            for f in files {
                args.push("-f".into());
                args.push(f.clone());
            }
        }
        args.push("--database".into());
        args.push(self.url.trim().to_string());
        if !self.user.trim().is_empty() {
            args.push("-u".into());
            args.push(self.user.trim().to_string());
        }
        if !self.db.trim().is_empty() {
            args.push("--db".into());
            args.push(self.db.trim().to_string());
        }
        match self.op {
            DbOp::Load => {
                if self.ungrouped {
                    args.push("--ungrouped".into());
                }
                for (flag, v) in [("--start-time", &self.from), ("--end-time", &self.to)] {
                    if !v.trim().is_empty() {
                        args.push(flag.into());
                        args.push(v.trim().to_string());
                    }
                }
            }
            DbOp::MergeNodes => {
                args.push("--old-node".into());
                args.push(self.old_node.trim().to_string());
                args.push("--new-node".into());
                args.push(self.new_node.trim().to_string());
            }
            DbOp::Hunt => {
                args.push("--investigation-from".into());
                args.push(self.hunt_from.trim().to_string());
                args.push("--alpha".into());
                args.push(self.alpha.trim().to_string());
                if !self.report.trim().is_empty() {
                    args.push("--report".into());
                    args.push(self.report.trim().to_string());
                }
            }
        }
        args
    }

    /// Neo4j's password, for the child's environment; Memgraph takes none.
    pub fn env(&self) -> Vec<(String, String)> {
        if self.memgraph || self.password.is_empty() {
            Vec::new()
        } else {
            vec![("NEO4J_PASSWORD".into(), self.password.clone())]
        }
    }
}

/// What `masstin --cortex-check` printed, as the tenant's answer: the facts
/// it gave when it accepted (the kind of key, the quota), or why not, in
/// words a person can act on.
pub(super) fn cortex_answer(ok: bool, text: &str) -> Result<Vec<String>, String> {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if ok {
        return Ok(lines.iter().filter(|l| l.starts_with("Key:") || l.starts_with("Quota:")).map(|l| l.to_string()).collect());
    }
    let said = lines.iter().rev().find_map(|l| l.split_once("Error:").map(|(_, e)| e.trim().to_string())).unwrap_or_else(|| lines.last().map(|l| l.to_string()).unwrap_or_else(|| "masstin ended without saying why".to_string()));
    let low = said.to_lowercase();
    Err(if low.contains("dns error") || low.contains("no such host") || low.contains("failed to lookup") {
        "That address does not exist. Check the API URL: in Cortex, Settings › Configurations › API Keys › Copy API URL gives it whole.".to_string()
    } else if low.contains("timed out") || low.contains("error trying to connect") || low.contains("connection refused") {
        format!("The tenant could not be reached from this computer (no network, a proxy, or a firewall in between). What was said: {}", said)
    } else {
        said.trim_start_matches("Cortex did not accept the connection:").trim().to_string()
    })
}

fn command_line(args: &[String]) -> String {
    format!("masstin {}", args.iter().map(|a| if a.contains(' ') { format!("\"{}\"", a) } else { a.clone() }).collect::<Vec<_>>().join(" "))
}

fn row(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.add_sized([150.0, 20.0], egui::Label::new(egui::RichText::new(label).color(TEXT)));
        add(ui);
    });
}

fn hint(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).color(theme::MUTED).size(12.0));
}

fn run_button(ui: &mut egui::Ui, text: String, problem: Option<&str>, busy: bool) -> bool {
    let b = egui::Button::new(theme::semibold(text, 13.5).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 30.0)).corner_radius(CornerRadius::same(7));
    let r = ui.add_enabled(problem.is_none() && !busy, b);
    let clicked = r.clicked();
    if let Some(p) = problem {
        ui.label(egui::RichText::new(format!("{}  {}", ic::WARNING, p)).color(CANDIDATE).small());
    } else if busy {
        ui.label(egui::RichText::new("something is running already").color(CANDIDATE).small());
    }
    clicked
}

impl Viewer {
    /// Ask the tenant whether the URL, the key and its ID work: a child
    /// masstin with `--cortex-check` (the one request that costs nothing),
    /// the key in its environment.
    pub(super) fn cortex_check_start(&mut self) {
        let f = &mut self.cortex_form;
        if f.tenant_problem().is_some() || matches!(f.check, CortexCheck::Asking(..)) {
            return;
        }
        let exe = Self::masstin_exe();
        let url = f.url.trim().trim_end_matches('/').to_string();
        let env = f.env();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut cmd = std::process::Command::new(&exe);
            cmd.args(["-a", "parse-cortex", "--cortex-url", &url, "--cortex-check"]).envs(env).stdin(std::process::Stdio::null());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(0x0800_0000);
            }
            let answer = match cmd.output() {
                Ok(o) => cortex_answer(o.status.success(), &format!("{}\n{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))),
                Err(e) => Err(format!("cannot start {}: {}", exe.display(), e)),
            };
            let _ = tx.send(answer);
        });
        f.checked = f.tenant_digest();
        f.check = CortexCheck::Asking(rx, std::time::Instant::now());
    }

    /// Evidence › Cortex XDR API…: the wizard, step by step.
    pub(super) fn cortex_window(&mut self, ctx: &egui::Context) {
        if !self.show_cortex {
            return;
        }
        // the tenant's answer, when it comes
        if let CortexCheck::Asking(rx, _) = &self.cortex_form.check {
            match rx.try_recv() {
                Ok(Ok(facts)) => {
                    self.cortex_form.check = CortexCheck::Accepted(facts);
                    if std::mem::take(&mut self.cortex_form.go_on) && self.cortex_form.step == 0 {
                        self.cortex_form.step = 1;
                    }
                }
                Ok(Err(why)) => {
                    self.cortex_form.check = CortexCheck::Refused(why);
                    self.cortex_form.go_on = false;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => ctx.request_repaint_after(std::time::Duration::from_millis(120)),
                Err(_) => self.cortex_form.check = CortexCheck::Refused("the check ended without an answer".into()),
            }
        }
        let beside = self.files.first().and_then(|t| Path::new(t).parent().map(|d| d.to_path_buf()));
        if self.cortex_form.output.trim().is_empty() {
            // next to the open timeline, else the folder masstin runs in
            let dir = beside.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
            self.cortex_form.output = dir.join("cortex.csv").to_string_lossy().to_string();
        }
        let running = self.job.as_ref().map_or(false, |j| j.kind == JobKind::Remote && j.title.contains("Cortex"));
        let busy = self.job.is_some();
        let mut open = true;
        let mut check = false;
        let mut run = false;
        let mut stop = false;
        let mut close = false;
        let tall = (ctx.content_rect().height() - 250.0).clamp(320.0, 620.0);
        egui::Window::new(format!("{}  Cortex XDR", ic::CLOUD)).id(egui::Id::new("cortex-wizard")).open(&mut open).collapsible(false).resizable(false).default_width(720.0).max_width(740.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.set_width(700.0);
            ui.set_max_width(700.0);
            super::ingest::stepper(ui, self.cortex_form.step, &["Tenant", "What to read", "Which events", "Timeline", "Run"]);
            ui.add_space(6.0);
            egui::ScrollArea::vertical().max_height(tall).auto_shrink([false, true]).show(ui, |ui| match self.cortex_form.step {
                0 => self.cortex_step_tenant(ui, &mut check),
                1 => self.cortex_step_sources(ui),
                2 => self.cortex_step_events(ui),
                3 => self.cortex_step_output(ui),
                _ => self.cortex_step_run(ui),
            });
            ui.add_space(8.0);
            theme::hairline(ui);
            let f = &mut self.cortex_form;
            let primary = |ui: &mut egui::Ui, text: String, on: bool| ui.add_enabled(on, egui::Button::new(theme::semibold(text, 13.5).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 30.0)).corner_radius(CornerRadius::same(7)));
            ui.horizontal(|ui| {
                if f.step > 0 && f.step < 4 && ui.add(egui::Button::new(format!("{}  Back", ic::ARROW_LEFT)).min_size(Vec2::new(0.0, 30.0))).clicked() {
                    f.step -= 1;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| match f.step {
                    0 => {
                        let asking = matches!(f.check, CortexCheck::Asking(..));
                        if f.connected() {
                            if primary(ui, format!("Next  {}", ic::ARROW_RIGHT), true).clicked() {
                                f.step = 1;
                            }
                        } else if primary(ui, format!("{}  Check and continue", ic::PLUGS_CONNECTED), f.tenant_problem().is_none() && !asking).on_hover_text("Ask the tenant whether these three values work (a request that costs no compute units) and go on when it says yes").on_disabled_hover_text(f.tenant_problem().unwrap_or("asking the tenant…")).clicked() {
                            check = true;
                            f.go_on = true;
                        }
                    }
                    1 => {
                        let any = f.network || f.eventlog || f.forensics;
                        if primary(ui, format!("Next  {}", ic::ARROW_RIGHT), any).on_disabled_hover_text("tick at least one source to read").clicked() {
                            f.step = 2;
                        }
                    }
                    2 => {
                        let bad = [&f.from, &f.to].iter().any(|t| !t.trim().is_empty() && parse_time(t).is_none());
                        if primary(ui, format!("Next  {}", ic::ARROW_RIGHT), !bad).on_disabled_hover_text("the times are full dates and times: YYYY-MM-DD HH:MM:SS").clicked() {
                            f.step = 3;
                        }
                    }
                    3 => {
                        let problem = f.problem().or(if !f.connected() { Some("the connection has not been checked with these values: go back to the first step") } else { None }).or(if busy { Some("something is running already") } else { None });
                        if primary(ui, format!("{}  Read from Cortex", ic::CLOUD), problem.is_none()).on_disabled_hover_text(problem.unwrap_or("")).clicked() {
                            run = true;
                        }
                        if let Some(p) = problem {
                            ui.label(egui::RichText::new(format!("{}  {}", ic::WARNING, p)).color(CANDIDATE).small());
                        }
                    }
                    _ => {
                        if running && self.job.as_ref().map_or(false, |j| j.done.is_none()) {
                            if ui.add(egui::Button::new(egui::RichText::new(format!("{}  Stop", ic::X)).color(SIGNIFICANT)).min_size(Vec2::new(0.0, 30.0))).clicked() {
                                stop = true;
                            }
                        } else {
                            if ui.add(egui::Button::new("Close").min_size(Vec2::new(0.0, 30.0))).clicked() {
                                close = true;
                            }
                            if ui.add(egui::Button::new(format!("{}  Read again", ic::ARROW_LEFT)).min_size(Vec2::new(0.0, 30.0))).on_hover_text("Back to the settings, to read another period or other sources").clicked() {
                                f.step = 2;
                            }
                        }
                    }
                });
            });
        });
        if check {
            self.cortex_check_start();
        }
        if stop {
            if let Some(j) = self.job.as_mut().filter(|j| j.kind == JobKind::Remote) {
                j.cancel();
            }
        }
        if run {
            let args = self.cortex_form.command();
            let env = self.cortex_form.env();
            let out = self.cortex_form.output.trim().to_string();
            self.start_job_env(JobKind::Remote, "Reading from Cortex XDR".into(), args, vec![out], false, env);
            self.cortex_form.step = 4;
        }
        if close || !open {
            // the key does not outlive the window
            if !self.job.as_ref().map_or(false, |j| j.done.is_none()) {
                self.cortex_form.key.clear();
                self.cortex_form.check = CortexCheck::NotAsked;
                self.cortex_form.step = 0;
            }
            self.show_cortex = false;
        }
    }

    fn cortex_step_tenant(&mut self, ui: &mut egui::Ui, check: &mut bool) {
        let f = &mut self.cortex_form;
        ui.label(egui::RichText::new("masstin reads lateral movement straight from your Cortex XDR tenant, through its XQL API, and writes one timeline. First, who to ask: three values the tenant gives you.").color(theme::MUTED));
        ui.add_space(6.0);
        egui::Frame::new().fill(theme::PANEL_2).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::same(10)).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(theme::semibold("Where to find them", 12.5).color(TEXT));
            for line in [
                "1.  In Cortex XDR: Settings › Configurations › API Keys.",
                "2.  New Key: role Instance Administrator (or any role that may run XQL queries). Standard or Advanced, masstin tells which.",
                "3.  Copy API URL (a button above the table) is the URL. The ID column of the key is its ID. The key itself is shown once, when it is made.",
            ] {
                ui.label(egui::RichText::new(line).color(theme::MUTED).size(12.0));
            }
        });
        theme::section(ui, "The tenant");
        row(ui, "API URL", |ui| {
            ui.add(egui::TextEdit::singleline(&mut f.url).desired_width(470.0).hint_text("https://api-yourtenant.xdr.eu.paloaltonetworks.com"));
        });
        row(ui, "Key ID", |ui| {
            ui.add(egui::TextEdit::singleline(&mut f.key_id).desired_width(80.0).hint_text("12"));
        });
        row(ui, "API key", |ui| {
            ui.add(egui::TextEdit::singleline(&mut f.key).password(true).desired_width(470.0).hint_text("paste the key"));
        });
        hint(ui, "The key goes to masstin in its environment, never on a command line, in a log or on disk, and is forgotten when this window closes.");
        ui.add_space(8.0);
        // the answer of the tenant
        let stale = !matches!(f.check, CortexCheck::NotAsked | CortexCheck::Asking(..)) && f.checked != f.tenant_digest();
        let (fill, stroke, icon, ink, title, lines): (Color32, Color32, &str, Color32, String, Vec<String>) = match &f.check {
            CortexCheck::Asking(_, since) => (theme::PANEL_2, theme::BORDER_2, ic::ARROWS_CLOCKWISE, theme::CYAN, format!("Asking the tenant…  {:.0} s", since.elapsed().as_secs_f32()), vec![]),
            _ if stale => (theme::PANEL_2, theme::BORDER_2, ic::PLUGS_CONNECTED, theme::MUTED, "The values changed: check the connection again".to_string(), vec![]),
            CortexCheck::Accepted(facts) => (Color32::from_rgba_unmultiplied(60, 220, 130, 26), Color32::from_rgb(60, 220, 130), ic::CHECK_CIRCLE, Color32::from_rgb(90, 235, 150), "Connected: the tenant accepted the URL, the key and its ID".to_string(), facts.clone()),
            CortexCheck::Refused(why) => (Color32::from_rgba_unmultiplied(236, 72, 96, 24), SIGNIFICANT, ic::WARNING, SIGNIFICANT, "The tenant did not accept the connection".to_string(), vec![why.clone()]),
            CortexCheck::NotAsked => (theme::PANEL_2, theme::BORDER_2, ic::PLUGS_CONNECTED, theme::MUTED, "Not checked yet".to_string(), vec!["The check is one request that costs no compute units: it asks for the tenant's XQL quota, which only a working key with the right role gets.".to_string()]),
        };
        egui::Frame::new().fill(fill).stroke(Stroke::new(1.0, draw::fade(stroke, 0.8))).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::same(10)).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                if matches!(f.check, CortexCheck::Asking(..)) {
                    ui.add(egui::Spinner::new().size(15.0).color(theme::ACCENT));
                } else {
                    ui.label(egui::RichText::new(icon).color(ink).size(17.0));
                }
                ui.label(theme::semibold(title, 13.5).color(ink));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let can = f.tenant_problem().is_none() && !matches!(f.check, CortexCheck::Asking(..));
                    if ui.add_enabled(can, egui::Button::new(format!("{}  Check the connection", ic::PLUGS_CONNECTED))).on_hover_text("Ask the tenant whether these three values work. It costs no compute units").on_disabled_hover_text(f.tenant_problem().unwrap_or("asking the tenant…")).clicked() {
                        *check = true;
                    }
                });
            });
            for l in lines {
                ui.add(egui::Label::new(egui::RichText::new(l).color(TEXT).size(12.5)).wrap());
            }
        });
    }

    fn cortex_step_sources(&mut self, ui: &mut egui::Ui) {
        let f = &mut self.cortex_form;
        ui.label(egui::RichText::new("A tenant holds lateral movement in three places. masstin reads the three and joins them into one timeline; untick what you do not want. Each is read with XQL queries, which spend the tenant's compute units.").color(theme::MUTED));
        ui.add_space(6.0);
        for (on, icon, title, what, note) in [
            (&mut f.network, ic::GRAPH, "Network connections of the endpoints", "Who connected to whom over RDP, SMB, SSH and WinRM, as every agent saw it. No accounts, but every machine with an agent, as far back as the tenant keeps its data.", "the widest view"),
            (&mut f.eventlog, ic::KEY, "Windows event logs the agents send", "Logons, logoffs, Kerberos, NTLM and shares (4624, 4625, 4648, 4768…): the accounts behind the connections, from every agent, with no triage needed.", "who it was"),
            (&mut f.forensics, ic::DETECTIVE, "Event logs collected by the forensics add-on", "The whole logs of the machines that were triaged or hunted, with the RDP, SMB client and WinRM channels. Left out by itself where the tenant has no add-on.", "the deepest, where there was a triage"),
        ] {
            let r = theme::card(ui, *on, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(if *on { ic::CHECK_CIRCLE } else { ic::CIRCLE }).color(if *on { theme::CYAN } else { theme::DIM }).size(17.0));
                    ui.label(egui::RichText::new(icon).color(theme::MUTED).size(16.0));
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(theme::semibold(title, 13.5).color(TEXT));
                            ui.label(egui::RichText::new(note).small().color(theme::DIM));
                        });
                        ui.add(egui::Label::new(egui::RichText::new(what).color(theme::MUTED).size(12.0)).wrap());
                    });
                });
            });
            if r.clicked() {
                *on = !*on;
            }
        }
    }

    fn cortex_step_events(&mut self, ui: &mut egui::Ui) {
        let f = &mut self.cortex_form;
        ui.label(egui::RichText::new("Which period to read, and what to leave out. A shorter period is faster and spends fewer compute units; start with the days around what you are looking into.").color(theme::MUTED));
        theme::section(ui, "Period (UTC)");
        ui.horizontal(|ui| {
            for (label, hours) in [("Last 24 hours", 24), ("Last 3 days", 72), ("Last 7 days", 168), ("Last 30 days", 720)] {
                if ui.button(label).on_hover_text("From that long ago up to now").clicked() {
                    f.last_hours(hours);
                }
            }
            if ui.button("The default").on_hover_text("Empty both: the last 7 days of the network and the agents' event logs, the last year of the forensics event logs").clicked() {
                f.from.clear();
                f.to.clear();
            }
        });
        row(ui, "From", |ui| {
            for (k, t) in [&mut f.from, &mut f.to].into_iter().enumerate() {
                let bad = !t.trim().is_empty() && parse_time(t).is_none();
                ui.add(egui::TextEdit::singleline(t).desired_width(170.0).hint_text("YYYY-MM-DD HH:MM:SS").text_color_opt(bad.then_some(SIGNIFICANT)));
                if k == 0 {
                    ui.label(egui::RichText::new("to").color(theme::MUTED));
                }
            }
        });
        hint(ui, "Empty: the last 7 days of the network and the agents' event logs, the last year of the forensics event logs.");
        theme::section(ui, "Filters");
        ui.checkbox(&mut f.ignore_local, "Leave out logons with no real origin: local sessions, unlocks, services, loopback").on_hover_text("Most of the agents' logon events are local to the machine and say nothing about movement between machines. Ticked, the timeline is a fraction of the size and reads faster (--ignore-local)");
        if f.network {
            row(ui, "Only this address", |ui| {
                ui.add(egui::TextEdit::singleline(&mut f.filter_ip).desired_width(170.0).hint_text("optional")).on_hover_text("Network connections: only the ones this address takes part in, as origin or destination (--filter-cortex-ip)");
            });
            ui.checkbox(&mut f.admin_ports, "Network: every admin port too (135, 139, 1433, 3306, 5900…)").on_hover_text("Besides RDP, SMB, SSH and WinRM: RPC, NetBIOS, SQL Server, MySQL and VNC. More rows, more compute units (--admin-ports)");
        }
        if f.forensics {
            row(ui, "Forensics event IDs", |ui| {
                ui.add(egui::TextEdit::singleline(&mut f.event_ids).desired_width(320.0).hint_text("the default set; or 4624,4625,4648")).on_hover_text("Forensics event logs: only these event IDs, separated by commas. Empty reads the set masstin knows (--cortex-event-ids)");
            });
        }
        egui::CollapsingHeader::new(theme::semibold("Advanced: paging (when a period holds more than the API returns at once)", 12.5)).id_salt("cortex-paging").show(ui, |ui| {
            row(ui, "Smallest window (s)", |ui| {
                ui.add(egui::TextEdit::singleline(&mut f.min_window).desired_width(70.0));
            });
            row(ui, "Most queries", |ui| {
                ui.add(egui::TextEdit::singleline(&mut f.max_passes).desired_width(70.0));
            });
            hint(ui, "The API returns a million rows at most. A period that reaches it is split in halves and each half asked again, down to the smallest window, with at most this many queries. The defaults fit almost every tenant.");
        });
    }

    fn cortex_step_output(&mut self, ui: &mut egui::Ui) {
        let f = &mut self.cortex_form;
        ui.label(egui::RichText::new("Where the timeline is written. When the reading ends it opens here, as a graph.").color(theme::MUTED));
        theme::section(ui, "Timeline to write");
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut f.output).desired_width(520.0));
            if ui.button(format!("{}  Save as…", ic::FLOPPY_DISK)).on_hover_text("Choose where the file is written and its name").clicked() {
                if let Some(p) = rfd::FileDialog::new().add_filter("CSV", &["csv"]).set_file_name("cortex.csv").save_file() {
                    f.output = p.to_string_lossy().to_string();
                }
            }
        });
        if Path::new(f.output.trim()).exists() {
            ui.label(egui::RichText::new(format!("{}  this file exists and will be written over", ic::WARNING)).color(CANDIDATE).small());
        }
        theme::section(ui, "What is about to happen");
        let sources: Vec<&str> = [(f.network, "network connections"), (f.eventlog, "the agents' event logs"), (f.forensics, "the forensics event logs")].iter().filter(|(on, _)| *on).map(|(_, n)| *n).collect();
        let period = if f.from.trim().is_empty() && f.to.trim().is_empty() { "the last 7 days (the last year for the forensics event logs)".to_string() } else { format!("{} to {} (UTC)", if f.from.trim().is_empty() { "the start" } else { f.from.trim() }, if f.to.trim().is_empty() { "now" } else { f.to.trim() }) };
        for (k, v) in [("Tenant", f.url.trim().to_string()), ("Reads", sources.join(", ")), ("Period", period), ("Leaves out", if f.ignore_local { "logons with no real origin".to_string() } else { "nothing".to_string() })] {
            ui.horizontal(|ui| {
                ui.add_sized([90.0, 18.0], egui::Label::new(egui::RichText::new(k).color(theme::MUTED)));
                ui.add(egui::Label::new(egui::RichText::new(v).color(TEXT)).wrap());
            });
        }
        ui.add_space(4.0);
        hint(ui, "The same from a terminal (the key is asked there, or taken from CORTEX_API_KEY and CORTEX_API_KEY_ID):");
        ui.add(egui::Label::new(egui::RichText::new(command_line(&f.command())).monospace().size(10.5).color(theme::DIM)).wrap());
    }

    fn cortex_step_run(&mut self, ui: &mut egui::Ui) {
        let Some(job) = self.job.as_ref().filter(|j| j.kind == JobKind::Remote && j.title.contains("Cortex")) else {
            ui.label(egui::RichText::new("Nothing is running. The timeline, if the reading ended well, is open in the window behind this one.").color(theme::MUTED));
            return;
        };
        ui.label(egui::RichText::new("The tenant runs each query and masstin fetches what it returns. A big period takes minutes: the bar is the share of the period read so far.").color(theme::MUTED));
        ui.add_space(6.0);
        super::ingest::progress_ui(ui, job);
        match &job.done {
            Some(Err(e)) if !job.stopped => {
                ui.add_space(4.0);
                egui::Frame::new().fill(Color32::from_rgba_unmultiplied(236, 72, 96, 22)).stroke(Stroke::new(1.0, draw::fade(SIGNIFICANT, 0.7))).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::same(10)).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(egui::RichText::new(format!("{}  {}", ic::WARNING, e)).color(SIGNIFICANT));
                    for l in job.log.iter().filter(|l| l.contains("Error") || l.contains("error")).take(3) {
                        ui.add(egui::Label::new(egui::RichText::new(l).color(TEXT).size(12.5)).wrap());
                    }
                });
            }
            Some(Ok(())) => {
                ui.add_space(4.0);
                egui::Frame::new().fill(Color32::from_rgba_unmultiplied(38, 228, 226, 14)).stroke(Stroke::new(1.0, draw::fade(theme::CYAN, 0.6))).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::same(10)).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(theme::semibold(format!("{}  The timeline is written and open", ic::CHECK_CIRCLE), 13.5).color(theme::CYAN));
                    for (k, v) in &job.progress.summary {
                        ui.label(egui::RichText::new(format!("{}: {}", k, v)).color(TEXT).size(12.5));
                    }
                });
            }
            _ => {}
        }
        egui::CollapsingHeader::new(egui::RichText::new("What masstin says").small().color(theme::MUTED)).id_salt("cortex-log").show(ui, |ui| {
            egui::ScrollArea::vertical().id_salt("cortex-log-lines").max_height(160.0).stick_to_bottom(true).show(ui, |ui| {
                for l in job.log.iter().rev().take(200).rev() {
                    ui.add(egui::Label::new(egui::RichText::new(l).monospace().size(10.5).color(theme::DIM)).wrap());
                }
            });
        });
    }

    pub(super) fn db_window(&mut self, ctx: &egui::Context) {
        if !self.show_db {
            return;
        }
        let files = self.files.clone();
        let busy = self.job.is_some();
        let f = &mut self.db_form;
        if f.hunt_from.is_empty() && !files.is_empty() {
            f.hunt_from = fmt_time(self.store.t_min + (self.store.t_max - self.store.t_min) * 2 / 3);
        }
        let mut open = true;
        let mut run = false;
        egui::Window::new(format!("{}  Graph databases", ic::DATABASE)).open(&mut open).collapsible(false).resizable(false).default_width(640.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            hint(ui, "The timeline in Neo4j or Memgraph, for Cypher queries of your own and their browsers. masstin's window does the same without a database: this is for teams that keep one.");
            theme::section(ui, "Database");
            ui.horizontal(|ui| {
                let before = f.memgraph;
                ui.radio_value(&mut f.memgraph, false, "Neo4j");
                ui.radio_value(&mut f.memgraph, true, "Memgraph");
                if before != f.memgraph {
                    // each one's usual user
                    if f.memgraph && f.user == "neo4j" {
                        f.user.clear();
                    } else if !f.memgraph && f.user.is_empty() {
                        f.user = "neo4j".into();
                    }
                }
            });
            row(ui, "Address", |ui| {
                ui.add(egui::TextEdit::singleline(&mut f.url).desired_width(240.0).hint_text("localhost:7687"));
            });
            row(ui, "User", |ui| {
                ui.add(egui::TextEdit::singleline(&mut f.user).desired_width(160.0).hint_text(if f.memgraph { "none" } else { "neo4j" }));
            });
            if !f.memgraph {
                row(ui, "Password", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut f.password).password(true).desired_width(240.0));
                });
            }
            row(ui, "Database name", |ui| {
                ui.add(egui::TextEdit::singleline(&mut f.db).desired_width(160.0).hint_text(if f.memgraph { "memgraph" } else { "neo4j" }));
            });
            if !f.memgraph {
                hint(ui, "The password goes to masstin in its environment (NEO4J_PASSWORD), never on the command line.");
            }
            theme::section(ui, "What to do");
            ui.radio_value(&mut f.op, DbOp::Load, "Load the open timeline(s) into it");
            ui.radio_value(&mut f.op, DbOp::MergeNodes, "Merge two host nodes in it (two names of one machine)");
            ui.radio_value(&mut f.op, DbOp::Hunt, "Run the statistical hunt on the graph it holds");
            ui.add_space(4.0);
            match f.op {
                DbOp::Load => {
                    if files.is_empty() {
                        ui.label(egui::RichText::new("Open a timeline first: it is what gets loaded.").color(CANDIDATE).small());
                    } else {
                        for t in &files {
                            ui.label(egui::RichText::new(format!("{}  {}", ic::TABLE, t)).size(12.0).color(theme::MUTED));
                        }
                    }
                    ui.checkbox(&mut f.ungrouped, "One relationship per event, not one per account, origin and destination (--ungrouped)");
                    row(ui, "Only from", |ui| {
                        ui.add(egui::TextEdit::singleline(&mut f.from).desired_width(160.0).hint_text("the first event"));
                        ui.label(egui::RichText::new("to").color(theme::MUTED));
                        ui.add(egui::TextEdit::singleline(&mut f.to).desired_width(160.0).hint_text("the last"));
                    });
                }
                DbOp::MergeNodes => {
                    row(ui, "Host that goes", |ui| {
                        ui.add(egui::TextEdit::singleline(&mut f.old_node).desired_width(240.0).hint_text("10.0.0.5"));
                    });
                    row(ui, "Host that stays", |ui| {
                        ui.add(egui::TextEdit::singleline(&mut f.new_node).desired_width(240.0).hint_text("WEB01"));
                    });
                    hint(ui, "Its relationships move to the one that stays (--old-node, --new-node). In this window, Tools › Merged hosts does the same without a database.");
                }
                DbOp::Hunt => {
                    row(ui, "Investigation from", |ui| {
                        ui.add(egui::TextEdit::singleline(&mut f.hunt_from).desired_width(160.0).hint_text("YYYY-MM-DD HH:MM:SS"));
                    });
                    row(ui, "False discovery rate", |ui| {
                        ui.add(egui::TextEdit::singleline(&mut f.alpha).desired_width(70.0));
                    });
                    row(ui, "Report (optional)", |ui| {
                        ui.add(egui::TextEdit::singleline(&mut f.report).desired_width(380.0).hint_text("a Markdown file"));
                    });
                    hint(ui, "The graph must have been loaded with one relationship per event (--ungrouped). The full hunt, with seeds, Sigma and detectors, is Hunt › Run the hunt on the timeline itself.");
                }
            }
            ui.add_space(4.0);
            ui.add(egui::Label::new(egui::RichText::new(command_line(&f.command(&files))).monospace().size(10.5).color(theme::DIM)).wrap());
            ui.add_space(4.0);
            run = run_button(ui, format!("{}  Run", ic::DATABASE), f.problem(&files), busy);
        });
        if run {
            let args = self.db_form.command(&files);
            let env = self.db_form.env();
            let title = format!("{} ({})", match self.db_form.op { DbOp::Load => "Loading into the database", DbOp::MergeNodes => "Merging the nodes", DbOp::Hunt => "Hunting in the database" }, if self.db_form.memgraph { "Memgraph" } else { "Neo4j" });
            self.db_form.password.clear();
            self.start_job_env(JobKind::Remote, title, args, Vec::new(), false, env);
            self.show_db = false;
        } else {
            self.show_db = open;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cortex() -> CortexForm {
        let mut c = CortexForm::default();
        c.url = "https://api-x.xdr.eu.paloaltonetworks.com/".into();
        c.key_id = "12".into();
        c.key = "secret-key".into();
        c.output = "c.csv".into();
        c
    }

    #[test]
    fn the_cortex_command_holds_no_secret() {
        let c = cortex();
        assert_eq!(c.problem(), None);
        let args = c.command();
        // the three sources, local logons left out: the window's usual run
        assert_eq!(args, vec!["-a", "parse-cortex", "--cortex-url", "https://api-x.xdr.eu.paloaltonetworks.com", "--ignore-local", "-o", "c.csv", "--overwrite"]);
        assert!(!args.iter().any(|a| a.contains("secret")));
        assert_eq!(c.env(), vec![("CORTEX_API_KEY_ID".to_string(), "12".to_string()), ("CORTEX_API_KEY".to_string(), "secret-key".to_string())]);
    }

    #[test]
    fn the_cortex_options_go_where_they_belong() {
        let mut c = cortex();
        c.from = "2026-11-01 00:00:00".into();
        c.admin_ports = true;
        c.event_ids = "4624".into();
        c.min_window = "60".into();
        let s = c.command().join(" ");
        assert!(s.contains("--start-time 2026-11-01 00:00:00 --admin-ports --ignore-local --cortex-event-ids 4624 --cortex-min-window-secs 60 -o"), "{}", s);
        c.ignore_local = false;
        assert!(c.command().join(" ").contains("--admin-ports --cortex-event-ids 4624"));
        // only the forensics: named, and the network's options left out
        c.network = false;
        c.eventlog = false;
        let s = c.command().join(" ");
        assert!(s.starts_with("-a parse-cortex --cortex-url https://api-x.xdr.eu.paloaltonetworks.com --cortex-sources forensics"), "{}", s);
        assert!(s.contains("--cortex-event-ids 4624") && !s.contains("--admin-ports"));
        c.forensics = false;
        assert_eq!(c.problem(), Some("tick at least one source to read"));
        c.network = true;
        c.eventlog = true;
        assert_eq!(c.sources().as_deref(), Some("network,eventlog"));
        c.url = "https://x.paloaltonetworks.com".into();
        assert!(c.problem().is_some());
        c.url = "https://api-x".into();
        c.key_id = "twelve".into();
        assert!(c.problem().is_some());
    }

    #[test]
    fn the_database_actions_by_engine_and_operation() {
        let files = vec!["t.csv".to_string()];
        let mut d = DbForm::default();
        assert_eq!(d.command(&files), vec!["-a", "load-neo4j", "-f", "t.csv", "--database", "localhost:7687", "-u", "neo4j"]);
        d.password = "pw".into();
        assert_eq!(d.env(), vec![("NEO4J_PASSWORD".to_string(), "pw".to_string())]);
        assert!(!d.command(&files).iter().any(|a| a == "pw"));
        d.memgraph = true;
        d.user.clear();
        d.ungrouped = true;
        assert_eq!(d.command(&files).join(" "), "-a load-memgraph -f t.csv --database localhost:7687 --ungrouped");
        assert!(d.env().is_empty());
        d.op = DbOp::MergeNodes;
        assert!(d.problem(&files).is_some());
        d.old_node = "10.0.0.5".into();
        d.new_node = "WEB01".into();
        assert_eq!(d.command(&files).join(" "), "-a merge-memgraph-nodes --database localhost:7687 --old-node 10.0.0.5 --new-node WEB01");
        d.op = DbOp::Hunt;
        d.hunt_from = "2026-11-10 00:00:00".into();
        d.memgraph = false;
        d.user = "neo4j".into();
        d.report = "r.md".into();
        assert_eq!(d.problem(&files), None);
        assert_eq!(d.command(&files).join(" "), "-a graph-hunt-neo4j --database localhost:7687 -u neo4j --investigation-from 2026-11-10 00:00:00 --alpha 0.05 --report r.md");
        d.op = DbOp::Load;
        assert!(d.problem(&[]).is_some());
    }
}

#[cfg(test)]
mod cortex_wizard_tests {
    use super::*;

    /// What the check printed becomes the tenant's answer: its facts when
    /// it accepted, the reason in plain words when it did not.
    #[test]
    fn the_checks_output_is_read_as_the_tenants_answer() {
        let ok = "  [1/1] Checking the connection with Cortex XDR...\n        Tenant: https://api-x.xdr.eu.paloaltonetworks.com\n        Auth: API key from $CORTEX_API_KEY (id from $CORTEX_API_KEY_ID)\n        Key: Advanced (signed with a nonce and the time)\n        Quota: 1.25 of 100 compute units used today\n";
        assert_eq!(cortex_answer(true, ok), Ok(vec!["Key: Advanced (signed with a nonce and the time)".to_string(), "Quota: 1.25 of 100 compute units used today".to_string()]));
        let dns = "Masstin - Error: Cortex did not accept the connection: error sending request for url (https://api-x/public_api/v1/xql/get_quota): error trying to connect: dns error: No such host is known. (os error 11001)";
        assert!(cortex_answer(false, dns).unwrap_err().starts_with("That address does not exist"));
        let refused = "        Tenant: https://api-x\nMasstin - Error: Cortex did not accept the connection: 401 on the first request (XQL quota): Public API request unauthorized · the key or its ID is not accepted";
        assert_eq!(cortex_answer(false, refused).unwrap_err(), "401 on the first request (XQL quota): Public API request unauthorized · the key or its ID is not accepted");
        assert!(cortex_answer(false, "").unwrap_err().contains("without saying why"));
    }

    /// A check is about three values: changing any of them asks again.
    #[test]
    fn a_check_holds_for_the_values_it_was_made_with() {
        let mut f = CortexForm { url: "https://api-x.xdr.eu.paloaltonetworks.com".into(), key_id: "12".into(), key: "k".into(), ..CortexForm::default() };
        assert!(f.tenant_problem().is_none() && !f.connected());
        f.check = CortexCheck::Accepted(vec![]);
        f.checked = f.tenant_digest();
        assert!(f.connected());
        f.key.push('x');
        assert!(!f.connected());
        f.key.pop();
        f.url.push('/');
        assert!(f.connected(), "a slash at the end of the URL is the same tenant");
        assert_eq!(CortexForm { url: "http://x".into(), ..CortexForm::default() }.tenant_problem().map(|p| p.starts_with("the API URL")), Some(true));
        f.last_hours(24);
        assert!(parse_time(&f.from).is_some() && parse_time(&f.to).is_some() && parse_time(&f.to).unwrap() - parse_time(&f.from).unwrap() == 86_400);
    }
}
