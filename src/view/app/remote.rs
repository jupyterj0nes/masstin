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
    /// false: the network connections (`parse-cortex`); true: the Windows
    /// event logs the forensics add-on collects (`parse-cortex-evtx-forensics`)
    pub evtx: bool,
    pub url: String,
    pub key_id: String,
    pub key: String,
    pub from: String,
    pub to: String,
    pub filter_ip: String,
    pub admin_ports: bool,
    pub event_ids: String,
    pub min_window: String,
    pub max_passes: String,
    pub output: String,
}

impl Default for CortexForm {
    fn default() -> Self {
        CortexForm { evtx: false, url: String::new(), key_id: String::new(), key: String::new(), from: String::new(), to: String::new(), filter_ip: String::new(), admin_ports: false, event_ids: String::new(), min_window: "300".into(), max_passes: "200".into(), output: String::new() }
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
        None
    }

    /// The command line: no secret in it.
    pub fn command(&self) -> Vec<String> {
        let action = if self.evtx { "parse-cortex-evtx-forensics" } else { "parse-cortex" };
        let mut args = vec!["-a".to_string(), action.to_string(), "--cortex-url".into(), self.url.trim().trim_end_matches('/').to_string()];
        for (flag, v) in [("--start-time", &self.from), ("--end-time", &self.to)] {
            if !v.trim().is_empty() {
                args.push(flag.into());
                args.push(v.trim().to_string());
            }
        }
        if !self.filter_ip.trim().is_empty() {
            args.push("--filter-cortex-ip".into());
            args.push(self.filter_ip.trim().to_string());
        }
        if !self.evtx && self.admin_ports {
            args.push("--admin-ports".into());
        }
        if self.evtx && !self.event_ids.trim().is_empty() {
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
    pub(super) fn cortex_window(&mut self, ctx: &egui::Context) {
        if !self.show_cortex {
            return;
        }
        let beside = self.files.first().and_then(|t| Path::new(t).parent().map(|d| d.to_path_buf()));
        let f = &mut self.cortex_form;
        if f.output.trim().is_empty() {
            // next to the open timeline, else the folder masstin runs in
            let dir = beside.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
            f.output = dir.join("cortex.csv").to_string_lossy().to_string();
        }
        let mut open = true;
        let mut run = false;
        let busy = self.job.is_some();
        egui::Window::new(format!("{}  Cortex XDR API", ic::CLOUD)).open(&mut open).collapsible(false).resizable(false).default_width(640.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            hint(ui, "Lateral movement straight from a Cortex XDR tenant, through its XQL API, into a timeline. The key needs the Instance Administrator role; the query spends the tenant's compute units.");
            theme::section(ui, "What to read");
            ui.radio_value(&mut f.evtx, false, "Network connections of the endpoints: RDP, SMB, SSH, WinRM (parse-cortex)");
            ui.radio_value(&mut f.evtx, true, "Windows event logs collected by the forensics add-on (parse-cortex-evtx-forensics)");
            theme::section(ui, "The tenant");
            row(ui, "API URL", |ui| {
                ui.add(egui::TextEdit::singleline(&mut f.url).desired_width(440.0).hint_text("https://api-yourtenant.xdr.eu.paloaltonetworks.com"));
            });
            row(ui, "Key ID", |ui| {
                ui.add(egui::TextEdit::singleline(&mut f.key_id).desired_width(80.0).hint_text("12"));
            });
            row(ui, "API key", |ui| {
                ui.add(egui::TextEdit::singleline(&mut f.key).password(true).desired_width(440.0).hint_text("a Standard key"));
            });
            hint(ui, "Cortex › Settings › Configurations › API Keys: Copy API URL, the key's ID column and the key itself. The key goes to masstin in its environment, never on the command line, and is forgotten once the run starts.");
            theme::section(ui, "Which events");
            row(ui, "From", |ui| {
                ui.add(egui::TextEdit::singleline(&mut f.from).desired_width(160.0).hint_text("YYYY-MM-DD HH:MM:SS"));
                ui.label(egui::RichText::new("to").color(theme::MUTED));
                ui.add(egui::TextEdit::singleline(&mut f.to).desired_width(160.0).hint_text("YYYY-MM-DD HH:MM:SS"));
            });
            row(ui, "Only this address", |ui| {
                ui.add(egui::TextEdit::singleline(&mut f.filter_ip).desired_width(160.0).hint_text("optional"));
            });
            if f.evtx {
                row(ui, "Event IDs", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut f.event_ids).desired_width(300.0).hint_text("the default set; or 4624,4625,4648"));
                });
            } else {
                ui.checkbox(&mut f.admin_ports, "Every admin port too: 135, 139, 1433, 3306, 5900… besides RDP, SMB, SSH and WinRM (--admin-ports)");
            }
            egui::CollapsingHeader::new(theme::semibold("Paging (when a window hits the API's million rows)", 12.5)).id_salt("cortex-paging").show(ui, |ui| {
                row(ui, "Smallest window (s)", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut f.min_window).desired_width(70.0));
                });
                row(ui, "Most passes", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut f.max_passes).desired_width(70.0));
                });
                hint(ui, "A window that returns the API's maximum is split in halves down to this size, at most this many queries (--cortex-min-window-secs, --cortex-max-passes).");
            });
            theme::section(ui, "Timeline to write");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut f.output).desired_width(470.0));
                if ui.button(format!("{}  Save as…", ic::FLOPPY_DISK)).clicked() {
                    if let Some(p) = rfd::FileDialog::new().add_filter("CSV", &["csv"]).set_file_name("cortex.csv").save_file() {
                        f.output = p.to_string_lossy().to_string();
                    }
                }
            });
            if Path::new(f.output.trim()).exists() {
                ui.label(egui::RichText::new(format!("{}  this file exists and will be written over", ic::WARNING)).color(CANDIDATE).small());
            }
            ui.add_space(4.0);
            ui.add(egui::Label::new(egui::RichText::new(command_line(&f.command())).monospace().size(10.5).color(theme::DIM)).wrap());
            ui.add_space(4.0);
            run = run_button(ui, format!("{}  Read from Cortex", ic::CLOUD), f.problem(), busy);
        });
        if run {
            let args = self.cortex_form.command();
            let env = self.cortex_form.env();
            let out = self.cortex_form.output.trim().to_string();
            self.cortex_form.key.clear();
            self.start_job_env(JobKind::Remote, "Reading from Cortex XDR".into(), args, vec![out], false, env);
            self.show_cortex = false;
        } else {
            self.show_cortex = open;
        }
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
        assert_eq!(args, vec!["-a", "parse-cortex", "--cortex-url", "https://api-x.xdr.eu.paloaltonetworks.com", "-o", "c.csv", "--overwrite"]);
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
        assert!(s.contains("--start-time 2026-11-01 00:00:00 --admin-ports --cortex-min-window-secs 60 -o"));
        assert!(!s.contains("--cortex-event-ids"));
        c.evtx = true;
        let s = c.command().join(" ");
        assert!(s.starts_with("-a parse-cortex-evtx-forensics"));
        assert!(s.contains("--cortex-event-ids 4624") && !s.contains("--admin-ports"));
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
