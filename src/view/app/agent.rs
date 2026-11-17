//! On to agentc00pr, the case workbench of the family, with what is open
//! here. The timelines go into a case of agentc00pr, a new one or one it
//! already has, with the options agentc00pr's own command line gives
//! (`--new-case`, `--add`, `--scan`), and its window opens on that case.
//! Nothing of masstin's is written for it: a timeline carries the record
//! of its ingest in its file next to it (`<name>.masstin`), and agentc00pr brings
//! the evidence named there into the case with masstin as already run.

use super::*;
use crate::view::icons as ic;
use crate::view::theme;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;

/// The day agentc00pr is published.
const RELEASE: (i32, u32, u32) = (2026, 12, 1);

/// The case of agentc00pr a timeline is tied to, and how that is known.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Link {
    /// agentc00pr opened this window, on this case
    OpenedFrom(String),
    /// the timeline's masstin file says it was taken to this case, and the
    /// case is there
    TakenTo(String),
    /// it says so, and the case is not there any more
    Gone(String),
}

/// The key of the timeline's file the case is kept under.
const LINK_KEY: &str = "agentc00pr";

fn is_case_folder(folder: &str) -> bool {
    std::path::Path::new(folder).join("case.json").is_file()
}

/// What ties these timelines to a case: the case agentc00pr said it opened
/// this window from (`opened_from`: `AGENTC00PR_CASE`), else the one the
/// first timeline's masstin file names.
pub(super) fn link_of(files: &[String], opened_from: Option<String>) -> Option<Link> {
    if let Some(c) = opened_from.filter(|c| is_case_folder(c)) {
        return Some(Link::OpenedFrom(c));
    }
    let folder = crate::timeline_file::get(files.first()?, LINK_KEY)?.get("case")?.as_str()?.to_string();
    Some(if is_case_folder(&folder) { Link::TakenTo(folder) } else { Link::Gone(folder) })
}

/// Note in the timelines' masstin files the case they are in.
fn remember_link(files: &[String], folder: &str) {
    for f in files {
        let _ = crate::timeline_file::set(f, LINK_KEY, serde_json::json!({ "case": folder }));
    }
}

/// Whether the case in this folder names this timeline among its evidence
/// (as it was added, or as the copy a hunt made of it). None when the case
/// cannot be read that way: then nothing is concluded.
pub(super) fn in_case(folder: &str, timeline: &str) -> Option<bool> {
    let text = std::fs::read_to_string(std::path::Path::new(folder).join("case.json")).ok()?;
    let case: serde_json::Value = serde_json::from_str(&text).ok()?;
    let evidence = case.get("evidence")?.as_array()?;
    let norm = |s: &str| crate::timeline_file::absolute(s).replace(BACKSLASH, "/").to_lowercase();
    let want = norm(timeline);
    let mut any_path = false;
    for e in evidence {
        for key in ["original_path", "hunted_copy"] {
            if let Some(p) = e.get(key).and_then(|p| p.as_str()).filter(|p| !p.is_empty()) {
                any_path = true;
                if norm(p) == want {
                    return Some(true);
                }
            }
        }
    }
    // a case with evidence and no path under those names is written another way
    if !evidence.is_empty() && !any_path {
        return None;
    }
    Some(false)
}

const BACKSLASH: char = 92 as char;

fn same_folder(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.replace('\\', "/").trim_end_matches('/').to_lowercase();
    norm(a) == norm(b)
}

/// What names a row of the timeline to agentc00pr's `--event`:
/// `TIME,USER,ORIGIN,DESTINATION`, from the row as the file has it (so
/// agentc00pr, which reads the same file, finds it): the time as written,
/// the account, the origin (the name unless it is the destination's own,
/// else the address) and the destination. None for a row with no time or
/// no destination.
pub(super) fn event_of_row(fields: &[String]) -> Option<String> {
    let clean = |i: usize| -> String {
        let t = fields.get(i).map(|s| s.trim()).unwrap_or("");
        if t == "-" || t.contains(',') { String::new() } else { t.to_string() }
    };
    let (time, dest, user, name, ip) = (clean(0), clean(1), clean(5), clean(7), clean(8));
    if time.is_empty() || dest.is_empty() {
        return None;
    }
    let short = |s: &str| s.split('.').next().unwrap_or(s).to_uppercase();
    let origin = if !name.is_empty() && short(&name) != short(&dest) { name } else { ip };
    Some(format!("{time},{user},{origin},{dest}"))
}

/// The arguments that open agentc00pr's window on a case, on these events
/// when some are named: a file of them, one per line.
fn window_arguments(folder: &str, events: &[String]) -> Result<Vec<String>, String> {
    let mut a: Vec<String> = ["--case", folder, "--panel", "investigate", "--load-all"].iter().map(|s| s.to_string()).collect();
    if !events.is_empty() {
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let path = std::env::temp_dir().join(format!("masstin-events-{}-{}.txt", std::process::id(), stamp));
        std::fs::write(&path, events.join("\n")).map_err(|e| format!("cannot write the events for agentc00pr ({}): {}", path.display(), e))?;
        a.push("--events-file".into());
        a.push(path.to_string_lossy().to_string());
    }
    Ok(a)
}

pub(super) struct AgentDialog {
    /// the events agentc00pr's window opens on once the case is settled
    /// (a connection, or the rows picked); empty: the whole timeline
    pub events: Vec<String>,
    /// the case these timelines are tied to, when they are
    pub link: Option<Link>,
    pub exe: Option<PathBuf>,
    /// the cases agentc00pr knows: (name, folder)
    pub cases: Vec<(String, String)>,
    pub new_case: bool,
    pub name: String,
    /// the folder the new case's folder is made in
    pub parent: String,
    pub pick: usize,
    pub msg: String,
    rx: Option<Receiver<Result<String, String>>>,
}

/// The agentc00pr that opened this window (it says so: `AGENTC00PR_EXE`),
/// else the one next to masstin, else on the PATH.
pub(super) fn find_agentc00pr() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("AGENTC00PR_EXE").map(PathBuf::from).filter(|p| p.is_file()) {
        return Some(p);
    }
    let names: &[&str] = if cfg!(windows) { &["agentc00pr.exe"] } else { &["agentc00pr"] };
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.to_path_buf())) {
        for n in names {
            let p = dir.join(n);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        for n in names {
            let p = dir.join(n);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// One line of `agentc00pr --cases`: `name   folder  ·  2 evidence, …`.
pub(super) fn parse_case_line(line: &str) -> Option<(String, String)> {
    let head = line.split("  ·  ").next()?.trim_end();
    // the folder starts where a path does: a drive, a share or a root
    let b = head.as_bytes();
    let at = (0..b.len()).find(|&i| {
        let start_of_token = i == 0 || b[i - 1] == b' ';
        start_of_token && ((i + 2 < b.len() && b[i].is_ascii_alphabetic() && b[i + 1] == b':' && (b[i + 2] == b'\\' || b[i + 2] == b'/')) || b[i..].starts_with(b"\\\\") || (b[i] == b'/' && i > 0))
    })?;
    let (name, folder) = (head[..at].trim(), head[at..].trim());
    if name.is_empty() || name == "?" || folder.is_empty() {
        return None;
    }
    Some((name.to_string(), folder.to_string()))
}

fn quiet(cmd: &mut std::process::Command) {
    cmd.stdin(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
}

fn known_cases(exe: &PathBuf) -> Vec<(String, String)> {
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--cases");
    quiet(&mut cmd);
    match cmd.output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).lines().filter_map(parse_case_line).collect(),
        Err(_) => Vec::new(),
    }
}

/// The arguments that put these timelines into the case.
pub(super) fn add_arguments(folder: &str, new_name: Option<&str>, timelines: &[String]) -> Vec<String> {
    let mut a = vec!["--case".to_string(), folder.to_string()];
    if let Some(n) = new_name {
        a.push("--new-case".into());
        a.push(n.to_string());
    }
    for t in timelines {
        a.push("--add".into());
        a.push(t.clone());
    }
    a.push("--scan".into());
    a
}

fn last_parent_path() -> Option<PathBuf> {
    super::ingest::config_file("agentc00pr.json")
}

fn last_parent() -> String {
    let saved = last_parent_path().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str::<String>(&s).ok());
    match saved {
        Some(s) if !s.is_empty() => s,
        _ => std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(|h| PathBuf::from(h).join("cases").to_string_lossy().to_string()).unwrap_or_default(),
    }
}

fn remember_parent(parent: &str) {
    if let Some(p) = last_parent_path() {
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(s) = serde_json::to_string(parent) {
            let _ = std::fs::write(p, s);
        }
    }
}

impl Viewer {
    /// The dialog: agentc00pr found or not, its cases, a name for a new one.
    pub(super) fn open_agentc00pr(&mut self) {
        let exe = find_agentc00pr();
        let mut cases = exe.as_ref().map(known_cases).unwrap_or_default();
        let name = self.files.first().and_then(|f| std::path::Path::new(f).file_stem().map(|s| s.to_string_lossy().to_string())).unwrap_or_else(|| "case".to_string());
        // already tied to a case: that case is the one offered
        let link = link_of(&self.files, std::env::var("AGENTC00PR_CASE").ok());
        let (mut new_case, mut pick) = (true, 0);
        if let Some(Link::OpenedFrom(folder)) | Some(Link::TakenTo(folder)) = &link {
            pick = match cases.iter().position(|(_, f)| same_folder(f, folder)) {
                Some(i) => i,
                None => {
                    let n = std::path::Path::new(folder).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| folder.clone());
                    cases.insert(0, (n, folder.clone()));
                    0
                }
            };
            new_case = false;
        }
        self.agent = Some(AgentDialog { events: Vec::new(), link, exe, cases, new_case, name, parent: last_parent(), pick, msg: String::new(), rx: None });
    }

    /// These rows in agentc00pr's viewer: its window on the case the
    /// timeline is in, showing only them. A timeline tied to a case that
    /// has it goes straight there; otherwise the dialog settles the case
    /// first (a new one, another one) and the window opens on the rows
    /// after it.
    pub(super) fn rows_to_agentc00pr(&mut self, rows: &[(u16, u32)], what: &str) {
        let mut events: Vec<String> = Vec::new();
        let mut unnamed = 0usize;
        for r in rows {
            match self.store.raw_row(r.0, r.1).ok().and_then(|f| event_of_row(&f)) {
                Some(e) => {
                    if !events.contains(&e) {
                        events.push(e);
                    }
                }
                None => unnamed += 1,
            }
        }
        if events.is_empty() {
            self.status = format!("{}: no row with a time and a destination to show in agentc00pr", what);
            return;
        }
        let exe = find_agentc00pr();
        let link = link_of(&self.files, std::env::var("AGENTC00PR_CASE").ok());
        let folder = match &link {
            Some(Link::OpenedFrom(f)) | Some(Link::TakenTo(f)) if self.files.iter().all(|t| in_case(f, t) != Some(false)) => Some(f.clone()),
            _ => None,
        };
        match (exe, folder) {
            (Some(exe), Some(folder)) => {
                let n = events.len();
                let started = window_arguments(&folder, &events).and_then(|args| {
                    let mut win = std::process::Command::new(&exe);
                    win.args(&args);
                    win.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
                    win.spawn().map(|_| ()).map_err(|e| format!("agentc00pr's window did not start: {}", e))
                });
                self.status = match started {
                    Ok(()) => format!("agentc00pr opened on {}, on the {} event(s) of {}{}", folder, n, what, if unnamed > 0 { format!(" ({} row(s) without a time or a destination left out)", unnamed) } else { String::new() }),
                    Err(e) => e,
                };
            }
            // not tied to a case that has the timeline (or no agentc00pr):
            // the dialog first, the rows after it
            _ => {
                self.open_agentc00pr();
                if let Some(d) = self.agent.as_mut() {
                    d.events = events;
                }
            }
        }
    }

    /// Put the open timelines into the case and open agentc00pr on it.
    pub(super) fn agent_go(&mut self) {
        let Some(d) = self.agent.as_mut() else { return };
        let Some(exe) = d.exe.clone() else { return };
        if self.files.is_empty() {
            d.msg = "No timeline is open: there is nothing to take to agentc00pr".into();
            return;
        }
        let (folder, new_name) = if d.new_case {
            let name = d.name.trim().to_string();
            if name.is_empty() || d.parent.trim().is_empty() {
                d.msg = "A new case needs a name and a folder to be made in".into();
                return;
            }
            (PathBuf::from(d.parent.trim()).join(&name).to_string_lossy().to_string(), Some(name))
        } else {
            match d.cases.get(d.pick) {
                Some((_, folder)) => (folder.clone(), None),
                None => {
                    d.msg = "agentc00pr has no case yet: make a new one".into();
                    return;
                }
            }
        };
        if d.new_case {
            remember_parent(d.parent.trim());
        }
        let args = add_arguments(&folder, new_name.as_deref(), &self.files);
        let files = self.files.clone();
        let events = d.events.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        d.rx = Some(rx);
        d.msg = format!("Putting {} timeline(s) into {}…", self.files.len(), folder);
        std::thread::spawn(move || {
            let mut cmd = std::process::Command::new(&exe);
            cmd.args(&args);
            quiet(&mut cmd);
            let added = match cmd.output() {
                Ok(o) => {
                    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
                    // a timeline already in the case is refused and the rest goes on: only a
                    // case that could not be made or opened stops it
                    if !o.status.success() && !std::path::Path::new(&folder).join("case.json").is_file() {
                        let _ = tx.send(Err(text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("agentc00pr refused the case").to_string()));
                        return;
                    }
                    // every timeline must be in the case now: one that is not (the case
                    // is open in a window of agentc00pr, which is the one that saves it)
                    // is said, not opened on as if it were
                    let left: Vec<&String> = files.iter().filter(|f| in_case(&folder, f) == Some(false)).collect();
                    if !left.is_empty() {
                        let names: Vec<String> = left.iter().map(|f| std::path::Path::new(f.as_str()).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| f.to_string())).collect();
                        let why = if text.contains("being processed by the window") {
                            "the case is open in a window of agentc00pr, which is the one that saves it: add the timeline there (drop it on Ingest), or close that window and try again".to_string()
                        } else {
                            text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("agentc00pr did not say why").trim().to_string()
                        };
                        let _ = tx.send(Err(format!("{} did not get into the case {}: {}", names.join(", "), folder, why)));
                        return;
                    }
                    text.lines().filter(|l| l.contains("added from the timeline's ingest record")).count()
                }
                Err(e) => {
                    let _ = tx.send(Err(format!("agentc00pr did not start: {}", e)));
                    return;
                }
            };
            // the timelines say from now on which case they are in
            remember_link(&files, &folder);
            let args = match window_arguments(&folder, &events) {
                Ok(a) => a,
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            };
            let mut win = std::process::Command::new(&exe);
            win.args(&args);
            win.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
            let _ = tx.send(match win.spawn() {
                Ok(_) if !events.is_empty() => Ok(format!("agentc00pr opened on {}, on the {} event(s) picked", folder, events.len())),
                Ok(_) => Ok(if added > 0 { format!("agentc00pr opened on {} ({} piece(s) of evidence came in with the timeline's ingest record)", folder, added) } else { format!("agentc00pr opened on {}", folder) }),
                Err(e) => Err(format!("the case is ready in {}, but agentc00pr's window did not start: {}", folder, e)),
            });
        });
    }

    pub(super) fn agent_window(&mut self, ctx: &egui::Context) {
        let Some(d) = self.agent.as_mut() else { return };
        // the answer of the work under way
        if let Some(rx) = &d.rx {
            match rx.try_recv() {
                Ok(Ok(done)) => {
                    self.status = done;
                    self.agent = None;
                    return;
                }
                Ok(Err(e)) => {
                    d.msg = e;
                    d.rx = None;
                }
                Err(_) => ctx.request_repaint_after(std::time::Duration::from_millis(150)),
            }
        }
        let busy = d.rx.is_some();
        let files: Vec<String> = self.files.clone();
        let mut open = true;
        let mut go = false;
        let mut close = false;
        egui::Window::new(format!("{}  On to agentc00pr", ic::APP_WINDOW)).id(egui::Id::unique("agentc00pr")).open(&mut open).collapsible(false).resizable(false).default_width(600.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.set_width(580.0);
            ui.label("agentc00pr is the case workbench of the family: the same evidence through caarea, faramir, allymacb and masstin, one timeline of them all, the hunts side by side.");
            ui.add_space(6.0);
            if d.exe.is_none() {
                let today = chrono::Utc::now().date_naive();
                let release = chrono::NaiveDate::from_ymd_opt(RELEASE.0, RELEASE.1, RELEASE.2).unwrap_or(today);
                if today < release {
                    ui.label(theme::semibold("It is released on 1 December 2026.", 13.5));
                    ui.label(egui::RichText::new("From then on, with agentc00pr next to masstin (or on the PATH), this takes the timelines open here into a case of it, with the evidence they were read from.").color(theme::MUTED));
                } else {
                    ui.label(theme::semibold("agentc00pr was not found next to masstin nor on the PATH.", 13.5));
                    ui.label(egui::RichText::new("github.com/jupyterj0nes/agentc00pr has it. With it in place, this takes the timelines open here into a case of it, with the evidence they were read from.").color(theme::MUTED));
                }
                ui.add_space(8.0);
                if ui.button("Close").clicked() {
                    close = true;
                }
                return;
            }
            theme::section(ui, "What goes");
            for f in files.iter().take(4) {
                let name = std::path::Path::new(f).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| f.clone());
                let with = if crate::ingest_record::read(f).is_some() { "with its ingest record: the evidence it was read from comes into the case, masstin as already run on it" } else { "no ingest record with it: the timeline alone" };
                ui.horizontal(|ui| {
                    ui.label(theme::semibold(&name, 12.5)).on_hover_text(f);
                    ui.label(egui::RichText::new(with).color(theme::MUTED).small());
                });
            }
            if files.len() > 4 {
                ui.label(egui::RichText::new(format!("and {} more", files.len() - 4)).color(theme::MUTED).small());
            }
            if files.is_empty() {
                ui.label(egui::RichText::new("No timeline is open.").color(theme::MUTED));
            }
            if !d.events.is_empty() {
                ui.label(egui::RichText::new(format!("{}  Once the timeline is in a case, agentc00pr opens on the {} event(s) picked here, and only them.", ic::CROSSHAIR, d.events.len())).color(theme::ACCENT));
            }
            ui.add_space(4.0);
            match &d.link {
                Some(Link::OpenedFrom(folder)) => {
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new(format!("{}  agentc00pr opened this window from its case {}: that is the one offered.", ic::LINK, folder)).color(theme::ACCENT));
                }
                Some(Link::TakenTo(folder)) => {
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new(format!("{}  This timeline is already in the case {}: that is the one offered.", ic::LINK, folder)).color(theme::ACCENT));
                }
                Some(Link::Gone(folder)) => {
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new(format!("{}  This timeline was taken to the case {}, which is not there any more (moved, renamed or deleted). Pick the case where it is now, or make a new one.", ic::WARNING, folder)).color(CANDIDATE));
                }
                None => {}
            }
            theme::section(ui, "Into which case");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut d.new_case, true, "A new case");
                ui.add_enabled_ui(!d.cases.is_empty(), |ui| ui.selectable_value(&mut d.new_case, false, format!("One it has ({})", d.cases.len()))).inner.on_disabled_hover_text("agentc00pr has no case yet");
            });
            ui.add_space(4.0);
            if d.new_case {
                egui::Grid::new("agent-new").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                    ui.label(egui::RichText::new("name").color(theme::MUTED));
                    ui.add(egui::TextEdit::singleline(&mut d.name).desired_width(300.0));
                    ui.end_row();
                    ui.label(egui::RichText::new("made in").color(theme::MUTED));
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut d.parent).desired_width(380.0).hint_text("the folder that holds your cases"));
                        if ui.button("Browse…").clicked() {
                            if let Some(p) = rfd::FileDialog::new().set_title("The folder the case is made in").pick_folder() {
                                d.parent = p.to_string_lossy().to_string();
                            }
                        }
                    });
                    ui.end_row();
                });
                if !d.name.trim().is_empty() && !d.parent.trim().is_empty() {
                    ui.label(egui::RichText::new(format!("the case's folder: {}", PathBuf::from(d.parent.trim()).join(d.name.trim()).display())).color(theme::DIM).small());
                }
            } else {
                egui::ComboBox::from_id_salt("agent-case").width(520.0).selected_text(d.cases.get(d.pick).map(|(n, f)| format!("{}   {}", n, f)).unwrap_or_default()).show_ui(ui, |ui| {
                    for (i, (n, f)) in d.cases.iter().enumerate() {
                        ui.selectable_value(&mut d.pick, i, format!("{}   {}", n, f));
                    }
                });
                ui.label(egui::RichText::new("A timeline that is already in that case stays as it is there.").color(theme::DIM).small());
            }
            ui.add_space(8.0);
            theme::hairline(ui);
            if !d.msg.is_empty() {
                ui.label(egui::RichText::new(&d.msg).color(if busy { theme::MUTED } else { CANDIDATE }).small());
            }
            ui.horizontal(|ui| {
                let b = egui::Button::new(theme::semibold(format!("{}  Open in agentc00pr", ic::APP_WINDOW), 13.5).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 30.0));
                if ui.add_enabled(!busy && !files.is_empty(), b).clicked() {
                    go = true;
                }
                if ui.add_enabled(!busy, egui::Button::new("Cancel").min_size(Vec2::new(0.0, 30.0))).clicked() {
                    close = true;
                }
            });
        });
        if go {
            self.agent_go();
        }
        if close || !open {
            self.agent = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_of_the_case_list_gives_its_name_and_folder() {
        assert_eq!(parse_case_line("ing                          D:\\demo\\ag-test\\case-ing  ·  2 evidence, 1 done, 0 failed, 0 notables, 0 IOCs  ·  updated 2026-11-16T23:49:57Z"), Some(("ing".to_string(), "D:\\demo\\ag-test\\case-ing".to_string())));
        assert_eq!(parse_case_line("a case with a very long name that goes past the column D:/cases/long  ·  0 evidence"), Some(("a case with a very long name that goes past the column".to_string(), "D:/cases/long".to_string())));
        assert_eq!(parse_case_line("lab                          /home/me/cases/lab  ·  1 evidence"), Some(("lab".to_string(), "/home/me/cases/lab".to_string())));
        assert_eq!(parse_case_line("share                        \\\\nas\\cases\\x  ·  1 evidence"), Some(("share".to_string(), "\\\\nas\\cases\\x".to_string())));
        assert_eq!(parse_case_line("?                            D:\\gone  ·  unreadable: no case.json"), None);
        assert_eq!(parse_case_line(""), None);
    }

    /// A timeline knows the case it is in: the one agentc00pr opened the
    /// window from, else the one its masstin file names, there or gone.
    #[test]
    fn a_timeline_is_tied_to_its_case() {
        let dir = std::env::temp_dir().join(format!("masstin_agent_link_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("case-a")).unwrap();
        std::fs::create_dir_all(dir.join("case-b")).unwrap();
        std::fs::write(dir.join("case-a").join("case.json"), "{}").unwrap();
        std::fs::write(dir.join("case-b").join("case.json"), "{}").unwrap();
        let tl = dir.join("t.csv").to_string_lossy().to_string();
        std::fs::write(&tl, "x\n").unwrap();
        let (a, b) = (dir.join("case-a").to_string_lossy().to_string(), dir.join("case-b").to_string_lossy().to_string());
        // nothing says
        assert_eq!(link_of(&[tl.clone()], None), None);
        assert_eq!(link_of(&[], None), None);
        // taken to a case: its masstin file says so, next to what else it holds
        crate::timeline_file::set(&tl, "hunt", serde_json::json!({"alpha": 0.05})).unwrap();
        remember_link(&[tl.clone()], &a);
        assert_eq!(link_of(&[tl.clone()], None), Some(Link::TakenTo(a.clone())));
        assert_eq!(crate::timeline_file::get(&tl, "hunt").unwrap()["alpha"].as_f64(), Some(0.05));
        // opened from another case by agentc00pr: that one, when it is a case
        assert_eq!(link_of(&[tl.clone()], Some(b.clone())), Some(Link::OpenedFrom(b.clone())));
        assert_eq!(link_of(&[tl.clone()], Some(dir.join("nowhere").to_string_lossy().to_string())), Some(Link::TakenTo(a.clone())));
        // the case went away
        std::fs::remove_dir_all(dir.join("case-a")).unwrap();
        assert_eq!(link_of(&[tl.clone()], None), Some(Link::Gone(a.clone())));
        assert!(same_folder("D:\\Cases\\X\\", "d:/cases/x") && !same_folder("D:/cases/x", "D:/cases/y"));
        // whether a case names a timeline among its evidence, however the path is written
        let other = dir.join("other.csv").to_string_lossy().to_string();
        std::fs::write(dir.join("case-b").join("case.json"), serde_json::json!({"evidence": [{"original_path": tl.replace(BACKSLASH, "/").to_uppercase(), "hunted_copy": ""}, {"original_path": "D:/other/x.zip"}]}).to_string()).unwrap();
        assert_eq!(in_case(&b, &tl), Some(true));
        assert_eq!(in_case(&b, &other), Some(false));
        // a case that cannot be read that way concludes nothing
        assert_eq!(in_case(&dir.join("nowhere").to_string_lossy(), &tl), None);
        std::fs::write(dir.join("case-b").join("case.json"), serde_json::json!({"evidence": [{"where": "x"}]}).to_string()).unwrap();
        assert_eq!(in_case(&b, &tl), None);
        std::fs::write(dir.join("case-b").join("case.json"), serde_json::json!({"evidence": []}).to_string()).unwrap();
        assert_eq!(in_case(&b, &tl), Some(false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A row is named to agentc00pr by what the file says of it.
    #[test]
    fn a_row_is_named_to_agentc00pr_as_the_file_has_it() {
        let row = |t: &str, dst: &str, user: &str, sc: &str, si: &str| -> Vec<String> { vec![t.into(), dst.into(), "SUCCESSFUL_LOGON".into(), "4624".into(), "3".into(), user.into(), "CORP".into(), sc.into(), si.into()] };
        assert_eq!(event_of_row(&row("2026-11-03T11:12:56.143498Z", "SRV01.corp.test", "alice", "WS01", "10.0.0.7")).as_deref(), Some("2026-11-03T11:12:56.143498Z,alice,WS01,SRV01.corp.test"));
        assert_eq!(event_of_row(&row("2026-11-03T11:12:56.143498Z", "SRV01", "alice", "-", "10.0.0.7")).as_deref(), Some("2026-11-03T11:12:56.143498Z,alice,10.0.0.7,SRV01"));
        // the server's own name as the origin says nothing: the address
        assert_eq!(event_of_row(&row("2026-11-03T11:12:56Z", "SRV01.corp.test", "alice", "srv01", "10.0.0.7")).as_deref(), Some("2026-11-03T11:12:56Z,alice,10.0.0.7,SRV01.corp.test"));
        assert_eq!(event_of_row(&row("2026-11-03T11:12:56Z", "SRV01", "-", "", "")).as_deref(), Some("2026-11-03T11:12:56Z,,,SRV01"));
        assert_eq!(event_of_row(&row("", "SRV01", "alice", "WS01", "")), None);
        assert_eq!(event_of_row(&row("2026-11-03T11:12:56Z", "", "alice", "WS01", "")), None);
        // the window's arguments: the case, and a file of the events when some are named
        assert_eq!(window_arguments("D:/c/x", &[]).unwrap(), vec!["--case", "D:/c/x", "--panel", "investigate", "--load-all"]);
        let a = window_arguments("D:/c/x", &["t,u,o,d".to_string(), "t2,u,o,d".to_string()]).unwrap();
        assert_eq!((a.len(), a[5].as_str()), (7, "--events-file"));
        assert_eq!(std::fs::read_to_string(&a[6]).unwrap(), "t,u,o,d\nt2,u,o,d");
        let _ = std::fs::remove_file(&a[6]);
    }

    #[test]
    fn the_timelines_go_in_with_agentc00prs_own_options() {
        let t = ["D:\\c\\a.csv".to_string(), "D:\\c\\b.csv".to_string()];
        assert_eq!(add_arguments("D:\\cases\\x", Some("x"), &t), vec!["--case", "D:\\cases\\x", "--new-case", "x", "--add", "D:\\c\\a.csv", "--add", "D:\\c\\b.csv", "--scan"]);
        assert_eq!(add_arguments("D:\\cases\\y", None, &t[..1]), vec!["--case", "D:\\cases\\y", "--add", "D:\\c\\a.csv", "--scan"]);
    }
}
