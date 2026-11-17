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

pub(super) struct AgentDialog {
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

/// agentc00pr next to masstin, else on the PATH.
pub(super) fn find_agentc00pr() -> Option<PathBuf> {
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
        let cases = exe.as_ref().map(known_cases).unwrap_or_default();
        let name = self.files.first().and_then(|f| std::path::Path::new(f).file_stem().map(|s| s.to_string_lossy().to_string())).unwrap_or_else(|| "case".to_string());
        self.agent = Some(AgentDialog { exe, cases, new_case: true, name, parent: last_parent(), pick: 0, msg: String::new(), rx: None });
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
                    text.lines().filter(|l| l.contains("added from the timeline's ingest record")).count()
                }
                Err(e) => {
                    let _ = tx.send(Err(format!("agentc00pr did not start: {}", e)));
                    return;
                }
            };
            let mut win = std::process::Command::new(&exe);
            win.args(["--case", &folder, "--panel", "investigate", "--load-all"]);
            win.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
            let _ = tx.send(match win.spawn() {
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
            ui.add_space(4.0);
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

    #[test]
    fn the_timelines_go_in_with_agentc00prs_own_options() {
        let t = ["D:\\c\\a.csv".to_string(), "D:\\c\\b.csv".to_string()];
        assert_eq!(add_arguments("D:\\cases\\x", Some("x"), &t), vec!["--case", "D:\\cases\\x", "--new-case", "x", "--add", "D:\\c\\a.csv", "--add", "D:\\c\\b.csv", "--scan"]);
        assert_eq!(add_arguments("D:\\cases\\y", None, &t[..1]), vec!["--case", "D:\\cases\\y", "--add", "D:\\c\\a.csv", "--scan"]);
    }
}
