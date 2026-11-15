//! The hunt, as a wizard. Hunt › Run the hunt… (or the toolbar's Hunt) walks
//! the analyst through what `masstin -a graph-hunt-csv` takes, one question
//! a step, each with the usual answer already in place: run straight to the
//! end and the hunt is the one it always was (the investigation from the
//! last third of the timeline, a false discovery rate of 5 %, every
//! detector, the verdicts written into the timeline). The steps:
//!
//! 1. When: where the investigation starts (before it, the network's
//!    normal), and where it ends if not with the timeline.
//! 2. What you know (optional): the hosts, addresses or accounts known to
//!    be compromised, from which the incident is rebuilt hop by hop
//!    (`--seed`), and the Sigma hits of Hayabusa or Chainsaw that
//!    corroborate a connection (`--sigma`).
//! 3. How strict: the false discovery rate (`--alpha`) and the detectors
//!    (`--skip-detectors` / `--only-detectors`), each said in words.
//! 4. Results: the verdicts into the timeline or not (`--no-annotate`, with
//!    the findings table then written to a file of its own, `-o`), the
//!    analyst's report in Markdown (`--report`), the verdicts and notes of
//!    an earlier timeline carried over (`--carry-marks`). The command the
//!    window runs is shown whole: a terminal runs the same.

use std::path::Path;

use super::tasks::JobKind;
use super::*;
use crate::view::icons as ic;
use crate::view::theme;

/// The detectors, as `--skip-detectors` names them, with what each looks for.
pub(super) const DETECTORS: [(&str, &str); 13] = [
    ("novel-edge", "an account used on a machine it never logged on to before"),
    ("origin-fanout", "an origin reaching machines it never reached before"),
    ("cred-rotation", "an origin using accounts it never used before"),
    ("community-bridge", "an origin crossing into a part of the network it does not belong to"),
    ("failed-sweep", "failed logons spread over many machines"),
    ("preauth-sweep", "machines touched without authenticating (SSH pre-auth)"),
    ("probe-then-success", "refused attempts, then a login the same day with an account new for that origin"),
    ("rare-logon-type", "a logon type that is rare for the machine it lands on"),
    ("causal-path", "a chain of logons that switches credentials on the way to new access"),
    ("credential-switch", "an account owned by other origins, used to reach somewhere new"),
    ("pagerank-spike", "a machine suddenly central in the network (PageRank)"),
    ("betweenness-spike", "a machine suddenly on many paths between others (betweenness)"),
    ("sigma", "a Sigma hit on a machine while a login session is open on it (needs the Sigma hits)"),
];

/// The false discovery rates offered by name.
pub(super) const ALPHAS: [(&str, &str, &str); 3] = [
    ("0.01", "Strict", "fewer findings, almost no false ones: a big, noisy network"),
    ("0.05", "Usual", "the default: one finding in twenty may be noise"),
    ("0.10", "Wide", "more findings to read: a small network, or nothing found at 5 %"),
];

pub(super) struct HuntForm {
    /// 0 when, 1 what you know, 2 how strict, 3 results
    pub step: usize,
    pub from: String,
    pub end: String,
    pub alpha: String,
    pub seeds: String,
    pub seed_from: String,
    pub seed_to: String,
    pub sigma: String,
    /// one per DETECTORS entry: on runs it
    pub detectors: [bool; 13],
    /// write hunt, hunt_score, hunt_why into the timeline(s)
    pub annotate: bool,
    /// the findings table, required when the timeline is left untouched
    pub findings: String,
    pub report_on: bool,
    pub report: String,
    pub carry: String,
}

impl Default for HuntForm {
    fn default() -> Self {
        HuntForm {
            step: 0,
            from: String::new(),
            end: String::new(),
            alpha: String::new(),
            seeds: String::new(),
            seed_from: String::new(),
            seed_to: String::new(),
            sigma: String::new(),
            detectors: [true; 13],
            annotate: true,
            findings: String::new(),
            report_on: false,
            report: String::new(),
            carry: String::new(),
        }
    }
}

impl HuntForm {
    /// Seeds given: the incident is rebuilt from them, in the report.
    pub fn seeded(&self) -> bool {
        !self.seeds.trim().is_empty()
    }

    /// The report is written: asked for, or needed by the seeds.
    pub fn report_wanted(&self) -> bool {
        self.report_on || self.seeded()
    }

    /// `--skip-detectors` or `--only-detectors`, whichever is shorter; none
    /// when every detector runs.
    pub fn detector_arg(&self) -> Option<(&'static str, String)> {
        let on: Vec<&str> = DETECTORS.iter().zip(self.detectors.iter()).filter(|(_, o)| **o).map(|((n, _), _)| *n).collect();
        let off: Vec<&str> = DETECTORS.iter().zip(self.detectors.iter()).filter(|(_, o)| !**o).map(|((n, _), _)| *n).collect();
        if off.is_empty() {
            None
        } else if on.len() < off.len() {
            Some(("--only-detectors", on.join(",")))
        } else {
            Some(("--skip-detectors", off.join(",")))
        }
    }

    /// What is wrong with the form, said for the analyst; None when it runs.
    pub fn problem(&self) -> Option<&'static str> {
        if parse_time(&self.from).is_none() {
            return Some("the investigation needs a start: a full date and time");
        }
        if !self.end.trim().is_empty() && parse_time(&self.end).is_none() {
            return Some("the end is not a full date and time");
        }
        if !self.alpha.trim().parse::<f64>().map_or(false, |a| a > 0.0 && a < 1.0) {
            return Some("the false discovery rate is a number between 0 and 1");
        }
        for t in [&self.seed_from, &self.seed_to] {
            if !t.trim().is_empty() && parse_time(t).is_none() {
                return Some("the seeds' times are full dates and times");
            }
        }
        if !self.detectors.iter().any(|d| *d) {
            return Some("at least one detector has to run");
        }
        if !self.annotate && self.findings.trim().is_empty() {
            return Some("the timeline is left untouched: the findings need a file of their own");
        }
        if self.report_wanted() && self.report.trim().is_empty() {
            return Some("the report needs a file");
        }
        None
    }

    /// The command line: the usual answers give the hunt it always was.
    pub fn command(&self, files: &[String]) -> Vec<String> {
        let mut args = vec!["-a".to_string(), "graph-hunt-csv".to_string()];
        for f in files {
            args.push("-f".into());
            args.push(f.clone());
        }
        args.push("--investigation-from".into());
        args.push(self.from.trim().to_string());
        if !self.end.trim().is_empty() {
            args.push("--end-time".into());
            args.push(self.end.trim().to_string());
        }
        args.push("--alpha".into());
        args.push(self.alpha.trim().to_string());
        if self.seeded() {
            args.push("--seed".into());
            args.push(self.seeds.trim().to_string());
            for (flag, v) in [("--seed-from", &self.seed_from), ("--seed-to", &self.seed_to)] {
                if !v.trim().is_empty() {
                    args.push(flag.into());
                    args.push(v.trim().to_string());
                }
            }
        }
        if !self.sigma.trim().is_empty() {
            args.push("--sigma".into());
            args.push(self.sigma.trim().to_string());
        }
        if let Some((flag, v)) = self.detector_arg() {
            args.push(flag.into());
            args.push(v);
        }
        if !self.annotate {
            args.push("--no-annotate".into());
            args.push("-o".into());
            args.push(self.findings.trim().to_string());
        }
        if self.report_wanted() {
            args.push("--report".into());
            args.push(self.report.trim().to_string());
        }
        if !self.carry.trim().is_empty() {
            args.push("--carry-marks".into());
            args.push(self.carry.trim().to_string());
        }
        args
    }
}

/// A file next to the first timeline: `<stem><suffix>`.
fn beside(files: &[String], suffix: &str) -> String {
    let Some(first) = files.first() else { return String::new() };
    let p = Path::new(first);
    let stem = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "timeline".into());
    p.parent().unwrap_or(Path::new("")).join(format!("{}{}", stem, suffix)).to_string_lossy().to_string()
}

fn command_line(args: &[String]) -> String {
    format!("masstin {}", args.iter().map(|a| if a.contains(' ') { format!("\"{}\"", a) } else { a.clone() }).collect::<Vec<_>>().join(" "))
}

fn hint(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).color(theme::MUTED).size(12.0));
}

/// A path field with File… and Folder… pickers.
fn path_row(ui: &mut egui::Ui, value: &mut String, hint_text: &str, file_filter: Option<(&str, &[&str])>, folder: bool) {
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(value).desired_width(400.0).hint_text(hint_text));
        if ui.button(format!("{}  File…", ic::ARCHIVE)).clicked() {
            let mut d = rfd::FileDialog::new();
            if let Some((name, ext)) = file_filter {
                d = d.add_filter(name, ext);
            }
            if let Some(p) = d.pick_file() {
                *value = p.to_string_lossy().to_string();
            }
        }
        if folder && ui.button(format!("{}  Folder…", ic::FOLDER_OPEN)).clicked() {
            if let Some(p) = rfd::FileDialog::new().pick_folder() {
                *value = p.to_string_lossy().to_string();
            }
        }
        if !value.trim().is_empty() && ui.add(egui::Button::new(egui::RichText::new(ic::X).color(theme::DIM)).frame(false)).on_hover_text("Clear").clicked() {
            value.clear();
        }
    });
}

/// A file to write, with Save as….
fn save_row(ui: &mut egui::Ui, value: &mut String, title: &str, filter: (&str, &[&str])) {
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(value).desired_width(470.0));
        if ui.button(format!("{}  Save as…", ic::FLOPPY_DISK)).clicked() {
            let name = Path::new(value.as_str()).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if let Some(p) = rfd::FileDialog::new().set_title(title).add_filter(filter.0, filter.1).set_file_name(name).save_file() {
                *value = p.to_string_lossy().to_string();
            }
        }
    });
}

fn time_field(ui: &mut egui::Ui, value: &mut String, hint_text: &str) {
    ui.add(egui::TextEdit::singleline(value).desired_width(170.0).hint_text(hint_text));
    if !value.trim().is_empty() && parse_time(value).is_none() {
        ui.label(egui::RichText::new("YYYY-MM-DD HH:MM:SS").color(CANDIDATE).small());
    }
}

impl Viewer {
    pub(super) fn hunt_window(&mut self, ctx: &egui::Context) {
        if !self.show_hunt {
            return;
        }
        if self.hunt_form.from.is_empty() {
            // the usual start: the window's From, or the last third of the timeline
            self.hunt_form.from = if !self.filter.from.trim().is_empty() { self.filter.from.clone() } else { fmt_time(self.store.t_min + (self.store.t_max - self.store.t_min) * 2 / 3) };
        }
        if self.hunt_form.alpha.is_empty() {
            self.hunt_form.alpha = format!("{}", self.alpha);
        }
        if self.hunt_form.report.is_empty() {
            self.hunt_form.report = beside(&self.files, "-hunt-report.md");
        }
        if self.hunt_form.findings.is_empty() {
            self.hunt_form.findings = beside(&self.files, "-findings.csv");
        }
        let mut open = true;
        let mut run = std::mem::take(&mut self.hunt_autorun);
        let tall = (ctx.content_rect().height() - 250.0).clamp(300.0, 600.0);
        egui::Window::new(format!("{}  Hunt", ic::DETECTIVE)).id(egui::Id::new("hunt-wizard")).open(&mut open).collapsible(false).resizable(false).default_width(720.0).anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO).show(ctx, |ui| {
            ui.set_width(700.0);
            super::ingest::stepper(ui, self.hunt_form.step, &["When", "What you know", "How strict", "Results"]);
            ui.add_space(6.0);
            egui::ScrollArea::vertical().max_height(tall).auto_shrink([false, true]).show(ui, |ui| match self.hunt_form.step {
                0 => self.hunt_step_when(ui),
                1 => self.hunt_step_known(ui),
                2 => self.hunt_step_strict(ui),
                _ => self.hunt_step_results(ui),
            });
            ui.add_space(8.0);
            theme::hairline(ui);
            let args = self.hunt_form.command(&self.files);
            let problem = self.hunt_form.problem();
            ui.horizontal(|ui| {
                if self.hunt_form.step > 0 && ui.add(egui::Button::new(format!("{}  Back", ic::ARROW_LEFT)).min_size(Vec2::new(0.0, 30.0))).clicked() {
                    self.hunt_form.step -= 1;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let primary = |text: String| egui::Button::new(theme::semibold(text, 13.5).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE).min_size(Vec2::new(0.0, 30.0)).corner_radius(CornerRadius::same(7));
                    let ready = problem.is_none() && self.job.is_none();
                    if ui.add_enabled(ready, primary(format!("{}  Run the hunt", ic::DETECTIVE))).on_disabled_hover_text(problem.unwrap_or("Something is running already")).clicked() {
                        run = true;
                    }
                    if self.hunt_form.step < 3 && ui.add(egui::Button::new(format!("Next  {}", ic::ARROW_RIGHT)).min_size(Vec2::new(0.0, 30.0))).clicked() {
                        self.hunt_form.step += 1;
                    }
                    ui.add(egui::Label::new(egui::RichText::new(command_line(&args)).monospace().size(10.5).color(theme::DIM)).truncate()).on_hover_text(command_line(&args));
                });
            });
            if let Some(p) = problem {
                ui.label(egui::RichText::new(format!("{}  {}", ic::WARNING, p)).color(CANDIDATE).small());
            }
        });
        if run && self.hunt_form.problem().is_none() {
            let args = self.hunt_form.command(&self.files);
            // the window reads the findings with the rate the hunt was run with
            if let Ok(a) = self.hunt_form.alpha.trim().parse::<f64>() {
                self.alpha = a;
            }
            self.hunt_last_report = if self.hunt_form.report_wanted() { Some(self.hunt_form.report.trim().to_string()) } else { None };
            self.start_job(JobKind::Hunt, "Hunting".into(), args, Vec::new(), false);
            self.show_hunt = false;
            self.hunt_form.step = 0;
            self.hunt_sweep = Some(std::time::Instant::now());
        } else {
            self.show_hunt = open;
        }
    }

    fn hunt_step_when(&mut self, ui: &mut egui::Ui) {
        hint(ui, "The hunt learns what is normal for this network from the time before the investigation starts, then tests every connection after it against that: what is new, and how unusual. Run straight to the end and the usual hunt runs.");
        theme::section(ui, "The investigation starts");
        ui.horizontal(|ui| {
            time_field(ui, &mut self.hunt_form.from, "YYYY-MM-DD HH:MM:SS");
            if ui.button("the window's From").on_hover_text("The time strip's left handle").clicked() {
                self.hunt_form.from = if self.filter.from.trim().is_empty() { fmt_time(self.store.t_min) } else { self.filter.from.clone() };
            }
            if ui.button("the last third").on_hover_text("The usual start: the first two thirds of the timeline are the normal").clicked() {
                self.hunt_form.from = fmt_time(self.store.t_min + (self.store.t_max - self.store.t_min) * 2 / 3);
            }
        });
        let baseline_days = parse_time(&self.hunt_form.from).map(|t| ((t - self.store.t_min) as f64 / 86400.0).max(0.0)).unwrap_or(0.0);
        ui.label(egui::RichText::new(format!("The normal: {:.1} day(s) of the timeline before that start. A week or more is best; with less the hunt has little to compare with.", baseline_days)).color(if baseline_days < 3.0 { CANDIDATE } else { theme::DIM }).small());
        theme::section(ui, "It ends (optional)");
        ui.horizontal(|ui| {
            time_field(ui, &mut self.hunt_form.end, "the end of the timeline");
        });
        hint(ui, "Leave it empty to test everything up to the last event (--end-time).");
    }

    fn hunt_step_known(&mut self, ui: &mut egui::Ui) {
        hint(ui, "Optional: what the case already knows. Both can stay empty.");
        theme::section(ui, "Known compromised");
        ui.add(egui::TextEdit::singleline(&mut self.hunt_form.seeds).desired_width(640.0).hint_text("hosts, IP addresses or accounts, separated by commas: WEB01, 10.0.0.5, svc-backup"));
        hint(ui, "From these the incident is rebuilt: every hop they took in the investigation, in order, with the session ends and how sure each hop is, as the first section of the report (--seed). The report is written for it.");
        if self.hunt_form.seeded() {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Logins that start the chain from").color(theme::MUTED));
                time_field(ui, &mut self.hunt_form.seed_from, "the investigation's start");
                ui.label(egui::RichText::new("to").color(theme::MUTED));
                time_field(ui, &mut self.hunt_form.seed_to, "its end");
            });
        }
        theme::section(ui, "Sigma hits");
        path_row(ui, &mut self.hunt_form.sigma, "Hayabusa or Chainsaw output: JSON / JSONL files or a folder", Some(("JSON", &["json", "jsonl"])), true);
        hint(ui, "A Sigma hit on a machine while a login session is open on it corroborates that connection, and the report names the rule (--sigma).");
    }

    fn hunt_step_strict(&mut self, ui: &mut egui::Ui) {
        theme::section(ui, "How strict");
        hint(ui, "Every finding is a probability measured on this network; the hunt keeps the ones that stay significant with this share of false findings at most (the false discovery rate, --alpha).");
        ui.add_space(4.0);
        let current = self.hunt_form.alpha.trim().parse::<f64>().ok();
        for (value, name, what) in ALPHAS {
            let on = current.map_or(false, |a| (a - value.parse::<f64>().unwrap()).abs() < 1e-9);
            let r = theme::card(ui, on, |ui| {
                ui.horizontal(|ui| {
                    ui.label(theme::semibold(name, 13.5).color(TEXT));
                    ui.label(egui::RichText::new(format!("{} %", (value.parse::<f64>().unwrap() * 100.0).round())).monospace().size(11.0).color(theme::DIM));
                    ui.label(egui::RichText::new(what).color(theme::MUTED).size(12.0));
                });
            });
            if r.clicked() {
                self.hunt_form.alpha = value.to_string();
            }
        }
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("or another rate").color(theme::MUTED));
            ui.add(egui::TextEdit::singleline(&mut self.hunt_form.alpha).desired_width(70.0));
        });
        theme::section(ui, "What it looks for");
        ui.horizontal(|ui| {
            hint(ui, "Every detector runs by default; untick one to leave it out.");
            if ui.small_button("all").clicked() {
                self.hunt_form.detectors = [true; 13];
            }
        });
        for (i, (name, what)) in DETECTORS.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.hunt_form.detectors[i], "");
                ui.label(egui::RichText::new(*what).size(12.5).color(if self.hunt_form.detectors[i] { TEXT } else { theme::DIM }));
                ui.label(egui::RichText::new(*name).monospace().size(10.5).color(theme::DIM));
            });
        }
        if self.hunt_form.detectors[12] && self.hunt_form.sigma.trim().is_empty() {
            ui.label(egui::RichText::new("The Sigma detector has nothing to read without the Sigma hits (the previous step).").color(theme::DIM).small());
        }
    }

    fn hunt_step_results(&mut self, ui: &mut egui::Ui) {
        theme::section(ui, "The verdicts");
        ui.radio_value(&mut self.hunt_form.annotate, true, "Written into the timeline: the hunt, score and why columns of every row (the verdicts and notes already there are kept)");
        ui.radio_value(&mut self.hunt_form.annotate, false, "The timeline left untouched: the findings go to a table of their own");
        if self.hunt_form.annotate {
            ui.label(egui::RichText::new(format!("{}  The open timeline is rewritten in place.", ic::INFO)).color(theme::DIM).small());
        } else {
            save_row(ui, &mut self.hunt_form.findings, "Findings table to write", ("CSV", &["csv"]));
            ui.label(egui::RichText::new(format!("{}  The window shows what the timeline holds: with it untouched, nothing new lights up here (-o, --no-annotate).", ic::WARNING)).color(CANDIDATE).small());
        }
        theme::section(ui, "The analyst's report");
        let seeded = self.hunt_form.seeded();
        if seeded {
            let mut on = true;
            ui.add_enabled(false, egui::Checkbox::new(&mut on, "Write it, in Markdown")).on_disabled_hover_text("The incident rebuilt from the known compromised goes in the report");
        } else {
            ui.checkbox(&mut self.hunt_form.report_on, "Write it, in Markdown");
        }
        hint(ui, "One story per origin with a significant connection, most unusual first, in words, with the count behind every statement (--report).");
        if self.hunt_form.report_wanted() {
            save_row(ui, &mut self.hunt_form.report, "Report to write", ("Markdown", &["md"]));
        }
        theme::section(ui, "Marks from an earlier timeline (optional)");
        path_row(ui, &mut self.hunt_form.carry, "an earlier timeline of the same evidence", Some(("CSV", &["csv"])), false);
        hint(ui, "Its verdicts and notes are copied onto the same rows here: the evidence parsed again keeps the analyst's work (--carry-marks).");
        theme::section(ui, "The command");
        let args = self.hunt_form.command(&self.files);
        ui.add(egui::Label::new(egui::RichText::new(command_line(&args)).monospace().size(11.5).color(theme::MUTED)).wrap());
        ui.label(egui::RichText::new("The same line works in a terminal or a script.").color(theme::DIM).small());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usual() -> HuntForm {
        let mut f = HuntForm::default();
        f.from = "2026-11-10 00:00:00".into();
        f.alpha = "0.05".into();
        f.report = "D:/c/t-hunt-report.md".into();
        f.findings = "D:/c/t-findings.csv".into();
        f
    }

    #[test]
    fn the_usual_answers_are_the_hunt_it_always_was() {
        let f = usual();
        assert_eq!(f.problem(), None);
        assert_eq!(
            f.command(&["D:/c/t.csv".to_string()]),
            vec!["-a", "graph-hunt-csv", "-f", "D:/c/t.csv", "--investigation-from", "2026-11-10 00:00:00", "--alpha", "0.05"]
        );
    }

    #[test]
    fn the_detector_list_names_the_shorter_side() {
        let mut f = usual();
        f.detectors[10] = false;
        f.detectors[11] = false;
        assert_eq!(f.detector_arg(), Some(("--skip-detectors", "pagerank-spike,betweenness-spike".to_string())));
        f.detectors = [false; 13];
        f.detectors[0] = true;
        assert_eq!(f.detector_arg(), Some(("--only-detectors", "novel-edge".to_string())));
        f.detectors = [false; 13];
        assert!(f.problem().is_some());
    }

    #[test]
    fn seeds_bring_the_report_with_them() {
        let mut f = usual();
        f.seeds = " WEB01, 10.0.0.5 ".into();
        f.seed_from = "2026-11-10 01:00:00".into();
        let c = f.command(&["t.csv".to_string()]);
        let s = c.join(" ");
        assert!(s.contains("--seed WEB01, 10.0.0.5 --seed-from 2026-11-10 01:00:00"));
        assert!(!s.contains("--seed-to"));
        assert!(s.ends_with("--report D:/c/t-hunt-report.md"));
        f.report.clear();
        assert_eq!(f.problem(), Some("the report needs a file"));
    }

    #[test]
    fn an_untouched_timeline_needs_a_findings_file() {
        let mut f = usual();
        f.annotate = false;
        let s = f.command(&["t.csv".to_string()]).join(" ");
        assert!(s.contains("--no-annotate -o D:/c/t-findings.csv"));
        f.findings = "  ".into();
        assert!(f.problem().is_some());
    }

    #[test]
    fn sigma_carry_and_end_on_the_command_line() {
        let mut f = usual();
        f.end = "2026-11-11 00:00:00".into();
        f.sigma = "D:/hayabusa/out.jsonl".into();
        f.carry = "D:/c/old.csv".into();
        let c = f.command(&["t.csv".to_string()]);
        let s = c.join(" ");
        assert!(s.contains("--end-time 2026-11-11 00:00:00 --alpha 0.05 --sigma D:/hayabusa/out.jsonl --carry-marks D:/c/old.csv"));
        f.end = "tomorrow".into();
        assert!(f.problem().is_some());
    }

    #[test]
    fn every_detector_the_engine_knows_is_offered() {
        let mut names: Vec<&str> = DETECTORS.iter().map(|(n, _)| *n).collect();
        let mut engine: Vec<&str> = crate::graph_hunt_common::engine::DETECTORS.to_vec();
        names.sort();
        engine.sort();
        assert_eq!(names, engine);
    }

    #[test]
    fn the_report_and_findings_go_beside_the_timeline() {
        let files = vec![std::path::Path::new("D:/c").join("case.csv").to_string_lossy().to_string()];
        assert!(beside(&files, "-hunt-report.md").ends_with("case-hunt-report.md"));
        assert_eq!(beside(&[], ".md"), "");
    }
}
