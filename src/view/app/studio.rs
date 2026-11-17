//! The rule studio: a custom-parser rule built against the log it is for.
//! Tools › Rule studio… (or *Build a rule…* in the ingest wizard) opens a
//! log masstin does not know; on the left its lines, each coloured by the
//! line type that reads it (grey: none); on the right the rule, step by
//! step: where to start (the library's rules ranked by how much of this log
//! they read, or an empty rule in the format masstin guessed), the line
//! types (a selection in a line is what tells them apart), the fields each
//! line holds, the timeline's columns made of them, and the lines still
//! read by none; under them the rows of the timeline the rule writes. The
//! preview runs `parse-custom`'s own engine, so what it shows is what the
//! command line writes; the rule is saved as the YAML `--rules` reads.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::*;
use crate::parse_custom::{self as pc, Extract, LineOutcome, MatchRule, Parser as RuleParser, RuleFile, Verdict};
use crate::view::icons as ic;
use crate::view::theme;

/// Lines of the log the studio reads (the first ones).
const MAX_LINES: usize = 5000;

/// The event types a line can be.
pub(super) const EVENT_TYPES: [(&str, &str); 4] = [
    ("SUCCESSFUL_LOGON", "a logon that worked"),
    ("FAILED_LOGON", "a logon refused"),
    ("LOGOFF", "a session ending"),
    ("CONNECT", "a connection (no logon)"),
];

/// The timeline's columns a rule fills, with what each is.
pub(super) const COLUMNS: [(&str, &str, &str); 13] = [
    ("time_created", "Time", "when it happened"),
    ("computer", "Destination", "the machine logged on to (dst_computer)"),
    ("event_type", "Event", "the kind of line"),
    ("event_id", "Event ID", "the vendor's name or code for it"),
    ("logon_type", "Logon type", "VPN, SSH, RDP…"),
    ("target_user_name", "Account", "the account logged on with"),
    ("target_domain_name", "Account's domain", ""),
    ("workstation_name", "Origin name", "the machine it came from (src_computer)"),
    ("ip_address", "Origin address", "the address it came from (src_ip)"),
    ("subject_user_name", "Subject account", "who asked, when not the same"),
    ("subject_domain_name", "Subject's domain", ""),
    ("logon_id", "Session ID", "to pair a logon with its end"),
    ("detail", "Detail", "free text for the analyst"),
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Tab {
    Start,
    Lines,
    Fields,
    Columns,
    Rejected,
    Yaml,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Show {
    All,
    Read,
    Rejected,
}

pub(super) struct Studio {
    pub open: bool,
    pub log_path: String,
    lines: Vec<String>,
    load_error: Option<String>,
    pub rule: RuleFile,
    pub saved_path: Option<String>,
    started_from: String,
    ranked: Vec<(&'static str, usize)>,
    sel_line: usize,
    sel_parser: usize,
    tab: Tab,
    show: Show,
    outcomes: Vec<LineOutcome>,
    rule_error: Option<String>,
    dirty: bool,
    /// the text selected in the selected line
    selection: String,
    new_type: usize,
    status: String,
    /// what the rule is told, recomputed on every change
    checks: Vec<Check>,
    /// the YAML last written, to tell an unsaved change
    saved_yaml: Option<String>,
    /// the step's explanation is shown (its name always is)
    guide_open: bool,
}

impl Default for Studio {
    fn default() -> Self {
        Studio {
            open: false,
            log_path: String::new(),
            lines: Vec::new(),
            load_error: None,
            rule: empty_rule(Extract::Keyvalue { pair_separator: " ".into(), kv_separator: "=".into(), trim: true }),
            saved_path: None,
            started_from: String::new(),
            ranked: Vec::new(),
            sel_line: 0,
            sel_parser: 0,
            tab: Tab::Start,
            show: Show::All,
            outcomes: Vec::new(),
            rule_error: None,
            dirty: true,
            selection: String::new(),
            new_type: 0,
            status: String::new(),
            checks: Vec::new(),
            saved_yaml: None,
            guide_open: true,
        }
    }
}

pub(super) fn empty_rule(_extract: Extract) -> RuleFile {
    RuleFile { meta: None, prefilter: None, parsers: Vec::new() }
}

/// The extractor's name, as the YAML says it.
fn extract_kind(e: &Extract) -> &'static str {
    match e {
        Extract::Keyvalue { .. } => "key=value",
        Extract::Csv { .. } => "delimited (CSV)",
        Extract::Json { .. } => "JSON",
        Extract::Regex { .. } => "free text (regex)",
    }
}

/// A sub-parser for one kind of line: lines holding `needle`, read with
/// `extract`, its columns guessed from the fields of `sample`.
pub(super) fn new_parser(event_type: &str, needle: &str, extract: Extract, sample: &str, n: usize) -> RuleParser {
    let fields = pc::fields_of(&extract, sample).unwrap_or_default();
    let extract = with_json_fields(extract, &fields);
    let mut map = guess_columns(&fields, &extract);
    map.insert("event_type".into(), event_type.to_string());
    map.insert("filename".into(), "${__source_file}".into());
    let slug: String = needle.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(24).collect();
    RuleParser {
        name: format!("{}-{}", event_type.to_ascii_lowercase().replace('_', "-"), if slug.is_empty() { n.to_string() } else { slug }),
        match_rule: MatchRule { contains: if needle.is_empty() { Vec::new() } else { vec![needle.to_string()] }, contains_any: Vec::new(), regex: None },
        extract,
        sub_extract: None,
        map,
    }
}

/// JSON fields are named by the rule: every scalar path of the sample, as a
/// variable of the same name (dots as underscores).
fn with_json_fields(extract: Extract, fields: &[(String, String)]) -> Extract {
    match extract {
        Extract::Json { fields: f } if f.is_empty() => Extract::Json { fields: fields.iter().map(|(p, _)| (var_of(p), p.clone())).collect() },
        other => other,
    }
}

fn var_of(path: &str) -> String {
    path.replace('.', "_")
}

/// The variables a sub-parser's extractor names, for one line: what `${…}`
/// can say in the columns.
fn variables(p: &RuleParser, line: &str) -> Vec<(String, String)> {
    let fields = pc::fields_of(&p.extract, line).unwrap_or_default();
    match &p.extract {
        Extract::Csv { fields_by_index, .. } => fields
            .iter()
            .enumerate()
            .filter_map(|(i, (_, v))| fields_by_index.get(&(i as u32)).map(|n| (n.clone(), v.clone())))
            .collect(),
        Extract::Json { fields: named } => {
            let by_path: BTreeMap<&str, &str> = fields.iter().map(|(p, v)| (p.as_str(), v.as_str())).collect();
            named.iter().map(|(var, path)| (var.clone(), by_path.get(path.as_str()).map(|s| s.to_string()).unwrap_or_default())).collect()
        }
        _ => fields,
    }
}

/// The columns a rule usually fills, guessed from the field names.
pub(super) fn guess_columns(fields: &[(String, String)], extract: &Extract) -> BTreeMap<String, String> {
    let names: Vec<String> = match extract {
        Extract::Json { .. } => fields.iter().map(|(p, _)| var_of(p)).collect(),
        Extract::Csv { .. } => Vec::new(),
        _ => fields.iter().map(|(n, _)| n.clone()).collect(),
    };
    let has = |n: &str| names.iter().find(|x| x.eq_ignore_ascii_case(n)).cloned();
    let first = |cands: &[&str]| cands.iter().find_map(|c| has(c));
    let mut map = BTreeMap::new();
    let mut put = |col: &str, v: Option<String>| {
        if let Some(v) = v {
            map.insert(col.to_string(), v);
        }
    };
    let time = match (has("date"), has("time")) {
        (Some(d), Some(t)) => Some(format!("${{{}}} ${{{}}}", d, t)),
        _ => first(&["timestamp", "eventtime", "time", "datetime", "@timestamp", "ts", "receive_time", "TimeCreated", "EventTime"]).map(|v| format!("${{{}}}", v)),
    };
    put("time_created", time);
    let var = |v: Option<String>| v.map(|v| format!("${{{}}}", v));
    put("computer", var(first(&["devname", "dst_host", "dsthost", "hostname", "host", "Computer", "dst", "dstip", "destination", "server"])));
    let user = first(&["user", "username", "srcuser", "dstuser", "TargetUserName", "account", "user_name", "usrName", "suser"]);
    put("target_user_name", var(user.clone()));
    put("subject_user_name", var(user));
    put("ip_address", var(first(&["remip", "srcip", "src_ip", "src", "client_ip", "IpAddress", "source_ip", "clientip", "sourceip"])));
    put("workstation_name", var(first(&["srchost", "src_host", "WorkstationName", "client_hostname", "shost"])));
    put("logon_type", var(first(&["logontype", "LogonType", "logon_type", "tunneltype"])));
    put("event_id", var(first(&["logid", "action", "EventID", "event_id", "eventid", "msgid"])));
    put("detail", var(first(&["msg", "message", "reason", "logdesc", "Message"])));
    map
}

impl Studio {
    /// Open the studio on a log: its first lines read, the library ranked.
    pub fn load(&mut self, path: &str) {
        self.log_path = path.to_string();
        self.lines.clear();
        self.load_error = None;
        match std::fs::File::open(path) {
            Ok(f) => {
                let lines = crate::textlines::EvidenceLines::new(std::io::BufReader::new(f));
                self.lines = lines.filter(|l| !l.trim().is_empty()).take(MAX_LINES).collect();
                if self.lines.is_empty() {
                    self.load_error = Some("no text lines in this file".into());
                }
            }
            Err(e) => self.load_error = Some(e.to_string()),
        }
        self.ranked = pc::rank_library(&self.lines);
        self.sel_line = 0;
        self.dirty = true;
        self.tab = Tab::Start;
    }

    /// For the autopilot: `library` starts from the best library rule,
    /// `empty` from nothing, a tab's name goes to it, `line=N` selects a line.
    pub(super) fn auto(&mut self, what: &str) {
        match what {
            "library" => {
                if let Some((name, _)) = self.ranked.first().copied() {
                    self.start_from_library(name);
                }
            }
            "empty" => self.start_empty(),
            "all" => self.add_line_type_for_all(),
            "start" => self.tab = Tab::Start,
            "lines" => self.tab = Tab::Lines,
            "fields" => self.tab = Tab::Fields,
            "columns" => self.tab = Tab::Columns,
            "rejected" => self.tab = Tab::Rejected,
            "yaml" => self.tab = Tab::Yaml,
            other => {
                if let Some(n) = other.strip_prefix("line=").and_then(|n| n.parse::<usize>().ok()) {
                    self.sel_line = n.min(self.lines.len().saturating_sub(1));
                }
            }
        }
        self.dirty = true;
    }

    fn line(&self, i: usize) -> &str {
        self.lines.get(i).map(|s| s.as_str()).unwrap_or("")
    }

    /// Start from a library rule.
    fn start_from_library(&mut self, name: &str) {
        if let Some((_, text)) = pc::LIBRARY.iter().find(|(n, _)| *n == name) {
            match pc::rule_from_yaml(text) {
                Ok(rf) => {
                    self.rule = rf;
                    self.started_from = name.to_string();
                    self.saved_path = None;
                    self.sel_parser = 0;
                    self.dirty = true;
                    self.tab = Tab::Lines;
                }
                Err(e) => self.status = format!("cannot read {}: {}", name, e),
            }
        }
    }

    /// Start from nothing, in the format masstin guessed.
    fn start_empty(&mut self) {
        self.rule = RuleFile { meta: None, prefilter: None, parsers: Vec::new() };
        self.started_from = "an empty rule".into();
        self.saved_path = None;
        self.sel_parser = 0;
        self.dirty = true;
        self.tab = Tab::Lines;
    }

    /// The extractor a new line type starts with: the selected type's, else
    /// the guessed one.
    fn base_extract(&self) -> Extract {
        self.rule.parsers.get(self.sel_parser).map(|p| p.extract.clone()).unwrap_or_else(|| pc::guess_extract(&self.lines))
    }

    fn add_line_type(&mut self) {
        let sample = self.line(self.sel_line).to_string();
        let needle = self.selection.trim().to_string();
        let et = EVENT_TYPES[self.new_type].0;
        let p = new_parser(et, &needle, self.base_extract(), &sample, self.rule.parsers.len() + 1);
        self.rule.parsers.push(p);
        self.sel_parser = self.rule.parsers.len() - 1;
        self.dirty = true;
    }

    /// One line type that reads every line: for logs whose lines all have
    /// the same shape (JSON, CSV, key=value).
    fn add_line_type_for_all(&mut self) {
        let sample = self.line(self.sel_line).to_string();
        let et = EVENT_TYPES[self.new_type].0;
        let mut p = new_parser(et, "", self.base_extract(), &sample, self.rule.parsers.len() + 1);
        p.name = format!("{}-every-line", et.to_ascii_lowercase().replace('_', "-"));
        // (a type with no condition reads nothing: this one is "any line")
        p.match_rule.regex = Some(".".to_string());
        self.rule.parsers.push(p);
        self.sel_parser = self.rule.parsers.len() - 1;
        self.dirty = true;
    }

    fn evaluate(&mut self) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        match pc::Engine::from_rule(self.rule.clone()) {
            Ok(e) => {
                self.rule_error = None;
                let name = Path::new(&self.log_path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                self.outcomes = self.lines.iter().enumerate().map(|(i, l)| e.eval(l, &name, i + 1, "")).collect();
            }
            Err(e) => {
                self.rule_error = Some(e);
                self.outcomes.clear();
            }
        }
        let saved = self.saved_yaml.as_deref() == Some(self.yaml().as_str());
        self.checks = run_checks(&self.lines, &self.rule, &self.outcomes, self.rule_error.as_deref(), saved);
    }

    fn counts(&self) -> (usize, usize, usize) {
        let rows = self.outcomes.iter().filter(|o| o.verdict == Verdict::Row).count();
        let unwritten = self.outcomes.iter().filter(|o| matches!(o.verdict, Verdict::NoOrigin | Verdict::NoDestination)).count();
        let rejected = self.outcomes.iter().filter(|o| o.verdict == Verdict::Rejected).count();
        (rows, unwritten, rejected)
    }

    fn yaml(&self) -> String {
        let body = pc::rule_to_yaml(&self.rule).unwrap_or_else(|e| format!("# {}", e));
        format!("# masstin custom-parser rule, made with the rule studio\n# from {} on {}\n{}", self.started_from, Path::new(&self.log_path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), body)
    }
}

/// A line type's colour.
fn colour(i: usize) -> Color32 {
    const P: [Color32; 6] = [theme::CYAN, theme::VIOLET, theme::MAGENTA, EDGE_OK, CANDIDATE, Color32::from_rgb(120, 180, 255)];
    P[i % P.len()]
}

// ───────────────────────── the checks ─────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(super) enum Level {
    Error,
    Warn,
    Info,
    Ok,
}

/// One thing the studio tells about the rule, with where to fix it.
#[derive(Clone, Debug)]
pub(super) struct Check {
    pub level: Level,
    pub text: String,
    pub tab: Tab,
    pub line: Option<usize>,
    pub parser: Option<usize>,
}

fn check(level: Level, text: impl Into<String>, tab: Tab, line: Option<usize>, parser: Option<usize>) -> Check {
    Check { level, text: text.into(), tab, line, parser }
}

/// The `${…}` a template names, each with its alternatives (`${a|b}`).
fn template_vars(t: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut rest = t;
    while let Some(a) = rest.find("${") {
        let after = &rest[a + 2..];
        let Some(b) = after.find('}') else { break };
        out.push(after[..b].split('|').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect());
        rest = &after[b + 1..];
    }
    out
}

/// Columns a row cannot do without, and the ones it should have.
const NEEDED: [(&str, &str); 2] = [("time_created", "Time"), ("computer", "Destination")];

/// Everything the studio has to say about the rule on these lines.
pub(super) fn run_checks(lines: &[String], rule: &RuleFile, outcomes: &[LineOutcome], rule_error: Option<&str>, saved: bool) -> Vec<Check> {
    let mut out = Vec::new();
    if lines.is_empty() {
        out.push(check(Level::Error, "Open a log: the rule is built against its lines", Tab::Start, None, None));
        return out;
    }
    if let Some(e) = rule_error {
        out.push(check(Level::Error, format!("The rule does not compile: {}", e), Tab::Fields, None, None));
        return out;
    }
    if rule.parsers.is_empty() {
        out.push(check(Level::Error, "No line type yet: start from the library, or select text in a line and make one", Tab::Start, None, None));
        return out;
    }
    let n = lines.len();
    let read = outcomes.iter().filter(|o| o.parser.is_some()).count();
    let rows = outcomes.iter().filter(|o| o.verdict == Verdict::Row).count();
    let share = read as f64 / n as f64;
    let first_rejected = outcomes.iter().position(|o| o.verdict == Verdict::Rejected);
    if read == 0 {
        out.push(check(Level::Error, "No line is read yet: the line types' text is in none of the lines", Tab::Lines, None, None));
    } else if share < 0.5 {
        out.push(check(Level::Warn, format!("Only {:.0} % of the lines are read: see what is left", share * 100.0), Tab::Rejected, first_rejected, None));
    } else if read < n {
        out.push(check(Level::Info, format!("{} line(s) read by none: noise, or a kind of line still to add", n - read), Tab::Rejected, first_rejected, None));
    } else {
        out.push(check(Level::Ok, "Every line is read", Tab::Lines, None, None));
    }
    // names
    let mut names = BTreeSet::new();
    for (i, p) in rule.parsers.iter().enumerate() {
        if !names.insert(p.name.trim().to_string()) {
            out.push(check(Level::Warn, format!("Two line types are called «{}»: the summary would mix them", p.name), Tab::Lines, None, Some(i)));
        }
    }
    for (i, p) in rule.parsers.iter().enumerate() {
        let mine: Vec<usize> = outcomes.iter().enumerate().filter(|(_, o)| o.parser.map(|x| x.1) == Some(i)).map(|(k, _)| k).collect();
        let et = p.map.get("event_type").map(|s| s.trim().to_string()).unwrap_or_default();
        if !EVENT_TYPES.iter().any(|(t, _)| *t == et) {
            out.push(check(Level::Error, format!("«{}»: say what its lines are (logon, failed logon, logoff, connection)", p.name), Tab::Lines, None, Some(i)));
        }
        if p.match_rule.contains.is_empty() && p.match_rule.contains_any.is_empty() && p.match_rule.regex.is_none() {
            out.push(check(Level::Error, format!("«{}» has no text to tell its lines apart: it reads none", p.name), Tab::Lines, None, Some(i)));
            continue;
        }
        if mine.is_empty() {
            // would it read any alone? then an earlier type takes its lines
            let alone = RuleFile { meta: None, prefilter: rule.prefilter.clone(), parsers: vec![p.clone()] };
            let shadowed = pc::Engine::from_rule(alone).ok().and_then(|e| lines.iter().position(|l| e.eval(l, "", 0, "").parser.is_some()));
            match shadowed {
                Some(k) => out.push(check(Level::Warn, format!("«{}» never gets a line: an earlier type takes them; move it up", p.name), Tab::Lines, Some(k), Some(i))),
                None => out.push(check(Level::Warn, format!("«{}» reads no line of this log", p.name), Tab::Lines, None, Some(i))),
            }
            continue;
        }
        for (col, label) in NEEDED {
            if p.map.get(col).map_or(true, |t| t.trim().is_empty()) {
                out.push(check(Level::Error, format!("«{}»: the {} column is empty", p.name, label), Tab::Columns, mine.first().copied(), Some(i)));
            }
        }
        let has = |c: &str| p.map.get(c).map_or(false, |t| !t.trim().is_empty());
        if !has("workstation_name") && !has("ip_address") {
            out.push(check(Level::Error, format!("«{}»: no origin (name or address): its lines make no row", p.name), Tab::Columns, mine.first().copied(), Some(i)));
        }
        if !has("target_user_name") && !has("subject_user_name") {
            out.push(check(Level::Warn, format!("«{}»: no account: the hunt and the map work on accounts", p.name), Tab::Columns, mine.first().copied(), Some(i)));
        }
        // ${…} that are empty on most of its lines
        for (col, tpl) in &p.map {
            for alts in template_vars(tpl) {
                if alts.iter().all(|a| a.starts_with("__")) {
                    continue;
                }
                let empty: Vec<usize> = mine.iter().copied().filter(|k| !alts.iter().any(|a| outcomes[*k].ctx.get(a).map_or(false, |v| !v.trim().is_empty()))).collect();
                if empty.len() * 2 > mine.len() {
                    let label = COLUMNS.iter().find(|c| c.0 == col).map(|c| c.1).unwrap_or(col.as_str());
                    out.push(check(Level::Warn, format!("«{}»: ${{{}}} in {} is empty on {} of its {} lines", p.name, alts.join("|"), label, empty.len(), mine.len()), Tab::Columns, empty.first().copied(), Some(i)));
                }
            }
        }
        // times masstin cannot read
        let bad: Vec<usize> = mine.iter().copied().filter(|k| outcomes[*k].record.as_ref().map_or(false, |r| parse_time(&r.time_created).is_none())).collect();
        if !bad.is_empty() {
            let ex = outcomes[bad[0]].record.as_ref().map(|r| r.time_created.clone()).unwrap_or_default();
            out.push(check(Level::Error, format!("«{}»: {} time(s) masstin cannot read, such as «{}»", p.name, bad.len(), ex), Tab::Columns, Some(bad[0]), Some(i)));
        }
        let unwritten: Vec<usize> = mine.iter().copied().filter(|k| matches!(outcomes[*k].verdict, Verdict::NoOrigin | Verdict::NoDestination)).collect();
        if !unwritten.is_empty() {
            out.push(check(Level::Warn, format!("«{}»: {} line(s) read but not written (no origin or no destination in them)", p.name, unwritten.len()), Tab::Rejected, Some(unwritten[0]), Some(i)));
        }
    }
    if rows > 0 && out.iter().all(|c| c.level >= Level::Info) {
        out.push(check(Level::Ok, format!("{} rows, every column a row needs is there", rows), Tab::Columns, None, None));
    }
    if !saved && rows > 0 {
        out.push(check(Level::Info, "Not saved: Save as… writes the YAML --rules reads", Tab::Yaml, None, None));
    }
    out.sort_by_key(|c| c.level);
    out
}

/// What a step looks like in the stepper: the worst check pointing at it.
fn step_level(checks: &[Check], tab: Tab) -> Option<Level> {
    checks.iter().filter(|c| c.tab == tab && c.level != Level::Info).map(|c| c.level).min()
}

fn level_colour(l: Level) -> Color32 {
    match l {
        Level::Error => SIGNIFICANT,
        Level::Warn => CANDIDATE,
        Level::Info => theme::MUTED,
        Level::Ok => EDGE_OK,
    }
}

fn level_icon(l: Level) -> &'static str {
    match l {
        Level::Error => ic::WARNING,
        Level::Warn => ic::WARNING,
        Level::Info => ic::INFO,
        Level::Ok => ic::CHECK_CIRCLE,
    }
}

/// An event type's colour, as the map draws it.
fn event_colour(et: &str) -> Color32 {
    match et {
        "SUCCESSFUL_LOGON" => EDGE_OK,
        "FAILED_LOGON" => SIGNIFICANT,
        "LOGOFF" => theme::MUTED,
        "CONNECT" => theme::CYAN,
        _ => theme::DIM,
    }
}

impl Viewer {
    pub(super) fn studio_window(&mut self, ctx: &egui::Context) {
        if !self.studio.open {
            return;
        }
        self.studio.evaluate();
        let mut open = true;
        let screen = ctx.content_rect();
        let mut use_in_ingest: Option<String> = None;
        egui::Window::new(format!("{}  Rule studio · custom logs", ic::TERMINAL_WINDOW))
            .id(egui::Id::new("rule-studio"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .fixed_size(Vec2::new(screen.width() * 0.92, screen.height() * 0.84))
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
                let st = &mut self.studio;
                ui.set_max_width(screen.width() * 0.92 - 16.0);
                // the top: the log, the rule, save
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Log").color(theme::MUTED));
                    ui.add(egui::Label::new(egui::RichText::new(if st.log_path.is_empty() { "none yet".to_string() } else { st.log_path.clone() }).monospace().size(11.5)).truncate());
                    if ui.button(format!("{}  Open a log…", ic::FOLDER_OPEN)).on_hover_text("Pick the log to build a rule for: a text file with one event per line (a VPN, a firewall, a proxy, a JSON export…)").clicked() {
                        if let Some(p) = rfd::FileDialog::new().set_title("A log masstin does not know").pick_file() {
                            st.load(&p.to_string_lossy());
                        }
                    }
                    ui.separator();
                    if ui.button(format!("{}  Open a rule…", ic::ARCHIVE)).on_hover_text("A YAML rule to go on with; its comments are not kept, so save it as a new file").clicked() {
                        if let Some(p) = rfd::FileDialog::new().add_filter("YAML rules", &["yaml", "yml"]).pick_file() {
                            match std::fs::read_to_string(&p).map_err(|e| e.to_string()).and_then(|t| pc::rule_from_yaml(&t)) {
                                Ok(rf) => {
                                    st.rule = rf;
                                    st.started_from = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                                    st.saved_path = None;
                                    st.sel_parser = 0;
                                    st.dirty = true;
                                    st.tab = Tab::Lines;
                                }
                                Err(e) => st.status = format!("cannot read the rule: {}", e),
                            }
                        }
                    }
                    let can_save = !st.rule.parsers.is_empty() && st.rule_error.is_none();
                    if ui.add_enabled(can_save, egui::Button::new(format!("{}  Save as…", ic::FLOPPY_DISK))).clicked() {
                        let name = Path::new(&st.log_path).file_stem().map(|s| format!("{}-rule.yaml", s.to_string_lossy())).unwrap_or_else(|| "rule.yaml".into());
                        if let Some(p) = rfd::FileDialog::new().set_title("Rule to write").add_filter("YAML rules", &["yaml"]).set_file_name(name).save_file() {
                            match std::fs::write(&p, st.yaml()) {
                                Ok(()) => {
                                    st.saved_yaml = Some(st.yaml());
                                    st.dirty = true;
                                    st.saved_path = Some(p.to_string_lossy().to_string());
                                    st.status = format!("Saved: {}", p.display());
                                }
                                Err(e) => st.status = format!("cannot write {}: {}", p.display(), e),
                            }
                        }
                    }
                    if let Some(sp) = st.saved_path.clone() {
                        if ui.add(egui::Button::new(theme::semibold(format!("{}  Use it in the ingest", ic::DOWNLOAD_SIMPLE), 13.0).color(theme::ACCENT_INK)).fill(theme::ACCENT).stroke(Stroke::NONE)).on_hover_text("The ingest wizard, with this log and this rule (--rules)").clicked() {
                            use_in_ingest = Some(sp);
                        }
                    }
                    if !st.status.is_empty() {
                        ui.label(egui::RichText::new(&st.status).color(theme::DIM).small());
                    }
                });
                if let Some(e) = &st.load_error {
                    ui.label(egui::RichText::new(format!("{}  {}", ic::WARNING, e)).color(SIGNIFICANT));
                }
                if let Some(e) = &st.rule_error {
                    ui.label(egui::RichText::new(format!("{}  the rule does not compile: {}", ic::WARNING, e)).color(SIGNIFICANT));
                }
                coverage_bar(ui, st);
                checks_panel(ui, st);
                theme::hairline(ui);
                let avail = ui.available_size();
                let preview_h = (avail.y * 0.30).clamp(140.0, 320.0);
                let top_h = avail.y - preview_h - 16.0;
                ui.allocate_ui_with_layout(Vec2::new(avail.x, top_h), egui::Layout::left_to_right(egui::Align::Min), |ui| {
                    ui.set_height(top_h);
                    let left_w = avail.x * 0.52;
                    let column = egui::Layout::top_down(egui::Align::Min);
                    ui.allocate_ui_with_layout(Vec2::new(left_w, top_h), column, |ui| {
                        ui.set_width(left_w);
                        ui.set_min_height(top_h);
                        studio_lines(ui, st, top_h);
                    });
                    // a divider as tall as the panes, not the window
                    let (div, painter) = ui.allocate_painter(Vec2::new(9.0, top_h), Sense::hover());
                    painter.line_segment([div.rect.center_top(), div.rect.center_bottom()], Stroke::new(1.0, theme::BORDER_2));
                    let right_w = avail.x - left_w - 20.0;
                    ui.allocate_ui_with_layout(Vec2::new(right_w, top_h), column, |ui| {
                        ui.set_width(right_w);
                        ui.set_min_height(top_h);
                        studio_rule(ui, st, top_h);
                    });
                });
                theme::hairline(ui);
                studio_preview(ui, st, preview_h);
            });
        if let Some(rules) = use_in_ingest {
            let log = self.studio.log_path.clone();
            self.studio.open = false;
            self.ingest_with(vec![log]);
            self.ingest.rules = rules;
            return;
        }
        if !open {
            self.studio.open = false;
        }
    }
}

/// The left: the log's lines, coloured by the line type that reads them.
fn studio_lines(ui: &mut egui::Ui, st: &mut Studio, h: f32) {
    let (rows, unwritten, rejected) = st.counts();
    ui.horizontal(|ui| {
        ui.label(theme::semibold(format!("{} lines", st.lines.len()), 13.0).color(TEXT));
        ui.label(egui::RichText::new(format!("{} rows", rows)).color(theme::CYAN));
        if unwritten > 0 {
            ui.label(egui::RichText::new(format!("{} read but not written", unwritten)).color(CANDIDATE)).on_hover_text("A row needs an origin (name or address) and a destination: fill those columns");
        }
        ui.label(egui::RichText::new(format!("{} read by none", rejected)).color(theme::DIM));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.selectable_value(&mut st.show, Show::Rejected, "read by none");
            ui.selectable_value(&mut st.show, Show::Read, "read");
            ui.selectable_value(&mut st.show, Show::All, "all");
        });
    });
    let idx: Vec<usize> = (0..st.lines.len())
        .filter(|i| match st.show {
            Show::All => true,
            Show::Read => st.outcomes.get(*i).map_or(false, |o| o.parser.is_some()),
            Show::Rejected => st.outcomes.get(*i).map_or(true, |o| o.parser.is_none()),
        })
        .collect();
    let row_h = 20.0;
    egui::ScrollArea::both().id_salt("studio-lines").max_height(h - 30.0).auto_shrink([false, false]).show_rows(ui, row_h, idx.len(), |ui, range| {
        ui.spacing_mut().item_spacing.y = 0.0;
        for &i in &idx[range] {
            let o = st.outcomes.get(i);
            let (c, tag) = match o.and_then(|o| o.parser) {
                Some((_, p)) => (colour(p), st.rule.parsers.get(p).map(|x| x.name.clone()).unwrap_or_default()),
                None => (theme::DIM, "read by none".to_string()),
            };
            let selected = st.sel_line == i;
            let r = ui.allocate_ui_with_layout(Vec2::new(ui.available_width().max(400.0), row_h), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.set_height(row_h);
                let (bar, p) = ui.allocate_painter(Vec2::new(4.0, row_h - 4.0), Sense::hover());
                p.rect_filled(bar.rect, CornerRadius::same(1), c);
                ui.label(egui::RichText::new(format!("{:>5}", i + 1)).monospace().size(10.5).color(theme::DIM));
                let base = if o.map_or(false, |o| o.parser.is_some()) { TEXT } else { theme::MUTED };
                let job = lit_line(&st.lines[i], st.selection.trim(), base, if selected { Some(Color32::from_rgba_unmultiplied(38, 228, 226, 34)) } else { None });
                ui.add(egui::Label::new(job).extend().sense(Sense::click()))
            });
            let resp = r.inner.on_hover_text(tag);
            if resp.clicked() {
                st.sel_line = i;
                st.selection.clear();
                if let Some((_, p)) = o.and_then(|o| o.parser) {
                    st.sel_parser = p;
                }
            }
        }
    });
}

/// The right: the rule, step by step.
fn studio_rule(ui: &mut egui::Ui, st: &mut Studio, h: f32) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        for (t, label) in [(Tab::Start, "1  Start"), (Tab::Lines, "2  Line types"), (Tab::Fields, "3  Fields"), (Tab::Columns, "4  Columns"), (Tab::Rejected, "5  Read by none"), (Tab::Yaml, "YAML")] {
            let lv = step_level(&st.checks, t);
            let mark = match lv {
                Some(Level::Error) => format!("{} ", ic::WARNING),
                Some(Level::Warn) => format!("{} ", ic::WARNING),
                Some(Level::Ok) => format!("{} ", ic::CHECK_CIRCLE),
                _ => String::new(),
            };
            let on = st.tab == t;
            let mut job = egui::text::LayoutJob::default();
            if !mark.is_empty() {
                job.append(&mark, 0.0, egui::TextFormat { color: level_colour(lv.unwrap()), font_id: FontId::proportional(13.0), ..Default::default() });
            }
            job.append(label, 0.0, egui::TextFormat { color: if on { theme::ACCENT_INK } else { TEXT }, font_id: FontId::proportional(13.0), ..Default::default() });
            let b = egui::Button::new(job).fill(if on { theme::ACCENT } else { theme::FIELD }).stroke(Stroke::new(1.0, lv.map(level_colour).filter(|_| !on).unwrap_or(theme::BORDER_2))).corner_radius(CornerRadius::same(14)).min_size(Vec2::new(0.0, 26.0));
            if ui.add(b).clicked() {
                st.tab = t;
            }
        }
    });
    ui.add_space(4.0);
    let guide_h = guide(ui, st);
    egui::ScrollArea::vertical().id_salt("studio-rule").max_height(h - 36.0 - guide_h).auto_shrink([false, false]).show(ui, |ui| match st.tab {
        Tab::Start => tab_start(ui, st),
        Tab::Lines => tab_lines(ui, st),
        Tab::Fields => tab_fields(ui, st),
        Tab::Columns => tab_columns(ui, st),
        Tab::Rejected => tab_rejected(ui, st),
        Tab::Yaml => {
            let mut y = st.yaml();
            ui.add(egui::TextEdit::multiline(&mut y).code_editor().desired_width(f32::INFINITY).interactive(true));
            ui.label(egui::RichText::new("What Save as… writes; masstin -a parse --rules reads it the same.").color(theme::DIM).small());
        }
    });
}

/// What each step is for, in the order the rule is made: (tab, title,
/// what to do, what "done" looks like).
const STEPS: [(Tab, &str, &str, &str); 6] = [
    (Tab::Start, "Where to start", "A rule teaches masstin to read a log it does not know: which lines matter, how each is cut into fields, and which field goes in which column of the timeline. Open a log (above), then start from a rule of the library that already reads part of it, or from an empty one.", "Done when a rule is started: the next step lists its line types."),
    (Tab::Lines, "Which lines matter", "A log holds several kinds of line (a login, a failure, a logout…). Each kind is a line type. Click a line on the left, select in the box below the words only that kind of line has (for instance «authenticated»), say what it is (a logon, a failed logon…) and add it. When every line has the same shape (JSON, CSV), one line type for all of them is enough: the button below.", "Done when the bar above is coloured: every colour is a line type, the dashed part is lines no type reads."),
    (Tab::Fields, "How a line is cut into fields", "Pick the line type on the left of this pane (step 2) and say what its lines look like: key=value pairs, columns split by a character, JSON, or free text read with a pattern. The table shows the fields masstin gets from the selected line: each is a name you use in the next step as ${name}.", "Done when the fields you need (the time, the user, where it came from, where it went) are in the table with the right values."),
    (Tab::Columns, "Which field goes in which column", "The timeline has fixed columns. For each one, write the field that fills it as ${name}, plain text, or both. A connection needs at least its time, an origin (src_ip or src_computer) and a destination (dst_computer): without them the line is read but no row is written.", "Done when the rows at the bottom show the values in the right columns and nothing is marked to fix."),
    (Tab::Rejected, "What is left unread", "The lines no line type reads. They may be noise (leave them) or a kind of line you still want: click one, go back to step 2 and make a line type for it.", "Done when only the lines you do not need are left here."),
    (Tab::Yaml, "The rule, written", "The rule as a file. Save as… (above) writes it; Use it in the ingest then reads the whole log with it. The same file works from the command line: masstin -a parse --rules FILE.", "Done: save it and use it in the ingest."),
];

/// The step's card: what it is for, what to do, and the way to the next.
/// Gives the height it took.
fn guide(ui: &mut egui::Ui, st: &mut Studio) -> f32 {
    let k = STEPS.iter().position(|s| s.0 == st.tab).unwrap_or(0);
    let (_, title, what, done) = STEPS[k];
    let top = ui.cursor().top();
    egui::Frame::new().fill(theme::FIELD).stroke(Stroke::new(1.0, theme::BORDER_2)).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::symmetric(10, 8)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(theme::semibold(format!("{}  Step {} of {} · {}", ic::FLAG, k + 1, STEPS.len(), title), 13.0).color(theme::CYAN));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let last = k + 1 == STEPS.len();
                if ui.add_enabled(!last, egui::Button::new(theme::semibold(format!("Next  {}", ic::ARROW_RIGHT), 12.5).color(if last { theme::DIM } else { theme::ACCENT_INK })).fill(if last { theme::FIELD } else { theme::ACCENT })).on_hover_text("The next step of the rule").clicked() {
                    st.tab = STEPS[k + 1].0;
                }
                if ui.add_enabled(k > 0, egui::Button::new(format!("{}  Back", ic::ARROW_LEFT))).on_hover_text("The step before").clicked() {
                    st.tab = STEPS[k - 1].0;
                }
                if st.guide_open {
                    if ui.small_button("hide the guide").on_hover_text("Keep only the step's name; show it again from here").clicked() {
                        st.guide_open = false;
                    }
                } else if ui.small_button("show the guide").clicked() {
                    st.guide_open = true;
                }
            });
        });
        if st.guide_open {
            ui.add(egui::Label::new(egui::RichText::new(what).color(TEXT).size(12.5)).wrap());
            ui.add(egui::Label::new(egui::RichText::new(format!("{}  {}", ic::CHECK_CIRCLE, done)).color(theme::MUTED).size(12.0)).wrap());
        }
    });
    ui.add_space(6.0);
    ui.cursor().top() - top
}

fn hint(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).color(theme::MUTED).size(12.0));
}

fn tab_start(ui: &mut egui::Ui, st: &mut Studio) {
    if st.lines.is_empty() {
        hint(ui, "Open a log first: a VPN, a firewall, a proxy, anything masstin does not read by itself.");
        return;
    }
    hint(ui, "masstin's library tried on this log: start from the one that reads most, or from an empty rule.");
    ui.horizontal(|ui| {
        theme::section(ui, "The library");
        theme::help(ui, "Rules that come with masstin for known products (VPNs, firewalls, proxies, JSON exports). Each was tried on this log: the count is how many of its lines it reads as it is. Starting from one keeps its line types, fields and columns; you only add what your log has and it lacks.");
    });
    if st.ranked.is_empty() {
        ui.label(egui::RichText::new("None of the library's rules reads a line of it.").color(theme::DIM));
    }
    let n = st.lines.len();
    for (name, rows) in st.ranked.clone() {
        let on = st.started_from == name;
        let text = egui::RichText::new(format!("{}   {} of {} lines", name, rows, n)).size(13.0).color(if on { theme::CYAN } else { TEXT });
        if ui.add(egui::Button::new(text).selected(on).min_size(Vec2::new(ui.available_width(), 28.0))).on_hover_text("Start from this rule").clicked() {
            st.start_from_library(name);
        }
    }
    ui.horizontal(|ui| {
        theme::section(ui, "Or from nothing");
        theme::help(ui, "A rule with no line types: you make them in the next step. masstin looked at the lines and guessed their shape (JSON, key=value, delimited or free text), which is what a new line type starts with; it can be changed in 3 Fields.");
    });
    let guessed = pc::guess_extract(&st.lines);
    if ui.button(format!("{}  An empty rule: the lines look {}", ic::PLUS, extract_kind(&guessed))).clicked() {
        st.start_empty();
    }
    ui.label(egui::RichText::new(format!("Started from: {}", if st.started_from.is_empty() { "nothing yet" } else { st.started_from.as_str() })).color(theme::DIM).small());
}

fn tab_lines(ui: &mut egui::Ui, st: &mut Studio) {
    hint(ui, "Each kind of line the log holds is a line type: the text that tells it apart, and what it is. The first type a line fits reads it.");
    theme::section(ui, "The selected line");
    let mut line = st.line(st.sel_line).to_string();
    let spans = st.rule.parsers.get(st.sel_parser).map(|p| field_spans(p, &line)).unwrap_or_default();
    let needle = st.selection.trim().to_string();
    let mut layouter = |ui: &egui::Ui, text: &dyn egui::TextBuffer, wrap: f32| {
        let mut job = coloured_line(text.as_str(), &spans, &needle);
        job.wrap.max_width = wrap;
        ui.fonts_mut(|f| f.layout_job(job))
    };
    let out = egui::TextEdit::multiline(&mut line).code_editor().desired_width(f32::INFINITY).desired_rows(2).layouter(&mut layouter).show(ui);
    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new("■ key").monospace().size(10.5).color(theme::DIM));
        ui.label(egui::RichText::new("■ value used in a column").monospace().size(10.5).color(theme::CYAN));
        ui.label(egui::RichText::new("■ value not used").monospace().size(10.5).color(theme::VIOLET));
        ui.label(egui::RichText::new("■ your selection").monospace().size(10.5).color(CANDIDATE));
    });
    if let Some(range) = out.cursor_range {
        let [a, b] = range.sorted_cursors();
        let (a, b) = (a.index.0, b.index.0);
        if b > a {
            st.selection = line.chars().skip(a).take(b - a).collect();
        }
    }
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Select the text that tells this kind of line apart, then:").color(theme::MUTED).size(12.0));
    });
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(if st.selection.trim().is_empty() { "(nothing selected)".to_string() } else { format!("\"{}\"", st.selection) }).monospace().color(theme::CYAN));
    });
    ui.horizontal(|ui| {
        egui::ComboBox::from_id_salt("studio-new-type").selected_text(EVENT_TYPES[st.new_type].0).show_ui(ui, |ui| {
            for (i, (t, what)) in EVENT_TYPES.iter().enumerate() {
                ui.selectable_value(&mut st.new_type, i, format!("{}  ({})", t, what));
            }
        });
        theme::help(ui, "What this kind of line is in the timeline. SUCCESSFUL_LOGON: someone got in. FAILED_LOGON: someone tried and was refused. LOGOFF: a session ended. CONNECT: a connection with no login in it (a firewall's allow, a proxy's request). It is the event_type column, and the colour of the connection in the graph.");
        let ok = !st.selection.trim().is_empty() && !st.lines.is_empty();
        if ui.add_enabled(ok, egui::Button::new(format!("{}  A line type for lines with this", ic::PLUS))).on_hover_text("Lines that hold the selected text are read by this new line type. Select the text first, in the box above").on_disabled_hover_text("Select in the box above the words that only this kind of line has").clicked() {
            st.add_line_type();
        }
    });
    ui.horizontal(|ui| {
        let structured = !matches!(st.base_extract(), Extract::Regex { .. });
        let label = format!("{}  One line type for every line", ic::STACK);
        let b = if structured && st.rule.parsers.is_empty() { egui::Button::new(theme::semibold(label, 13.0).color(theme::ACCENT_INK)).fill(theme::ACCENT) } else { egui::Button::new(label) };
        if ui.add_enabled(!st.lines.is_empty(), b).on_hover_text("Every line is read the same way, as the event chosen on the left. Right when the log is JSON, CSV or key=value and each line is one event").clicked() {
            st.add_line_type_for_all();
        }
        if structured {
            ui.label(egui::RichText::new(format!("the lines look {}: one type usually reads them all", extract_kind(&st.base_extract()))).color(theme::MUTED).size(12.0));
        }
        theme::help(ui, "A line type that reads every line. Use it when all the lines have the same fields (JSON objects, CSV rows, key=value pairs). If the log mixes logons and failures in the same shape, make it once, then in 4 Columns fill event_type from the field that says which it is, or add more specific line types above it (a line is read by the first type it fits; «up» moves a type earlier).");
    });
    theme::section(ui, "Line types");
    if st.rule.parsers.is_empty() {
        ui.label(egui::RichText::new("None yet.").color(theme::DIM));
    }
    let hits: Vec<usize> = (0..st.rule.parsers.len()).map(|p| st.outcomes.iter().filter(|o| o.parser.map(|x| x.1) == Some(p)).count()).collect();
    let mut remove = None;
    let mut up = None;
    for (i, p) in st.rule.parsers.iter_mut().enumerate() {
        let on = st.sel_parser == i;
        let r = theme::card(ui, on, |ui| {
            ui.horizontal(|ui| {
                let (bar, painter) = ui.allocate_painter(Vec2::new(5.0, 18.0), Sense::hover());
                painter.rect_filled(bar.rect, CornerRadius::same(1), colour(i));
                if ui.add(egui::TextEdit::singleline(&mut p.name).desired_width(220.0)).changed() {
                    st.dirty = true;
                }
                let mut et = p.map.get("event_type").cloned().unwrap_or_default();
                egui::ComboBox::from_id_salt(("studio-et", i)).selected_text(if et.is_empty() { "event?" } else { et.as_str() }).show_ui(ui, |ui| {
                    for (t, _) in EVENT_TYPES {
                        ui.selectable_value(&mut et, t.to_string(), t);
                    }
                });
                if p.map.get("event_type") != Some(&et) {
                    p.map.insert("event_type".into(), et);
                    st.dirty = true;
                }
                ui.label(egui::RichText::new(format!("{} lines", hits[i])).color(colour(i)));
                if i > 0 && ui.small_button("up").on_hover_text("Try this line type before the one above it: a line is read by the first type it fits, so the most specific go first").clicked() {
                    up = Some(i);
                }
                if ui.small_button(ic::X).on_hover_text("Remove this line type: its lines go back to «read by none»").clicked() {
                    remove = Some(i);
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("lines with").color(theme::DIM).small());
                let mut drop_needle = None;
                for (k, needle) in p.match_rule.contains.iter().enumerate() {
                    if ui.add(egui::Button::new(egui::RichText::new(format!("{}  {}", needle, ic::X)).monospace().size(11.0)).small()).on_hover_text("Remove this condition").clicked() {
                        drop_needle = Some(k);
                    }
                }
                if let Some(k) = drop_needle {
                    p.match_rule.contains.remove(k);
                    st.dirty = true;
                }
                if !st.selection.trim().is_empty() && ui.small_button(format!("+ \"{}\"", st.selection.trim())).on_hover_text("Also require the selected text").clicked() {
                    p.match_rule.contains.push(st.selection.trim().to_string());
                    st.dirty = true;
                }
                if let Some(re) = &p.match_rule.regex {
                    if re == "." {
                        ui.label(egui::RichText::new("every line").size(11.5).color(theme::CYAN)).on_hover_text("This line type reads any line (its condition is the pattern «.»). More specific types above it are tried first");
                    } else {
                        ui.label(egui::RichText::new(format!("regex {}", re)).monospace().size(11.0).color(theme::DIM));
                    }
                }
            });
        });
        if r.clicked() {
            st.sel_parser = i;
        }
    }
    if let Some(i) = up {
        st.rule.parsers.swap(i, i - 1);
        st.dirty = true;
    }
    if let Some(i) = remove {
        st.rule.parsers.remove(i);
        st.sel_parser = st.sel_parser.min(st.rule.parsers.len().saturating_sub(1));
        st.dirty = true;
    }
    if let Some(pf) = &st.rule.prefilter {
        ui.label(egui::RichText::new(format!("Only lines with all of {:?} or any of {:?} are tried (the rule's prefilter).", pf.contains_all, pf.contains_any)).color(theme::DIM).small());
    }
}

fn tab_fields(ui: &mut egui::Ui, st: &mut Studio) {
    let line = st.line(st.sel_line).to_string();
    let Some(p) = st.rule.parsers.get_mut(st.sel_parser) else {
        hint(ui, "Make a line type first (2 Line types).");
        return;
    };
    hint(ui, &format!("How the lines of «{}» are split into fields. The table shows the selected line.", p.name));
    let kind = extract_kind(&p.extract);
    let mut changed = false;
    ui.horizontal(|ui| {
        theme::help(ui, "The shape of this kind of line. key=value: user=ana src=10.0.0.5 … (say what splits the pairs and what splits key from value). delimited: columns split by a comma, a tab, a bar; you name the ones you use. JSON: one object per line; its values are the fields. free text: anything else, read with a pattern where each field is a named group, (?P<user>\\S+).");
        ui.label(egui::RichText::new("The lines are").color(theme::MUTED));
        egui::ComboBox::from_id_salt("studio-extract").selected_text(kind).show_ui(ui, |ui| {
            let opts: [(&str, Extract); 4] = [
                ("key=value", Extract::Keyvalue { pair_separator: " ".into(), kv_separator: "=".into(), trim: true }),
                ("delimited (CSV)", Extract::Csv { delimiter: ",".into(), quote: Some("\"".into()), fields_by_index: BTreeMap::new() }),
                ("JSON", Extract::Json { fields: BTreeMap::new() }),
                ("free text (regex)", Extract::Regex { pattern: String::new() }),
            ];
            for (name, e) in opts {
                if ui.selectable_label(kind == name, name).clicked() && kind != name {
                    let fields = pc::fields_of(&e, &line).unwrap_or_default();
                    p.extract = with_json_fields(e, &fields);
                    changed = true;
                }
            }
        });
    });
    match &mut p.extract {
        Extract::Keyvalue { pair_separator, kv_separator, trim } => {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("pairs split by").color(theme::MUTED));
                changed |= ui.add(egui::TextEdit::singleline(pair_separator).desired_width(40.0)).changed();
                ui.label(egui::RichText::new("key and value by").color(theme::MUTED));
                changed |= ui.add(egui::TextEdit::singleline(kv_separator).desired_width(40.0)).changed();
                changed |= ui.checkbox(trim, "trim spaces").changed();
            });
        }
        Extract::Csv { delimiter, quote, .. } => {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("columns split by").color(theme::MUTED));
                changed |= ui.add(egui::TextEdit::singleline(delimiter).desired_width(40.0)).changed();
                let mut q = quote.clone().unwrap_or_default();
                ui.label(egui::RichText::new("quoted with").color(theme::MUTED));
                if ui.add(egui::TextEdit::singleline(&mut q).desired_width(40.0)).changed() {
                    *quote = if q.is_empty() { None } else { Some(q) };
                    changed = true;
                }
            });
            hint(ui, "Name the columns the rule uses: the name is what ${name} says in 4 Columns.");
        }
        Extract::Regex { pattern } => {
            ui.label(egui::RichText::new("The pattern: a named group (?P<name>…) for each field").color(theme::MUTED));
            changed |= ui.add(egui::TextEdit::multiline(pattern).code_editor().desired_rows(2).desired_width(f32::INFINITY)).changed();
            if let Err(e) = regex::Regex::new(pattern) {
                ui.label(egui::RichText::new(format!("{}  {}", ic::WARNING, e)).color(SIGNIFICANT).small());
            }
        }
        Extract::Json { .. } => {
            hint(ui, "Every scalar of the object is a field, nested ones by their dot path.");
        }
    }
    theme::section(ui, "Fields of the selected line");
    match pc::fields_of(&p.extract, &line) {
        Err(e) => {
            ui.label(egui::RichText::new(e).color(CANDIDATE));
        }
        Ok(fields) => {
            egui::Grid::new("studio-fields").striped(true).num_columns(3).spacing([12.0, 4.0]).show(ui, |ui| {
                for (i, (name, value)) in fields.iter().enumerate() {
                    match &mut p.extract {
                        Extract::Csv { fields_by_index, .. } => {
                            ui.label(egui::RichText::new(name).monospace().color(theme::DIM));
                            let mut n = fields_by_index.get(&(i as u32)).cloned().unwrap_or_default();
                            if ui.add(egui::TextEdit::singleline(&mut n).desired_width(120.0).hint_text("unnamed")).changed() {
                                if n.trim().is_empty() {
                                    fields_by_index.remove(&(i as u32));
                                } else {
                                    fields_by_index.insert(i as u32, n.trim().to_string());
                                }
                                changed = true;
                            }
                        }
                        Extract::Json { fields: named } => {
                            let mut on = named.values().any(|p| p == name);
                            if ui.checkbox(&mut on, "").changed() {
                                if on {
                                    named.insert(var_of(name), name.clone());
                                } else {
                                    named.retain(|_, p| p != name);
                                }
                                changed = true;
                            }
                            ui.label(egui::RichText::new(format!("${{{}}}", var_of(name))).monospace().color(theme::CYAN));
                        }
                        _ => {
                            ui.label(egui::RichText::new(format!("${{{}}}", name)).monospace().color(theme::CYAN));
                            ui.label("");
                        }
                    }
                    ui.add(egui::Label::new(egui::RichText::new(value).monospace().size(11.5)).truncate());
                    ui.end_row();
                }
            });
        }
    }
    if changed {
        st.dirty = true;
    }
}

fn tab_columns(ui: &mut egui::Ui, st: &mut Studio) {
    let line = st.line(st.sel_line).to_string();
    let outcome = st.outcomes.get(st.sel_line).cloned();
    let Some(p) = st.rule.parsers.get_mut(st.sel_parser) else {
        hint(ui, "Make a line type first (2 Line types).");
        return;
    };
    hint(ui, &format!("The timeline's columns for «{}»: text, fields (${{name}}), or both: ${{date}} ${{time}} joins two; ${{user|srcuser}} takes the first that has a value.", p.name));
    let vars = variables(p, &line);
    let mut changed = false;
    ui.horizontal(|ui| {
        if ui.button(format!("{}  Guess them from the field names", ic::ARROWS_CLOCKWISE)).on_hover_text("Fill the columns from fields with telling names (user, src, srcip, dst, time…). What is already filled is kept; check the guess in the rows below").clicked() {
            let fields = pc::fields_of(&p.extract, &line).unwrap_or_default();
            for (k, v) in guess_columns(&fields, &p.extract) {
                p.map.entry(k).or_insert(v);
            }
            changed = true;
        }
    });
    let here = outcome.filter(|o| o.parser.map(|x| x.1) == Some(st.sel_parser)).and_then(|o| o.record);
    row_card(ui, here.as_ref());
    egui::Grid::new("studio-columns").striped(true).num_columns(3).spacing([10.0, 5.0]).show(ui, |ui| {
        for (key, label, what) in COLUMNS {
            ui.label(egui::RichText::new(label).color(TEXT)).on_hover_text(what);
            ui.horizontal(|ui| {
                let mut v = p.map.get(key).cloned().unwrap_or_default();
                let resp = ui.add(egui::TextEdit::singleline(&mut v).desired_width(240.0).font(egui::TextStyle::Monospace));
                let mut add: Option<String> = None;
                egui::ComboBox::from_id_salt(("studio-ins", key)).selected_text("+").width(28.0).show_ui(ui, |ui| {
                    for (n, val) in &vars {
                        if ui.selectable_label(false, format!("${{{}}}   {}", n, val.chars().take(40).collect::<String>())).clicked() {
                            add = Some(format!("${{{}}}", n));
                        }
                    }
                });
                if let Some(a) = add {
                    if !v.is_empty() && !v.ends_with(' ') {
                        v.push(' ');
                    }
                    v.push_str(&a);
                }
                if resp.changed() || p.map.get(key).map_or(!v.is_empty(), |old| *old != v) {
                    if v.is_empty() {
                        p.map.remove(key);
                    } else {
                        p.map.insert(key.to_string(), v);
                    }
                    changed = true;
                }
            });
            let value = here.as_ref().map(|r| match key {
                "time_created" => r.time_created.clone(),
                "computer" => r.computer.clone(),
                "event_type" => r.event_type.clone(),
                "event_id" => r.event_id.clone(),
                "logon_type" => r.logon_type.clone(),
                "target_user_name" => r.target_user_name.clone(),
                "target_domain_name" => r.target_domain_name.clone(),
                "workstation_name" => r.workstation_name.clone(),
                "ip_address" => r.ip_address.clone(),
                "subject_user_name" => r.subject_user_name.clone(),
                "subject_domain_name" => r.subject_domain_name.clone(),
                "logon_id" => r.logon_id.clone(),
                _ => r.detail.clone(),
            });
            let bad_time = key == "time_created" && value.as_ref().map_or(false, |v| parse_time(v).is_none());
            ui.add(egui::Label::new(egui::RichText::new(value.unwrap_or_else(|| "(the selected line is not of this type)".into())).monospace().size(11.0).color(if bad_time { SIGNIFICANT } else { theme::MUTED })).truncate())
                .on_hover_text(if bad_time { "masstin cannot read this time: give it the date and the time (YYYY-MM-DD HH:MM:SS, ISO 8601, epoch, syslog)" } else { "" });
            ui.end_row();
        }
    });
    if changed {
        st.dirty = true;
    }
}

fn tab_rejected(ui: &mut egui::Ui, st: &mut Studio) {
    let rejected: Vec<usize> = st.outcomes.iter().enumerate().filter(|(_, o)| o.verdict == Verdict::Rejected).map(|(i, _)| i).collect();
    let unwritten: Vec<usize> = st.outcomes.iter().enumerate().filter(|(_, o)| matches!(o.verdict, Verdict::NoOrigin | Verdict::NoDestination)).map(|(i, _)| i).collect();
    hint(ui, "What the rule does not turn into rows yet. Click one to select it, then make a line type for it (2) or fill its columns (4).");
    if !unwritten.is_empty() {
        theme::section(ui, "Read, but not written (a row needs an origin and a destination)");
        for &i in unwritten.iter().take(60) {
            let why = match st.outcomes[i].verdict {
                Verdict::NoOrigin => "no origin",
                _ => "no destination",
            };
            if ui.add(egui::Label::new(egui::RichText::new(format!("{:>5}  [{}]  {}", i + 1, why, st.lines[i])).monospace().size(11.0).color(CANDIDATE)).truncate().sense(Sense::click())).clicked() {
                st.sel_line = i;
                if let Some((_, p)) = st.outcomes[i].parser {
                    st.sel_parser = p;
                }
                st.tab = Tab::Columns;
            }
        }
    }
    theme::section(ui, &format!("Read by none ({})", rejected.len()));
    // the commonest shapes first: lines grouped by their first words
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for &i in &rejected {
        let key: String = st.lines[i].split_whitespace().filter(|w| !w.chars().any(|c| c.is_ascii_digit())).take(3).collect::<Vec<_>>().join(" ");
        groups.entry(key).or_default().push(i);
    }
    let mut groups: Vec<(String, Vec<usize>)> = groups.into_iter().collect();
    groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    let seen: BTreeSet<usize> = BTreeSet::new();
    let _ = seen;
    for (_, is) in groups.iter().take(40) {
        let i = is[0];
        if ui.add(egui::Label::new(egui::RichText::new(format!("{:>4}×  {}", is.len(), st.lines[i])).monospace().size(11.0).color(theme::MUTED)).truncate().sense(Sense::click())).on_hover_text("Select it").clicked() {
            st.sel_line = i;
            st.selection.clear();
            st.tab = Tab::Lines;
        }
    }
}

/// The bottom: the rows the rule writes, as the timeline will hold them.
fn studio_preview(ui: &mut egui::Ui, st: &Studio, h: f32) {
    let rows: Vec<(usize, &LineOutcome)> = st.outcomes.iter().enumerate().filter(|(_, o)| o.verdict == Verdict::Row).collect();
    let bad_times = rows.iter().filter(|(_, o)| o.record.as_ref().map_or(false, |r| parse_time(&r.time_created).is_none())).count();
    ui.horizontal(|ui| {
        ui.label(theme::semibold(format!("The timeline: {} rows", rows.len()), 13.0).color(TEXT));
        if bad_times > 0 {
            ui.label(egui::RichText::new(format!("{}  {} with a time masstin cannot read", ic::WARNING, bad_times)).color(SIGNIFICANT));
        }
    });
    let cols = ["line", "time_created", "dst_computer", "event_type", "event_id", "logon_type", "target_user_name", "src_computer", "src_ip", "detail"];
    egui::ScrollArea::both().id_salt("studio-preview").max_height(h - 24.0).auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("studio-preview-grid").striped(true).num_columns(cols.len()).spacing([12.0, 3.0]).show(ui, |ui| {
            for c in cols {
                ui.label(egui::RichText::new(c).monospace().size(10.5).color(theme::DIM));
            }
            ui.end_row();
            for (i, o) in rows.iter().take(300) {
                let Some(r) = &o.record else { continue };
                ui.label(egui::RichText::new(format!("{}", i + 1)).monospace().size(10.5).color(colour(o.parser.map(|x| x.1).unwrap_or(0))));
                let bad = parse_time(&r.time_created).is_none();
                ui.label(egui::RichText::new(&r.time_created).monospace().size(11.0).color(if bad { SIGNIFICANT } else { TEXT }));
                ui.label(egui::RichText::new(r.computer.as_str()).monospace().size(11.0));
                pill_label(ui, &r.event_type, event_colour(&r.event_type));
                for v in [&r.event_id, &r.logon_type, &r.target_user_name, &r.workstation_name, &r.ip_address] {
                    ui.label(egui::RichText::new(v.as_str()).monospace().size(11.0));
                }
                ui.add(egui::Label::new(egui::RichText::new(r.detail.chars().take(90).collect::<String>()).monospace().size(11.0).color(theme::MUTED)));
                ui.end_row();
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORTI: &str = r#"date=2026-11-10 time=00:41:02 devname="FGT-LEO" type="event" subtype="vpn" action="ssl-login-fail" remip=203.0.113.45 user="admin" reason="denied" msg="SSL user failed to logged in"
date=2026-11-10 time=08:02:11 devname="FGT-LEO" type="event" subtype="vpn" action="tunnel-up" remip=198.51.100.7 user="ana.ruiz" tunneltype="ssl-web""#;

    fn studio() -> Studio {
        let mut st = Studio::default();
        st.lines = FORTI.lines().map(|s| s.to_string()).collect();
        st.log_path = "FGT.log".into();
        st
    }

    #[test]
    fn a_rule_built_from_two_selections_reads_the_log() {
        let mut st = studio();
        st.start_empty();
        st.sel_line = 0;
        st.selection = "ssl-login-fail".into();
        st.new_type = 1;
        st.add_line_type();
        st.sel_line = 1;
        st.selection = "tunnel-up".into();
        st.new_type = 0;
        st.add_line_type();
        st.evaluate();
        assert_eq!(st.rule_error, None);
        assert_eq!(st.counts(), (2, 0, 0));
        let r0 = st.outcomes[0].record.clone().unwrap();
        assert_eq!(r0.event_type, "FAILED_LOGON");
        assert_eq!(r0.time_created, "2026-11-10 00:41:02");
        assert_eq!(r0.computer, "FGT-LEO");
        assert_eq!(r0.ip_address, "203.0.113.45");
        assert_eq!(r0.target_user_name, "admin");
        assert!(parse_time(&r0.time_created).is_some());
        let r1 = st.outcomes[1].record.clone().unwrap();
        assert_eq!(r1.event_type, "SUCCESSFUL_LOGON");
        assert_eq!(r1.logon_type, "ssl-web");
    }

    #[test]
    fn the_studio_writes_a_yaml_the_engine_reads_back_the_same() {
        let mut st = studio();
        st.start_empty();
        st.selection = "tunnel-up".into();
        st.sel_line = 1;
        st.add_line_type();
        let y = st.yaml();
        let back = pc::rule_from_yaml(&y).unwrap();
        assert_eq!(pc::rule_to_yaml(&back).unwrap(), pc::rule_to_yaml(&st.rule).unwrap());
        let e = pc::Engine::from_rule(back).unwrap();
        assert_eq!(e.eval(&st.lines[1], "FGT.log", 2, "").verdict, Verdict::Row);
        assert_eq!(e.eval(&st.lines[0], "FGT.log", 1, "").verdict, Verdict::Rejected);
    }

    #[test]
    fn starting_from_the_library_keeps_its_rule() {
        let mut st = studio();
        st.ranked = pc::rank_library(&st.lines);
        assert_eq!(st.ranked[0].0, "vpn/fortinet-ssl-vpn.yaml");
        st.start_from_library("vpn/fortinet-ssl-vpn.yaml");
        st.evaluate();
        assert_eq!(st.counts().0, 2);
        assert!(st.yaml().contains("fortinet-sslvpn-tunnel-up"));
    }

    #[test]
    fn one_line_type_reads_every_line_of_a_json_log() {
        let mut st = Studio::default();
        st.lines = vec![
            r#"{"ts":"2026-11-10T08:00:00Z","user":"bob","src":"10.0.0.9","host":"VPN1"}"#.to_string(),
            r#"{"ts":"2026-11-10T08:05:00Z","user":"ana","src":"10.0.0.7","host":"VPN1"}"#.to_string(),
        ];
        st.rule = RuleFile { meta: None, prefilter: None, parsers: Vec::new() };
        st.add_line_type_for_all();
        // one type, with no text to tell lines apart, and the fields named
        assert_eq!(st.rule.parsers.len(), 1);
        assert!(st.rule.parsers[0].match_rule.contains.is_empty());
        assert_eq!(st.rule.parsers[0].match_rule.regex.as_deref(), Some("."));
        assert_eq!(st.rule.parsers[0].name, "successful-logon-every-line");
        st.dirty = true;
        st.evaluate();
        assert_eq!(st.counts(), (2, 0, 0));
        // every step of the guide is a tab, in the order the rule is made
        assert_eq!(STEPS.len(), 6);
        assert!(STEPS[0].0 == Tab::Start && STEPS[5].0 == Tab::Yaml);
        st.auto("columns");
        assert!(st.tab == Tab::Columns);
    }

    #[test]
    fn json_lines_get_their_fields_named() {
        let line = r#"{"ts":"2026-11-10T08:00:00Z","user":{"name":"bob"},"src":"10.0.0.9","host":"VPN1"}"#;
        let p = new_parser("SUCCESSFUL_LOGON", "\"user\"", Extract::Json { fields: BTreeMap::new() }, line, 1);
        match &p.extract {
            Extract::Json { fields } => assert_eq!(fields.get("user_name").map(|s| s.as_str()), Some("user.name")),
            _ => panic!(),
        }
        assert_eq!(p.map.get("ip_address").map(|s| s.as_str()), Some("${src}"));
        assert_eq!(p.map.get("computer").map(|s| s.as_str()), Some("${host}"));
        assert_eq!(p.map.get("time_created").map(|s| s.as_str()), Some("${ts}"));
        let e = pc::Engine::from_rule(RuleFile { meta: None, prefilter: None, parsers: vec![p] }).unwrap();
        let o = e.eval(line, "x.log", 1, "");
        assert_eq!(o.verdict, Verdict::Row);
        assert_eq!(o.record.unwrap().ip_address, "10.0.0.9");
    }

    #[test]
    fn a_csv_column_named_in_the_studio_is_a_variable() {
        let line = "2026-11-10 08:00:00,bob,10.0.0.9,VPN1,login";
        let mut by = BTreeMap::new();
        by.insert(1u32, "user".to_string());
        by.insert(2u32, "src".to_string());
        let p = RuleParser { name: "x".into(), match_rule: MatchRule { contains: vec!["login".into()], contains_any: vec![], regex: None }, extract: Extract::Csv { delimiter: ",".into(), quote: None, fields_by_index: by }, sub_extract: None, map: BTreeMap::new() };
        let v = variables(&p, line);
        assert_eq!(v, vec![("user".to_string(), "bob".to_string()), ("src".to_string(), "10.0.0.9".to_string())]);
    }
}

// ───────────────────────── drawing ─────────────────────────

/// The big bar: how the log's lines are shared out among the line types.
fn coverage_bar(ui: &mut egui::Ui, st: &mut Studio) {
    let n = st.lines.len();
    if n == 0 {
        return;
    }
    let mut per: Vec<usize> = vec![0; st.rule.parsers.len()];
    let mut unwritten = 0usize;
    for o in &st.outcomes {
        if let Some((_, p)) = o.parser {
            if p < per.len() {
                per[p] += 1;
            }
            if o.verdict != Verdict::Row {
                unwritten += 1;
            }
        }
    }
    let read: usize = per.iter().sum();
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 30.0), Sense::click());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, CornerRadius::same(8), theme::FIELD);
    let mut x = rect.left();
    let mut hovered: Option<String> = None;
    let pointer = resp.hover_pos();
    for (i, k) in per.iter().enumerate() {
        if *k == 0 {
            continue;
        }
        let w = rect.width() * (*k as f32 / n as f32);
        let seg = Rect::from_min_size(Pos2::new(x, rect.top()), Vec2::new(w, rect.height()));
        let c = colour(i);
        let mesh_rect = seg.shrink2(Vec2::new(0.5, 3.0));
        p.rect_filled(mesh_rect, CornerRadius::same(5), draw::fade(c, 0.85));
        if w > 70.0 {
            let name = st.rule.parsers.get(i).map(|x| x.name.as_str()).unwrap_or("");
            p.text(seg.center(), Align2::CENTER_CENTER, format!("{}  {}", k, name), FontId::proportional(11.5), theme::ACCENT_INK);
        }
        if pointer.map_or(false, |q| seg.contains(q)) {
            hovered = Some(format!("{}: {} line(s), {:.0} %", st.rule.parsers.get(i).map(|x| x.name.as_str()).unwrap_or(""), k, 100.0 * *k as f32 / n as f32));
        }
        x += w;
    }
    let rest = n - read;
    if rest > 0 {
        let seg = Rect::from_min_max(Pos2::new(x, rect.top()), rect.right_bottom());
        dashed(&p, seg.shrink2(Vec2::new(1.0, 3.0)), theme::DIM);
        if seg.width() > 80.0 {
            p.text(seg.center(), Align2::CENTER_CENTER, format!("{} read by none", rest), FontId::proportional(11.5), theme::MUTED);
        }
        if pointer.map_or(false, |q| seg.contains(q)) {
            hovered = Some(format!("{} line(s) read by none: click to see them", rest));
        }
    }
    let pct = 100.0 * read as f32 / n as f32;
    p.text(rect.right_center() - Vec2::new(10.0, 0.0), Align2::RIGHT_CENTER, format!("{:.0} %", pct), FontId::proportional(15.0), if pct >= 99.5 { EDGE_OK } else { TEXT });
    if let Some(h) = hovered {
        resp.clone().on_hover_text(h);
    }
    if resp.clicked() && rest > 0 {
        st.tab = Tab::Rejected;
    }
    if unwritten > 0 {
        ui.label(egui::RichText::new(format!("{}  {} of the lines read make no row (no origin or no destination)", ic::WARNING, unwritten)).color(CANDIDATE).small());
    }
}

fn dashed(p: &egui::Painter, r: Rect, c: Color32) {
    let pts = vec![r.left_top(), r.right_top(), r.right_bottom(), r.left_bottom(), r.left_top()];
    p.add(egui::Shape::dashed_line(&pts, Stroke::new(1.0, c), 5.0, 4.0));
}

/// The checks, worst first, each a link to where it is fixed.
fn checks_panel(ui: &mut egui::Ui, st: &mut Studio) {
    let checks = st.checks.clone();
    let errors = checks.iter().filter(|c| c.level == Level::Error).count();
    let warns = checks.iter().filter(|c| c.level == Level::Warn).count();
    let head = if errors > 0 {
        (format!("{}  {} to fix", ic::WARNING, errors), SIGNIFICANT)
    } else if warns > 0 {
        (format!("{}  {} to look at", ic::WARNING, warns), CANDIDATE)
    } else {
        (format!("{}  The rule is ready", ic::CHECK_CIRCLE), EDGE_OK)
    };
    egui::Frame::new().fill(Color32::from_rgba_unmultiplied(head.1.r(), head.1.g(), head.1.b(), 14)).stroke(Stroke::new(1.0, draw::fade(head.1, 0.55))).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::symmetric(10, 6)).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            ui.label(theme::semibold(head.0, 13.0).color(head.1));
            ui.add_space(8.0);
            for c in checks.iter().filter(|c| c.level != Level::Ok).take(6) {
                let col = level_colour(c.level);
                let b = egui::Button::new(egui::RichText::new(format!("{}  {}", level_icon(c.level), c.text)).size(12.0).color(col)).fill(Color32::from_rgba_unmultiplied(col.r(), col.g(), col.b(), 18)).stroke(Stroke::new(1.0, draw::fade(col, 0.5))).corner_radius(CornerRadius::same(12));
                if ui.add(b).on_hover_text("Go there").clicked() {
                    st.tab = c.tab;
                    if let Some(l) = c.line {
                        st.sel_line = l;
                    }
                    if let Some(p) = c.parser {
                        st.sel_parser = p;
                    }
                }
            }
            let more = checks.iter().filter(|c| c.level != Level::Ok).count().saturating_sub(6);
            if more > 0 {
                ui.label(egui::RichText::new(format!("and {} more", more)).color(theme::DIM).small());
            }
            for c in checks.iter().filter(|c| c.level == Level::Ok) {
                ui.label(egui::RichText::new(format!("{}  {}", ic::CHECK_CIRCLE, c.text)).size(12.0).color(EDGE_OK));
            }
        });
    });
}

/// A line with every occurrence of `needle` lit.
fn lit_line(line: &str, needle: &str, base: Color32, bg: Option<Color32>) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let font = FontId::monospace(11.5);
    let plain = egui::TextFormat { font_id: font.clone(), color: base, background: bg.unwrap_or(Color32::TRANSPARENT), ..Default::default() };
    let lit = egui::TextFormat { font_id: font, color: theme::ACCENT_INK, background: CANDIDATE, ..Default::default() };
    if needle.is_empty() {
        job.append(line, 0.0, plain);
        return job;
    }
    let mut rest = line;
    while let Some(k) = rest.find(needle) {
        job.append(&rest[..k], 0.0, plain.clone());
        job.append(needle, 0.0, lit.clone());
        rest = &rest[k + needle.len()..];
    }
    job.append(rest, 0.0, plain);
    job
}

/// Where a parser's fields are in a line: (start, end, kind), kind 0 a key,
/// 1 a value a column uses, 2 a value no column uses.
fn field_spans(p: &RuleParser, line: &str) -> Vec<(usize, usize, u8)> {
    let used: BTreeSet<String> = p.map.values().flat_map(|t| template_vars(t)).flatten().collect();
    let names: Vec<(String, String)> = variables(p, line);
    let mut spans = Vec::new();
    let mut from = 0usize;
    for (name, value) in &names {
        if value.is_empty() {
            continue;
        }
        let key_at = if matches!(p.extract, Extract::Keyvalue { .. }) { line[from..].find(name.as_str()).map(|k| k + from) } else { None };
        if let Some(k) = key_at {
            spans.push((k, k + name.len(), 0u8));
            from = k + name.len();
        }
        if let Some(v) = line[from..].find(value.as_str()).map(|v| v + from) {
            spans.push((v, v + value.len(), if used.contains(name) { 1 } else { 2 }));
            from = v + value.len();
        }
    }
    spans
}

/// The selected line drawn with its fields and the selection.
fn coloured_line(line: &str, spans: &[(usize, usize, u8)], needle: &str) -> egui::text::LayoutJob {
    let font = FontId::monospace(12.0);
    let mut kinds: Vec<u8> = vec![255; line.len()];
    for (a, b, k) in spans {
        for x in kinds.iter_mut().take((*b).min(line.len())).skip(*a) {
            *x = *k;
        }
    }
    if !needle.is_empty() {
        let mut from = 0;
        while let Some(k) = line[from..].find(needle) {
            let a = from + k;
            for x in kinds.iter_mut().take(a + needle.len()).skip(a) {
                *x = 9;
            }
            from = a + needle.len();
        }
    }
    let fmt = |k: u8| match k {
        0 => egui::TextFormat { font_id: font.clone(), color: theme::DIM, ..Default::default() },
        1 => egui::TextFormat { font_id: font.clone(), color: theme::CYAN, ..Default::default() },
        2 => egui::TextFormat { font_id: font.clone(), color: theme::VIOLET, ..Default::default() },
        9 => egui::TextFormat { font_id: font.clone(), color: theme::ACCENT_INK, background: CANDIDATE, ..Default::default() },
        _ => egui::TextFormat { font_id: font.clone(), color: TEXT, ..Default::default() },
    };
    let mut job = egui::text::LayoutJob::default();
    let mut start = 0;
    let bytes: Vec<usize> = line.char_indices().map(|(i, _)| i).chain(std::iter::once(line.len())).collect();
    for w in bytes.windows(2) {
        let (a, _) = (w[0], w[1]);
        if kinds.get(a) != kinds.get(start) {
            job.append(&line[start..a], 0.0, fmt(kinds[start]));
            start = a;
        }
    }
    if start < line.len() {
        job.append(&line[start..], 0.0, fmt(kinds[start]));
    }
    job
}

/// The row the selected line makes, drawn: origin → destination.
fn row_card(ui: &mut egui::Ui, rec: Option<&crate::parse::LogData>) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 86.0), Sense::hover());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, CornerRadius::same(10), theme::PANEL_2);
    let Some(r) = rec else {
        p.text(rect.center(), Align2::CENTER_CENTER, "Select a line of this type to see the row it makes", FontId::proportional(12.5), theme::DIM);
        return;
    };
    let c = event_colour(&r.event_type);
    let origin = if !r.workstation_name.trim().is_empty() && r.workstation_name != r.ip_address { format!("{}\n{}", r.workstation_name, r.ip_address) } else { r.ip_address.clone() };
    let left = Rect::from_center_size(Pos2::new(rect.left() + 110.0, rect.center().y), Vec2::new(180.0, 52.0));
    let right = Rect::from_center_size(Pos2::new(rect.right() - 110.0, rect.center().y), Vec2::new(180.0, 52.0));
    for (b, text, missing) in [(left, origin.clone(), origin.trim().is_empty()), (right, r.computer.clone(), r.computer.trim().is_empty())] {
        let col = if missing { SIGNIFICANT } else { theme::CYAN };
        p.rect_filled(b, CornerRadius::same(9), Color32::from_rgba_unmultiplied(col.r(), col.g(), col.b(), 22));
        p.rect_stroke(b, CornerRadius::same(9), Stroke::new(1.2, col), egui::StrokeKind::Inside);
        p.text(b.center(), Align2::CENTER_CENTER, if missing { "missing".to_string() } else { text }, FontId::monospace(12.0), if missing { SIGNIFICANT } else { TEXT });
    }
    p.text(left.center_top() - Vec2::new(0.0, 4.0), Align2::CENTER_BOTTOM, "origin", FontId::proportional(10.0), theme::DIM);
    p.text(right.center_top() - Vec2::new(0.0, 4.0), Align2::CENTER_BOTTOM, "destination", FontId::proportional(10.0), theme::DIM);
    let a = Pos2::new(left.right() + 8.0, rect.center().y);
    let b = Pos2::new(right.left() - 8.0, rect.center().y);
    p.line_segment([a, b], Stroke::new(2.5, c));
    p.add(egui::Shape::convex_polygon(vec![b, b + Vec2::new(-10.0, -6.0), b + Vec2::new(-10.0, 6.0)], c, Stroke::NONE));
    let mid = Pos2::new((a.x + b.x) / 2.0, rect.center().y);
    let account = if r.target_user_name.trim().is_empty() { r.subject_user_name.clone() } else { r.target_user_name.clone() };
    p.text(mid - Vec2::new(0.0, 8.0), Align2::CENTER_BOTTOM, if account.trim().is_empty() { "(no account)".to_string() } else { account }, FontId::proportional(13.0), TEXT);
    p.text(mid + Vec2::new(0.0, 6.0), Align2::CENTER_TOP, format!("{}  ·  {}  ·  {}", r.event_type, if r.logon_type.is_empty() { "-" } else { r.logon_type.as_str() }, r.time_created), FontId::monospace(11.0), c);
}

fn pill_label(ui: &mut egui::Ui, text: &str, c: Color32) {
    egui::Frame::new().fill(Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), 28)).stroke(Stroke::new(1.0, draw::fade(c, 0.7))).corner_radius(CornerRadius::same(9)).inner_margin(egui::Margin::symmetric(6, 0)).show(ui, |ui| {
        ui.label(egui::RichText::new(text).monospace().size(10.5).color(c));
    });
}

#[cfg(test)]
mod check_tests {
    use super::*;

    const LOG: &str = r#"date=2026-11-10 time=00:41:02 devname="FGT" action="ssl-login-fail" remip=203.0.113.45 user="admin"
date=2026-11-10 time=08:02:11 devname="FGT" action="tunnel-up" remip=198.51.100.7 user="ana"
date=2026-11-10 time=09:00:00 devname="FGT" action="update" msg="other""#;

    fn st() -> Studio {
        let mut s = Studio::default();
        s.lines = LOG.lines().map(|l| l.to_string()).collect();
        s.start_empty();
        s
    }

    fn texts(s: &Studio) -> Vec<String> {
        s.checks.iter().map(|c| format!("{:?} {}", c.level, c.text)).collect()
    }

    #[test]
    fn an_empty_rule_says_to_make_a_line_type() {
        let mut s = st();
        s.evaluate();
        assert_eq!(s.checks[0].level, Level::Error);
        assert!(s.checks[0].text.contains("No line type"));
    }

    #[test]
    fn a_good_rule_is_ready_and_says_what_is_left() {
        let mut s = st();
        s.selection = "ssl-login-fail".into();
        s.new_type = 1;
        s.add_line_type();
        s.sel_line = 1;
        s.selection = "tunnel-up".into();
        s.new_type = 0;
        s.add_line_type();
        s.evaluate();
        let t = texts(&s);
        assert!(!s.checks.iter().any(|c| c.level <= Level::Warn), "{:?}", t);
        assert!(t.iter().any(|x| x.contains("1 line(s) read by none")), "{:?}", t);
        assert!(t.iter().any(|x| x.contains("Not saved")), "{:?}", t);
        assert!(t.iter().any(|x| x.contains("2 rows")), "{:?}", t);
    }

    #[test]
    fn a_shadowed_type_and_a_missing_origin_are_told() {
        let mut s = st();
        s.selection = "devname".into();
        s.add_line_type();
        s.selection = "tunnel-up".into();
        s.sel_line = 1;
        s.add_line_type();
        s.rule.parsers[0].map.remove("ip_address");
        s.dirty = true;
        s.evaluate();
        let t = texts(&s);
        assert!(t.iter().any(|x| x.contains("never gets a line") && x.starts_with("Warn")), "{:?}", t);
        assert!(t.iter().any(|x| x.contains("no origin") && x.starts_with("Error")), "{:?}", t);
        let shadow = s.checks.iter().find(|c| c.text.contains("never gets")).unwrap();
        assert_eq!(shadow.parser, Some(1));
        assert_eq!(shadow.tab, Tab::Lines);
    }

    #[test]
    fn an_unreadable_time_and_an_empty_variable_are_told() {
        let mut s = st();
        s.selection = "tunnel-up".into();
        s.sel_line = 1;
        s.add_line_type();
        s.rule.parsers[0].map.insert("time_created".into(), "${time}".into());
        s.rule.parsers[0].map.insert("logon_type".into(), "${nothere}".into());
        s.dirty = true;
        s.evaluate();
        let t = texts(&s);
        assert!(t.iter().any(|x| x.starts_with("Error") && x.contains("cannot read")), "{:?}", t);
        assert!(t.iter().any(|x| x.starts_with("Warn") && x.contains("${nothere}")), "{:?}", t);
        let bad = s.checks.iter().find(|c| c.text.contains("cannot read")).unwrap();
        assert_eq!((bad.tab, bad.line), (Tab::Columns, Some(1)));
    }

    #[test]
    fn saving_clears_the_not_saved_note() {
        let mut s = st();
        s.selection = "tunnel-up".into();
        s.sel_line = 1;
        s.add_line_type();
        s.evaluate();
        assert!(texts(&s).iter().any(|x| x.contains("Not saved")));
        s.saved_yaml = Some(s.yaml());
        s.dirty = true;
        s.evaluate();
        assert!(!texts(&s).iter().any(|x| x.contains("Not saved")));
    }

    #[test]
    fn template_variables_and_field_spans() {
        assert_eq!(template_vars("${date} ${time} x ${a|b}"), vec![vec!["date".to_string()], vec!["time".to_string()], vec!["a".to_string(), "b".to_string()]]);
        let mut s = st();
        s.selection = "tunnel-up".into();
        s.sel_line = 1;
        s.add_line_type();
        let line = s.lines[1].clone();
        let spans = field_spans(&s.rule.parsers[0], &line);
        let used: Vec<&str> = spans.iter().filter(|x| x.2 == 1).map(|x| &line[x.0..x.1]).collect();
        assert!(used.contains(&"198.51.100.7") && used.contains(&"ana") && used.contains(&"FGT"), "{:?}", used);
        assert!(spans.iter().any(|x| x.2 == 0 && &line[x.0..x.1] == "remip"));
    }
}
