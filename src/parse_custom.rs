// =============================================================================
//   Custom log parser — flexible YAML-driven parsing for VPN/Firewall/Proxy logs
//
//   Usage:
//     masstin -a parse-custom --rules path/to/rule.yaml -f logfile.log -o out.csv
//     masstin -a parse-custom --rules path/to/rules_dir/ -f log1.log -f log2.log -o out.csv
//     masstin -a parse-custom --rules rule.yaml -f log.log --dry-run
//
//   See docs/custom-parsers.md for the full schema specification and
//   rules/ for the community rule library (Palo Alto, Cisco, Fortinet, ...).
// =============================================================================

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::parse::LogData;

// ─── YAML schema ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RuleFile {
    pub meta: Option<Meta>,
    #[serde(default)]
    pub prefilter: Option<Prefilter>,
    pub parsers: Vec<Parser>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Meta {
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub product: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub versions_tested: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub reference_url: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Prefilter {
    #[serde(default)]
    pub contains_any: Vec<String>,
    #[serde(default)]
    pub contains_all: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Parser {
    pub name: String,
    #[serde(rename = "match")]
    pub match_rule: MatchRule,
    pub extract: Extract,
    #[serde(default)]
    pub sub_extract: Option<SubExtract>,
    pub map: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct MatchRule {
    #[serde(default)]
    pub contains: Vec<String>,
    #[serde(default)]
    pub contains_any: Vec<String>,
    #[serde(default)]
    pub regex: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Extract {
    Csv {
        #[serde(default = "default_comma")]
        delimiter: String,
        #[serde(default)]
        quote: Option<String>,
        fields_by_index: BTreeMap<u32, String>,
    },
    Regex {
        pattern: String,
    },
    Keyvalue {
        #[serde(default = "default_space")]
        pair_separator: String,
        #[serde(default = "default_equals")]
        kv_separator: String,
        #[serde(default)]
        trim: bool,
    },
    /// Parse the line as one JSON object (NDJSON: one object per line) and pull
    /// scalar fields by dot-path into named context variables. Handles both flat
    /// schemas (Mordor / nxlog / HELK: `EventID`, `TargetUserName`, `SourceIp`...)
    /// and nested ones (Winlogbeat: `winlog.event_id`, `winlog.event_data.X`).
    /// Example:
    ///   fields:
    ///     user: "TargetUserName"       # flat
    ///     eid:  "winlog.event_id"      # nested
    Json {
        #[serde(default)]
        fields: BTreeMap<String, String>,
    },
}

fn default_comma() -> String { ",".to_string() }
fn default_space() -> String { " ".to_string() }
fn default_equals() -> String { "=".to_string() }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SubExtract {
    pub field: String,
    /// Optional: strip everything up to and including the first occurrence of this string
    /// before applying the extractor. Useful when the field starts with narrative prose
    /// (e.g. "GlobalProtect gateway user auth OK. Login from: ...") and you only want
    /// the key-value portion.
    #[serde(default)]
    pub strip_before: Option<String>,
    #[serde(flatten)]
    pub extract: Extract,
}

// ─── Compiled form (regex pre-compiled, etc.) ───────────────────────────────

struct CompiledRuleFile {
    source_path: PathBuf,
    prefilter: Option<CompiledPrefilter>,
    parsers: Vec<CompiledParser>,
}

struct CompiledPrefilter {
    contains_any: Vec<String>,
    contains_all: Vec<String>,
}

struct CompiledParser {
    name: String,
    contains: Vec<String>,
    contains_any: Vec<String>,
    match_regex: Option<Regex>,
    extract: Extract,
    sub_extract: Option<SubExtract>,
    extract_regex: Option<Regex>,
    sub_extract_regex: Option<Regex>,
    map: BTreeMap<String, String>,
}

fn compile_rule_file(path: &Path, rf: RuleFile) -> Result<CompiledRuleFile, String> {
    let prefilter = rf.prefilter.map(|p| CompiledPrefilter {
        contains_any: p.contains_any,
        contains_all: p.contains_all,
    });

    let mut parsers = Vec::with_capacity(rf.parsers.len());
    for (idx, p) in rf.parsers.into_iter().enumerate() {
        let match_regex = if let Some(ref r) = p.match_rule.regex {
            Some(Regex::new(r).map_err(|e| format!(
                "parser #{} '{}': invalid match.regex '{}': {}", idx, p.name, r, e
            ))?)
        } else {
            None
        };

        let extract_regex = match &p.extract {
            Extract::Regex { pattern } => Some(
                Regex::new(pattern).map_err(|e| format!(
                    "parser #{} '{}': invalid extract.pattern '{}': {}", idx, p.name, pattern, e
                ))?
            ),
            _ => None,
        };

        let sub_extract_regex = match &p.sub_extract {
            Some(se) => match &se.extract {
                Extract::Regex { pattern } => Some(
                    Regex::new(pattern).map_err(|e| format!(
                        "parser #{} '{}': invalid sub_extract.pattern '{}': {}",
                        idx, p.name, pattern, e
                    ))?
                ),
                _ => None,
            },
            None => None,
        };

        parsers.push(CompiledParser {
            name: p.name,
            contains: p.match_rule.contains,
            contains_any: p.match_rule.contains_any,
            match_regex,
            extract: p.extract,
            sub_extract: p.sub_extract,
            extract_regex,
            sub_extract_regex,
            map: p.map,
        });
    }

    Ok(CompiledRuleFile {
        source_path: path.to_path_buf(),
        prefilter,
        parsers,
    })
}

// ─── Rule loading ───────────────────────────────────────────────────────────

fn load_rules_from_path(path: &Path) -> Result<Vec<CompiledRuleFile>, String> {
    let mut out = Vec::new();
    if path.is_file() {
        let rf = load_single_rule_file(path)?;
        out.push(compile_rule_file(path, rf)?);
    } else if path.is_dir() {
        for entry in walkdir::WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            let p = entry.path();
            if p.is_file() {
                if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                    if ext == "yaml" || ext == "yml" {
                        match load_single_rule_file(p) {
                            Ok(rf) => out.push(compile_rule_file(p, rf)?),
                            Err(e) => eprintln!("  [rules] skip {}: {}", p.display(), e),
                        }
                    }
                }
            }
        }
    } else {
        return Err(format!("rules path does not exist: {}", path.display()));
    }
    if out.is_empty() {
        return Err(format!("no rules loaded from {}", path.display()));
    }
    Ok(out)
}

fn load_single_rule_file(path: &Path) -> Result<RuleFile, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    serde_yaml_ng::from_str::<RuleFile>(&text)
        .map_err(|e| format!("YAML parse error in {}: {}", path.display(), e))
}

// ─── Main entry point ───────────────────────────────────────────────────────

pub fn parse_custom(
    files: &[String],
    rules_path: &str,
    output: Option<&String>,
    dry_run: bool,
) {
    crate::banner::print_phase("1", "3", "Loading custom parser rules...");
    let rules = match load_rules_from_path(Path::new(rules_path)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  Error: {}", e);
            return;
        }
    };
    let total_parsers: usize = rules.iter().map(|r| r.parsers.len()).sum();
    crate::banner::print_info(&format!(
        "  Loaded {} rule file(s), {} parsers total",
        rules.len(),
        total_parsers
    ));
    for r in &rules {
        crate::banner::print_info(&format!(
            "    - {} ({} parsers)",
            r.source_path.display(),
            r.parsers.len()
        ));
    }

    crate::banner::print_phase("2", "3", &format!("Processing {} log file(s)...", files.len()));

    let mut all_records: Vec<LogData> = Vec::new();
    // matched lines that name no origin or no destination: not a row
    let mut no_origin = 0usize;
    let mut no_destination = 0usize;
    let mut total_lines = 0usize;
    let mut total_matched = 0usize;
    let mut total_rejected = 0usize;
    let mut per_parser_hits: HashMap<String, usize> = HashMap::new();
    let mut rejected_samples: Vec<(String, usize, String)> = Vec::new();

    for file_path in files {
        let fname = Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(file_path)
            .to_string();

        crate::banner::print_info(&format!("  Processing: {}", file_path));

        let file = match File::open(file_path) {
            Ok(f) => f,
            Err(e) => {
                crate::banner::print_warning(&format!("    cannot open: {}", e));
                continue;
            }
        };
        // the last day this file can hold, for syslog stamps without a
        // year: its logrotate suffix, or the day after it was last written
        let year_bound = crate::parse_linux::rotation_date_from_name(&fname).or_else(|| {
            std::fs::metadata(file_path)
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| chrono::DateTime::<chrono::Utc>::from(t).date_naive() + chrono::Duration::days(1))
        });
        let year_bound = year_bound.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default();
        let mut lines = crate::textlines::EvidenceLines::new(BufReader::new(file));

        let mut file_lines = 0usize;
        let mut file_matched = 0usize;
        let mut file_rejected = 0usize;

        for (lineno, line) in (&mut lines).enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            file_lines += 1;

            let out = eval_line(&rules, &line, &fname, lineno + 1, &year_bound);
            let matched = out.parser.is_some();
            if let Some(name) = &out.parser_name {
                match out.verdict {
                    Verdict::NoDestination => no_destination += 1,
                    Verdict::NoOrigin => no_origin += 1,
                    _ => {}
                }
                if let Some(rec) = out.record.filter(|_| out.verdict == Verdict::Row) {
                    all_records.push(rec);
                }
                *per_parser_hits.entry(name.clone()).or_insert(0) += 1;
                file_matched += 1;
            }

            if !matched {
                file_rejected += 1;
                if rejected_samples.len() < 20 {
                    rejected_samples.push((fname.clone(), lineno + 1, line.clone()));
                }
            }
        }

        crate::banner::print_info(&format!(
            "    lines={} matched={} rejected={}",
            file_lines, file_matched, file_rejected
        ));
        total_lines += file_lines;
        total_matched += file_matched;
        total_rejected += file_rejected;
    }

    // Summary
    crate::banner::print_info("");
    eprintln!("  ──────────────────────────────────────────────────");
    eprintln!("  Custom parser summary:");
    eprintln!("    Lines read:    {}", total_lines);
    eprintln!("    Matched:       {} ({:.1}%)", total_matched,
        if total_lines > 0 { 100.0 * total_matched as f64 / total_lines as f64 } else { 0.0 });
    eprintln!("    Rejected:      {}", total_rejected);
    if no_origin + no_destination > 0 {
        eprintln!("    Not written:   {} without an origin, {} without a destination (matched, but a row needs both)", no_origin, no_destination);
    }
    if !per_parser_hits.is_empty() {
        eprintln!("    Hits per parser:");
        let mut hits: Vec<(&String, &usize)> = per_parser_hits.iter().collect();
        hits.sort_by(|a, b| b.1.cmp(a.1));
        for (name, count) in hits {
            eprintln!("      {:6} {}", count, name);
        }
    }

    if dry_run {
        crate::banner::print_info("");
        crate::banner::print_info("  [dry-run] not writing CSV. First 5 matched records:");
        for rec in all_records.iter().take(5) {
            eprintln!("    {} | {} | user={} | src={} | dst={} | detail={}",
                rec.time_created, rec.event_type, rec.subject_user_name,
                rec.workstation_name, rec.computer, rec.detail);
        }
        if !rejected_samples.is_empty() {
            crate::banner::print_info("");
            crate::banner::print_info("  [dry-run] First rejected lines (no rule matched):");
            for (f, ln, text) in rejected_samples.iter().take(5) {
                // by characters: a cut at byte 120 inside a letter was a panic
                let preview: String = text.chars().take(120).collect();
                eprintln!("    {}:{}  {}", f, ln, preview);
            }
        }
        return;
    }

    // Apply noise filter (--ignore-local / --exclude-*) if configured.
    let all_records: Vec<LogData> = all_records
        .into_iter()
        .filter(|r| crate::filter::should_keep_record(r))
        .collect();

    // Write output CSV
    crate::banner::print_phase("3", "3", &format!(
        "Writing {} records to output...", all_records.len()
    ));
    if let Some(out_path) = output {
        if let Err(e) = write_csv(out_path, &all_records) {
            crate::banner::print_warning(&format!("  Error writing output: {}", e));
        } else {
            crate::banner::print_info(&format!("  Wrote {} records to {}", all_records.len(), crate::banner::output_label(out_path)));
        }

        // Write rejected lines alongside the output, in debug mode only
        if crate::parse::is_debug_mode() && total_rejected > 0 {
            let rej_path = format!("{}.rejected.log", out_path);
            if let Ok(mut f) = File::create(&rej_path) {
                for (file, ln, text) in &rejected_samples {
                    let _ = writeln!(f, "{}:{}\t{}", file, ln, text);
                }
                crate::banner::print_info(&format!(
                    "  Rejected line samples saved to {} (debug mode)", rej_path
                ));
            }
        }
    } else if let Err(e) = crate::csv_out::write_timeline(&all_records, None) {
        // no -o: the timeline goes to stdout, as with every other parser
        crate::banner::print_warning(&format!("  Error writing output: {}", e));
    }
}

// ─── One line through the rules (parse-custom and the rule studio) ──────────

/// What became of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// a row of the timeline
    Row,
    /// matched, but names no origin: not written
    NoOrigin,
    /// matched, but names no destination: not written
    NoDestination,
    /// no sub-parser took it
    Rejected,
}

/// A line's result: which sub-parser took it (rule file, parser), the
/// variables it extracted, the row it made.
#[derive(Debug, Clone)]
pub struct LineOutcome {
    pub parser: Option<(usize, usize)>,
    pub parser_name: Option<String>,
    pub ctx: HashMap<String, String>,
    pub record: Option<LogData>,
    pub verdict: Verdict,
}

/// Rules ready to run: what the studio previews with, the same code the
/// command line runs.
pub struct Engine {
    rules: Vec<CompiledRuleFile>,
}

impl Engine {
    /// One rule file, as edited in the studio.
    pub fn from_rule(rf: RuleFile) -> Result<Engine, String> {
        Ok(Engine { rules: vec![compile_rule_file(Path::new("<studio>"), rf)?] })
    }

    pub fn eval(&self, line: &str, fname: &str, lineno: usize, year_bound: &str) -> LineOutcome {
        eval_line(&self.rules, line, fname, lineno, year_bound)
    }
}

fn eval_line(rules: &[CompiledRuleFile], line: &str, fname: &str, lineno: usize, year_bound: &str) -> LineOutcome {
    for (fi, rf) in rules.iter().enumerate() {
        if !prefilter_accepts(rf.prefilter.as_ref(), line) {
            continue;
        }
        for (pi, p) in rf.parsers.iter().enumerate() {
            if !parser_matches(p, line) {
                continue;
            }
            let mut ctx: HashMap<String, String> = HashMap::new();
            ctx.insert("__source_file".to_string(), fname.to_string());
            ctx.insert("__line_number".to_string(), lineno.to_string());
            ctx.insert("__year_bound".to_string(), year_bound.to_string());
            if !apply_extract(&p.extract, p.extract_regex.as_ref(), line, &mut ctx) {
                continue;
            }
            if let Some(se) = &p.sub_extract {
                if let Some(value) = ctx.get(&se.field).cloned() {
                    let sub_input: String = match &se.strip_before {
                        Some(needle) => match value.find(needle.as_str()) {
                            Some(pos) => value[pos + needle.len()..].to_string(),
                            None => value,
                        },
                        None => value,
                    };
                    apply_extract(&se.extract, p.sub_extract_regex.as_ref(), &sub_input, &mut ctx);
                }
            }
            let record = build_log_data(&p.map, &ctx, fname);
            // every masstin row has an origin and a destination; a line that
            // names neither source nor target is counted, not written
            let blank = |v: &str| {
                let t = v.trim();
                t.is_empty() || t == "-"
            };
            let verdict = if blank(&record.computer) {
                Verdict::NoDestination
            } else if blank(&record.workstation_name) && blank(&record.ip_address) {
                Verdict::NoOrigin
            } else {
                Verdict::Row
            };
            return LineOutcome { parser: Some((fi, pi)), parser_name: Some(p.name.clone()), ctx, record: Some(record), verdict };
        }
    }
    LineOutcome { parser: None, parser_name: None, ctx: HashMap::new(), record: None, verdict: Verdict::Rejected }
}

/// The fields an extractor takes out of a line, in the line's order, for the
/// studio's field table (a CSV's columns named by position, `#0`, `#1`…).
pub fn fields_of(ex: &Extract, line: &str) -> Result<Vec<(String, String)>, String> {
    match ex {
        Extract::Csv { delimiter, quote, .. } => Ok(split_csv(line, delimiter, quote.as_deref())
            .into_iter()
            .enumerate()
            .map(|(i, v)| (format!("#{}", i), v.trim().to_string()))
            .collect()),
        Extract::Keyvalue { pair_separator, kv_separator, trim } => {
            let mut out = Vec::new();
            for pair in kv_pairs(line, pair_separator, kv_separator) {
                let pair = if *trim { pair.trim() } else { pair.as_str() };
                if let Some(pos) = pair.find(kv_separator.as_str()) {
                    let key = pair[..pos].trim().to_string();
                    let val = pair[pos + kv_separator.len()..].trim().trim_matches('"').trim_matches('\'').trim().to_string();
                    if !key.is_empty() {
                        out.push((key, val));
                    }
                }
            }
            Ok(out)
        }
        Extract::Json { .. } => {
            let v: JsonValue = serde_json::from_str(line.trim()).map_err(|e| format!("not a JSON object: {}", e))?;
            let mut out = Vec::new();
            flatten_json("", &v, &mut out);
            Ok(out)
        }
        Extract::Regex { pattern } => {
            let re = Regex::new(pattern).map_err(|e| e.to_string())?;
            let caps = re.captures(line).ok_or("the pattern does not match this line")?;
            Ok(re.capture_names().flatten().filter_map(|n| caps.name(n).map(|m| (n.to_string(), m.as_str().to_string()))).collect())
        }
    }
}

/// The key=value pairs of a line, a quoted value kept whole even when it
/// holds the pair separator (`msg="SSL tunnel up"`).
fn kv_pairs(line: &str, pair_sep: &str, kv_sep: &str) -> Vec<String> {
    if pair_sep != " " {
        return line.split(pair_sep).map(|s| s.to_string()).collect();
    }
    let _ = kv_sep;
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for c in line.chars() {
        if c == '"' {
            in_quote = !in_quote;
        }
        if c == ' ' && !in_quote {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn flatten_json(prefix: &str, v: &JsonValue, out: &mut Vec<(String, String)>) {
    match v {
        JsonValue::Object(m) => {
            for (k, x) in m {
                let path = if prefix.is_empty() { k.clone() } else { format!("{}.{}", prefix, k) };
                flatten_json(&path, x, out);
            }
        }
        other => {
            if let Some(s) = json_scalar(other) {
                out.push((prefix.to_string(), s));
            }
        }
    }
}

/// The likely extractor for these lines: JSON objects, key=value pairs, a
/// delimited row (`,` `;` `|` or tab), or free text (a regex to write).
pub fn guess_extract(lines: &[String]) -> Extract {
    let sample: Vec<&str> = lines.iter().map(|l| l.trim()).filter(|l| !l.is_empty()).take(200).collect();
    let n = sample.len().max(1) as f64;
    let share = |f: &dyn Fn(&str) -> bool| sample.iter().filter(|l| f(l)).count() as f64 / n;
    if share(&|l| l.starts_with('{') && serde_json::from_str::<JsonValue>(l).is_ok()) > 0.8 {
        return Extract::Json { fields: BTreeMap::new() };
    }
    let kv_re = Regex::new(r#"(^|\s)[A-Za-z_][\w.-]*="#).unwrap();
    if share(&|l| kv_re.find_iter(l).count() >= 3) > 0.8 {
        return Extract::Keyvalue { pair_separator: " ".into(), kv_separator: "=".into(), trim: true };
    }
    let kv_colon = Regex::new(r#"(^|[\s;])[A-Za-z_][\w.-]*:""#).unwrap();
    if share(&|l| kv_colon.find_iter(l).count() >= 3) > 0.8 {
        return Extract::Keyvalue { pair_separator: ";".into(), kv_separator: ":".into(), trim: true };
    }
    for d in [",", "\t", "|", ";"] {
        let counts: Vec<usize> = sample.iter().map(|l| l.matches(d).count()).collect();
        if let (Some(min), Some(max)) = (counts.iter().min(), counts.iter().max()) {
            if *min >= 3 && max - min <= 1 {
                return Extract::Csv { delimiter: d.to_string(), quote: Some("\"".into()), fields_by_index: BTreeMap::new() };
            }
        }
    }
    Extract::Regex { pattern: String::new() }
}

/// The rule library shipped with masstin (rules/), inside the binary: the
/// studio's presets work wherever masstin is installed.
pub const LIBRARY: [(&str, &str); 13] = [
    ("firewall/checkpoint-admin.yaml", include_str!("../rules/firewall/checkpoint-admin.yaml")),
    ("firewall/cisco-asa.yaml", include_str!("../rules/firewall/cisco-asa.yaml")),
    ("firewall/fortinet-fortigate.yaml", include_str!("../rules/firewall/fortinet-fortigate.yaml")),
    ("firewall/palo-alto-traffic.yaml", include_str!("../rules/firewall/palo-alto-traffic.yaml")),
    ("json/cloudflare-access.yaml", include_str!("../rules/json/cloudflare-access.yaml")),
    ("json/mordor.yaml", include_str!("../rules/json/mordor.yaml")),
    ("json/zscaler-zpa.yaml", include_str!("../rules/json/zscaler-zpa.yaml")),
    ("proxy/squid.yaml", include_str!("../rules/proxy/squid.yaml")),
    ("vpn/checkpoint-remote-access.yaml", include_str!("../rules/vpn/checkpoint-remote-access.yaml")),
    ("vpn/cisco-anyconnect.yaml", include_str!("../rules/vpn/cisco-anyconnect.yaml")),
    ("vpn/fortinet-ssl-vpn.yaml", include_str!("../rules/vpn/fortinet-ssl-vpn.yaml")),
    ("vpn/openvpn.yaml", include_str!("../rules/vpn/openvpn.yaml")),
    ("vpn/palo-alto-globalprotect.yaml", include_str!("../rules/vpn/palo-alto-globalprotect.yaml")),
];

/// Read a rule from its YAML text.
pub fn rule_from_yaml(text: &str) -> Result<RuleFile, String> {
    serde_yaml_ng::from_str::<RuleFile>(text).map_err(|e| e.to_string())
}

/// A rule as YAML text, as the command line reads it.
pub fn rule_to_yaml(rf: &RuleFile) -> Result<String, String> {
    serde_yaml_ng::to_string(rf).map_err(|e| e.to_string())
}

/// The library's rules ranked by how many of these lines they read (rows
/// written), best first; the ones that read none are left out.
pub fn rank_library(lines: &[String]) -> Vec<(&'static str, usize)> {
    let mut out = Vec::new();
    for (name, text) in LIBRARY {
        let Ok(rf) = rule_from_yaml(text) else { continue };
        let Ok(engine) = Engine::from_rule(rf) else { continue };
        let rows = lines.iter().enumerate().filter(|(i, l)| engine.eval(l, "sample", i + 1, "").verdict == Verdict::Row).count();
        if rows > 0 {
            out.push((name, rows));
        }
    }
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    out
}

// ─── Matching ───────────────────────────────────────────────────────────────

fn prefilter_accepts(pf: Option<&CompiledPrefilter>, line: &str) -> bool {
    match pf {
        None => true,
        Some(p) => {
            if !p.contains_any.is_empty() && !p.contains_any.iter().any(|s| line.contains(s)) {
                return false;
            }
            if !p.contains_all.is_empty() && !p.contains_all.iter().all(|s| line.contains(s)) {
                return false;
            }
            true
        }
    }
}

fn parser_matches(p: &CompiledParser, line: &str) -> bool {
    if !p.contains.is_empty() && !p.contains.iter().all(|s| line.contains(s)) {
        return false;
    }
    if !p.contains_any.is_empty() && !p.contains_any.iter().any(|s| line.contains(s)) {
        return false;
    }
    if let Some(re) = &p.match_regex {
        if !re.is_match(line) {
            return false;
        }
    }
    // If no match criteria at all, don't match anything
    p.match_regex.is_some() || !p.contains.is_empty() || !p.contains_any.is_empty()
}

// ─── Extraction ─────────────────────────────────────────────────────────────

fn apply_extract(
    ex: &Extract,
    regex: Option<&Regex>,
    input: &str,
    ctx: &mut HashMap<String, String>,
) -> bool {
    match ex {
        Extract::Csv { delimiter, quote, fields_by_index } => {
            let fields = split_csv(input, delimiter, quote.as_deref());
            for (idx, name) in fields_by_index {
                if let Some(val) = fields.get(*idx as usize) {
                    ctx.insert(name.clone(), val.trim().to_string());
                }
            }
            true
        }
        Extract::Regex { .. } => {
            if let Some(re) = regex {
                if let Some(caps) = re.captures(input) {
                    for name in re.capture_names().flatten() {
                        if let Some(m) = caps.name(name) {
                            ctx.insert(name.to_string(), m.as_str().to_string());
                        }
                    }
                    return true;
                }
            }
            false
        }
        Extract::Json { fields } => {
            let parsed: JsonValue = match serde_json::from_str(input.trim()) {
                Ok(v) => v,
                Err(_) => return false, // not a JSON line: let another parser try
            };
            for (var, path) in fields {
                if let Some(s) = json_path_get(&parsed, path).and_then(json_scalar) {
                    ctx.insert(var.clone(), s);
                }
            }
            true
        }
        Extract::Keyvalue { pair_separator, kv_separator, trim } => {
            // a quoted value keeps its spaces (msg="SSL tunnel up")
            for pair in kv_pairs(input, pair_separator, kv_separator) {
                let pair = if *trim { pair.trim() } else { pair.as_str() };
                if let Some(pos) = pair.find(kv_separator.as_str()) {
                    let key = pair[..pos].trim().to_string();
                    let val = pair[pos + kv_separator.len()..].trim();
                    // quotes first, then the padding some vendors keep inside
                    // them (Check Point writes user:" Jane Doe ")
                    let val = val.trim_matches('"').trim_matches('\'').trim().to_string();
                    if !key.is_empty() {
                        ctx.insert(key, val);
                    }
                }
            }
            true
        }
    }
}

/// Walk a dot-path (`a.b.c`) into a JSON value, returning the node at the end.
fn json_path_get<'a>(v: &'a JsonValue, path: &str) -> Option<&'a JsonValue> {
    let mut cur = v;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// Render a scalar JSON value as a string (objects / arrays / null → None).
fn json_scalar(v: &JsonValue) -> Option<String> {
    match v {
        JsonValue::String(s) => Some(s.clone()),
        JsonValue::Number(n) => Some(n.to_string()),
        JsonValue::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Minimal CSV splitter that honours a single-character quote.
fn split_csv(input: &str, delimiter: &str, quote: Option<&str>) -> Vec<String> {
    let delim_char = delimiter.chars().next().unwrap_or(',');
    let quote_char = quote.and_then(|q| q.chars().next());

    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if let Some(qc) = quote_char {
            if c == qc {
                if in_quote && i + 1 < chars.len() && chars[i + 1] == qc {
                    // Escaped quote inside quoted field
                    cur.push(qc);
                    i += 2;
                    continue;
                }
                in_quote = !in_quote;
                i += 1;
                continue;
            }
        }
        if c == delim_char && !in_quote {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
        i += 1;
    }
    out.push(cur);
    out
}

// ─── Mapping → LogData ──────────────────────────────────────────────────────

fn build_log_data(
    map: &BTreeMap<String, String>,
    ctx: &HashMap<String, String>,
    fallback_filename: &str,
) -> LogData {
    let get = |key: &str| -> String {
        map.get(key)
            .map(|tpl| substitute(tpl, ctx))
            .unwrap_or_default()
    };

    let mut ld = LogData {
        // vendor timestamps the fallback reads (asctime, epoch) are written
        // as ISO UTC so the CSV stays homogeneous; masstin's own shapes
        // are kept as they come
        time_created: crate::timefmt::normalise_for_csv_bounded(
            &get("time_created"),
            ctx.get("__year_bound").and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok()),
        ),
        computer: get("computer"),
        event_type: get("event_type"),
        event_id: get("event_id"),
        subject_user_name: get("subject_user_name"),
        subject_domain_name: get("subject_domain_name"),
        target_user_name: get("target_user_name"),
        target_domain_name: get("target_domain_name"),
        logon_type: get("logon_type"),
        workstation_name: get("workstation_name"),
        ip_address: get("ip_address"),
        logon_id: get("logon_id"),
        filename: get("filename"),
        detail: get("detail"),
    };

    if ld.filename.is_empty() {
        ld.filename = fallback_filename.to_string();
    }
    ld
}

/// Substitute ${var} references in a template using ctx. `${a|b|c}` takes
/// the first of the alternatives that has a non-empty value, so a rule can
/// cover a vendor that names the same thing two ways (Check Point writes
/// the account as `user` on some records and `src_user_name` on others).
/// Unknown variables are left as empty string.
fn substitute(template: &str, ctx: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'{' {
            if let Some(end_rel) = template[i + 2..].find('}') {
                let end = i + 2 + end_rel;
                let name = &template[i + 2..end];
                if let Some(val) = name.split('|').map(|n| n.trim()).filter_map(|n| ctx.get(n)).find(|v| !v.is_empty()) {
                    out.push_str(val);
                }
                i = end + 1;
                continue;
            }
        }
        out.push(template[i..].chars().next().unwrap());
        i += template[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
    }
    out
}

// ─── CSV output ─────────────────────────────────────────────────────────────

fn write_csv(path: &str, records: &[LogData]) -> Result<(), String> {
    // Canonical masstin CSV schema (csv_out::HEADER): the 14 event columns
    // and the empty analysis tail, so that parse-custom output is
    // compatible with merge / graph-hunt-csv / the loaders. Field order:
    //   time_created, dst_computer, event_type, event_id, logon_type,
    //   target_user_name, target_domain_name, src_computer, src_ip,
    //   subject_user_name, subject_domain_name, logon_id, detail, log_filename,
    //   hunt, hunt_score, hunt_why, verdict, notes
    //
    // LogData struct uses historical field names internally; the mapping is:
    //   LogData.computer          → dst_computer
    //   LogData.workstation_name  → src_computer
    //   LogData.ip_address        → src_ip
    //   LogData.filename          → log_filename
    let mut wtr = csv::Writer::from_path(path).map_err(|e| e.to_string())?;
    wtr.write_record(crate::csv_out::HEADER.split(',')).map_err(|e| e.to_string())?;
    for r in records {
        wtr.write_record(&[
            &r.time_created, &r.computer, &r.event_type, &r.event_id, &r.logon_type,
            &r.target_user_name, &r.target_domain_name, &r.workstation_name, &r.ip_address,
            &r.subject_user_name, &r.subject_domain_name, &r.logon_id, &r.detail, &r.filename,
            "", "", "", "", "",
        ]).map_err(|e| e.to_string())?;
    }
    wtr.flush().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(|l| l.to_string()).collect()
    }

    const FORTI: &str = r#"date=2026-11-10 time=00:41:02 devname="FGT-LEO" type="event" subtype="vpn" action="ssl-login-fail" remip=203.0.113.45 user="admin" reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"
date=2026-11-10 time=08:02:11 devname="FGT-LEO" type="event" subtype="vpn" action="tunnel-up" remip=198.51.100.7 user="ana.ruiz" tunneltype="ssl-web" group="vpn-users"
date=2026-11-10 time=09:00:00 devname="FGT-LEO" type="event" subtype="system" action="update" msg="nothing to do with vpn""#;

    #[test]
    fn a_quoted_value_keeps_its_spaces() {
        let ex = Extract::Keyvalue { pair_separator: " ".into(), kv_separator: "=".into(), trim: true };
        let mut ctx = HashMap::new();
        apply_extract(&ex, None, r#"user="ana" msg="SSL tunnel up" remip=1.2.3.4"#, &mut ctx);
        assert_eq!(ctx.get("msg").map(|s| s.as_str()), Some("SSL tunnel up"));
        assert_eq!(ctx.get("remip").map(|s| s.as_str()), Some("1.2.3.4"));
        assert_eq!(ctx.get("user").map(|s| s.as_str()), Some("ana"));
    }

    #[test]
    fn every_library_rule_reads_as_yaml_and_compiles() {
        for (name, text) in LIBRARY {
            let rf = rule_from_yaml(text).unwrap_or_else(|e| panic!("{}: {}", name, e));
            Engine::from_rule(rf).unwrap_or_else(|e| panic!("{}: {}", name, e));
        }
    }

    #[test]
    fn the_library_ranks_the_fortigate_rule_first_on_a_fortigate_log() {
        let ranked = rank_library(&lines(FORTI));
        assert_eq!(ranked.first().map(|r| r.0), Some("vpn/fortinet-ssl-vpn.yaml"));
        assert_eq!(ranked[0].1, 2);
    }

    #[test]
    fn a_line_through_the_engine_says_which_parser_and_what_row() {
        let rf = rule_from_yaml(LIBRARY.iter().find(|l| l.0 == "vpn/fortinet-ssl-vpn.yaml").unwrap().1).unwrap();
        let e = Engine::from_rule(rf).unwrap();
        let ls = lines(FORTI);
        let up = e.eval(&ls[1], "FGT.log", 2, "");
        assert_eq!(up.verdict, Verdict::Row);
        assert_eq!(up.parser_name.as_deref(), Some("fortinet-sslvpn-tunnel-up"));
        let rec = up.record.unwrap();
        assert_eq!(rec.event_type, "SUCCESSFUL_LOGON");
        assert_eq!(rec.ip_address, "198.51.100.7");
        assert_eq!(rec.computer, "FGT-LEO");
        assert_eq!(e.eval(&ls[2], "FGT.log", 3, "").verdict, Verdict::Rejected);
    }

    #[test]
    fn the_format_is_guessed_from_the_lines() {
        assert!(matches!(guess_extract(&lines(FORTI)), Extract::Keyvalue { .. }));
        let json = lines("{\"user\":\"a\",\"ip\":\"1.2.3.4\"}\n{\"user\":\"b\",\"ip\":\"1.2.3.5\"}");
        assert!(matches!(guess_extract(&json), Extract::Json { .. }));
        let csv = lines("2026-11-10,a,b,c,d\n2026-11-11,e,f,g,h");
        assert!(matches!(guess_extract(&csv), Extract::Csv { ref delimiter, .. } if delimiter == ","));
        assert!(matches!(guess_extract(&lines("Nov 10 sshd: hello world")), Extract::Regex { .. }));
    }

    #[test]
    fn the_fields_of_a_line_in_its_order() {
        let ls = lines(FORTI);
        let kv = guess_extract(&ls);
        let f = fields_of(&kv, &ls[0]).unwrap();
        assert_eq!(f[0], ("date".to_string(), "2026-11-10".to_string()));
        assert!(f.contains(&("msg".to_string(), "SSL user failed to logged in".to_string())));
        let j = fields_of(&Extract::Json { fields: BTreeMap::new() }, r#"{"a":{"b":1},"c":"x"}"#).unwrap();
        assert_eq!(j, vec![("a.b".to_string(), "1".to_string()), ("c".to_string(), "x".to_string())]);
        let c = fields_of(&Extract::Csv { delimiter: ",".into(), quote: Some("\"".into()), fields_by_index: BTreeMap::new() }, "a,\"b,c\",d").unwrap();
        assert_eq!(c[1], ("#1".to_string(), "b,c".to_string()));
    }

    #[test]
    fn a_rule_goes_to_yaml_and_back_the_same() {
        for (_, text) in LIBRARY {
            let rf = rule_from_yaml(text).unwrap();
            let again = rule_from_yaml(&rule_to_yaml(&rf).unwrap()).unwrap();
            assert_eq!(rule_to_yaml(&rf).unwrap(), rule_to_yaml(&again).unwrap());
        }
    }

    #[test]
    fn substitute_takes_the_first_non_empty_alternative() {
        let mut ctx = HashMap::new();
        ctx.insert("user".to_string(), String::new());
        ctx.insert("src_user_name".to_string(), "jdoe".to_string());
        ctx.insert("host".to_string(), "gw1".to_string());
        assert_eq!(substitute("${user|src_user_name}@${host}", &ctx), "jdoe@gw1");
        assert_eq!(substitute("${host|src_user_name}", &ctx), "gw1");
        assert_eq!(substitute("${nope|also_nope}-", &ctx), "-");
        assert_eq!(substitute("${host}", &ctx), "gw1");
    }
}
