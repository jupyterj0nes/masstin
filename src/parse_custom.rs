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

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};

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
    pub map: HashMap<String, String>,
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
        fields_by_index: HashMap<u32, String>,
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
    map: HashMap<String, String>,
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
    serde_yaml::from_str::<RuleFile>(&text)
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
        let reader = BufReader::new(file);

        let mut file_lines = 0usize;
        let mut file_matched = 0usize;
        let mut file_rejected = 0usize;

        for (lineno, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(_) => continue,
            };
            if line.trim().is_empty() {
                continue;
            }
            file_lines += 1;

            let mut matched = false;
            'rules: for rf in &rules {
                if !prefilter_accepts(rf.prefilter.as_ref(), &line) {
                    continue;
                }
                for p in &rf.parsers {
                    if !parser_matches(p, &line) {
                        continue;
                    }
                    // Extract
                    let mut ctx: HashMap<String, String> = HashMap::new();
                    ctx.insert("__source_file".to_string(), fname.clone());
                    ctx.insert("__line_number".to_string(), (lineno + 1).to_string());

                    if !apply_extract(&p.extract, p.extract_regex.as_ref(), &line, &mut ctx) {
                        continue;
                    }

                    // Sub-extract
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

                    // Map into LogData
                    let record = build_log_data(&p.map, &ctx, &fname);
                    all_records.push(record);
                    *per_parser_hits.entry(p.name.clone()).or_insert(0) += 1;
                    file_matched += 1;
                    matched = true;
                    break 'rules;
                }
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
                let preview = if text.len() > 120 { &text[..120] } else { text.as_str() };
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
            crate::banner::print_info(&format!("  Wrote {} records to {}", all_records.len(), out_path));
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
    } else {
        crate::banner::print_warning("  No -o specified, skipping CSV write");
    }
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
        Extract::Keyvalue { pair_separator, kv_separator, trim } => {
            for pair in input.split(pair_separator.as_str()) {
                let pair = if *trim { pair.trim() } else { pair };
                if let Some(pos) = pair.find(kv_separator.as_str()) {
                    let key = pair[..pos].trim().to_string();
                    let val = pair[pos + kv_separator.len()..].trim();
                    let val = val.trim_matches('"').trim_matches('\'').to_string();
                    if !key.is_empty() {
                        ctx.insert(key, val);
                    }
                }
            }
            true
        }
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
    map: &HashMap<String, String>,
    ctx: &HashMap<String, String>,
    fallback_filename: &str,
) -> LogData {
    let get = |key: &str| -> String {
        map.get(key)
            .map(|tpl| substitute(tpl, ctx))
            .unwrap_or_default()
    };

    let mut ld = LogData {
        time_created: get("time_created"),
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

/// Substitute ${var} references in a template using ctx.
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
                if let Some(val) = ctx.get(name) {
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
    // Canonical masstin CSV schema — must match MASSTIN_HEADER in merge.rs
    // so that parse-custom output is compatible with merge / load-neo4j /
    // load-memgraph. Field order:
    //   time_created, dst_computer, event_type, event_id, logon_type,
    //   target_user_name, target_domain_name, src_computer, src_ip,
    //   subject_user_name, subject_domain_name, logon_id, detail, log_filename
    //
    // LogData struct uses historical field names internally; the mapping is:
    //   LogData.computer          → dst_computer
    //   LogData.workstation_name  → src_computer
    //   LogData.ip_address        → src_ip
    //   LogData.filename          → log_filename
    let mut wtr = csv::Writer::from_path(path).map_err(|e| e.to_string())?;
    wtr.write_record(&[
        "time_created", "dst_computer", "event_type", "event_id", "logon_type",
        "target_user_name", "target_domain_name", "src_computer", "src_ip",
        "subject_user_name", "subject_domain_name", "logon_id", "detail", "log_filename",
    ]).map_err(|e| e.to_string())?;
    for r in records {
        wtr.write_record(&[
            &r.time_created, &r.computer, &r.event_type, &r.event_id, &r.logon_type,
            &r.target_user_name, &r.target_domain_name, &r.workstation_name, &r.ip_address,
            &r.subject_user_name, &r.subject_domain_name, &r.logon_id, &r.detail, &r.filename,
        ]).map_err(|e| e.to_string())?;
    }
    wtr.flush().map_err(|e| e.to_string())?;
    Ok(())
}
