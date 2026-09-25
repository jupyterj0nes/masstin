// Findings aggregator + CSV emitter, shared by both graph-hunt backends.
//
// 1. Aggregation. Per-edge detectors can emit several rows for the same
//    pattern (same detector, host and summary once timestamps and per-edge
//    counters are blanked out). They are collapsed to one row with the sum
//    of `events`, the first..last time and the highest score.
//
// 2. Corroboration. Independent detectors firing on the same ORIGIN are
//    stronger evidence than any of them alone. Each row gets
//        final = score + CORROBORATION_BONUS x (other evidence FAMILIES on its origin)
//    and a `corroboration` column listing them. Periodic-demoted rows keep
//    their demotion (the bonus is scaled by the same factor).
//
// 3. CSV. rank, score, events, detector, origin, host, time_window,
//    corroboration, summary, cypher_snippet.

use super::Finding;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::io::Write;

const CORROBORATION_BONUS: f64 = 0.25;

static TS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?").unwrap()
});
static COUNT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s*\((?:count|events)=\d+\)").unwrap());

struct Group<'a> {
    rep: &'a Finding,
    score: f64,
    events: u64,
    first: String,
    last: String,
}

fn aggregate(findings: &[Finding]) -> Vec<Group<'_>> {
    let mut order: Vec<(&'static str, String, String)> = Vec::new();
    let mut groups: HashMap<(&'static str, String, String), Group<'_>> = HashMap::new();
    for f in findings {
        let pattern = COUNT_RE.replace_all(&TS_RE.replace_all(&f.summary, "<ts>"), "").to_string();
        let key = (f.detector, f.host.clone(), pattern);
        let mut stamps: Vec<String> = TS_RE.find_iter(&f.time_window).map(|m| m.as_str().to_string()).collect();
        stamps.sort();
        let (first, last) = match (stamps.first(), stamps.last()) {
            (Some(a), Some(b)) => (a.clone(), b.clone()),
            _ => (f.time_window.clone(), f.time_window.clone()),
        };
        let ev = f.events.max(1);
        match groups.get_mut(&key) {
            Some(g) => {
                g.events += ev;
                if f.score > g.score { g.score = f.score; g.rep = f; }
                if first < g.first { g.first = first; }
                if last > g.last { g.last = last; }
            }
            None => {
                order.push(key.clone());
                groups.insert(key, Group { rep: f, score: f.score, events: ev, first, last });
            }
        }
    }
    order.into_iter().filter_map(|k| groups.remove(&k)).collect()
}

pub fn emit_csv(findings: &[Finding], output: Option<&str>) -> std::io::Result<()> {
    let header = "rank,score,events,detector,origin,host,time_window,corroboration,summary,cypher_snippet\n";

    let mut groups = aggregate(findings);
    if groups.len() < findings.len() {
        crate::banner::print_phase_detail(
            "Aggregated:",
            &format!("{} findings -> {} rows (one per detector / host / pattern)", findings.len(), groups.len()),
        );
    }

    // detectors per origin
    let mut by_origin: HashMap<String, BTreeSet<&'static str>> = HashMap::new();
    for g in &groups {
        if !g.rep.origin.is_empty() {
            by_origin.entry(g.rep.origin.clone()).or_default().insert(g.rep.detector);
        }
    }
    let mut rows: Vec<(f64, Group, String)> = groups
        .drain(..)
        .map(|g| {
            let dets: Vec<&str> = by_origin
                .get(&g.rep.origin)
                .map(|s| s.iter().copied().filter(|d| *d != g.rep.detector).collect())
                .unwrap_or_default();
            // The bonus counts independent KINDS of evidence, not detectors:
            // novel-edge, community-bridge and origin-fanout are all built on
            // the same fact ("this origin reached a destination it never had")
            // and must not reinforce each other.
            let own = family(g.rep.detector);
            let fams: BTreeSet<&str> = dets.iter().map(|d| family(d)).filter(|f| *f != own).collect();
            let demoted = g.rep.summary.contains("[periodic:");
            let bonus = CORROBORATION_BONUS * fams.len() as f64 * if demoted { super::PERIODIC_FACTOR } else { 1.0 };
            let corr = dets.join("+");
            (g.score + bonus, g, corr)
        })
        .collect();
    rows.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.1.events.cmp(&a.1.events))
    });

    let mut buf = String::new();
    buf.push_str(header);
    for (rank, (score, g, corr)) in rows.iter().enumerate() {
        let window = if g.first == g.last { g.first.clone() } else { format!("{} .. {}", g.first, g.last) };
        let summary = COUNT_RE.replace_all(&g.rep.summary, "").to_string();
        buf.push_str(&format!(
            "{},{:.4},{},{},{},{},{},{},{},{}\n",
            rank + 1,
            score,
            g.events,
            g.rep.detector,
            csv_escape(&g.rep.origin),
            csv_escape(&g.rep.host),
            csv_escape(&window),
            csv_escape(corr),
            csv_escape(&summary),
            csv_escape(&g.rep.cypher_snippet),
        ));
    }

    match output {
        Some(path) => {
            let mut file = std::fs::File::create(path)?;
            file.write_all(buf.as_bytes())?;
        }
        None => print!("{}", buf),
    }
    Ok(())
}

/// Evidence family of a detector: detectors in the same family are
/// derived from the same underlying fact.
fn family(detector: &str) -> &'static str {
    match detector {
        "novel-edge" | "community-bridge" | "origin-fanout" => "new-destination",
        "probe-then-success" => "probe",
        "cred-rotation" => "account-rotation",
        "failed-sweep" => "failures",
        "chain-motif" => "chain",
        "rare-logon-type" => "logon-type",
        "pagerank-spike" | "betweenness-spike" => "centrality",
        _ => "other",
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
