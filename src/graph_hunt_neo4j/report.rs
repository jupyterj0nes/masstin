// Findings aggregator + CSV emitter.
//
// Detectors that work per edge (novel-edge, community-bridge,
// rare-logon-type) emit one Finding per event, so a brute-force burst or
// a scanner sweep shows up as thousands of identical rows that differ
// only in the timestamp. Here they are collapsed to one row per
// (detector, host, pattern) — the pattern being the summary with
// timestamps and per-edge counters blanked out — carrying the number of
// underlying events, the first/last time seen and the highest score. The
// per-host / per-source detectors (cred-rotation, chain-motif, the
// centrality spikes) already emit one row per finding and pass through
// unchanged.
//
// Snippet column carries the Cypher query that reproduces the subgraph
// in Neo4j Browser.

use crate::graph_hunt_neo4j::detectors::Finding;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::io::Write;

static TS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?").unwrap()
});
static COUNT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s*\(count=\d+\)").unwrap());

struct Group<'a> {
    rep: &'a Finding,
    score: f64,
    events: usize,
    first: String,
    last: String,
}

/// Collapse per-event findings into per-pattern rows. Returns the groups
/// in descending score order (ties broken by event count).
fn aggregate(findings: &[Finding]) -> Vec<Group<'_>> {
    let mut order: Vec<(&'static str, String, String)> = Vec::new();
    let mut groups: HashMap<(&'static str, String, String), Group<'_>> = HashMap::new();
    for f in findings {
        let pattern = COUNT_RE.replace_all(&TS_RE.replace_all(&f.summary, "<ts>"), "").to_string();
        let key = (f.detector, f.host.clone(), pattern);
        let mut stamps: Vec<String> = TS_RE
            .find_iter(&f.time_window)
            .map(|m| m.as_str().to_string())
            .collect();
        stamps.sort();
        let (first, last) = match (stamps.first(), stamps.last()) {
            (Some(a), Some(b)) => (a.clone(), b.clone()),
            _ => (f.time_window.clone(), f.time_window.clone()),
        };
        match groups.get_mut(&key) {
            Some(g) => {
                g.events += 1;
                if f.score > g.score {
                    g.score = f.score;
                    g.rep = f;
                }
                if first < g.first { g.first = first; }
                if last > g.last { g.last = last; }
            }
            None => {
                order.push(key.clone());
                groups.insert(key, Group { rep: f, score: f.score, events: 1, first, last });
            }
        }
    }
    let mut out: Vec<Group<'_>> = order.into_iter().filter_map(|k| groups.remove(&k)).collect();
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.events.cmp(&a.events))
    });
    out
}

pub fn emit_csv(findings: &[Finding], output: Option<&str>) -> std::io::Result<()> {
    let header = "rank,score,events,detector,host,time_window,summary,cypher_snippet\n";

    let groups = aggregate(findings);
    if groups.len() < findings.len() {
        crate::banner::print_phase_detail(
            "Aggregated:",
            &format!("{} per-event findings -> {} rows (one per origin/user/destination pattern)",
                     findings.len(), groups.len()),
        );
    }

    let mut buf = String::new();
    buf.push_str(header);
    for (rank, g) in groups.iter().enumerate() {
        let window = if g.first == g.last {
            g.first.clone()
        } else {
            format!("{} .. {}", g.first, g.last)
        };
        let summary = COUNT_RE.replace_all(&g.rep.summary, "").to_string();
        buf.push_str(&format!(
            "{},{:.4},{},{},{},{},{},{}\n",
            rank + 1,
            g.score,
            g.events,
            g.rep.detector,
            csv_escape(&g.rep.host),
            csv_escape(&window),
            csv_escape(&summary),
            csv_escape(&g.rep.cypher_snippet),
        ));
    }

    match output {
        Some(path) => {
            let mut file = std::fs::File::create(path)?;
            file.write_all(buf.as_bytes())?;
        }
        None => {
            print!("{}", buf);
        }
    }
    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
