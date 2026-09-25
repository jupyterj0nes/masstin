// rare-logon-type detector. Surfaces window edges whose logon_type is
// rare in the baseline FOR THE DESTINATION'S HOST CLASS — not globally.
//
// Why class-stratified: logon_type semantics are Windows-specific. A
// Linux destination's edges (carried by wtmp/auth.log/SSH) frequently
// report logon_type=0 (the loader's "absent" sentinel for non-Windows
// sources), which is a legitimate value on Linux but globally rare in a
// mixed enterprise corpus. A naive global rarity test fires a flood of
// false positives on every Linux SSH event. Stratifying the rarity
// distribution by destination class (Linux vs Windows) keeps the
// detector sharp on the real targets: types like 9 (NewCredentials),
// 8 (NetworkCleartext), 11 (CachedInteractive), exotic types appearing
// suddenly on Windows hosts.
//
// Findings are deduplicated per (origin, destination, user, logon_type)
// tuple — one row instead of N when the attacker fires the same odd
// type repeatedly between the same hosts. The earliest event_time of
// the tuple is reported as the finding's time_window.

use crate::graph_hunt_neo4j::baseline::Baseline;
use crate::graph_hunt_neo4j::detectors::Finding;
use crate::graph_hunt_common::{auth_ok, is_series};
use futures::stream::*;
use neo4rs::*;
use std::collections::{HashMap, HashSet};

/// Per-class threshold below which a type counts as "rare". 0.5% works
/// for the canonical suspicious types (8/9/11 on Windows) without
/// lighting up routine RDP/SMB. Stratification removes the type=0 Linux
/// noise the old global threshold suffered from.
const RARITY_THRESHOLD: f64 = 0.005;

/// Cheap heuristic for Windows vs Linux destination, used to look up the
/// right baseline rarity distribution. The masstin loader uppercases all
/// hostnames so we only need to test the uppercase form.
fn host_class(name: &str) -> &'static str {
    let n = name; // already uppercase from loader
    if n.starts_with("LX-")
        || n.contains("LINUX")
        || n.contains("UBUNTU")
        || n.contains("DEBIAN")
        || n.contains("CENTOS")
        || n.contains("RHEL")
    {
        "linux"
    } else {
        "windows"
    }
}

pub async fn run(graph: &Graph, bl: &Baseline) -> Vec<Finding> {
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    let by_class = match fetch_baseline_by_class(graph, &cutoff_str).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("  [rare-logon-type] baseline distribution query failed: {}", e);
            return Vec::new();
        }
    };

    if by_class.is_empty() {
        return Vec::new();
    }

    // Pre-compute per-class total to normalize the frequencies.
    let class_total: HashMap<&str, u64> = by_class
        .iter()
        .map(|(cls, counts)| (cls.as_str(), counts.values().sum()))
        .collect();

    let q = format!(
        "MATCH (a:host)-[r]->(b:host)
         WHERE r.time >= datetime('{}') AND {}
         RETURN a.name AS origin,
                b.name AS destination,
                type(r) AS user,
                toString(r.logon_type) AS logon_type,
                toString(r.time) AS event_time",
        cutoff_str, auth_ok("r")
    );

    let mut findings: Vec<Finding> = Vec::new();
    let mut seen: HashSet<(String, String, String, String)> = HashSet::new();
    let mut stream = match graph.execute(query(&q)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [rare-logon-type] window query failed: {}", e);
            return findings;
        }
    };

    loop {
        match stream.next().await {
            Ok(Some(row)) => {
                let origin: String = row.get("origin").unwrap_or_default();
                let destination: String = row.get("destination").unwrap_or_default();
                let user: String = row.get("user").unwrap_or_default();
                let logon_type: String = row.get("logon_type").unwrap_or_default();
                let event_time: String = row.get("event_time").unwrap_or_default();

                if origin.is_empty() || destination.is_empty() {
                    continue;
                }

                // Deduplicate identical occurrences — one finding per
                // (origin, destination, user, logon_type) tuple is enough
                // to draw the analyst's eye.
                let key = (
                    origin.clone(),
                    destination.clone(),
                    user.clone(),
                    logon_type.clone(),
                );
                if !seen.insert(key) {
                    continue;
                }

                // Stratify: look up the rarity ONLY in the destination's
                // host class. type=0 on Linux is the norm; on Windows
                // it would still surface as "never seen".
                let cls = host_class(&destination);
                let class_freqs = match by_class.get(cls) {
                    Some(m) => m,
                    None => continue,
                };
                let total = match class_total.get(cls).copied() {
                    Some(t) if t > 0 => t,
                    _ => continue,
                };

                let baseline_count = class_freqs.get(&logon_type).copied().unwrap_or(0);
                let freq = baseline_count as f64 / total as f64;
                if freq >= RARITY_THRESHOLD {
                    continue;
                }

                let score = 1.0 - (freq / RARITY_THRESHOLD).min(1.0);
                let pct = freq * 100.0;

                let rarity_descr = if baseline_count == 0 {
                    format!("never appeared in baseline among {} destinations", cls)
                } else {
                    format!(
                        "{} of {} baseline events to {} destinations ({:.3}% — below {:.1}% threshold)",
                        baseline_count, total, cls, pct, RARITY_THRESHOLD * 100.0
                    )
                };

                let summary = format!(
                    "{origin} -> {destination} ({cls}) as user='{user}' logon_type='{lt}'. \
                     Type {lt} is rare for {cls} hosts: {descr}",
                    origin = origin,
                    destination = destination,
                    user = user,
                    lt = logon_type,
                    cls = cls,
                    descr = rarity_descr,
                );

                let snippet = format!(
                    "MATCH (a:host)-[r]->(b:host) \
                     WHERE r.time >= datetime('{}') AND toString(r.logon_type) = '{}' \
                     RETURN a, r, b",
                    cutoff_str, logon_type
                );

                findings.push(Finding {
                    detector: "rare-logon-type",
                    origin: origin.clone(),
                    account: user.clone(),
                    events: 1,
                    host: destination,
                    time_window: event_time,
                    score,
                    summary,
                    cypher_snippet: snippet,
                });
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("  [rare-logon-type] row read failed: {}", e);
                break;
            }
        }
    }

    findings
}

/// Fetch per-host-class baseline frequency: class -> logon_type -> count.
/// We classify in Rust (Cypher can't easily host the rule set) so the
/// query stays simple and portable.
async fn fetch_baseline_by_class(
    graph: &Graph,
    cutoff_str: &str,
) -> neo4rs::Result<HashMap<String, HashMap<String, u64>>> {
    let q = format!(
        "MATCH ()-[r]->(b:host)
         WHERE r.time < datetime('{}') AND {} AND {}
         RETURN toString(r.logon_type) AS lt, b.name AS dst, count(r) AS c",
        cutoff_str, auth_ok("r"), is_series("r")
    );
    let mut stream = graph.execute(query(&q)).await?;
    let mut by_class: HashMap<String, HashMap<String, u64>> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let lt: String = row.get("lt").unwrap_or_default();
        let dst: String = row.get("dst").unwrap_or_default();
        let c: i64 = row.get("c").unwrap_or(0);
        let cls = host_class(&dst).to_string();
        *by_class
            .entry(cls)
            .or_insert_with(HashMap::new)
            .entry(lt)
            .or_insert(0) += c.max(0) as u64;
    }
    Ok(by_class)
}
