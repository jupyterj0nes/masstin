// rare-logon-type detector. Surfaces window edges whose logon_type is
// globally rare in the baseline — independent of which destination
// received them. This complements novel-edge, which only checks whether
// a type was new for one specific destination. rare-logon-type catches
// types that are exotic on the WHOLE network: NetworkCleartext (8),
// NewCredentials/runas-netonly (9), CachedInteractive (11), or anything
// custom the corpus rarely sees.
//
// Implementation: compute per-type frequency in the baseline, then for
// every window edge check whether its type sits below the rarity
// threshold. Emit one finding per matching edge. The score scales with
// rarity — a type that never appeared at all lands at 1.0, a type just
// under the threshold lands near 0.

use crate::graph_hunt::baseline::Baseline;
use crate::graph_hunt::detectors::Finding;
use futures::stream::*;
use neo4rs::*;
use std::collections::HashMap;

/// Types whose share of baseline events is below this fraction count as
/// "rare". 0.005 = 0.5%. Type 10 (RDP) in a normal enterprise corpus
/// sits well above this; types 8/9/11 sit well below. Tuned to fire on
/// the latter without lighting up legitimate RDP traffic.
const RARITY_THRESHOLD: f64 = 0.005;

pub async fn run(graph: &Graph, bl: &Baseline) -> Vec<Finding> {
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    let baseline_freq = match fetch_baseline_distribution(graph, &cutoff_str).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("  [rare-logon-type] baseline distribution query failed: {}", e);
            return Vec::new();
        }
    };

    if baseline_freq.is_empty() {
        return Vec::new();
    }

    let total: u64 = baseline_freq.values().sum();
    if total == 0 {
        return Vec::new();
    }

    let q = format!(
        "MATCH (a:host)-[r]->(b:host)
         WHERE r.time >= localDateTime('{}')
         RETURN a.name AS origin,
                b.name AS destination,
                type(r) AS user,
                toString(r.logon_type) AS logon_type,
                toString(r.time) AS event_time",
        cutoff_str
    );

    let mut findings: Vec<Finding> = Vec::new();
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

                let baseline_count = baseline_freq.get(&logon_type).copied().unwrap_or(0);
                let freq = baseline_count as f64 / total as f64;
                if freq >= RARITY_THRESHOLD {
                    continue;
                }

                let score = 1.0 - (freq / RARITY_THRESHOLD).min(1.0);
                let pct = freq * 100.0;

                let rarity_descr = if baseline_count == 0 {
                    "never appeared in baseline".to_string()
                } else {
                    format!(
                        "appeared in {} of {} baseline events ({:.3}% — below {:.1}% threshold)",
                        baseline_count, total, pct, RARITY_THRESHOLD * 100.0
                    )
                };

                let summary = format!(
                    "{origin} -> {destination} as user='{user}' logon_type='{lt}'. \
                     Type {lt} is globally rare: {descr}",
                    origin = origin,
                    destination = destination,
                    user = user,
                    lt = logon_type,
                    descr = rarity_descr,
                );

                let snippet = format!(
                    "MATCH (a:host)-[r]->(b:host) \
                     WHERE r.time >= localDateTime('{}') AND toString(r.logon_type) = '{}' \
                     RETURN a, r, b",
                    cutoff_str, logon_type
                );

                findings.push(Finding {
                    detector: "rare-logon-type",
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

async fn fetch_baseline_distribution(
    graph: &Graph,
    cutoff_str: &str,
) -> neo4rs::Result<HashMap<String, u64>> {
    let q = format!(
        "MATCH ()-[r]->()
         WHERE r.time < localDateTime('{}')
         RETURN toString(r.logon_type) AS lt, count(r) AS c",
        cutoff_str
    );
    let mut stream = graph.execute(query(&q)).await?;
    let mut out: HashMap<String, u64> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let lt: String = row.get("lt").unwrap_or_default();
        let c: i64 = row.get("c").unwrap_or(0);
        out.insert(lt, c.max(0) as u64);
    }
    Ok(out)
}
