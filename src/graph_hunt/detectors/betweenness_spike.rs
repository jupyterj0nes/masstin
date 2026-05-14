// betweenness-spike detector. Same pattern as pagerank-spike but using
// betweenness centrality instead of PageRank. Where PageRank captures
// "how important is this node from a random-walk perspective",
// betweenness captures "how many shortest paths between other nodes
// pass through this one" — which is closer to the operational notion
// of a pivot. A host with high betweenness is a bridge; a sudden share
// of incoming window traffic on a high-betweenness host is, by
// construction, a likely pivot.
//
// Computation flow mirrors pagerank-spike: single MAGE call across the
// full graph, joined in one Cypher round-trip against incoming-degree
// counts split by the cutoff. The two detectors are deliberately
// redundant — they corroborate each other on real pivots and disagree
// on edge cases (PageRank weights inbound importance; betweenness
// weights bridging structure), which gives the analyst two angles on
// the same suspicion.

use crate::graph_hunt::baseline::Baseline;
use crate::graph_hunt::detectors::Finding;
use futures::stream::*;
use neo4rs::*;

/// Floor below which we drop the finding to avoid drowning the analyst
/// in nodes that are barely bridge-like. Calibrated against the same
/// 30-day corpus that calibrated pagerank-spike's threshold.
const MIN_SCORE: f64 = 0.0001;

pub async fn run(graph: &Graph, bl: &Baseline) -> Vec<Finding> {
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    let q = format!(
        "CALL betweenness_centrality.get() YIELD node, betweenness_centrality
         WITH node, betweenness_centrality AS bc
         MATCH (a:host)-[r]->(node)
         WITH node.name AS host, bc,
              count(CASE WHEN r.time < localDateTime('{cutoff}') THEN 1 END) AS in_base,
              count(CASE WHEN r.time >= localDateTime('{cutoff}') THEN 1 END) AS in_window
         WHERE in_window > 0 AND (in_base + in_window) > 0
         WITH host, bc, in_base, in_window,
              toFloat(in_window) / toFloat(in_base + in_window) AS novelty_ratio
         WITH host, bc, in_base, in_window, novelty_ratio,
              bc * novelty_ratio AS score
         WHERE score >= {min_score}
         RETURN host, bc, in_base, in_window, novelty_ratio, score
         ORDER BY score DESC",
        cutoff = cutoff_str,
        min_score = MIN_SCORE,
    );

    let mut findings: Vec<Finding> = Vec::new();
    let mut stream = match graph.execute(query(&q)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [betweenness-spike] query failed: {}", e);
            return findings;
        }
    };

    loop {
        match stream.next().await {
            Ok(Some(row)) => {
                let host: String = row.get("host").unwrap_or_default();
                let bc: f64 = row.get("bc").unwrap_or(0.0);
                let in_base: i64 = row.get("in_base").unwrap_or(0);
                let in_window: i64 = row.get("in_window").unwrap_or(0);
                let novelty_ratio: f64 = row.get("novelty_ratio").unwrap_or(0.0);
                let score: f64 = row.get("score").unwrap_or(0.0);

                if host.is_empty() {
                    continue;
                }

                let summary = format!(
                    "{host}: betweenness={bc:.5}, novelty_ratio={nr:.2} \
                     ({iw} window edges / {tot} total). Composite = betweenness * novelty.",
                    host = host, bc = bc, nr = novelty_ratio,
                    iw = in_window, tot = in_base + in_window,
                );

                let snippet = format!(
                    "MATCH (a:host)-[r]->(b:host {{name: '{}'}}) \
                     WHERE r.time >= localDateTime('{}') \
                     RETURN a, r, b",
                    host, cutoff_str
                );

                findings.push(Finding {
                    detector: "betweenness-spike",
                    host,
                    time_window: format!("from {}", cutoff_str),
                    score,
                    summary,
                    cypher_snippet: snippet,
                });
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("  [betweenness-spike] row read failed: {}", e);
                break;
            }
        }
    }

    findings
}
