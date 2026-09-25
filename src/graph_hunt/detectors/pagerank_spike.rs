// pagerank-spike detector. Surfaces hosts that are simultaneously (a)
// globally important in the graph topology and (b) receiving an
// abnormally novel share of their incoming traffic in the investigation
// window. The intuition is the classic pivot signature: a host that
// already mattered for legitimate reasons (it has high rank because many
// systems talk to it) and that suddenly starts hearing from sources or
// at a rate it never did before — that's what an attacker uses as a
// stepping stone.
//
// We run MAGE's `pagerank.get()` on the full graph once, then for every
// node we split its incoming degree into pre-cutoff (baseline) and
// post-cutoff (window) counts in the same Cypher round-trip. The composite
// score is `rank * novelty_ratio` where novelty_ratio is the fraction of
// incoming edges that fall inside the window. Pure-baseline hosts get 0,
// pure-window hosts get rank-only (which is near zero if they're not
// central), and only the combination of "central AND newly-active" lights
// up.
//
// This is intentionally NOT a two-snapshot pagerank comparison. The
// Neo4j sister detector (`src/graph_hunt_neo4j/detectors/pagerank_spike.rs`)
// projects a baseline-only GDS graph and compares centrality deltas to
// suppress structural hubs cleanly. MAGE has no equivalent: the only
// procedures with `*_subgraph` variants are community detection (Louvain
// and Leiden), not centrality. `pagerank.get`, `nxalg.pagerank`, and
// `igraphalg.pagerank` all operate on the live full graph; they accept
// algorithm parameters (damping, weights) but no subgraph argument.
//
// The available workarounds (temporarily DELETE window edges + restore,
// or zero-weighting window edges) are either dangerous on failure or
// not structurally equivalent — random walks still traverse zero-weight
// edges through the graph topology. So the Memgraph variant keeps the
// legacy single-pass weighted-novelty approach (score = rank *
// novelty_ratio over the full graph), accepting that legitimate hubs
// like SCCM monitoring servers will surface as residual FPs in the
// long tail. Top-K precision stays competitive because these hubs
// don't dominate the top of the score ranking; they accumulate in the
// 50-200 positions where DFIR triage typically doesn't reach.

use crate::graph_hunt::baseline::Baseline;
use crate::graph_hunt::detectors::Finding;
use futures::stream::*;
use neo4rs::*;

/// Minimum composite score for a host to surface as a finding. Below this
/// threshold the signal is statistically uninteresting (either the host is
/// peripheral, the novelty is marginal, or both) and emitting it would
/// drown the analyst in noise.
const MIN_SCORE: f64 = 0.0001;

pub async fn run(graph: &Graph, bl: &Baseline) -> Vec<Finding> {
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    // Single round-trip: run MAGE pagerank, join the result against each
    // node's incoming-edge counts split by the cutoff, derive the composite
    // score, sort descending. Memgraph's `CASE WHEN ... END` works inside
    // count() the same way it does in Neo4j.
    let q = format!(
        "CALL pagerank.get() YIELD node, rank
         WITH node, rank
         MATCH (a:host)-[r]->(node)
         WITH node.name AS host, rank,
              count(CASE WHEN r.time < localDateTime('{cutoff}') AND {auth} THEN 1 END) AS in_base,
              count(CASE WHEN r.time >= localDateTime('{cutoff}') AND {auth} THEN 1 END) AS in_window
         WHERE in_window > 0 AND (in_base + in_window) > 0
         WITH host, rank, in_base, in_window,
              toFloat(in_window) / toFloat(in_base + in_window) AS novelty_ratio
         WITH host, rank, in_base, in_window, novelty_ratio,
              rank * novelty_ratio AS score
         WHERE score >= {min_score}
         RETURN host, rank, in_base, in_window, novelty_ratio, score
         ORDER BY score DESC",
        cutoff = cutoff_str,
        auth = crate::graph_hunt_common::auth_ok("r"),
        min_score = MIN_SCORE,
    );

    let mut findings: Vec<Finding> = Vec::new();
    let mut stream = match graph.execute(query(&q)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [pagerank-spike] query failed: {}", e);
            return findings;
        }
    };

    loop {
        match stream.next().await {
            Ok(Some(row)) => {
                let host: String = row.get("host").unwrap_or_default();
                let rank: f64 = row.get("rank").unwrap_or(0.0);
                let in_base: i64 = row.get("in_base").unwrap_or(0);
                let in_window: i64 = row.get("in_window").unwrap_or(0);
                let novelty_ratio: f64 = row.get("novelty_ratio").unwrap_or(0.0);
                let score: f64 = row.get("score").unwrap_or(0.0);

                if host.is_empty() {
                    continue;
                }

                let summary = format!(
                    "{host}: rank={rank:.5}, novelty_ratio={nr:.2} \
                     ({iw} window edges / {tot} total). Composite score = rank * novelty.",
                    host = host,
                    rank = rank,
                    nr = novelty_ratio,
                    iw = in_window,
                    tot = in_base + in_window,
                );

                // Cypher snippet to inspect the actual window edges feeding
                // into this host — copy/paste into Memgraph Lab to see the
                // subgraph that produced the spike.
                let snippet = format!(
                    "MATCH (a:host)-[r]->(b:host {{name: '{}'}}) \
                     WHERE r.time >= localDateTime('{}') \
                     RETURN a, r, b",
                    host, cutoff_str
                );

                findings.push(Finding {
                    detector: "pagerank-spike",
            origin: String::new(),
            account: String::new(),
            events: 1,
                    host,
                    time_window: format!("from {}", cutoff_str),
                    score,
                    summary,
                    cypher_snippet: snippet,
                });
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("  [pagerank-spike] row read failed: {}", e);
                break;
            }
        }
    }

    findings
}
