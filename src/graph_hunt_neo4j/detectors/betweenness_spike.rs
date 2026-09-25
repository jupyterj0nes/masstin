// betweenness-spike detector. Two-snapshot variant: computes betweenness
// centrality both on the full graph (baseline + window) and on a
// baseline-only projection, then emits only when a host's betweenness
// has GROWN materially from the baseline snapshot. The whole point is to
// suppress hosts that are structural bridges by design — SCCM,
// jumpboxes, Citrix farms, etc. — which always score high on
// single-snapshot betweenness but represent no actual anomaly. A real
// pivot, by contrast, is exactly a host that was peripheral in baseline
// and became central during the investigation window.
//
// Score: (bc_full - bc_baseline) * novelty_ratio. Both factors must be
// positive for the host to surface. novelty_ratio scales the centrality
// jump by how unusual the host's incoming traffic mix is in the window —
// a host whose betweenness rose but whose incoming edges are dominated
// by the same old sources is less interesting than one where the rise
// coincides with a surge of new traffic.
//
// Fallback: if the baseline projection wasn't created (e.g. zero
// pre-cutoff edges, or a transient projection error), we degrade to the
// historical single-snapshot scoring and emit a warning, so the
// pipeline never silently produces nothing.

use crate::graph_hunt_neo4j::baseline::Baseline;
use crate::graph_hunt_neo4j::detectors::Finding;
use futures::stream::*;
use neo4rs::*;
use std::collections::HashMap;

/// Floor below which we drop the finding. Calibrated against the small
/// 5M control corpus where genuine pivots produce composite scores in
/// the 0.5-10 range and legitimate noise sits well below 0.0001.
const MIN_SCORE: f64 = 0.0001;

/// Minimum absolute delta required for a host to surface. Suppresses
/// hosts whose centrality rose by a negligible amount (typical for
/// uniform-growth corpora) regardless of how high novelty_ratio looks.
/// Set conservatively low — meaningful pivots usually produce deltas
/// orders of magnitude above this.
const MIN_DELTA: f64 = 0.5;

pub async fn run(graph: &Graph, bl: &Baseline, projection: &str) -> Vec<Finding> {
    // Resilience against GDS 2.x catalog-vanishing across pool sessions.
    if let Err(e) = crate::graph_hunt_neo4j::ensure_projection(graph, projection).await {
        eprintln!("  [betweenness-spike] cannot ensure projection: {}", e);
        return Vec::new();
    }
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    let baseline_available = crate::graph_hunt_neo4j::baseline_projection_exists(graph).await;
    let baseline_projection = crate::graph_hunt_neo4j::baseline_projection_name();

    // Pull betweenness over the full graph. Same single-pass + window-join
    // shape as before: GDS streams (nodeId, score), we hydrate the host
    // name and split incoming degree into baseline vs window in one
    // Cypher round-trip so novelty_ratio is computed server-side.
    let q_full = format!(
        "CALL gds.betweenness.stream('{proj}') YIELD nodeId, score
         WITH gds.util.asNode(nodeId) AS node, score AS bc
         MATCH (a:host)-[r]->(node)
         WITH node.name AS host, bc,
              count(CASE WHEN r.time < datetime('{cutoff}') AND {auth} THEN 1 END) AS in_base,
              count(CASE WHEN r.time >= datetime('{cutoff}') AND {auth} THEN 1 END) AS in_window
         WHERE in_window > 0 AND (in_base + in_window) > 0
         RETURN host, bc, in_base, in_window
         ORDER BY bc DESC",
        proj = projection,
        cutoff = cutoff_str,
        auth = crate::graph_hunt_common::auth_ok("r"),
    );

    let full_rows = match collect_full(graph, &q_full).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  [betweenness-spike] full-graph query failed: {}", e);
            return Vec::new();
        }
    };

    // Pull betweenness over the baseline-only projection. We only need
    // (host, bc) — incoming-degree split was already computed against the
    // full graph above. If the baseline projection isn't there we fall
    // back to a "no baseline known" empty map: every host's baseline
    // centrality is treated as 0, which makes the detector behave
    // identically to single-snapshot mode.
    let baseline_bc: HashMap<String, f64> = if baseline_available {
        match fetch_baseline_betweenness(graph, baseline_projection).await {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "  [betweenness-spike] baseline betweenness query failed ({}); \
                     falling back to single-snapshot mode",
                    e
                );
                HashMap::new()
            }
        }
    } else {
        eprintln!(
            "  [betweenness-spike] baseline projection unavailable; \
             scoring on full-graph centrality alone (legacy behaviour)"
        );
        HashMap::new()
    };
    let two_snapshot = baseline_available && !baseline_bc.is_empty();

    let mut findings: Vec<Finding> = Vec::new();
    for row in full_rows {
        let host = row.host;
        let bc_full = row.bc;
        let in_base = row.in_base;
        let in_window = row.in_window;
        let total = in_base + in_window;
        if total <= 0 {
            continue;
        }
        let novelty_ratio = in_window as f64 / total as f64;

        // Centrality delta: how much more central is this host now than
        // it was in the baseline-only world?
        let bc_baseline = baseline_bc.get(&host).copied().unwrap_or(0.0);
        let delta = if two_snapshot {
            bc_full - bc_baseline
        } else {
            // Single-snapshot fallback: treat the full-graph betweenness
            // as if all of it were new. Preserves recall when the
            // baseline projection isn't usable.
            bc_full
        };
        if two_snapshot && delta < MIN_DELTA {
            continue;
        }
        let score = delta * novelty_ratio;
        if score < MIN_SCORE {
            continue;
        }

        let summary = if two_snapshot {
            format!(
                "{host}: betweenness {bb:.3} -> {bf:.3} (delta={d:.3}), \
                 novelty_ratio={nr:.2} ({iw} window / {tot} total incoming). \
                 Two-snapshot composite = delta * novelty.",
                host = host, bb = bc_baseline, bf = bc_full, d = delta,
                nr = novelty_ratio, iw = in_window, tot = total,
            )
        } else {
            format!(
                "{host}: betweenness={bc:.5}, novelty_ratio={nr:.2} \
                 ({iw} window edges / {tot} total). Single-snapshot fallback \
                 (no baseline projection) — composite = betweenness * novelty.",
                host = host, bc = bc_full, nr = novelty_ratio,
                iw = in_window, tot = total,
            )
        };

        let snippet = format!(
            "MATCH (a:host)-[r]->(b:host {{name: '{}'}}) \
             WHERE r.time >= datetime('{}') \
             RETURN a, r, b",
            host, cutoff_str
        );

        findings.push(Finding {
            detector: "betweenness-spike",
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

    findings.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    findings
}

struct FullRow {
    host: String,
    bc: f64,
    in_base: i64,
    in_window: i64,
}

async fn collect_full(graph: &Graph, q: &str) -> neo4rs::Result<Vec<FullRow>> {
    let mut stream = graph.execute(query(q)).await?;
    let mut out: Vec<FullRow> = Vec::new();
    while let Some(row) = stream.next().await? {
        let host: String = row.get("host").unwrap_or_default();
        if host.is_empty() {
            continue;
        }
        out.push(FullRow {
            host,
            bc: row.get("bc").unwrap_or(0.0),
            in_base: row.get("in_base").unwrap_or(0),
            in_window: row.get("in_window").unwrap_or(0),
        });
    }
    Ok(out)
}

async fn fetch_baseline_betweenness(
    graph: &Graph,
    projection: &str,
) -> neo4rs::Result<HashMap<String, f64>> {
    let q = format!(
        "CALL gds.betweenness.stream('{}') YIELD nodeId, score
         RETURN gds.util.asNode(nodeId).name AS host, score AS bc",
        projection
    );
    let mut stream = graph.execute(query(&q)).await?;
    let mut out: HashMap<String, f64> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let host: String = row.get("host").unwrap_or_default();
        let bc: f64 = row.get("bc").unwrap_or(0.0);
        if !host.is_empty() {
            out.insert(host, bc);
        }
    }
    Ok(out)
}
