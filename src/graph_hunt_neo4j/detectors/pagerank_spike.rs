// pagerank-spike detector. Two-snapshot variant: surfaces hosts that
// gained PageRank materially during the investigation window, rather than
// hosts that simply rank high in absolute terms. The single-snapshot
// version (PageRank on the full graph * novelty_ratio + MAD-z gate) had
// the same structural problem as betweenness-spike — legitimate hubs
// always score high so the detector either drowns the analyst at scale
// or, after over-tightening, suppresses real pivots too. The fix is
// algorithmic, not threshold-based: compare PageRank on the full graph
// against PageRank on a baseline-only projection and score on the delta.
//
// Score: (rank_full - rank_baseline) * novelty_ratio for hosts that
// (a) qualify via the existing MIN_BASELINE_EDGES gate, (b) have a
// positive PageRank delta, and (c) pass the robust MAD-z outlier test
// over the delta distribution. The MAD test stays because it's a
// distribution-aware filter that catches anomalies even when the absolute
// delta values are corpus-specific.
//
// Fallback: if the baseline projection isn't available we revert to the
// previous behaviour (rank * novelty_ratio with MAD-z over
// novelty_ratio), emit a warning, and continue. Keeps recall at parity
// with the single-snapshot version when something is wrong with the
// projection layer.

use crate::graph_hunt_neo4j::baseline::Baseline;
use crate::graph_hunt_neo4j::detectors::Finding;
use futures::stream::*;
use neo4rs::*;
use std::collections::HashMap;

/// Minimum number of baseline edges a host must have to be considered.
/// Below this the novelty_ratio is statistically meaningless and the
/// host gets dropped from scoring. Tuned empirically: 20 removes the
/// Security.evtx-asymmetry noise without losing real hub pivots
/// (DCs/fileservers have thousands of baseline edges, well above 20).
const MIN_BASELINE_EDGES: i64 = 20;

/// MAD z-score above which an observation counts as a genuine outlier.
/// 2.0 is a deliberately mild cutoff: in a homogeneous baseline (most
/// hubs gain similar amounts of rank) MAD is tiny and even small
/// deviations cross z=2; in a heterogeneous one it weeds out routine
/// drift. 3.0 (the classical Hampler value) over-suppressed the detector
/// on test corpora where hubs grow at similar rates.
const MAD_Z_THRESHOLD: f64 = 2.0;

/// Lower bound on the final composite score for a host to surface. Set
/// high enough to silence pure-noise hits; set low enough to let genuine
/// pivots through. Tuned against the small control corpus.
const MIN_SCORE: f64 = 0.0001;

#[derive(Debug, Clone)]
struct Candidate {
    host: String,
    rank: f64,
    in_base: i64,
    in_window: i64,
    novelty_ratio: f64,
}

pub async fn run(graph: &Graph, bl: &Baseline, projection: &str) -> Vec<Finding> {
    // Resilience against GDS 2.x catalog-vanishing across pool sessions.
    if let Err(e) = crate::graph_hunt_neo4j::ensure_projection(graph, projection).await {
        eprintln!("  [pagerank-spike] cannot ensure projection: {}", e);
        return Vec::new();
    }
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    let baseline_available = crate::graph_hunt_neo4j::baseline_projection_exists(graph).await;
    let baseline_projection = crate::graph_hunt_neo4j::baseline_projection_name();

    // Pass 1: PageRank on the full graph, joined with the window/baseline
    // incoming-degree split in a single Cypher round-trip. The MIN_BASELINE
    // gate stays here because at zero pre-cutoff edges novelty_ratio is
    // meaningless and the delta calculation later can't rescue that.
    let q = format!(
        "CALL gds.pageRank.stream('{proj}') YIELD nodeId, score
         WITH gds.util.asNode(nodeId) AS node, score AS rank
         MATCH (a:host)-[r]->(node)
         WITH node.name AS host, rank,
              count(CASE WHEN r.time < datetime('{cutoff}') THEN 1 END) AS in_base,
              count(CASE WHEN r.time >= datetime('{cutoff}') THEN 1 END) AS in_window
         WHERE in_window > 0
           AND in_base >= {min_base}
         WITH host, rank, in_base, in_window,
              toFloat(in_window) / toFloat(in_base + in_window) AS novelty_ratio
         RETURN host, rank, in_base, in_window, novelty_ratio
         ORDER BY rank DESC",
        proj = projection,
        cutoff = cutoff_str,
        min_base = MIN_BASELINE_EDGES,
    );

    let mut candidates: Vec<Candidate> = Vec::new();
    let mut stream = match graph.execute(query(&q)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [pagerank-spike] query failed: {}", e);
            return Vec::new();
        }
    };
    loop {
        match stream.next().await {
            Ok(Some(row)) => {
                let host: String = row.get("host").unwrap_or_default();
                if host.is_empty() {
                    continue;
                }
                candidates.push(Candidate {
                    host,
                    rank: row.get("rank").unwrap_or(0.0),
                    in_base: row.get("in_base").unwrap_or(0),
                    in_window: row.get("in_window").unwrap_or(0),
                    novelty_ratio: row.get("novelty_ratio").unwrap_or(0.0),
                });
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("  [pagerank-spike] row read failed: {}", e);
                break;
            }
        }
    }

    if candidates.is_empty() {
        return Vec::new();
    }

    // Pass 2: PageRank on the baseline-only projection. Empty fallback
    // map = single-snapshot behaviour.
    let baseline_rank: HashMap<String, f64> = if baseline_available {
        match fetch_baseline_pagerank(graph, baseline_projection).await {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "  [pagerank-spike] baseline pagerank query failed ({}); \
                     falling back to single-snapshot mode",
                    e
                );
                HashMap::new()
            }
        }
    } else {
        eprintln!(
            "  [pagerank-spike] baseline projection unavailable; \
             scoring on full-graph rank alone (legacy behaviour)"
        );
        HashMap::new()
    };
    let two_snapshot = baseline_available && !baseline_rank.is_empty();

    // For each candidate compute the "observation" we'll MAD-test over.
    // Two-snapshot: the rank delta. Single-snapshot: novelty_ratio (legacy).
    let observations: Vec<f64> = if two_snapshot {
        candidates
            .iter()
            .map(|c| {
                let prev = baseline_rank.get(&c.host).copied().unwrap_or(0.0);
                (c.rank - prev).max(0.0)
            })
            .collect()
    } else {
        candidates.iter().map(|c| c.novelty_ratio).collect()
    };
    let (median, mad) = median_and_mad(observations.iter().copied());

    let mut findings: Vec<Finding> = Vec::new();
    for (c, &observed) in candidates.iter().zip(observations.iter()) {
        // Robust z-score: scale the deviation by 1/0.6745 so MAD-z is
        // comparable to a regular z-score under Gaussianity. Degenerate
        // MAD == 0 (every host has identical observation, typically a
        // tiny corpus) → treat any positive observation as outlier.
        let z = if mad > 0.0 {
            0.6745 * (observed - median).abs() / mad
        } else if observed > 0.0 {
            f64::INFINITY
        } else {
            0.0
        };
        if z < MAD_Z_THRESHOLD && mad > 0.0 {
            continue;
        }

        // Composite score: in two-snapshot mode it's delta * novelty_ratio
        // (must surface only hosts whose rank GAINED meaningfully AND whose
        // incoming mix is novelty-skewed). In fallback it's the original
        // rank * novelty_ratio.
        let prev = baseline_rank.get(&c.host).copied().unwrap_or(0.0);
        let composite = if two_snapshot {
            (c.rank - prev).max(0.0) * c.novelty_ratio
        } else {
            c.rank * c.novelty_ratio
        };
        if composite < MIN_SCORE {
            continue;
        }

        let summary = if two_snapshot {
            format!(
                "{host}: pagerank {prev:.5} -> {cur:.5} (delta={d:.5}), \
                 novelty_ratio={nr:.2} ({iw} window / {tot} total incoming), \
                 MAD-z={z:.1} (median delta = {med:.5}). \
                 Two-snapshot composite = delta * novelty.",
                host = c.host, prev = prev, cur = c.rank,
                d = (c.rank - prev).max(0.0),
                nr = c.novelty_ratio, iw = c.in_window, tot = c.in_base + c.in_window,
                z = z, med = median,
            )
        } else {
            format!(
                "{host}: rank={rank:.5}, novelty_ratio={nr:.2} \
                 ({iw} window / {tot} total incoming), MAD-z={z:.1} \
                 (median novelty across qualified hosts = {med:.2}). \
                 Single-snapshot fallback (no baseline projection) — \
                 composite = rank * novelty.",
                host = c.host, rank = c.rank, nr = c.novelty_ratio,
                iw = c.in_window, tot = c.in_base + c.in_window,
                z = z, med = median,
            )
        };

        let snippet = format!(
            "MATCH (a:host)-[r]->(b:host {{name: '{}'}}) \
             WHERE r.time >= datetime('{}') \
             RETURN a, r, b",
            c.host, cutoff_str
        );

        findings.push(Finding {
            detector: "pagerank-spike",
            host: c.host.clone(),
            time_window: format!("from {}", cutoff_str),
            score: composite,
            summary,
            cypher_snippet: snippet,
        });
    }
    findings.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    findings
}

async fn fetch_baseline_pagerank(
    graph: &Graph,
    projection: &str,
) -> neo4rs::Result<HashMap<String, f64>> {
    let q = format!(
        "CALL gds.pageRank.stream('{}') YIELD nodeId, score
         RETURN gds.util.asNode(nodeId).name AS host, score AS rank",
        projection
    );
    let mut stream = graph.execute(query(&q)).await?;
    let mut out: HashMap<String, f64> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let host: String = row.get("host").unwrap_or_default();
        let rank: f64 = row.get("rank").unwrap_or(0.0);
        if !host.is_empty() {
            out.insert(host, rank);
        }
    }
    Ok(out)
}

/// Median + Median Absolute Deviation. Both robust to outliers — exactly
/// what we want when the goal is identifying outliers in the input.
fn median_and_mad<I: IntoIterator<Item = f64>>(values: I) -> (f64, f64) {
    let mut v: Vec<f64> = values.into_iter().collect();
    if v.is_empty() {
        return (0.0, 0.0);
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = median_sorted(&v);
    let mut devs: Vec<f64> = v.iter().map(|x| (x - median).abs()).collect();
    devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = median_sorted(&devs);
    (median, mad)
}

fn median_sorted(v: &[f64]) -> f64 {
    let n = v.len();
    if n == 0 {
        return 0.0;
    }
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}
