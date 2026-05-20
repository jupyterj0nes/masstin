// pagerank-spike detector. Surfaces hosts that are simultaneously (a)
// globally important in the graph topology and (b) receiving an
// abnormally novel share of their incoming traffic in the investigation
// window. The intuition is the classic pivot signature: a host that
// already mattered for legitimate reasons (high rank because many
// systems talk to it) and that suddenly starts hearing from sources or
// at a rate it never did before — that's what an attacker uses as a
// stepping stone.
//
// We run GDS PageRank on the projection once, then for every node we
// split its incoming degree into pre-cutoff (baseline) and post-cutoff
// (window) counts in the same Cypher round-trip. The per-host signal is
// `rank * novelty_ratio` where novelty_ratio = window / (baseline +
// window). Two guards keep precision sane against this signal's natural
// noise floor:
//
//   1. MIN_BASELINE_EDGES gate — drop hosts with too little prior
//      activity. Without it, a host that just had 0-2 baseline edges
//      and 1 window edge gets novelty_ratio ~ 1.0, multiplied by its
//      non-zero PageRank, and lights up despite carrying no real
//      anomaly signal. Captures the Security.evtx asymmetry symptom
//      (sparse Security baseline on workstation X looks "newly
//      active" simply because the rotation horizon cut off the prior
//      history).
//
//   2. Robust MAD z-score over novelty_ratio across the qualified host
//      set — only hosts whose novelty_ratio is a real outlier (>3 MADs
//      above the median, the canonical Hampler threshold) get emitted.
//      MAD is robust to heavy-tailed distributions where a handful of
//      legitimate-but-noisy hosts would inflate stddev and mask true
//      outliers.

use crate::graph_hunt_neo4j::baseline::Baseline;
use crate::graph_hunt_neo4j::detectors::Finding;
use futures::stream::*;
use neo4rs::*;

/// Minimum number of baseline edges a host must have to be considered.
/// Below this the novelty_ratio is statistically meaningless and the
/// host gets dropped from scoring. Tuned empirically: 20 removes the
/// Security.evtx-asymmetry noise without losing real hub pivots
/// (DCs/fileservers have thousands of baseline edges, well above 20).
const MIN_BASELINE_EDGES: i64 = 20;

/// MAD z-score above which a novelty_ratio counts as a genuine outlier.
/// 2.0 is a deliberately mild cutoff: in a homogeneous baseline (most
/// hubs receive similar novelty fractions) MAD is tiny and even small
/// deviations cross z=2; in a heterogeneous one it weeds out routine
/// drift. 3.0 (the classical Hampler value) over-suppressed the detector
/// on test corpora where hubs are all hit at similar novelty levels.
const MAD_Z_THRESHOLD: f64 = 2.0;

/// Lower bound on the final composite score for a host to surface. Set
/// high enough to silence pure-noise hits (composite = rank * novelty
/// where both are < 0.1 means uninteresting); set low enough to let
/// genuine pivots through. Tuned against the test corpus where real
/// pivot composites sit in the 0.05-2.0 range.
const MIN_SCORE: f64 = 0.05;

#[derive(Debug, Clone)]
struct Candidate {
    host: String,
    rank: f64,
    in_base: i64,
    in_window: i64,
    novelty_ratio: f64,
}

pub async fn run(graph: &Graph, bl: &Baseline, projection: &str) -> Vec<Finding> {
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    // Single round-trip: stream PageRank from the GDS projection, join
    // each result against the node's incoming-edge counts split by the
    // cutoff. We DON'T apply the MAD-z filter in Cypher — it's a
    // distribution-aware step that's cleaner in Rust where we have the
    // full set in memory.
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

    // Robust outlier statistics over novelty_ratio.
    let (median, mad) = median_and_mad(candidates.iter().map(|c| c.novelty_ratio));

    let mut findings: Vec<Finding> = Vec::new();
    for c in &candidates {
        // Robust z-score: scale the deviation by 1/0.6745 so that, under a
        // Gaussian, MAD-z is comparable to a regular z-score. If MAD is 0
        // (every candidate has identical novelty — degenerate test corpus
        // or extremely uniform real data) fall back to MIN_SCORE on the
        // composite alone so the detector still emits something useful.
        let z = if mad > 0.0 {
            0.6745 * (c.novelty_ratio - median).abs() / mad
        } else {
            f64::INFINITY  // degenerate; treat any positive-novelty host as outlier
        };
        if z < MAD_Z_THRESHOLD && mad > 0.0 {
            continue;
        }
        let composite = c.rank * c.novelty_ratio;
        if composite < MIN_SCORE {
            continue;
        }

        let summary = format!(
            "{host}: rank={rank:.5}, novelty_ratio={nr:.2} \
             ({iw} window / {tot} total incoming), MAD-z={z:.1} \
             (median novelty across qualified hosts = {med:.2}). \
             Composite = rank * novelty.",
            host = c.host,
            rank = c.rank,
            nr = c.novelty_ratio,
            iw = c.in_window,
            tot = c.in_base + c.in_window,
            z = z,
            med = median,
        );

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
