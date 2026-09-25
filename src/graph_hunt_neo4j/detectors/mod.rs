// Detector registry. Each detector is a small module that issues Cypher
// queries (or MAGE calls) against the graph and returns a Vec<Finding>. The
// orchestrator below filters detectors by --skip / --only and the current
// GraphMode, then concatenates their findings.

use crate::graph_hunt_neo4j::baseline::Baseline;
use crate::graph_hunt_neo4j::schema::GraphMode;
use neo4rs::Graph;
use std::collections::HashSet;

mod novel_edge;
mod chain_motif;
mod pagerank_spike;
mod betweenness_spike;
mod community_bridge;
mod cred_rotation;
mod rare_logon_type;

pub use crate::graph_hunt_common::Finding;

#[derive(Clone, Copy)]
struct DetectorSpec {
    name: &'static str,
    requires_ungrouped: bool,
}

const DETECTORS: &[DetectorSpec] = &[
    DetectorSpec { name: "origin-fanout",      requires_ungrouped: false },
    DetectorSpec { name: "probe-then-success", requires_ungrouped: true  },
    DetectorSpec { name: "failed-sweep",       requires_ungrouped: false },
    DetectorSpec { name: "novel-edge",        requires_ungrouped: false },
    DetectorSpec { name: "community-bridge",  requires_ungrouped: false },
    DetectorSpec { name: "rare-logon-type",   requires_ungrouped: false },
    DetectorSpec { name: "pagerank-spike",    requires_ungrouped: false },
    DetectorSpec { name: "betweenness-spike", requires_ungrouped: false },
    DetectorSpec { name: "chain-motif",       requires_ungrouped: true  },
    DetectorSpec { name: "cred-rotation",     requires_ungrouped: true  },
];

fn enabled(
    spec: &DetectorSpec,
    mode: GraphMode,
    skip: &HashSet<String>,
    only: &HashSet<String>,
) -> bool {
    if spec.requires_ungrouped && mode != GraphMode::Ungrouped {
        return false;
    }
    if !only.is_empty() {
        return only.contains(spec.name);
    }
    !skip.contains(spec.name)
}

pub async fn run_all(
    graph: &Graph,
    bl: &Baseline,
    skip: &HashSet<String>,
    only: &HashSet<String>,
    projection: &str,
) -> Vec<Finding> {
    let mut all: Vec<Finding> = Vec::new();
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();
    let d = crate::graph_hunt_common::NEO4J;
    // Baseline facts shared by the origin-level detectors and the
    // periodicity pass.
    let facts = match crate::graph_hunt_common::fetch_baseline_facts(graph, &d, &cutoff_str).await {
        Ok(f) => Some(f),
        Err(e) => { eprintln!("  [baseline-facts] query failed: {}", e); None }
    };

    for spec in DETECTORS {
        if !enabled(spec, bl.mode, skip, only) {
            eprintln!("  [skip] detector '{}' disabled for this run", spec.name);
            continue;
        }
        eprintln!("  [run]  detector '{}'", spec.name);

        // The three algorithmic detectors run their GDS procedure against
        // the projection created upstream in graph_hunt_neo4j::mod; the
        // others are pure Cypher and ignore it.
        let findings: Vec<Finding> = match spec.name {
            "novel-edge" => novel_edge::run(graph, bl).await,
            "chain-motif" => chain_motif::run(graph, bl).await,
            "pagerank-spike" => pagerank_spike::run(graph, bl, projection).await,
            "betweenness-spike" => betweenness_spike::run(graph, bl, projection).await,
            "community-bridge" => community_bridge::run(graph, bl, projection).await,
            "cred-rotation" => cred_rotation::run(graph, bl).await,
            "rare-logon-type" => rare_logon_type::run(graph, bl).await,
            "origin-fanout" => match &facts { Some(f) => crate::graph_hunt_common::origin_fanout(graph, &d, f).await, None => Vec::new() },
            "probe-then-success" => match &facts { Some(f) => crate::graph_hunt_common::probe_then_success(graph, &d, f).await, None => Vec::new() },
            "failed-sweep" => match &facts { Some(f) => crate::graph_hunt_common::failed_sweep(graph, &d, f).await, None => Vec::new() },
            _ => Vec::new(),
        };

        eprintln!("         -> {} finding(s)", findings.len());
        all.extend(findings);
    }

    // Demote scheduled, pre-existing activity (monitoring probes,
    // inventory jobs) instead of relying on allow-lists.
    if let Some(f) = &facts {
        crate::graph_hunt_common::apply_periodicity(graph, &d, f, &mut all).await;
    }

    all
}
