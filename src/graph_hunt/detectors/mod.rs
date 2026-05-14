// Detector registry. Each detector is a small module that issues Cypher
// queries (or MAGE calls) against the graph and returns a Vec<Finding>. The
// orchestrator below filters detectors by --skip / --only and the current
// GraphMode, then concatenates their findings.

use crate::graph_hunt::baseline::Baseline;
use crate::graph_hunt::schema::GraphMode;
use neo4rs::Graph;
use std::collections::HashSet;

mod novel_edge;
mod chain_motif;
mod pagerank_spike;
mod betweenness_spike;
mod community_bridge;
mod cred_rotation;
mod rare_logon_type;

pub struct Finding {
    pub detector: &'static str,
    pub host: String,
    pub time_window: String,
    pub score: f64,
    pub summary: String,
    pub cypher_snippet: String,
}

#[derive(Clone, Copy)]
struct DetectorSpec {
    name: &'static str,
    requires_ungrouped: bool,
}

const DETECTORS: &[DetectorSpec] = &[
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
) -> Vec<Finding> {
    let mut all: Vec<Finding> = Vec::new();

    for spec in DETECTORS {
        if !enabled(spec, bl.mode, skip, only) {
            eprintln!("  [skip] detector '{}' disabled for this run", spec.name);
            continue;
        }
        eprintln!("  [run]  detector '{}'", spec.name);

        let findings: Vec<Finding> = match spec.name {
            "novel-edge" => novel_edge::run(graph, bl).await,
            "chain-motif" => chain_motif::run(graph, bl).await,
            "pagerank-spike" => pagerank_spike::run(graph, bl).await,
            "betweenness-spike" => betweenness_spike::run(graph, bl).await,
            "community-bridge" => community_bridge::run(graph, bl).await,
            "cred-rotation" => cred_rotation::run(graph, bl).await,
            "rare-logon-type" => rare_logon_type::run(graph, bl).await,
            _ => Vec::new(),
        };

        eprintln!("         -> {} finding(s)", findings.len());
        all.extend(findings);
    }

    all
}
