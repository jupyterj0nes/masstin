// graph-hunt: detect lateral movement anomalies on a graph already loaded
// into Memgraph. Uses native graph algorithms (PageRank, Louvain, betweenness)
// plus structural detectors (novel edges, chain motifs, cred rotation) against
// a per-host/per-edge baseline computed from the corpus before
// `--investigation-from`. Output: a ranked CSV of findings with the Cypher
// snippet needed to inspect each one in Memgraph Lab.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use neo4rs::*;
use std::collections::HashSet;

mod baseline;
mod detectors;
mod report;
mod schema;

pub use schema::GraphMode;

/// Parse the --investigation-from CLI value into a UTC datetime.
fn parse_cutoff(raw: &str) -> Option<DateTime<Utc>> {
    let trimmed = raw.trim();
    NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|naive| Utc.from_utc_datetime(&naive))
}

fn parse_detector_list(raw: &str) -> HashSet<String> {
    raw.split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Entry point for the GraphHunt action. Connects to Memgraph, detects the
/// graph mode (grouped vs ungrouped), runs the enabled detectors against the
/// baseline/investigation split, and emits a ranked CSV.
pub async fn graph_hunt(
    database: &str,
    user: &str,
    investigation_from: &str,
    skip_detectors: Option<&str>,
    only_detectors: Option<&str>,
    output: Option<&str>,
) {
    let start_clock = std::time::Instant::now();

    let cutoff = match parse_cutoff(investigation_from) {
        Some(dt) => dt,
        None => {
            eprintln!(
                "Masstin - Error: --investigation-from must be \"YYYY-MM-DD HH:MM:SS\" (got: {})",
                investigation_from
            );
            return;
        }
    };

    let skip_set = skip_detectors
        .map(parse_detector_list)
        .unwrap_or_default();
    let only_set = only_detectors
        .map(parse_detector_list)
        .unwrap_or_default();

    // Phase 1: Connect
    crate::banner::print_phase("1", "4", "Connecting to Memgraph...");
    crate::banner::print_phase_detail("Database:", database);
    crate::banner::print_phase_detail("Cutoff:", &cutoff.to_rfc3339());

    let config = match ConfigBuilder::default()
        .uri(database)
        .user(user)
        .password("")
        .db("memgraph")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Masstin - Error: failed to build Memgraph config: {}", e);
            return;
        }
    };
    let graph = match Graph::connect(config).await {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Masstin - Error: cannot connect to Memgraph: {}", e);
            return;
        }
    };
    crate::banner::print_phase_result("Connected");

    // Phase 2: Detect graph mode
    crate::banner::print_phase("2", "4", "Inspecting graph schema...");
    let mode = match schema::detect_mode(&graph).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Masstin - Error: schema inspection failed: {}", e);
            return;
        }
    };
    match mode {
        GraphMode::Ungrouped => {
            crate::banner::print_phase_result("Ungrouped graph (full detector set available)");
        }
        GraphMode::Grouped => {
            crate::banner::print_phase_result("Grouped graph detected");
            schema::print_grouped_disclaimer();
        }
        GraphMode::Empty => {
            eprintln!("Masstin - Error: graph is empty or contains no edges. Load data first with -a load-memgraph.");
            return;
        }
    }

    // Phase 3: Baseline (events strictly before cutoff).
    crate::banner::print_phase("3", "4", "Computing baseline...");
    let bl = match baseline::compute(&graph, cutoff, mode).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Masstin - Error: baseline query failed: {}", e);
            return;
        }
    };
    crate::banner::print_phase_result("Baseline computed");

    if bl.edges_in_window == 0 {
        eprintln!(
            "Masstin - Warning: 0 edges at or after {}. Cutoff may be after the entire corpus.",
            cutoff.to_rfc3339()
        );
    }

    crate::banner::print_phase("4", "4", "Running detectors...");
    let findings = detectors::run_all(&graph, &bl, &skip_set, &only_set).await;
    crate::banner::print_phase_result(&format!("{} finding(s)", findings.len()));

    // Emit CSV
    if let Err(e) = report::emit_csv(&findings, output) {
        eprintln!("Masstin - Error: cannot write findings CSV: {}", e);
        return;
    }

    let elapsed = start_clock.elapsed();
    crate::banner::print_phase_detail(
        "Done:",
        &format!("{} findings in {:.2}s", findings.len(), elapsed.as_secs_f64()),
    );
}
