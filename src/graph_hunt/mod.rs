// graph-hunt: statistical lateral-movement hunt on a graph loaded into
// Memgraph. Connection and schema check only; the analysis is the shared
// engine (graph_hunt_common::engine, docs/graph-hunt-statistics.md). MAGE
// is not needed: edges are read once over bolt and every statistic is
// computed in memory.

use crate::graph_hunt_common::{engine, schema, MEMGRAPH};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use neo4rs::*;
use std::collections::HashSet;

pub use schema::GraphMode;

fn parse_cutoff(raw: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(raw.trim(), "%Y-%m-%d %H:%M:%S").ok().map(|n| Utc.from_utc_datetime(&n))
}

fn parse_detector_list(raw: &str) -> HashSet<String> {
    raw.split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect()
}

/// Settings shared by both backends; None (after printing why) on bad input.
pub(crate) fn settings(
    investigation_from: &str,
    skip_detectors: Option<&str>,
    only_detectors: Option<&str>,
    alpha: f64,
    end_time: Option<&str>,
) -> Option<engine::Settings> {
    let cutoff = match parse_cutoff(investigation_from) {
        Some(c) => c,
        None => {
            eprintln!("Masstin - Error: --investigation-from must be \"YYYY-MM-DD HH:MM:SS\" (got: {})", investigation_from);
            return None;
        }
    };
    if !(alpha > 0.0 && alpha < 1.0) {
        eprintln!("Masstin - Error: --alpha must be between 0 and 1 (got: {})", alpha);
        return None;
    }
    let only = only_detectors.map(parse_detector_list).unwrap_or_default();
    let skip = skip_detectors.map(parse_detector_list).unwrap_or_default();
    let known: HashSet<&str> = engine::DETECTORS.iter().copied().collect();
    for d in only.iter().chain(skip.iter()) {
        if !known.contains(d.as_str()) {
            eprintln!("Masstin - Error: unknown detector '{}'. Known: {}", d, engine::DETECTORS.join(", "));
            return None;
        }
    }
    let end = match end_time {
        None => None,
        // the shared --end-time option is stored as "YYYY-MM-DD HH:MM:SS -0000"
        Some(raw) => match parse_cutoff(raw.get(..19).unwrap_or(raw)) {
            Some(e) if e > cutoff => Some(e),
            _ => {
                eprintln!("Masstin - Error: --end-time must be \"YYYY-MM-DD HH:MM:SS\" and after --investigation-from (got: {})", raw);
                return None;
            }
        },
    };
    Some(engine::Settings { cutoff, alpha, only, skip, end })
}

pub async fn graph_hunt(
    database: &str,
    user: &str,
    investigation_from: &str,
    skip_detectors: Option<&str>,
    only_detectors: Option<&str>,
    alpha: f64,
    end_time: Option<&str>,
    output: Option<&str>,
    report: Option<&str>,
) {
    let settings = match settings(investigation_from, skip_detectors, only_detectors, alpha, end_time) {
        Some(s) => s,
        None => return,
    };
    crate::banner::print_phase("1", "4", "Connecting to Memgraph...");
    crate::banner::print_phase_detail("Database:", database);
    crate::banner::print_phase_detail("Cutoff:", &settings.cutoff.to_rfc3339());
    crate::banner::print_phase_detail("Alpha (FDR):", &format!("{}", alpha));
    let config = match ConfigBuilder::default().uri(database).user(user).password("").db("memgraph").build() {
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

    crate::banner::print_phase("2", "4", "Inspecting graph schema...");
    match schema::detect_mode(&graph).await {
        Ok(GraphMode::Ungrouped) => crate::banner::print_phase_result("Ungrouped graph (per-event times available)"),
        Ok(GraphMode::Grouped) => {
            schema::print_grouped_error("load-memgraph");
            return;
        }
        Ok(GraphMode::Empty) => {
            eprintln!("Masstin - Error: graph is empty. Load data first with -a load-memgraph.");
            return;
        }
        Err(e) => {
            eprintln!("Masstin - Error: schema inspection failed: {}", e);
            return;
        }
    }
    engine::run(&graph, &MEMGRAPH, &settings, output, report).await;
}
