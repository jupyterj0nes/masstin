// graph-hunt-neo4j: statistical lateral-movement hunt on a graph loaded
// into Neo4j. Connection and schema check only; the analysis is the shared
// engine (graph_hunt_common::engine, docs/graph-hunt-statistics.md). No
// server-side plugin is needed: edges are read once over bolt and every
// statistic, including PageRank, betweenness and Louvain, is computed in
// memory.

use crate::graph_hunt_common::{engine, schema, NEO4J};
use neo4rs::*;

pub use schema::GraphMode;

pub async fn graph_hunt_neo4j(
    database: &str,
    user: &str,
    db: &str,
    investigation_from: &str,
    skip_detectors: Option<&str>,
    only_detectors: Option<&str>,
    alpha: f64,
    end_time: Option<&str>,
    output: Option<&str>,
) {
    let settings = match crate::graph_hunt::settings(investigation_from, skip_detectors, only_detectors, alpha, end_time) {
        Some(s) => s,
        None => return,
    };
    crate::banner::print_phase("1", "4", "Connecting to Neo4j...");
    crate::banner::print_phase_detail("Database:", database);
    crate::banner::print_phase_detail("Cutoff:", &settings.cutoff.to_rfc3339());
    crate::banner::print_phase_detail("Alpha (FDR):", &format!("{}", alpha));
    let pass = match std::env::var("NEO4J_PASSWORD") {
        Ok(p) if !p.is_empty() => {
            crate::banner::print_phase_detail("Auth:", "password from $NEO4J_PASSWORD");
            p
        }
        _ => rpassword::prompt_password("MASSTIN - Enter Neo4j database password: ").unwrap_or_default(),
    };
    let config = match ConfigBuilder::default().uri(database).user(user).password(&pass).db(db).build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Masstin - Error: failed to build Neo4j config: {}", e);
            return;
        }
    };
    crate::banner::print_phase_detail("Database (Neo4j):", db);
    let graph = match Graph::connect(config).await {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Masstin - Error: cannot connect to Neo4j: {}", e);
            return;
        }
    };
    crate::banner::print_phase_result("Connected");

    crate::banner::print_phase("2", "4", "Inspecting graph schema...");
    match schema::detect_mode(&graph).await {
        Ok(GraphMode::Ungrouped) => crate::banner::print_phase_result("Ungrouped graph (per-event times available)"),
        Ok(GraphMode::Grouped) => {
            schema::print_grouped_error("load-neo4j");
            return;
        }
        Ok(GraphMode::Empty) => {
            eprintln!("Masstin - Error: graph is empty. Load data first with -a load-neo4j.");
            return;
        }
        Err(e) => {
            eprintln!("Masstin - Error: schema inspection failed: {}", e);
            return;
        }
    }
    engine::run(&graph, &NEO4J, &settings, output).await;
}
