// graph-hunt-neo4j: detect lateral movement anomalies on a graph already
// loaded into Neo4j. Sister module to `graph_hunt` (which targets Memgraph
// MAGE); the analytical content is the same — same 7 detectors against the
// same baseline/window split — only the procedure calls and a few Cypher
// dialect differences change. The three algorithmic detectors (pagerank,
// betweenness, louvain) call GDS instead of MAGE, which forces an explicit
// graph projection here that MAGE does not need.
//
// Output: a ranked CSV of findings with the Cypher snippet needed to inspect
// each one in Neo4j Browser.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use futures::stream::*;
use neo4rs::*;
use std::collections::HashSet;

mod baseline;
mod detectors;
mod report;
mod schema;

pub use schema::GraphMode;

/// Name of the in-memory GDS projection used by the three algorithmic
/// detectors. Created once before the detector phase, dropped after.
/// Hard-coded because nothing else should be probing other projections in
/// parallel during a hunt — and if it collides with a leftover from a
/// previous interrupted run we drop-and-recreate.
const PROJECTION_NAME: &str = "mass-hunt";

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

/// Entry point for the GraphHuntNeo4j action. Mirrors graph_hunt but targets
/// Neo4j: reads the password from $NEO4J_PASSWORD (or prompts), projects the
/// graph into GDS, runs the enabled detectors against the
/// baseline/investigation split, and drops the projection.
pub async fn graph_hunt_neo4j(
    database: &str,
    user: &str,
    db: &str,
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

    let skip_set = skip_detectors.map(parse_detector_list).unwrap_or_default();
    let only_set = only_detectors.map(parse_detector_list).unwrap_or_default();

    // Phase 1: Connect
    crate::banner::print_phase("1", "4", "Connecting to Neo4j...");
    crate::banner::print_phase_detail("Database:", database);
    crate::banner::print_phase_detail("Cutoff:", &cutoff.to_rfc3339());

    // Password: env var first (scripts/CI), interactive prompt otherwise.
    // Same convention as `load-neo4j`.
    let pass = match std::env::var("NEO4J_PASSWORD") {
        Ok(p) if !p.is_empty() => {
            crate::banner::print_phase_detail("Auth:", "password from $NEO4J_PASSWORD");
            p
        }
        _ => rpassword::prompt_password("MASSTIN - Enter Neo4j database password: ")
            .unwrap_or_default(),
    };

    let config = match ConfigBuilder::default()
        .uri(database)
        .user(user)
        .password(&pass)
        .db(db)
        .build()
    {
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
            eprintln!("Masstin - Error: graph is empty or contains no edges. Load data first with -a load-neo4j.");
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

    // Phase 4: GDS projection + detectors + drop. Projection wraps the
    // detector phase so pagerank/betweenness/louvain can run against an
    // in-memory native GDS view. The drop runs unconditionally even on
    // detector failure so the projection name does not survive into the
    // next hunt (GDS rejects re-creation of an existing name).
    crate::banner::print_phase("4", "4", "Running detectors...");
    // Best-effort cleanup of any leftover projection from a previous run.
    let _ = drop_projection(&graph).await;
    if let Err(e) = create_projection(&graph).await {
        eprintln!("Masstin - Error: GDS projection failed: {}", e);
        eprintln!("Masstin - Hint: ensure the Graph Data Science plugin is installed and Neo4j was restarted after install.");
        return;
    }

    let findings = detectors::run_all(&graph, &bl, &skip_set, &only_set, PROJECTION_NAME).await;

    // Always drop; ignore the result. The projection lives in JVM heap only,
    // a failed drop leaks a few MB until the DBMS restarts.
    let _ = drop_projection(&graph).await;

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

/// Create the GDS graph projection over (:host) nodes and every relationship
/// type (the loader uses the sanitized username as the rel type, so there's
/// no canonical small set to enumerate). Uses `gds.graph.project()` which
/// is the GDS 2.x procedure name (Neo4j 5.x / 2026.x). GDS 1.x used
/// `gds.graph.create()` and is EOL — masstin requires GDS 2.x on the
/// server side from this version on.
async fn create_projection(graph: &Graph) -> neo4rs::Result<()> {
    let q = format!(
        "CALL gds.graph.project('{}', 'host', '*') YIELD graphName, nodeCount, relationshipCount",
        PROJECTION_NAME
    );
    let mut stream = graph.execute(query(&q)).await?;
    if let Some(row) = stream.next().await? {
        let nodes: i64 = row.get("nodeCount").unwrap_or(0);
        let rels: i64 = row.get("relationshipCount").unwrap_or(0);
        crate::banner::print_phase_detail(
            "Projection:",
            &format!("'{}' ({} nodes, {} rels)", PROJECTION_NAME, nodes, rels),
        );
    }
    Ok(())
}

/// Drop the GDS projection. `failIfMissing=false` so the initial cleanup
/// call doesn't error when there is nothing to drop yet.
async fn drop_projection(graph: &Graph) -> neo4rs::Result<()> {
    let q = format!(
        "CALL gds.graph.drop('{}', false) YIELD graphName",
        PROJECTION_NAME
    );
    let mut stream = graph.execute(query(&q)).await?;
    let _ = stream.next().await?;
    Ok(())
}
