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
mod schema;

pub use schema::GraphMode;

/// Name of the in-memory GDS projection used by the three algorithmic
/// detectors. Created once before the detector phase, dropped after.
/// Hard-coded because nothing else should be probing other projections in
/// parallel during a hunt — and if it collides with a leftover from a
/// previous interrupted run we drop-and-recreate.
const PROJECTION_NAME: &str = "mass-hunt";

/// Companion projection containing ONLY the baseline edges (r.time <
/// cutoff). Used by `betweenness-spike` and `pagerank-spike` to compute
/// a centrality "before" snapshot. The two-snapshot delta = full -
/// baseline tells us whether a host's pivot-ness is structural (was
/// already a hub, suppress) or genuinely new in the window (fire). Without
/// it, legitimate hubs like SCCM/jumpboxes drown out real pivots at large
/// scale because their absolute centrality is always high.
const PROJECTION_BASELINE_NAME: &str = "mass-hunt-baseline";

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
    // Best-effort cleanup of any leftover projections from a previous run.
    let _ = drop_projection_named(&graph, PROJECTION_NAME).await;
    let _ = drop_projection_named(&graph, PROJECTION_BASELINE_NAME).await;
    if let Err(e) = create_projection(&graph).await {
        eprintln!("Masstin - Error: GDS projection failed: {}", e);
        eprintln!("Masstin - Hint: ensure the Graph Data Science plugin is installed and Neo4j was restarted after install.");
        return;
    }
    // Baseline-only projection for the two-snapshot centrality detectors.
    // Non-fatal: if it fails, betweenness/pagerank fall back to
    // single-snapshot behaviour with a warning emitted inside the detector.
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();
    if let Err(e) = create_baseline_projection(&graph, &cutoff_str).await {
        eprintln!(
            "  [graph-hunt-neo4j] WARNING: baseline projection failed ({}); \
             betweenness/pagerank will fall back to single-snapshot mode.",
            e
        );
    }

    let findings = detectors::run_all(&graph, &bl, &skip_set, &only_set, PROJECTION_NAME).await;

    // Always drop both; ignore the result. Projections live in JVM heap
    // only — a failed drop leaks a few MB until the DBMS restarts.
    let _ = drop_projection_named(&graph, PROJECTION_NAME).await;
    let _ = drop_projection_named(&graph, PROJECTION_BASELINE_NAME).await;

    crate::banner::print_phase_result(&format!("{} finding(s)", findings.len()));

    // Emit CSV
    if let Err(e) = crate::graph_hunt_common::report::emit_csv(&findings, output) {
        eprintln!("Masstin - Error: cannot write findings CSV: {}", e);
        return;
    }

    let elapsed = start_clock.elapsed();
    crate::banner::print_phase_detail(
        "Done:",
        &format!("{} findings in {:.2}s", findings.len(), elapsed.as_secs_f64()),
    );
}

/// Check whether the GDS catalog has a projection by this name in the
/// current database. Used by `ensure_projection` to decide whether to
/// (re)create. In Neo4j 2026.x / GDS 2.x we have observed the projection
/// silently disappearing between consecutive algorithm calls when the
/// neo4rs connection pool happens to fan out across sessions — the GDS
/// catalog is per-session in some configurations, and a connection that
/// landed on the default `neo4j` database won't see a projection created
/// on a named database like `detection-test`. Re-checking from each
/// detector defensively side-steps the issue regardless of which
/// session the call lands on.
pub(crate) async fn projection_exists(graph: &Graph, name: &str) -> neo4rs::Result<bool> {
    let q = format!("CALL gds.graph.exists('{}') YIELD exists RETURN exists", name);
    let mut stream = graph.execute(query(&q)).await?;
    if let Some(row) = stream.next().await? {
        return Ok(row.get("exists").unwrap_or(false));
    }
    Ok(false)
}

/// Idempotent helper: confirm the projection exists, recreating it if
/// missing. Algorithmic detectors should call this at the start of their
/// `run()` to be resilient against the GDS 2.x catalog-vanishing
/// behaviour described on `projection_exists`.
pub(crate) async fn ensure_projection(graph: &Graph, name: &str) -> neo4rs::Result<()> {
    match projection_exists(graph, name).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            eprintln!("  [graph-hunt-neo4j] projection '{}' missing from catalog, re-projecting", name);
            create_projection(graph).await
        }
        Err(e) => {
            // Catalog probe itself failed (auth/transient) — try to project
            // anyway; the create call will surface a meaningful error if
            // the server is truly unhealthy.
            eprintln!("  [graph-hunt-neo4j] projection probe failed ({}), re-projecting anyway", e);
            create_projection(graph).await
        }
    }
}

/// True once the server has been identified as running GDS 1.x, whose
/// projection procedures are named `gds.graph.create[.cypher]` instead of
/// the GDS 2.x `gds.graph.project`. Algorithm procedures (pageRank,
/// louvain, betweenness, util.asNode) share their names across both
/// generations, so the projection calls are the only thing that differs.
/// Detected lazily: the first `gds.graph.project` failing with
/// ProcedureNotFound flips the flag and the call is retried in 1.x form.
static GDS_LEGACY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn gds_legacy() -> bool {
    GDS_LEGACY.load(std::sync::atomic::Ordering::Relaxed)
}


/// Create the GDS graph projection over (:host) nodes and every relationship
/// type (the loader uses the sanitized username as the rel type, so there's
/// no canonical small set to enumerate). Uses `gds.graph.project()` (GDS
/// 2.x, Neo4j 5.x / 2026.x) and falls back to `gds.graph.create()` when
/// the server still runs GDS 1.x (Neo4j 4.x installs, e.g. Neo4j Desktop
/// 4.2 + GDS 1.4).
pub(crate) async fn create_projection(graph: &Graph) -> neo4rs::Result<()> {
    detect_gds_generation(graph).await;
    let (nodes, rels) = project_filtered(graph, PROJECTION_NAME, None).await?;
    crate::banner::print_phase_detail(
        "Projection:",
        &format!("'{}' ({} nodes, {} weighted host pairs, authenticated logins only)", PROJECTION_NAME, nodes, rels),
    );
    Ok(())
}

/// Decide once whether the server runs GDS 1.x (projection procedures
/// `gds.graph.create[.cypher]`) or 2.x (`gds.graph.project`). Algorithm
/// procedures share their names across both.
async fn detect_gds_generation(graph: &Graph) {
    if let Ok(mut s) = graph.execute(query("RETURN gds.version() AS v")).await {
        if let Ok(Some(row)) = s.next().await {
            let v: String = row.get("v").unwrap_or_default();
            if v.starts_with("1.") {
                if !gds_legacy() {
                    crate::banner::print_phase_detail("GDS:", &format!("{} (1.x) — using gds.graph.create.cypher", v));
                }
                GDS_LEGACY.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

/// Project (:host)-[auth]->(:host) into GDS, one relationship per host pair
/// with `weight` = number of authenticated logins. Failed and
/// unauthenticated attempts are left out on purpose: a scanner that
/// "reaches" every host reached none, and counting it made PageRank,
/// betweenness and Louvain report probe targets as pivots. `extra` adds a
/// time filter for the baseline projection.
async fn project_filtered(graph: &Graph, name: &str, extra: Option<&str>) -> neo4rs::Result<(i64, i64)> {
    let mut wh = crate::graph_hunt_common::auth_ok("r");
    if let Some(x) = extra {
        wh = format!("{} AND {}", wh, x);
    }
    let q = if gds_legacy() {
        let inner = wh.replace('\'', "\"");
        format!(
            "CALL gds.graph.create.cypher('{name}',
                'MATCH (n:host) RETURN id(n) AS id',
                'MATCH (a:host)-[r]->(b:host) WHERE {inner} WITH a, b, count(*) AS c RETURN id(a) AS source, id(b) AS target, toFloat(c) AS weight')
             YIELD nodeCount, relationshipCount
             RETURN nodeCount, relationshipCount",
            name = name,
            inner = inner,
        )
    } else {
        format!(
            "MATCH (a:host)-[r]->(b:host) WHERE {wh}
             WITH a, b, toFloat(count(*)) AS w
             WITH gds.graph.project('{name}', a, b, {{relationshipProperties: {{weight: w}}}}) AS g
             RETURN g.nodeCount AS nodeCount, g.relationshipCount AS relationshipCount",
            wh = wh,
            name = name,
        )
    };
    let mut stream = graph.execute(query(&q)).await?;
    let mut out = (0, 0);
    if let Some(row) = stream.next().await? {
        out = (row.get("nodeCount").unwrap_or(0), row.get("relationshipCount").unwrap_or(0));
    }
    Ok(out)
}

/// Drop a GDS projection by name. `failIfMissing=false` so the initial
/// cleanup call doesn't error when there is nothing to drop yet. Used for
/// both `mass-hunt` and `mass-hunt-baseline`.
pub(crate) async fn drop_projection_named(graph: &Graph, name: &str) -> neo4rs::Result<()> {
    let q = format!(
        "CALL gds.graph.drop('{}', false) YIELD graphName",
        name
    );
    let mut stream = graph.execute(query(&q)).await?;
    let _ = stream.next().await?;
    Ok(())
}

/// Create the baseline-only GDS projection: the same (:host)-[*]->(:host)
/// shape as the main projection but restricted to edges that fall strictly
/// before the cutoff. Uses GDS 2.x's Cypher projection function form,
/// which lets us push the time filter into the projection itself instead
/// of trying to compute on a filtered subgraph at algorithm-call time.
///
/// If the corpus has zero pre-cutoff edges (extremely short investigation,
/// or wrong cutoff) the projection is still created with whatever node
/// set the Cypher pattern yields and zero relationships — both
/// betweenness and pagerank correctly produce 0.0 scores on it, so the
/// downstream delta math degenerates to "delta = full" which is the
/// correct behavior (no baseline, so every centrality is "new").
pub(crate) async fn create_baseline_projection(
    graph: &Graph,
    cutoff_str: &str,
) -> neo4rs::Result<()> {
    let time_filter = format!("r.time < datetime('{}')", cutoff_str);
    let (nodes, rels) = project_filtered(graph, PROJECTION_BASELINE_NAME, Some(&time_filter)).await?;
    crate::banner::print_phase_detail(
        "Baseline projection:",
        &format!("'{}' ({} nodes, {} weighted host pairs < cutoff)", PROJECTION_BASELINE_NAME, nodes, rels),
    );
    Ok(())
}

/// Check existence of the baseline projection — used by the two-snapshot
/// detectors to decide whether to take the delta path or fall back to
/// single-snapshot. Mirrors `projection_exists` for the main projection.
pub(crate) async fn baseline_projection_exists(graph: &Graph) -> bool {
    projection_exists(graph, PROJECTION_BASELINE_NAME)
        .await
        .unwrap_or(false)
}

pub(crate) fn baseline_projection_name() -> &'static str {
    PROJECTION_BASELINE_NAME
}
