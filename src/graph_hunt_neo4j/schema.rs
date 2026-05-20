// Schema inspection for graph-hunt. Determines whether the graph was loaded
// in grouped mode (one edge per (origin,user,logon_type,destination) with
// `earliest_date` only) or ungrouped mode (one edge per CSV row with its own
// timestamp). Detector availability depends on this — see the disclaimer
// banner.

use futures::stream::*;
use neo4rs::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphMode {
    Ungrouped,
    Grouped,
    Empty,
}

/// Inspect a sample of edges to decide whether per-event timestamps are
/// available. The heuristic: pick the (origin, target_user_name, logon_type,
/// destination) tuples with more than one edge between them; if any tuple has
/// edges with distinct `time` values, the graph is ungrouped. If every tuple
/// has exactly one edge (or all duplicates share the same time), it is
/// grouped.
pub async fn detect_mode(graph: &Graph) -> neo4rs::Result<GraphMode> {
    // Quick emptiness check first — without this, a brand-new database
    // would be flagged as "grouped" purely because the sample below is empty.
    let mut count_stream = graph
        .execute(query("MATCH ()-[r]->() RETURN count(r) AS c LIMIT 1"))
        .await?;
    let total: i64 = match count_stream.next().await? {
        Some(row) => row.get("c").unwrap_or(0),
        None => 0,
    };
    if total == 0 {
        return Ok(GraphMode::Empty);
    }

    // Look at up to 200 (origin, user, type, destination) tuples that have
    // 2+ edges. If any tuple has 2+ distinct timestamps, ungrouped.
    let probe = "MATCH (a:host)-[r]->(b:host)
                 WITH a.name AS src, b.name AS dst, type(r) AS u, r.logon_type AS lt, count(r) AS c, count(DISTINCT r.time) AS d
                 WHERE c > 1
                 RETURN src, dst, u, lt, c, d
                 LIMIT 200";
    let mut stream = graph.execute(query(probe)).await?;
    let mut saw_duplicates = false;
    while let Some(row) = stream.next().await? {
        let c: i64 = row.get("c").unwrap_or(0);
        let d: i64 = row.get("d").unwrap_or(0);
        if c > 1 {
            saw_duplicates = true;
            if d > 1 {
                return Ok(GraphMode::Ungrouped);
            }
        }
    }

    // No tuple with 2+ distinct timestamps. If we saw duplicates at all with
    // a single timestamp each, it's grouped-with-count-1 noise. Either way,
    // the temporal-detector set is unsafe to enable.
    if saw_duplicates {
        Ok(GraphMode::Grouped)
    } else {
        // Every (origin, user, type, destination) appears exactly once. This
        // is the typical shape of a grouped load — `count` is stored as a
        // property and the timestamp is `earliest_date`. We cannot tell apart
        // "grouped" from "ungrouped with one event per tuple" but the safe
        // assumption for the detector matrix is grouped.
        Ok(GraphMode::Grouped)
    }
}

pub fn print_grouped_disclaimer() {
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║  WARNING: GROUPED GRAPH DETECTED                                 ║");
    eprintln!("║                                                                  ║");
    eprintln!("║  The graph was loaded without --ungrouped, so per-event          ║");
    eprintln!("║  timestamps are not available. The following detectors will     ║");
    eprintln!("║  be SKIPPED:                                                     ║");
    eprintln!("║                                                                  ║");
    eprintln!("║    - chain-motif       (needs per-event timestamps)              ║");
    eprintln!("║    - cred-rotation     (needs per-event timestamps)              ║");
    eprintln!("║                                                                  ║");
    eprintln!("║  And the following will run in DEGRADED mode (two-snapshot       ║");
    eprintln!("║  comparison instead of sliding window):                          ║");
    eprintln!("║                                                                  ║");
    eprintln!("║    - pagerank-spike                                              ║");
    eprintln!("║    - betweenness-spike                                           ║");
    eprintln!("║                                                                  ║");
    eprintln!("║  For full detection, reload with:                                ║");
    eprintln!("║    masstin -a load-memgraph --ungrouped ...                      ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
    eprintln!();
}
