// chain-motif detector. Finds A→B→C chains in the investigation window where
// each consecutive hop happens within a short time delta AND the user (rel
// type) changes between hops. That's the canonical lateral-movement
// signature: an operator lands on B with one credential, then immediately
// pivots to C with a different one.
//
// Requires ungrouped data. In grouped mode the timestamps collapse to the
// earliest event per (origin,user,type,destination) tuple, and "earliest
// only" cannot distinguish "B was reached at 10:00 then C at 10:00:30" from
// "B has been reached repeatedly since 10:00, then C since 10:00:30 each by
// independent sessions". The disclaimer banner in schema.rs already advises
// the analyst on this.

use crate::graph_hunt::baseline::Baseline;
use crate::graph_hunt::detectors::Finding;
use chrono::NaiveDateTime;
use futures::stream::*;
use neo4rs::*;

/// Maximum seconds allowed between consecutive hops in the chain. 5 minutes
/// is intentionally generous for v1 — operator-driven pivoting can be slow
/// when manual, and we'd rather over-emit and let the analyst filter than
/// miss a real chain because someone took 30 seconds to type the next
/// command. Aggressive operators (impacket scripts) easily land under 2s
/// per hop; this threshold catches both.
const MAX_HOP_GAP_SECONDS: i64 = 300;

pub async fn run(graph: &Graph, bl: &Baseline) -> Vec<Finding> {
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    // Depth-2 chain query. We pull both hops, require strict temporal
    // ordering, cap the gap, and demand distinct relationship types
    // (= distinct usernames). The pivot host is the middle node B.
    //
    // Memgraph supports direct arithmetic between LocalDateTimes producing
    // a Duration, and Durations can be compared with `<=`. We cap the gap
    // via `duration({seconds: N})` and compute the actual elapsed seconds
    // in Rust from the returned timestamp strings — that keeps the query
    // portable across Memgraph versions where Duration accessor semantics
    // (component-of vs total) differ.
    let q = format!(
        "MATCH (a:host)-[r1]->(b:host)-[r2]->(c:host)
         WHERE r1.time >= localDateTime('{cutoff}')
           AND r2.time >= localDateTime('{cutoff}')
           AND r1.time < r2.time
           AND (r2.time - r1.time) <= duration('PT{gap}S')
           AND type(r1) <> type(r2)
           AND a.name <> c.name
         RETURN a.name AS a, b.name AS b, c.name AS c,
                type(r1) AS u1, type(r2) AS u2,
                toString(r1.logon_type) AS lt1,
                toString(r2.logon_type) AS lt2,
                toString(r1.time) AS t1, toString(r2.time) AS t2
         LIMIT 5000",
        cutoff = cutoff_str,
        gap = MAX_HOP_GAP_SECONDS
    );

    let mut findings: Vec<Finding> = Vec::new();
    let mut stream = match graph.execute(query(&q)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [chain-motif] query failed: {}", e);
            return findings;
        }
    };

    loop {
        match stream.next().await {
            Ok(Some(row)) => {
                let a: String = row.get("a").unwrap_or_default();
                let b: String = row.get("b").unwrap_or_default();
                let c: String = row.get("c").unwrap_or_default();
                let u1: String = row.get("u1").unwrap_or_default();
                let u2: String = row.get("u2").unwrap_or_default();
                let lt1: String = row.get("lt1").unwrap_or_default();
                let lt2: String = row.get("lt2").unwrap_or_default();
                let t1: String = row.get("t1").unwrap_or_default();
                let t2: String = row.get("t2").unwrap_or_default();

                if a.is_empty() || b.is_empty() || c.is_empty() {
                    continue;
                }

                let gap_seconds = parse_gap_seconds(&t1, &t2).unwrap_or(MAX_HOP_GAP_SECONDS);

                // Score: faster chains are more suspicious. 0s gap → 1.0,
                // MAX_HOP_GAP_SECONDS → 0.5. The novelty of the involved
                // edges adds a bonus.
                let speed_score = 1.0
                    - (gap_seconds as f64 / (2.0 * MAX_HOP_GAP_SECONDS as f64)).min(0.5);

                let novelty_bonus = {
                    let mut n = 0u32;
                    if !bl.is_known_edge(&a, &b) {
                        n += 1;
                    }
                    if !bl.is_known_edge(&b, &c) {
                        n += 1;
                    }
                    n as f64 * 0.1
                };
                let score = (speed_score + novelty_bonus).min(1.0);

                let summary = format!(
                    "Pivot via {b}: {a} -[{u1}/lt={lt1}]-> {b} -[{u2}/lt={lt2}]-> {c} \
                     ({gap}s between hops, credentials changed)",
                    a = a, b = b, c = c, u1 = u1, u2 = u2,
                    lt1 = lt1, lt2 = lt2, gap = gap_seconds,
                );

                let snippet = format!(
                    "MATCH (a:host {{name:'{}'}})-[r1]->(b:host {{name:'{}'}})-[r2]->(c:host {{name:'{}'}}) \
                     WHERE r1.time = localDateTime('{}') AND r2.time = localDateTime('{}') \
                     RETURN a, r1, b, r2, c",
                    a, b, c, t1, t2
                );

                findings.push(Finding {
                    detector: "chain-motif",
                    host: b,
                    time_window: format!("{} .. {}", t1, t2),
                    score,
                    summary,
                    cypher_snippet: snippet,
                });
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("  [chain-motif] row read failed: {}", e);
                break;
            }
        }
    }

    findings
}

/// Parse the two ISO-ish timestamp strings Memgraph returns from
/// `toString(localDateTime)` (no timezone suffix, optional fractional
/// seconds) and yield the elapsed seconds between them. Returns None if
/// either side fails to parse — the caller falls back to the worst-case
/// gap so the chain still gets reported, just with the lowest speed score.
fn parse_gap_seconds(t1: &str, t2: &str) -> Option<i64> {
    let fmts = ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"];
    let parse = |s: &str| -> Option<NaiveDateTime> {
        for f in fmts {
            if let Ok(dt) = NaiveDateTime::parse_from_str(s, f) {
                return Some(dt);
            }
        }
        None
    };
    let a = parse(t1)?;
    let b = parse(t2)?;
    Some((b - a).num_seconds())
}
