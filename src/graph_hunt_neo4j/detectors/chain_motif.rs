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

use crate::graph_hunt_neo4j::baseline::Baseline;
use crate::graph_hunt_neo4j::detectors::Finding;
use futures::stream::*;
use neo4rs::*;
use crate::graph_hunt_common::auth_ok;

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
    // Neo4j 4.x notes that bit us here:
    //   1. Direct subtraction between two DateTime values is not supported
    //      (Memgraph allows it and returns a Duration). Use
    //      `duration.between(a, b)` to compute the difference.
    //   2. Worse: comparing two Duration values with `<=` is officially
    //      undefined in Neo4j 4.x — months and days can't be totally
    //      ordered (a "month" duration is not commensurate with a "30
    //      days" duration). The comparison silently drops nearly all rows
    //      and yields a tiny handful of false matches with gap == exactly
    //      300s (the engine's fallback was effectively == not <=).
    //   3. Reading `.seconds` directly off a Duration returns ONLY the
    //      seconds component, not the total — so a 7-hour gap whose
    //      seconds field happens to be 4 would pass `<= 300`. Wrong again.
    //
    // The portable, correct form: `duration.inSeconds(a, b).seconds`
    // normalizes the entire interval into a Duration whose only populated
    // component is seconds, so `.seconds` returns the total elapsed
    // seconds as an integer suitable for arithmetic comparison.
    let q = format!(
        "MATCH (a:host)-[r1]->(b:host)-[r2]->(c:host)
         WHERE r1.time >= datetime('{cutoff}')
           AND r2.time >= datetime('{cutoff}')
           AND r1.time < r2.time
           AND duration.inSeconds(r1.time, r2.time).seconds <= {gap}
           AND type(r1) <> type(r2)
           AND a.name <> c.name
           AND {auth1} AND {auth2}
         RETURN a.name AS a, b.name AS b, c.name AS c,
                type(r1) AS u1, type(r2) AS u2,
                toString(r1.logon_type) AS lt1,
                toString(r2.logon_type) AS lt2,
                toString(r1.time) AS t1, toString(r2.time) AS t2
         LIMIT 5000",
        cutoff = cutoff_str,
        gap = MAX_HOP_GAP_SECONDS,
        auth1 = auth_ok("r1"),
        auth2 = auth_ok("r2"),
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

                // Novelty filter: require AT LEAST ONE hop of the chain to be
                // an (origin, destination) pair that was never observed in
                // the baseline. Without this filter the detector drowns in
                // legitimate baseline chains where two adjacent edges happen
                // to fall under MAX_HOP_GAP_SECONDS with different rel
                // types (e.g. a service crawl + an admin RDP one minute
                // later through the same pivot). Validated on the test
                // corpus: drops chain-motif's noise from ~1300 chains to a
                // small set dominated by real lateral-movement patterns.
                let novel_hop_count = {
                    let mut n = 0u32;
                    if !bl.is_known_edge(&a, &b) { n += 1; }
                    if !bl.is_known_edge(&b, &c) { n += 1; }
                    n
                };
                if novel_hop_count == 0 {
                    continue;
                }

                // Score: faster chains are more suspicious. 0s gap → 1.0,
                // MAX_HOP_GAP_SECONDS → 0.5. The novelty hop count adds a
                // bonus on top — novel-both-hops chains beat novel-one-hop.
                let speed_score = 1.0
                    - (gap_seconds as f64 / (2.0 * MAX_HOP_GAP_SECONDS as f64)).min(0.5);
                let novelty_bonus = novel_hop_count as f64 * 0.1;
                let score = (speed_score + novelty_bonus).min(1.0);

                let summary = format!(
                    "Pivot via {b}: {a} -[{u1}/lt={lt1}]-> {b} -[{u2}/lt={lt2}]-> {c} \
                     ({gap}s between hops, credentials changed)",
                    a = a, b = b, c = c, u1 = u1, u2 = u2,
                    lt1 = lt1, lt2 = lt2, gap = gap_seconds,
                );

                let snippet = format!(
                    "MATCH (a:host {{name:'{}'}})-[r1]->(b:host {{name:'{}'}})-[r2]->(c:host {{name:'{}'}}) \
                     WHERE r1.time = datetime('{}') AND r2.time = datetime('{}') \
                     RETURN a, r1, b, r2, c",
                    a, b, c, t1, t2
                );

                findings.push(Finding {
                    detector: "chain-motif",
                    origin: a.clone(),
                    account: u1.clone(),
                    events: 2,
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
    // Neo4j prints `...:46Z`, Memgraph `...:46.000000`: the shared parser
    // handles both (the old local formats failed on the `Z` and every
    // Neo4j chain fell back to the 300 s worst case).
    let a = crate::graph_hunt_common::parse_ts(t1)?;
    let b = crate::graph_hunt_common::parse_ts(t2)?;
    Some((b - a).num_seconds())
}
