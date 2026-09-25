// community-bridge detector. Runs Louvain community detection (MAGE's
// `community_detection.get`) on the full graph, then walks every edge in
// the investigation window looking for the canonical "bridge to a new
// island" signature: an edge whose origin and destination sit in
// different communities AND the origin has never previously touched any
// node in the destination's community.
//
// AD networks cluster naturally by function and geography: HR talks to
// HR, the North subsidiary talks to itself, DCs replicate among
// themselves. A legitimate cross-cluster jump exists in baseline too
// (admin from HQ touching a North server, for example). The detector
// fires only when the origin's prior cluster footprint never included
// the destination cluster — that is, a brand-new bridge in addition to
// being cross-community.

use crate::graph_hunt::baseline::Baseline;
use crate::graph_hunt::detectors::Finding;
use futures::stream::*;
use neo4rs::*;
use crate::graph_hunt_common::{auth_ok, browser_snippet, MEMGRAPH as D};
use std::collections::{HashMap, HashSet};

/// Context gate thresholds — same calibration as
/// `src/graph_hunt_neo4j/detectors/community_bridge.rs`. The Memgraph
/// variant runs single-snapshot Louvain on the full graph (MAGE lacks
/// the lightweight named-projection model GDS has, so a two-snapshot
/// community detection on baseline-only edges would require a heavy
/// Cypher subgraph collection — deferred). The context gate alone
/// recovers a large share of the precision win.
const MIN_BASELINE_EVENTS_AT_DEST: u64 = 50;
const MAX_ORIGIN_OUTDEGREE_FRACTION: f64 = 0.30;

pub async fn run(graph: &Graph, bl: &Baseline) -> Vec<Finding> {
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    // Step 1: community per node (Louvain on the full graph).
    let community_of = match fetch_communities(graph).await {
        Ok(m) if !m.is_empty() => m,
        Ok(_) => {
            eprintln!("  [community-bridge] community_detection returned no rows");
            return Vec::new();
        }
        Err(e) => {
            eprintln!("  [community-bridge] community_detection failed: {}", e);
            return Vec::new();
        }
    };

    // Step 2: per-origin, the set of communities it already touched in baseline.
    //         If an origin never touched destination's community before, that's
    //         the genuine bridge signal we want to surface.
    let origin_baseline_communities =
        match fetch_origin_baseline_communities(graph, &cutoff_str, &community_of).await {
            Ok(m) => m,
            Err(e) => {
                eprintln!("  [community-bridge] baseline-by-community query failed: {}", e);
                return Vec::new();
            }
        };

    // Step 3: walk the window edges, emit findings on genuine bridges.
    let q = format!(
        "MATCH (a:host)-[r]->(b:host)
         WHERE r.time >= localDateTime('{}') AND {}
         RETURN a.name AS origin,
                b.name AS destination,
                type(r) AS user,
                toString(head(collect(r.logon_type))) AS logon_type,
                toString(min(r.time)) AS event_time,
                toString(max(r.time)) AS last_time,
                count(*) AS n",
        cutoff_str, auth_ok("r")
    );

    let mut findings: Vec<Finding> = Vec::new();
    let mut stream = match graph.execute(query(&q)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [community-bridge] window query failed: {}", e);
            return findings;
        }
    };

    loop {
        match stream.next().await {
            Ok(Some(row)) => {
                let origin: String = row.get("origin").unwrap_or_default();
                let destination: String = row.get("destination").unwrap_or_default();
                let user: String = row.get("user").unwrap_or_default();
                let logon_type: String = row.get("logon_type").unwrap_or_default();
                let event_time: String = row.get("event_time").unwrap_or_default();
                let last_time: String = row.get("last_time").unwrap_or_default();
                let n: i64 = row.get("n").unwrap_or(1);

                if origin.is_empty() || destination.is_empty() {
                    continue;
                }

                // Context gate 1: sparse-baseline destination.
                if bl.baseline_event_count_for_dest(&destination) < MIN_BASELINE_EVENTS_AT_DEST {
                    continue;
                }

                // Context gate 2: "talks to everything" origin.
                let host_count = bl.destination_count() as f64;
                let origin_outdeg = bl.outgoing_degree(&origin) as f64;
                // Rotation = a known account of an infrastructure origin reaching
                // one more host. A NEW account on such an origin is not rotation.
                if origin_outdeg / host_count > MAX_ORIGIN_OUTDEGREE_FRACTION
                    && bl.origin_used_account(&origin, &user)
                {
                    continue;
                }

                // Origin must have authenticated history before the cutoff:
                // a brand-new origin has no community of its own (it is a
                // singleton in the baseline Louvain run), so every edge it
                // makes would "bridge" trivially and only repeat novel-edge.
                if bl.outgoing_degree(&origin) == 0 {
                    continue;
                }
                let oc = community_of.get(&origin).copied();
                let dc = community_of.get(&destination).copied();
                let (oc, dc) = match (oc, dc) {
                    (Some(a), Some(b)) => (a, b),
                    _ => continue,
                };
                if oc == dc {
                    continue;
                }
                let touched = origin_baseline_communities
                    .get(&origin)
                    .cloned()
                    .unwrap_or_default();
                if touched.contains(&dc) {
                    continue;
                }

                // Score: cross-community bridges are intrinsically suspicious;
                // novel bridges to never-touched communities even more so. We
                // emit a flat 0.7 so they consistently land between strong
                // multi-axis novel-edge findings (1.0) and the single-axis
                // novelty ones (0.33).
                let score = 0.7;

                let summary = format!(
                    "{origin} (comm={oc}) -> {destination} (comm={dc}) as user='{user}' \
                     logon_type='{lt}'. Origin had never touched destination's \
                     community before the cutoff.",
                    origin = origin, destination = destination,
                    oc = oc, dc = dc, user = user, lt = logon_type,
                );

                let snippet = browser_snippet(&D, &origin, Some(&destination), Some(&user), &event_time, Some(&last_time));

                findings.push(Finding {
                    detector: "community-bridge",
                    host: destination,
                    origin: origin.clone(),
                    account: user.clone(),
                    events: n.max(1) as u64,
                    time_window: format!("{} .. {}", event_time, last_time),
                    score,
                    summary,
                    cypher_snippet: snippet,
                });
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("  [community-bridge] row read failed: {}", e);
                break;
            }
        }
    }

    findings
}

async fn fetch_communities(graph: &Graph) -> neo4rs::Result<HashMap<String, i64>> {
    let q = "CALL community_detection.get() YIELD node, community_id
             RETURN node.name AS name, community_id";
    let mut stream = graph.execute(query(q)).await?;
    let mut out: HashMap<String, i64> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let name: String = row.get("name").unwrap_or_default();
        let cid: i64 = row.get("community_id").unwrap_or(-1);
        if !name.is_empty() && cid >= 0 {
            out.insert(name, cid);
        }
    }
    Ok(out)
}

async fn fetch_origin_baseline_communities(
    graph: &Graph,
    cutoff_str: &str,
    community_of: &HashMap<String, i64>,
) -> neo4rs::Result<HashMap<String, HashSet<i64>>> {
    let q = format!(
        "MATCH (a:host)-[r]->(b:host)
         WHERE r.time < localDateTime('{}') AND {}
         RETURN a.name AS origin, collect(DISTINCT b.name) AS dests",
        cutoff_str, auth_ok("r")
    );
    let mut stream = graph.execute(query(&q)).await?;
    let mut out: HashMap<String, HashSet<i64>> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let origin: String = row.get("origin").unwrap_or_default();
        let dests: Vec<String> = row.get("dests").unwrap_or_default();
        if origin.is_empty() {
            continue;
        }
        let entry = out.entry(origin).or_insert_with(HashSet::new);
        for d in dests {
            if let Some(c) = community_of.get(&d) {
                entry.insert(*c);
            }
        }
    }
    Ok(out)
}
