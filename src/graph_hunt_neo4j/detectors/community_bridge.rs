// community-bridge detector. Two-snapshot variant: runs Louvain on the
// baseline-only GDS projection (edges with `r.time < cutoff`) rather than
// on the full graph, then walks every edge in the investigation window
// looking for the canonical "bridge to a new island" signature — an edge
// whose origin and destination sit in different baseline communities AND
// the origin had never touched any node in the destination's community
// before the cutoff.
//
// AD networks cluster naturally by function and geography: HR talks to
// HR, the North subsidiary talks to itself, DCs replicate among
// themselves. A legitimate cross-cluster jump exists in baseline too
// (admin from HQ touching a North server, for example). The detector
// fires only when the origin's prior cluster footprint never included
// the destination cluster — that is, a brand-new bridge in addition to
// being cross-community.
//
// Why two-snapshot Louvain matters: Louvain is sensitive to the edge set
// it sees. Running it on the full graph (baseline + window) lets
// investigation-window edges shift community boundaries — a host that
// was peripheral in baseline can end up in a different community because
// window edges connected it to another cluster. That destroys the "the
// origin never touched destination's community" comparison (we're
// effectively comparing baseline touches against a window-influenced
// community map). Running Louvain only on the baseline freezes the
// community structure to the pre-cutoff state, which is the right
// reference for the historical-touch gate. Same pattern that fixed
// betweenness-spike and pagerank-spike.
//
// Fallback: if the baseline projection isn't available (transient
// projection error, zero pre-cutoff edges), we degrade to the historical
// single-snapshot scoring against the full projection and emit a
// warning. Keeps recall at parity with the legacy detector when
// something is wrong with the projection layer.

use crate::graph_hunt_neo4j::baseline::Baseline;
use crate::graph_hunt_neo4j::detectors::Finding;
use futures::stream::*;
use neo4rs::*;
use crate::graph_hunt_common::{auth_ok, browser_snippet, NEO4J as D};
use std::collections::{HashMap, HashSet};

/// Context gate thresholds, mirroring novel-edge. Calibrated against the
/// stress-corpus FP analysis: 64 of the 81 residual community-bridge
/// FPs came from 5 infrastructure hosts (SIEM, MON, SCCM, BACKUP) whose
/// baseline out-degree exceeds 30% of the estate by design. The same
/// hosts produced zero true positives — attackers don't operate FROM
/// these hosts, they pivot TOWARD them — so the gate is a clean win.
/// The destination-density gate catches the secondary FP cluster
/// (LX-WEB-NORTH-01, LX-APP-NORTH-01, FS-LEGAL-HQ — small/isolated
/// communities with sparse baseline coverage).
const MIN_BASELINE_EVENTS_AT_DEST: u64 = 50;
const MAX_ORIGIN_OUTDEGREE_FRACTION: f64 = 0.30;

pub async fn run(graph: &Graph, bl: &Baseline, projection: &str) -> Vec<Finding> {
    // Resilience against GDS 2.x catalog-vanishing across pool sessions
    // for the FULL projection. The baseline projection is checked
    // separately below — if it's missing we fall back to single-snapshot
    // mode.
    if let Err(e) = crate::graph_hunt_neo4j::ensure_projection(graph, projection).await {
        eprintln!("  [community-bridge] cannot ensure projection: {}", e);
        return Vec::new();
    }
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    let baseline_available = crate::graph_hunt_neo4j::baseline_projection_exists(graph).await;
    let baseline_projection = crate::graph_hunt_neo4j::baseline_projection_name();
    let (community_projection, mode_note) = if baseline_available {
        (baseline_projection, "two-snapshot (Louvain on baseline-only)")
    } else {
        eprintln!(
            "  [community-bridge] baseline projection unavailable; \
             falling back to single-snapshot Louvain on full graph"
        );
        (projection, "single-snapshot fallback (Louvain on full graph)")
    };

    // Step 1: community per node, computed on the chosen projection.
    let community_of = match fetch_communities(graph, community_projection).await {
        Ok(m) if !m.is_empty() => m,
        Ok(_) => {
            eprintln!("  [community-bridge] louvain returned no rows");
            return Vec::new();
        }
        Err(e) => {
            eprintln!("  [community-bridge] louvain failed: {}", e);
            return Vec::new();
        }
    };

    // Step 2: per-origin, the set of communities it already touched in
    // baseline. Mapped through the community_of we just fetched so the
    // historical-touch set lives in the SAME community-id space as the
    // window-edge lookups below.
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
         WHERE r.time >= datetime('{}') AND {}
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

                // Context gate 1: sparse-baseline destination. A target
                // with too few baseline events doesn't have enough
                // historical signal for "first time origin reaches this
                // community" to be meaningful — likely a recently
                // onboarded host or a community whose retention dropped.
                if bl.baseline_event_count_for_dest(&destination) < MIN_BASELINE_EVENTS_AT_DEST {
                    continue;
                }

                // Context gate 2: "talks to everything" origin. Infra
                // hosts (SIEM, monitoring, SCCM, backup) legitimately
                // touch many communities; their cross-community window
                // edges are operational rotation, not signal.
                let host_count = bl.destination_count() as f64;
                let origin_outdeg = bl.outgoing_degree(&origin) as f64;
                // Rotation = a known account of an infrastructure origin reaching
                // one more host. A NEW account on such an origin is not rotation.
                if origin_outdeg / host_count > MAX_ORIGIN_OUTDEGREE_FRACTION
                    && bl.origin_used_account(&origin, &user)
                {
                    continue;
                }

                // If either endpoint has no community assignment, we
                // can't reason about cross-community structure. Skip
                // rather than fire — the host is either window-only
                // (in two-snapshot mode) or got dropped by GDS for
                // having no edges in the projection. Other detectors
                // still see this edge.
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
                     community before the cutoff. [{mode}]",
                    origin = origin, destination = destination,
                    oc = oc, dc = dc, user = user, lt = logon_type,
                    mode = mode_note,
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

async fn fetch_communities(
    graph: &Graph,
    projection: &str,
) -> neo4rs::Result<HashMap<String, i64>> {
    // gds.louvain.stream YIELDs (nodeId, communityId). gds.util.asNode
    // hydrates the nodeId so we can read the `name` property — same shape
    // the Memgraph variant gets from `community_detection.get`.
    let q = format!(
        "CALL gds.louvain.stream('{}', {{relationshipWeightProperty: 'weight'}}) YIELD nodeId, communityId
         RETURN gds.util.asNode(nodeId).name AS name, communityId AS community_id",
        projection
    );
    let mut stream = graph.execute(query(&q)).await?;
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
         WHERE r.time < datetime('{}') AND {}
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
