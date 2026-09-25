// Baseline computation for graph-hunt. Issues a small set of aggregation
// queries against the graph, restricted to events strictly before the cutoff,
// and builds the in-memory reference distributions consulted by every
// non-temporal detector (novel-edge, community-bridge, rare-logon-type).
//
// The baseline is intentionally NOT persisted to disk in this iteration. The
// project ships a single binary, the queries themselves are inexpensive
// compared to the graph load that precedes them, and adding a Parquet cache
// before we know the detector shape is final would be premature.

use crate::graph_hunt::schema::GraphMode;
use chrono::{DateTime, Utc};
use futures::stream::*;
use neo4rs::*;
use crate::graph_hunt_common::{auth_ok, is_series};
use std::collections::{HashMap, HashSet};

/// Stats for a single (origin, destination) host pair seen in the baseline
/// window. The detectors compare incoming investigation-window edges against
/// these sets — any value not in the set is "novel" for that pair.
#[derive(Debug, Default)]
pub struct EdgePairBaseline {
    pub users: HashSet<String>,
    pub logon_types: HashSet<String>,
    pub event_count: u64,
}

/// Stats for an individual host. The "in" half captures everything that
/// logged into this host during the baseline (who, from where, what logon
/// type); the "out" half captures every host this one talked to.
#[derive(Debug, Default)]
pub struct HostBaseline {
    pub incoming_users: HashSet<String>,
    pub incoming_sources: HashSet<String>,
    pub incoming_logon_types: HashSet<String>,
    pub outgoing_destinations: HashSet<String>,
}

/// Stats for a single user identity. Captures which destination hosts that
/// user ever reached and which logon types they used.
#[derive(Debug, Default)]
pub struct UserBaseline {
    pub hosts: HashSet<String>,
    pub logon_types: HashSet<String>,
}

#[derive(Debug)]
pub struct Baseline {
    pub cutoff: DateTime<Utc>,
    pub mode: GraphMode,
    pub edges_in_baseline: u64,
    pub edges_in_window: u64,
    pub edge_pairs: HashMap<(String, String), EdgePairBaseline>,
    pub hosts: HashMap<String, HostBaseline>,
    pub users: HashMap<String, UserBaseline>,
    /// Set of distinct (origin, user, destination) triples observed in the
    /// baseline. Used by the refactored `novel-edge` to fire on triples
    /// never seen pre-cutoff — strictly tighter than the original 3-axis
    /// OR test and captures the classic compromised-host + stolen-cred
    /// signature (both sub-pairs in baseline but never as the same event).
    pub triples: HashSet<(String, String, String)>,
    /// Per-destination total baseline event count, precomputed for O(1)
    /// lookup. Powers novel-edge and community-bridge context gates —
    /// destinations with too few baseline events have unreliable novelty
    /// signal regardless of how the detector's structural test fires.
    pub dest_event_count: HashMap<String, u64>,
}

impl Baseline {
    pub fn is_known_edge(&self, origin: &str, destination: &str) -> bool {
        self.edge_pairs
            .contains_key(&(origin.to_string(), destination.to_string()))
    }

    pub fn is_user_known_for(&self, destination: &str, user: &str) -> bool {
        match self.hosts.get(destination) {
            Some(h) => h.incoming_users.contains(user),
            None => false,
        }
    }

    pub fn is_logon_type_known_for(&self, destination: &str, logon_type: &str) -> bool {
        match self.hosts.get(destination) {
            Some(h) => h.incoming_logon_types.contains(logon_type),
            None => false,
        }
    }

    pub fn is_source_known_for(&self, destination: &str, source: &str) -> bool {
        match self.hosts.get(destination) {
            Some(h) => h.incoming_sources.contains(source),
            None => false,
        }
    }

    /// Triple-novelty check: did the (origin, user, destination) combo
    /// occur even once before the cutoff? Mirrors the Neo4j variant.
    pub fn is_known_triple(&self, origin: &str, user: &str, destination: &str) -> bool {
        self.triples.contains(&(
            origin.to_string(),
            user.to_string(),
            destination.to_string(),
        ))
    }

    /// Total baseline event count landing at a given destination. O(1)
    /// lookup. Returns 0 for destinations with no baseline presence.
    pub fn baseline_event_count_for_dest(&self, destination: &str) -> u64 {
        self.dest_event_count.get(destination).copied().unwrap_or(0)
    }

    /// Baseline out-degree of an origin host — distinct destinations
    /// reached before the cutoff. Used as proxy for "talks to everything"
    /// service/infrastructure hosts in context-gate suppression.
    pub fn outgoing_degree(&self, origin: &str) -> usize {
        self.hosts
            .get(origin)
            .map(|h| h.outgoing_destinations.len())
            .unwrap_or(0)
    }

    /// Total distinct hosts in baseline. Denominator for out-degree
    /// fraction comparisons. Floored at 1 so the caller's division
    /// never blows up on a degenerately empty baseline.
    pub fn host_count(&self) -> usize {
        self.hosts.len().max(1)
    }
}

/// Format a DateTime<Utc> as Memgraph's `localDateTime()` string. The loader
/// stores timestamps with no timezone (see src/load_memgraph.rs::strip_timezone),
/// so the baseline cutoff must follow the same shape: `YYYY-MM-DDTHH:MM:SS`.
fn cutoff_to_memgraph(cutoff: DateTime<Utc>) -> String {
    cutoff.format("%Y-%m-%dT%H:%M:%S").to_string()
}

pub async fn compute(
    graph: &Graph,
    cutoff: DateTime<Utc>,
    mode: GraphMode,
) -> neo4rs::Result<Baseline> {
    let cutoff_str = cutoff_to_memgraph(cutoff);

    // 1. Edge count split (baseline vs window).
    let edges_in_baseline = count_edges(graph, &cutoff_str, true).await?;
    let edges_in_window = count_edges(graph, &cutoff_str, false).await?;

    crate::banner::print_phase_detail(
        "Baseline edges:",
        &format!("{} events before {}", edges_in_baseline, cutoff_str),
    );
    crate::banner::print_phase_detail(
        "Window edges:",
        &format!("{} events at or after cutoff", edges_in_window),
    );
    if let Err(e) = crate::graph_hunt_common::check_coverage(graph, &crate::graph_hunt_common::MEMGRAPH, cutoff).await {
        crate::banner::print_warning(&format!("Coverage check failed: {}", e));
    }

    // 2. (origin, destination) pair stats.
    let edge_pairs = fetch_edge_pairs(graph, &cutoff_str).await?;

    // 3. Per-host incoming/outgoing stats, the (origin, user, destination)
    //    triple set, AND the per-destination total event count — all
    //    derived from the edge_pairs aggregation above with no extra
    //    round-trip. Each pair entry already carries the DISTINCT users
    //    seen on that pair; cross-joining pair with users yields the
    //    triple set; summing pair.event_count by destination yields the
    //    density map for context gates.
    let mut hosts: HashMap<String, HostBaseline> = HashMap::new();
    let mut triples: HashSet<(String, String, String)> = HashSet::new();
    let mut dest_event_count: HashMap<String, u64> = HashMap::new();
    for ((origin, destination), stats) in &edge_pairs {
        let host_in = hosts.entry(destination.clone()).or_default();
        for u in &stats.users {
            host_in.incoming_users.insert(u.clone());
            triples.insert((origin.clone(), u.clone(), destination.clone()));
        }
        for lt in &stats.logon_types {
            host_in.incoming_logon_types.insert(lt.clone());
        }
        host_in.incoming_sources.insert(origin.clone());

        let host_out = hosts.entry(origin.clone()).or_default();
        host_out.outgoing_destinations.insert(destination.clone());

        *dest_event_count.entry(destination.clone()).or_insert(0) += stats.event_count;
    }

    // 4. Per-user stats (label of the relationship is the username).
    let users = fetch_user_stats(graph, &cutoff_str).await?;

    crate::banner::print_phase_detail(
        "Baseline shape:",
        &format!(
            "{} edge-pairs, {} hosts, {} users, {} triples",
            edge_pairs.len(),
            hosts.len(),
            users.len(),
            triples.len(),
        ),
    );

    Ok(Baseline {
        cutoff,
        mode,
        edges_in_baseline,
        edges_in_window,
        edge_pairs,
        hosts,
        users,
        triples,
        dest_event_count,
    })
}

async fn count_edges(graph: &Graph, cutoff_str: &str, before: bool) -> neo4rs::Result<u64> {
    let op = if before { "<" } else { ">=" };
    let q = format!(
        "MATCH ()-[r]->() WHERE r.time {} localDateTime('{}') RETURN count(r) AS c",
        op, cutoff_str
    );
    let mut stream = graph.execute(query(&q)).await?;
    match stream.next().await? {
        Some(row) => {
            let c: i64 = row.get("c").unwrap_or(0);
            Ok(c.max(0) as u64)
        }
        None => Ok(0),
    }
}

async fn fetch_edge_pairs(
    graph: &Graph,
    cutoff_str: &str,
) -> neo4rs::Result<HashMap<(String, String), EdgePairBaseline>> {
    let q = format!(
        "MATCH (a:host)-[r]->(b:host)
         WHERE r.time < localDateTime('{}') AND {}
         RETURN a.name AS origin,
                b.name AS destination,
                collect(DISTINCT type(r)) AS users,
                collect(DISTINCT toString(r.logon_type)) AS logon_types,
                count(CASE WHEN {} THEN 1 END) AS freq",
        cutoff_str, auth_ok("r"), is_series("r")
    );

    let mut stream = graph.execute(query(&q)).await?;
    let mut out: HashMap<(String, String), EdgePairBaseline> = HashMap::new();

    while let Some(row) = stream.next().await? {
        let origin: String = row.get("origin").unwrap_or_default();
        let destination: String = row.get("destination").unwrap_or_default();
        let users: Vec<String> = row.get("users").unwrap_or_default();
        let logon_types: Vec<String> = row.get("logon_types").unwrap_or_default();
        let freq: i64 = row.get("freq").unwrap_or(0);

        if origin.is_empty() || destination.is_empty() {
            continue;
        }

        let entry = out
            .entry((origin, destination))
            .or_insert_with(EdgePairBaseline::default);
        entry.users.extend(users);
        entry.logon_types.extend(logon_types);
        entry.event_count = freq.max(0) as u64;
    }

    Ok(out)
}

async fn fetch_user_stats(
    graph: &Graph,
    cutoff_str: &str,
) -> neo4rs::Result<HashMap<String, UserBaseline>> {
    let q = format!(
        "MATCH (a:host)-[r]->(b:host)
         WHERE r.time < localDateTime('{}') AND {}
         RETURN type(r) AS user,
                collect(DISTINCT b.name) AS hosts,
                collect(DISTINCT toString(r.logon_type)) AS logon_types",
        cutoff_str, auth_ok("r")
    );

    let mut stream = graph.execute(query(&q)).await?;
    let mut out: HashMap<String, UserBaseline> = HashMap::new();

    while let Some(row) = stream.next().await? {
        let user: String = row.get("user").unwrap_or_default();
        let hosts: Vec<String> = row.get("hosts").unwrap_or_default();
        let logon_types: Vec<String> = row.get("logon_types").unwrap_or_default();
        if user.is_empty() {
            continue;
        }
        let entry = out.entry(user).or_insert_with(UserBaseline::default);
        entry.hosts.extend(hosts);
        entry.logon_types.extend(logon_types);
    }

    Ok(out)
}
