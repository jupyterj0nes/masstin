// Baseline computation for graph-hunt. Issues a small set of aggregation
// queries against the graph, restricted to events strictly before the cutoff,
// and builds the in-memory reference distributions consulted by every
// non-temporal detector (novel-edge, community-bridge, rare-logon-type).
//
// The baseline is intentionally NOT persisted to disk in this iteration. The
// project ships a single binary, the queries themselves are inexpensive
// compared to the graph load that precedes them, and adding a Parquet cache
// before we know the detector shape is final would be premature.

use crate::graph_hunt_neo4j::schema::GraphMode;
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
    /// baseline. Used by `novel-edge` to fire on triples never seen
    /// pre-cutoff — a strictly tighter notion than the original 3-axis
    /// disjunctive test, and the most direct expression of "actor pattern
    /// novelty" for lateral movement: a triple is novel exactly when the
    /// (who, from where, to where) combination is unprecedented, regardless
    /// of which sub-pair happens to be the new bit. The logon-type axis
    /// the old detector carried is now owned by the dedicated
    /// `rare-logon-type` detector — cleaner separation of responsibilities.
    pub triples: HashSet<(String, String, String)>,
    /// Per-destination total baseline event count, precomputed for O(1)
    /// lookup. Powers novel-edge's destination-density gate (a
    /// destination with too few baseline events has unreliable novelty
    /// signal regardless of how the detector's triple test fires).
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
    /// occur even once before the cutoff? Used by the refactored
    /// `novel-edge` detector. Strictly tighter than the 3-axis OR test it
    /// replaces — handles the "both sub-pairs known but never together"
    /// case (classic lateral-movement signature: attacker on compromised
    /// host using stolen creds to reach a known target).
    pub fn is_known_triple(&self, origin: &str, user: &str, destination: &str) -> bool {
        self.triples.contains(&(
            origin.to_string(),
            user.to_string(),
            destination.to_string(),
        ))
    }

    /// Total baseline event count landing at a given destination —
    /// summed across every (origin, destination) pair that targeted it
    /// before the cutoff. Used by novel-edge's context gate: a
    /// destination with too few baseline events is one where baseline
    /// coverage is too sparse to make "novelty" meaningful (newly
    /// onboarded host, host whose retention window dropped most of its
    /// past, etc.). Returns 0 for destinations with no baseline presence.
    /// Backed by the precomputed `dest_event_count` map — O(1).
    pub fn baseline_event_count_for_dest(&self, destination: &str) -> u64 {
        self.dest_event_count.get(destination).copied().unwrap_or(0)
    }

    /// Baseline out-degree of an origin host — number of distinct
    /// destinations it touched before the cutoff. Used by novel-edge's
    /// context gate: an origin that talked to a huge fraction of the
    /// estate in baseline (services, monitoring agents, very-active
    /// admins) generates new triples as a matter of operational
    /// rotation, not anomaly.
    pub fn outgoing_degree(&self, origin: &str) -> usize {
        self.hosts
            .get(origin)
            .map(|h| h.outgoing_destinations.len())
            .unwrap_or(0)
    }

    /// Total number of distinct hosts seen in the baseline. Used as the
    /// denominator when comparing an origin's out-degree to "fraction
    /// of the estate". Falls back to 1 if the baseline is empty so the
    /// caller's division never blows up.
    pub fn host_count(&self) -> usize {
        self.hosts.len().max(1)
    }

    /// Hosts that received at least one authenticated login before the
    /// cutoff. This, not host_count (origins + destinations), is the
    /// denominator for "what fraction of the estate does this origin
    /// reach": in a collected-logs corpus there are hundreds of origins
    /// and a few dozen destinations, and dividing by all nodes made the
    /// fraction unable to exceed a few percent.
    /// Did this origin log in with this account (anywhere) before the cutoff?
    pub fn origin_used_account(&self, origin: &str, user: &str) -> bool {
        self.edge_pairs
            .iter()
            .any(|((o, _), st)| o == origin && st.users.contains(user))
    }

    pub fn destination_count(&self) -> usize {
        self.hosts.values().filter(|h| !h.incoming_sources.is_empty()).count().max(1)
    }
}

/// Format a DateTime<Utc> as Memgraph's `datetime()` string. The loader
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
    if let Err(e) = crate::graph_hunt_common::check_coverage(graph, &crate::graph_hunt_common::NEO4J, cutoff).await {
        crate::banner::print_warning(&format!("Coverage check failed: {}", e));
    }

    // 2. (origin, destination) pair stats.
    let edge_pairs = fetch_edge_pairs(graph, &cutoff_str).await?;

    // 3. Per-host incoming/outgoing stats, the (origin, user, destination)
    //    triple set, AND the per-destination total event count — all
    //    derived from the edge_pairs aggregation above, no extra
    //    round-trip needed. Each pair entry already carries the
    //    DISTINCT users seen on that pair in baseline; cross-joining
    //    pair with users yields the triple set; summing pair.event_count
    //    by destination yields the density map that novel-edge's
    //    context gate needs.
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
        "MATCH ()-[r]->() WHERE r.time {} datetime('{}') RETURN count(r) AS c",
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
         WHERE r.time < datetime('{}') AND {}
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
         WHERE r.time < datetime('{}') AND {}
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
