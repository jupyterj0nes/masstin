// novel-edge detector. Triple-novelty variant: for every edge in the
// investigation window, ask the single direct question that defines
// lateral movement at the topology level — has this exact (origin, user,
// destination) combination ever occurred before the cutoff?
//
// The earlier 3-axis OR-disjunction (pair-novel | user-novel |
// logon-type-novel) produced a noisy long tail at scale because each
// axis fires independently and the dominant cause of single-axis
// novelty at 200+ hosts is steady-state operational churn (admin
// touching a previously-untouched server, service account onboarded to
// a new host, etc.). The triple test eliminates that noise and adds a
// case the old detector missed entirely: both (origin, dest) and (user,
// dest) exist in baseline but never as the same event — exactly the
// fingerprint of an attacker on a compromised host using a stolen
// credential to reach a known target.
//
// Logon-type novelty is no longer this detector's responsibility. The
// dedicated `rare-logon-type` detector handles it with destination-class
// stratification and per-(origin, dest, user, type) deduplication —
// signals that don't fit naturally into a generic "novel edge" score.
//
// Score: 1.0 for a triple-novel edge. As a tiebreaker only, +0.1 if the
// logon_type observed on this edge is also unprecedented on the
// destination — pushes the most novel events above pure-triple ones in
// the ranking without introducing a separate firing rule.

use crate::graph_hunt_neo4j::baseline::Baseline;
use crate::graph_hunt_neo4j::detectors::Finding;
use futures::stream::*;
use neo4rs::*;

/// Context gate thresholds. These suppress two classes of residual
/// false positive that survive the triple-novelty test on realistic
/// enterprise corpora at scale:
///
///   * "Sparse baseline" destinations: hosts that have so few baseline
///     events that the absence of a triple is a coverage artifact (newly
///     onboarded host, log retention dropped most history) rather than
///     an anomaly. We require at least MIN_BASELINE_EVENTS_AT_DEST
///     events landing at the destination before novelty there is
///     statistically interesting.
///
///   * "Talks to everything" origins: hosts whose baseline out-degree
///     covers a large fraction of the estate — services, monitoring
///     agents, very-active admin workstations. New triples from these
///     origins are operational rotation, not lateral movement signal.
///     Filtering at MAX_ORIGIN_OUTDEGREE_FRACTION of total hosts catches
///     SCCM-style fan-out without affecting typical workstations
///     (which touch <15% of the estate at most).
const MIN_BASELINE_EVENTS_AT_DEST: u64 = 50;
const MAX_ORIGIN_OUTDEGREE_FRACTION: f64 = 0.30;

pub async fn run(graph: &Graph, bl: &Baseline) -> Vec<Finding> {
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();
    let host_count = bl.host_count() as f64;

    let q = format!(
        "MATCH (a:host)-[r]->(b:host)
         WHERE r.time >= datetime('{}')
         RETURN a.name AS origin,
                b.name AS destination,
                type(r) AS user,
                toString(r.logon_type) AS logon_type,
                toString(r.time) AS event_time,
                toString(r.count) AS event_count",
        cutoff_str
    );

    let mut findings: Vec<Finding> = Vec::new();
    let mut stream = match graph.execute(query(&q)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [novel-edge] query failed: {}", e);
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
                let event_count: String = row.get("event_count").unwrap_or_default();

                if origin.is_empty() || destination.is_empty() || user.is_empty() {
                    continue;
                }

                if bl.is_known_triple(&origin, &user, &destination) {
                    continue;
                }

                // Context gate 1: destination must have enough baseline
                // events to make novelty meaningful. Below the threshold,
                // a "novel" triple is more likely a coverage artifact
                // than an anomaly.
                if bl.baseline_event_count_for_dest(&destination) < MIN_BASELINE_EVENTS_AT_DEST {
                    continue;
                }

                // Context gate 2: origin must not be a "talks to
                // everything" host (services / monitoring / very-active
                // admins). New triples from those are rotation, not
                // signal. We compare against the full baseline host
                // population so the threshold is corpus-agnostic.
                let origin_outdeg = bl.outgoing_degree(&origin) as f64;
                if origin_outdeg / host_count > MAX_ORIGIN_OUTDEGREE_FRACTION {
                    continue;
                }

                // Triple is novel — fire at base score 1.0. Tiebreaker: if
                // the logon_type is also new on the destination, bump
                // slightly so the most surprising events float above
                // triple-only ones in the ranking. Bump is small on purpose:
                // logon-type novelty is owned by rare-logon-type and we
                // don't want to double-count it as a firing rule here.
                let type_novel = !bl.is_logon_type_known_for(&destination, &logon_type);
                let score = if type_novel { 1.1 } else { 1.0 };

                let pair_was_known = bl.is_known_edge(&origin, &destination);
                let user_was_known = bl.is_user_known_for(&destination, &user);
                let context = match (pair_was_known, user_was_known) {
                    (false, false) => "neither (origin,dest) nor (user,dest) had baseline history",
                    (true, false) => "(origin,dest) existed in baseline but user never reached this destination",
                    (false, true) => "user reached this destination from elsewhere but never from this origin",
                    (true, true) => "both sub-pairs existed in baseline but never as the same event \
                                     (classic compromised-host + stolen-cred signature)",
                };

                let summary = format!(
                    "{} -> {} as user='{}' logon_type='{}' (count={}). \
                     Triple novel: {}.{}",
                    origin,
                    destination,
                    user,
                    logon_type,
                    if event_count.is_empty() { "?".into() } else { event_count },
                    context,
                    if type_novel {
                        " Logon-type also unprecedented on this destination (tiebreaker bump)."
                    } else {
                        ""
                    },
                );

                let snippet = format!(
                    "MATCH (a:host {{name: '{}'}})-[r:{}]->(b:host {{name: '{}'}}) \
                     WHERE r.time = datetime('{}') RETURN a, r, b",
                    origin,
                    sanitize_label(&user),
                    destination,
                    event_time
                );

                findings.push(Finding {
                    detector: "novel-edge",
                    host: destination,
                    time_window: event_time,
                    score,
                    summary,
                    cypher_snippet: snippet,
                });
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("  [novel-edge] row read failed: {}", e);
                break;
            }
        }
    }

    findings
}

/// Mirror the relationship-label sanitization the loader applies (see
/// src/load_memgraph.rs around the rel_type_normalized block). Without this
/// the Cypher snippet we emit would parse-error for usernames that contain
/// `$`, `.`, hyphens, etc. — exactly the case for machine accounts and
/// service principals.
fn sanitize_label(user: &str) -> String {
    let stripped = user.split('@').next().unwrap_or(user);
    let mut s: String = stripped
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        s = format!("u{}", s);
    }
    if s.is_empty() {
        s = "NO_USER".to_string();
    }
    s.to_uppercase()
}
