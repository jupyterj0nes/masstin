// novel-edge detector. For every (origin, account, destination) combination
// seen in the investigation window, ask the one question that defines
// lateral movement at the topology level: has this exact triple ever
// occurred before the cutoff?
//
// Only authenticated logins with a real account are considered
// (`graph_hunt_common::auth_ok`): a refused or unauthenticated attempt is
// not a new relationship between two hosts, it is reported by
// `failed-sweep` instead. The window is aggregated per triple in Cypher, so
// a triple used 90 times is one finding with events=90, first..last time.
//
// The four context cases (which half of the triple was already known) are
// reported in the summary; the 3rd one — both sub-pairs known but never
// together — is the classic compromised-host + stolen-credential shape.
//
// Score: 1.0 per novel triple (+0.1 when the logon type is also new on the
// destination, as a tiebreaker only). Ranking against other detectors is
// done by the corroboration step in the report.

use crate::graph_hunt_common::{auth_ok, browser_snippet, Finding, NEO4J as D};
use crate::graph_hunt_neo4j::baseline::Baseline;
use futures::stream::*;
use neo4rs::*;

/// Context gates (see the long FP analysis in git history):
///  * destinations with fewer baseline events than this have thin history:
///    novelty there is reported with a reduced score (0.6), not dropped;
///  * origins whose baseline out-degree covers more than this fraction of
///    the estate are infrastructure (SCCM-style) rotating targets.
const MIN_BASELINE_EVENTS_AT_DEST: u64 = 50;
const MAX_ORIGIN_OUTDEGREE_FRACTION: f64 = 0.30;

pub async fn run(graph: &Graph, bl: &Baseline) -> Vec<Finding> {
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();
    let host_count = bl.destination_count() as f64;

    let q = format!(
        "MATCH (a:host)-[r]->(b:host)
         WHERE r.time >= {t} AND {ok}
         RETURN a.name AS origin, b.name AS destination, type(r) AS user,
                collect(DISTINCT toString(r.logon_type)) AS logon_types,
                toString(min(r.time)) AS first_time,
                toString(max(r.time)) AS last_time,
                count(*) AS n",
        t = D.t(&cutoff_str),
        ok = auth_ok("r"),
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
                let logon_types: Vec<String> = row.get("logon_types").unwrap_or_default();
                let first_time: String = row.get("first_time").unwrap_or_default();
                let last_time: String = row.get("last_time").unwrap_or_default();
                let n: i64 = row.get("n").unwrap_or(1);

                if origin.is_empty() || destination.is_empty() || user.is_empty() {
                    continue;
                }
                if bl.is_known_triple(&origin, &user, &destination) {
                    continue;
                }
                // Thin destination history (new host, truncated collection,
                // rotated logs): novelty there is weaker evidence, but it is
                // still reported — silently dropping it hid a brand-new
                // account on a host whose collection came in truncated.
                let dest_events = bl.baseline_event_count_for_dest(&destination);
                let thin_dest = dest_events < MIN_BASELINE_EVENTS_AT_DEST;
                let origin_outdeg = bl.outgoing_degree(&origin) as f64;
                // Rotation = a known account of an infrastructure origin reaching
                // one more host. A NEW account on such an origin is not rotation.
                if origin_outdeg / host_count > MAX_ORIGIN_OUTDEGREE_FRACTION
                    && bl.origin_used_account(&origin, &user)
                {
                    continue;
                }

                let logon_type = logon_types.first().cloned().unwrap_or_default();
                let type_novel = logon_types.iter().any(|lt| !bl.is_logon_type_known_for(&destination, lt));
                let score = if thin_dest { 0.6 } else if type_novel { 1.1 } else { 1.0 };

                let context = match (bl.is_known_edge(&origin, &destination), bl.is_user_known_for(&destination, &user)) {
                    (false, false) => "neither (origin,dest) nor (user,dest) had baseline history",
                    (true, false) => "(origin,dest) existed in baseline but user never reached this destination",
                    (false, true) => "user reached this destination from elsewhere but never from this origin",
                    (true, true) => "both sub-pairs existed in baseline but never as the same event \
                                     (classic compromised-host + stolen-cred signature)",
                };

                let summary = format!(
                    "{} -> {} as user='{}' logon_type='{}' (events={}). Triple novel: {}.{}",
                    origin, destination, user, logon_type, n, context,
                    if type_novel { " Logon type also unprecedented on this destination." } else { "" },
                );
                let summary = if thin_dest {
                    format!("{} Destination has only {} baseline events (thin history: weaker evidence).", summary, dest_events)
                } else {
                    summary
                };

                let snippet = browser_snippet(&D, &origin, Some(&destination), Some(&user), &first_time, Some(&last_time));

                findings.push(Finding {
                    detector: "novel-edge",
                    host: destination,
                    origin,
                    account: user,
                    time_window: format!("{} .. {}", first_time, last_time),
                    score,
                    events: n.max(1) as u64,
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
