// novel-edge detector. For every edge in the investigation window, check
// three independent novelty axes against the baseline:
//
//   1. The (origin, destination) host pair never appeared before.
//   2. The user (rel type) was never seen logging into this destination.
//   3. The logon type was never seen on this destination.
//
// An edge fires the detector when ANY of the three axes is novel. The score
// is the number of novel axes divided by 3, so a fully unprecedented event
// (new pair + new user + new logon type) lands at 1.0 and a single-axis
// novelty at ~0.33.
//
// Works identically in grouped and ungrouped graphs — the only difference is
// that in grouped mode each "event" carries the earliest_date timestamp plus
// a count, so a single novel edge may represent many original log lines.

use crate::graph_hunt::baseline::Baseline;
use crate::graph_hunt::detectors::Finding;
use futures::stream::*;
use neo4rs::*;

pub async fn run(graph: &Graph, bl: &Baseline) -> Vec<Finding> {
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    let q = format!(
        "MATCH (a:host)-[r]->(b:host)
         WHERE r.time >= localDateTime('{}')
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

                if origin.is_empty() || destination.is_empty() {
                    continue;
                }

                let pair_novel = !bl.is_known_edge(&origin, &destination);
                let user_novel = !bl.is_user_known_for(&destination, &user);
                let type_novel = !bl.is_logon_type_known_for(&destination, &logon_type);

                let novel_count =
                    pair_novel as u32 + user_novel as u32 + type_novel as u32;
                if novel_count == 0 {
                    continue;
                }

                let score = novel_count as f64 / 3.0;

                let mut reasons: Vec<String> = Vec::new();
                if pair_novel {
                    reasons.push(format!("origin→destination pair never seen before cutoff"));
                }
                if user_novel {
                    reasons.push(format!(
                        "user '{}' never logged into '{}' before cutoff",
                        user, destination
                    ));
                }
                if type_novel {
                    reasons.push(format!(
                        "logon_type '{}' never seen on '{}' before cutoff",
                        logon_type, destination
                    ));
                }

                let summary = format!(
                    "{} -> {} as user='{}' logon_type='{}' (count={}). Novel: {}",
                    origin,
                    destination,
                    user,
                    logon_type,
                    if event_count.is_empty() { "?".into() } else { event_count },
                    reasons.join("; ")
                );

                let snippet = format!(
                    "MATCH (a:host {{name: '{}'}})-[r:{}]->(b:host {{name: '{}'}}) \
                     WHERE r.time = localDateTime('{}') RETURN a, r, b",
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
