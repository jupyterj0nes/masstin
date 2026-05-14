// cred-rotation detector. A single source host that uses many distinct user
// identities in the investigation window is the canonical pass-the-hash /
// credential-spraying signature: the attacker has dumped multiple sets of
// credentials and is probing which ones still work, or pivoting through
// each of them in sequence.
//
// We count distinct relationship types (= distinct usernames) per source
// host in the window. A normal user has 1-2 identities at most (their
// own account, sometimes a service account); a script that sprays
// credentials often uses 5+ different accounts inside a minute.
//
// Requires ungrouped data — in grouped mode the count() distinct on
// rel-type collapses across the entire baseline and we lose the
// "happened in the window" signal.

use crate::graph_hunt::baseline::Baseline;
use crate::graph_hunt::detectors::Finding;
use futures::stream::*;
use neo4rs::*;

/// Minimum number of distinct users a single source host must employ in
/// the window before we surface it. Three is the canonical DFIR threshold
/// for "rotating creds": one alternate account is common, two is unusual,
/// three is almost always operator-driven.
const MIN_USERS: i64 = 3;

pub async fn run(graph: &Graph, bl: &Baseline) -> Vec<Finding> {
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    let q = format!(
        "MATCH (a:host)-[r]->(b:host)
         WHERE r.time >= localDateTime('{cutoff}')
         WITH a.name AS source,
              collect(DISTINCT type(r)) AS users,
              count(DISTINCT type(r)) AS user_count,
              min(r.time) AS t_min,
              max(r.time) AS t_max,
              collect(DISTINCT b.name) AS destinations
         WHERE user_count >= {min_users}
         RETURN source, users, user_count, destinations,
                toString(t_min) AS first_event,
                toString(t_max) AS last_event
         ORDER BY user_count DESC",
        cutoff = cutoff_str,
        min_users = MIN_USERS,
    );

    let mut findings: Vec<Finding> = Vec::new();
    let mut stream = match graph.execute(query(&q)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [cred-rotation] query failed: {}", e);
            return findings;
        }
    };

    loop {
        match stream.next().await {
            Ok(Some(row)) => {
                let source: String = row.get("source").unwrap_or_default();
                let users: Vec<String> = row.get("users").unwrap_or_default();
                let user_count: i64 = row.get("user_count").unwrap_or(0);
                let destinations: Vec<String> = row.get("destinations").unwrap_or_default();
                let first_event: String = row.get("first_event").unwrap_or_default();
                let last_event: String = row.get("last_event").unwrap_or_default();

                if source.is_empty() || user_count < MIN_USERS {
                    continue;
                }

                // Score saturates at 10 users — a host using 10+ identities
                // in the window is almost certainly automated. We map
                // [MIN_USERS, 10] linearly to [0.5, 1.0] so a borderline 3
                // doesn't dominate the ranking but still surfaces.
                let score = {
                    let lo = MIN_USERS as f64;
                    let hi = 10.0_f64;
                    let n = (user_count as f64).min(hi);
                    0.5 + 0.5 * ((n - lo) / (hi - lo)).max(0.0)
                };

                let users_display = users.join(", ");
                let dest_count = destinations.len();
                let summary = format!(
                    "Source '{source}' used {user_count} distinct users in the window \
                     ({first} .. {last}) across {dst_count} destination(s): {users_display}",
                    source = source,
                    user_count = user_count,
                    first = first_event,
                    last = last_event,
                    dst_count = dest_count,
                    users_display = users_display,
                );

                let snippet = format!(
                    "MATCH (a:host {{name: '{}'}})-[r]->(b:host) \
                     WHERE r.time >= localDateTime('{}') \
                     RETURN a, r, b",
                    source, cutoff_str
                );

                findings.push(Finding {
                    detector: "cred-rotation",
                    host: source,
                    time_window: format!("{} .. {}", first_event, last_event),
                    score,
                    summary,
                    cypher_snippet: snippet,
                });
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("  [cred-rotation] row read failed: {}", e);
                break;
            }
        }
    }

    findings
}
