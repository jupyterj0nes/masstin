// cred-rotation detector. A single source host that suddenly starts
// using identities it never used before is the canonical pass-the-hash /
// credential-spraying signature: the attacker has dumped credentials and
// is probing which ones still work or pivoting through each in sequence.
//
// Two thresholds, both must trip:
//   1. >= MIN_USERS distinct users from this source in the window
//      ("rotation" pattern — one alternate account is common, two is
//      unusual, three+ is operator-driven).
//   2. >= MIN_NOVEL_USERS of those users are NEW for this source vs the
//      baseline. This is what cuts the canonical FP class: an
//      infrastructure source (SCCM, monitoring, backup) using its
//      stable set of service accounts every day — high `user_count`
//      but all known, no novelty, not an attack. An attacker using
//      stolen identities will show novel users because those accounts
//      have no prior history from the attacker's beachhead.
//
// Requires ungrouped data — in grouped mode the count() distinct on
// rel-type collapses across the entire baseline and we lose the
// "happened in the window" signal.

use crate::graph_hunt::baseline::Baseline;
use crate::graph_hunt::detectors::Finding;
use futures::stream::*;
use neo4rs::*;
use std::collections::{HashMap, HashSet};

/// Minimum number of distinct users a single source host must employ in
/// the window before we surface it. Three is the canonical DFIR threshold
/// for "rotating creds".
const MIN_USERS: i64 = 3;

/// Minimum number of those users that must be NEW for this source
/// compared to its baseline behavior. Two means: at least two of the
/// accounts seen in the window were never used from this source in the
/// 90 days before the cutoff. Catches genuine cred-theft scenarios
/// without lighting up infrastructure that legitimately uses its full
/// service-account set every day.
const MIN_NOVEL_USERS: i64 = 2;

pub async fn run(graph: &Graph, bl: &Baseline) -> Vec<Finding> {
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    // Per-source baseline user set — fetched in one round-trip and held
    // in memory. The map is small (typically dozens of sources, each with
    // 1-10 users) so this is cheap.
    let baseline_users = match fetch_baseline_users_by_source(graph, &cutoff_str).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("  [cred-rotation] baseline users query failed: {}", e);
            return Vec::new();
        }
    };

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
            eprintln!("  [cred-rotation] window query failed: {}", e);
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

                // Novelty gate: which window users were never used from this
                // source in the baseline?
                let empty_set: HashSet<String> = HashSet::new();
                let baseline_for_source =
                    baseline_users.get(&source).unwrap_or(&empty_set);
                let novel_users: Vec<&String> = users
                    .iter()
                    .filter(|u| !baseline_for_source.contains(*u))
                    .collect();
                if (novel_users.len() as i64) < MIN_NOVEL_USERS {
                    continue;
                }

                // Score: map (window-user-count, novel-user-count) into
                // [0.5, 1.0]. The novel count weighs more — pure-novel
                // rotations are the strongest signal. Cap saturation at
                // 10 users / 8 novel.
                let novel_count = novel_users.len() as f64;
                let score = {
                    let user_part =
                        0.3 * ((user_count as f64 - MIN_USERS as f64) / (10.0 - MIN_USERS as f64))
                            .clamp(0.0, 1.0);
                    let novel_part =
                        0.5 + 0.2 * ((novel_count - MIN_NOVEL_USERS as f64) / 6.0).clamp(0.0, 1.0);
                    user_part + novel_part
                };

                let users_display = users.join(", ");
                let novel_display: Vec<&str> =
                    novel_users.iter().map(|s| s.as_str()).collect();
                let dest_count = destinations.len();
                let summary = format!(
                    "Source '{source}' used {user_count} distinct users in the window \
                     ({first} .. {last}) across {dst_count} destination(s); \
                     {novel} of them never seen from this source in baseline. \
                     Users: [{users_display}]. Novel: [{novel_list}].",
                    source = source,
                    user_count = user_count,
                    first = first_event,
                    last = last_event,
                    dst_count = dest_count,
                    novel = novel_users.len(),
                    users_display = users_display,
                    novel_list = novel_display.join(", "),
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

/// Fetch per-source set of usernames (= rel types) seen in the baseline.
/// Returns map: source_host -> set of usernames it used before cutoff.
async fn fetch_baseline_users_by_source(
    graph: &Graph,
    cutoff_str: &str,
) -> neo4rs::Result<HashMap<String, HashSet<String>>> {
    let q = format!(
        "MATCH (a:host)-[r]->()
         WHERE r.time < localDateTime('{}')
         RETURN a.name AS source, collect(DISTINCT type(r)) AS users",
        cutoff_str
    );
    let mut stream = graph.execute(query(&q)).await?;
    let mut out: HashMap<String, HashSet<String>> = HashMap::new();
    while let Some(row) = stream.next().await? {
        let source: String = row.get("source").unwrap_or_default();
        let users: Vec<String> = row.get("users").unwrap_or_default();
        if source.is_empty() {
            continue;
        }
        out.insert(source, users.into_iter().collect());
    }
    Ok(out)
}
