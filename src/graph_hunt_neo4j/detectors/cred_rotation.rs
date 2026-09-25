// cred-rotation detector. A single source host that starts using
// identities it never used before is the canonical pass-the-hash /
// credential-spraying signature.
//
// Both thresholds must trip:
//   1. >= MIN_USERS distinct ACCOUNTS from this source in the window;
//   2. >= MIN_NOVEL_USERS of them never used from this source before the
//      cutoff.
// Accounts are relationship types other than the no-account ones
// (`NO_USER`, `_UNKNOWN_`): an unauthenticated connection is not an
// identity and must not count as one. Failed attempts DO count — trying an
// account is using it, which is the point of spraying.
//
// Requires ungrouped data.

use crate::graph_hunt_common::{browser_snippet, Finding, NEO4J as D, NO_ACCOUNT_TYPES};
use crate::graph_hunt_neo4j::baseline::Baseline;
use futures::stream::*;
use neo4rs::*;
use std::collections::{HashMap, HashSet};

const MIN_USERS: i64 = 3;
const MIN_NOVEL_USERS: i64 = 2;

pub async fn run(graph: &Graph, bl: &Baseline) -> Vec<Finding> {
    let cutoff_str = bl.cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    let baseline_users = match fetch_baseline_users_by_source(graph, &cutoff_str).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("  [cred-rotation] baseline users query failed: {}", e);
            return Vec::new();
        }
    };

    let q = format!(
        "MATCH (a:host)-[r]->(b:host)
         WHERE r.time >= {t} AND NOT type(r) IN {na}
         WITH a.name AS source,
              collect(DISTINCT type(r)) AS users,
              count(DISTINCT type(r)) AS user_count,
              count(*) AS n,
              min(r.time) AS t_min,
              max(r.time) AS t_max,
              collect(DISTINCT b.name) AS destinations
         WHERE user_count >= {min_users}
         RETURN source, users, user_count, n, destinations,
                toString(t_min) AS first_event,
                toString(t_max) AS last_event
         ORDER BY user_count DESC",
        t = D.t(&cutoff_str),
        na = NO_ACCOUNT_TYPES,
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
                let n: i64 = row.get("n").unwrap_or(1);
                let destinations: Vec<String> = row.get("destinations").unwrap_or_default();
                let first_event: String = row.get("first_event").unwrap_or_default();
                let last_event: String = row.get("last_event").unwrap_or_default();

                if source.is_empty() || user_count < MIN_USERS {
                    continue;
                }

                let empty_set: HashSet<String> = HashSet::new();
                let baseline_for_source = baseline_users.get(&source).unwrap_or(&empty_set);
                let novel_users: Vec<&String> = users.iter().filter(|u| !baseline_for_source.contains(*u)).collect();
                if (novel_users.len() as i64) < MIN_NOVEL_USERS {
                    continue;
                }

                // [0.5, 1.0]: novel accounts weigh more than the raw count.
                let novel_count = novel_users.len() as f64;
                let score = {
                    let user_part = 0.3 * ((user_count as f64 - MIN_USERS as f64) / (10.0 - MIN_USERS as f64)).clamp(0.0, 1.0);
                    let novel_part = 0.5 + 0.2 * ((novel_count - MIN_NOVEL_USERS as f64) / 6.0).clamp(0.0, 1.0);
                    user_part + novel_part
                };

                let summary = format!(
                    "Source '{source}' used {user_count} distinct accounts in the window \
                     ({first} .. {last}) across {dst_count} destination(s); \
                     {novel} of them never used from this source before the cutoff. \
                     Accounts: [{users_display}]. Novel: [{novel_list}].",
                    source = source,
                    user_count = user_count,
                    first = first_event,
                    last = last_event,
                    dst_count = destinations.len(),
                    novel = novel_users.len(),
                    users_display = users.join(", "),
                    novel_list = novel_users.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                );

                findings.push(Finding {
                    detector: "cred-rotation",
                    host: source.clone(),
                    origin: source.clone(),
                    account: String::new(),
                    time_window: format!("{} .. {}", first_event, last_event),
                    score,
                    events: n.max(1) as u64,
                    summary,
                    cypher_snippet: browser_snippet(&D, &source, None, None, &cutoff_str, None),
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

/// source -> accounts it used before the cutoff (no-account types excluded).
async fn fetch_baseline_users_by_source(
    graph: &Graph,
    cutoff_str: &str,
) -> neo4rs::Result<HashMap<String, HashSet<String>>> {
    let q = format!(
        "MATCH (a:host)-[r]->()
         WHERE r.time < {t} AND NOT type(r) IN {na}
         RETURN a.name AS source, collect(DISTINCT type(r)) AS users",
        t = D.t(cutoff_str),
        na = NO_ACCOUNT_TYPES,
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
