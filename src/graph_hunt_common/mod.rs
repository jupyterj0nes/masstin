// Shared pieces of graph-hunt used by every backend (Neo4j in
// `graph_hunt_neo4j`, Memgraph and timeline CSVs in `graph_hunt`). No
// server-side plugin (GDS, MAGE) is used: edges are read once and every
// statistic is computed in memory.
//
// Everything here speaks plain Cypher through neo4rs; the only dialect
// difference that matters is the temporal constructor (`datetime()` on
// Neo4j, `localDateTime()` on Memgraph) and whether APOC is available for
// Browser-ready virtual-graph snippets. Both are carried by `Dialect`.
//
// Contents:
//   * engine   — the statistical hunt (docs/graph-hunt-statistics.md)
//   * stats    — empirical p-values, Simes, Benjamini-Hochberg, hypergeometric
//   * algos    — PageRank, betweenness, Louvain (in memory)
//   * report   — analyst report, one story per origin (--report)
//   * resolve  — IP -> host name from same-login co-occurrence
//   * helpers  — account predicates, timestamp parsing, Browser snippets

use chrono::NaiveDateTime;

pub mod algos;
pub mod engine;
pub mod report;
pub mod resolve;
pub mod schema;
pub mod sigma;
pub mod stats;

// ───────────────────────────── Dialect ──────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct Dialect {
    /// Temporal constructor matching how the loader stored `r.time`.
    pub time_fn: &'static str,
    /// APOC available (Neo4j): snippets can build virtual graphs.
    pub apoc: bool,
}

pub const NEO4J: Dialect = Dialect { time_fn: "datetime", apoc: true };
pub const MEMGRAPH: Dialect = Dialect { time_fn: "localDateTime", apoc: false };

impl Dialect {
    /// `datetime('2026-09-20T00:00:00')` / `localDateTime('...')`.
    pub fn t(&self, s: &str) -> String {
        format!("{}('{}')", self.time_fn, s)
    }
}

// ─────────────────────────── edge predicates ────────────────────────────────

/// Relationship types the loaders use when there is no account: `NO_USER`
/// (empty user column) and `_UNKNOWN_` (auditd `acct="(unknown)"`, i.e. a
/// connection that never authenticated). They are not identities and must
/// not count as "an account" anywhere.
pub const NO_ACCOUNT_TYPES: &str = "['NO_USER','_UNKNOWN_']";

/// Which kinds of events a log family can show on a given day:
/// (logins, failures). lastlog holds one record per account and shows
/// neither; wtmp/utmp only record sessions that opened; btmp only
/// failures; everything else (secure, messages, audit, journal, evtx) both.
/// Unknown / empty families count as showing both.
pub fn coverage_kinds(family: &str) -> (bool, bool) {
    match family {
        "lastlog" => (false, false),
        "wtmp" | "utmp" => (true, false),
        "btmp" => (false, true),
        _ => (true, true),
    }
}

/// Merge [start, end] spans (seconds) into a sorted, non-overlapping list,
/// flattened as [s0, e0, s1, e1, ...] for storage as a node property.
pub fn merge_spans(mut v: Vec<(i64, i64)>) -> Vec<i64> {
    v.sort();
    let mut out: Vec<(i64, i64)> = Vec::new();
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if s <= last.1 => {
                if e > last.1 {
                    last.1 = e;
                }
            }
            _ => out.push((s, e)),
        }
    }
    out.into_iter().flat_map(|(s, e)| [s, e]).collect()
}

pub fn is_no_account(t: &str) -> bool {
    t == "NO_USER" || t == "_UNKNOWN_"
}

// ─────────────────────────── helpers ────────────────────────────────────────

/// Parse the string form of a stored timestamp from either backend:
/// `2026-09-23T15:35:09Z`, `...09.336951Z`, `...09+00:00`, Memgraph's
/// `2026-09-23T15:35:09.000000` (no zone).
pub fn parse_ts(s: &str) -> Option<NaiveDateTime> {
    let mut t = s.trim().trim_end_matches('Z').to_string();
    if let Some(i) = t.find('[') { t.truncate(i); }
    if let Some(tpos) = t.find('T') {
        if let Some(p) = t[tpos..].find(|c| c == '+' || c == '-') {
            t.truncate(tpos + p);
        }
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(&t, f) {
            return Some(dt);
        }
    }
    None
}


fn q(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Like `browser_snippet`, for a machine known under several node names
/// (an IP folded into its host name) and a set of destinations.
pub fn browser_snippet_multi(
    d: &Dialect,
    origins: &[String],
    dests: &[String],
    account: Option<&str>,
    from: &str,
    to: Option<&str>,
) -> String {
    let list = |v: &[String]| v.iter().map(|x| format!("'{}'", q(x))).collect::<Vec<_>>().join(", ");
    let from = from.trim_end_matches('Z');
    let mut w = vec![format!("a.name IN [{}]", list(origins)), format!("r.time >= {}", d.t(from))];
    if let Some(t) = to {
        w.push(format!("r.time < {}", d.t(t.trim_end_matches('Z'))));
    }
    if !dests.is_empty() {
        w.push(format!("b.name IN [{}]", list(dests)));
    }
    if let Some(a) = account {
        w.push(format!("type(r) = '{}'", q(a)));
    }
    let wh = w.join(" AND ");
    if d.apoc {
        format!(
            "MATCH (a:host)-[r]->(b:host) WHERE {wh}              WITH a.name AS o, b.name AS d, type(r) AS c, r.event_type AS res, count(*) AS n,              toString(min(r.time)) AS p, toString(max(r.time)) AS u              WITH collect({{o: o, d: d, c: c, res: res, n: n, p: p, u: u}}) AS f              WITH f, apoc.coll.toSet([x IN f | x.o] + [x IN f | x.d]) AS names              WITH f, apoc.map.fromLists(names, [x IN names | apoc.create.vNode(CASE WHEN x IN [{ol}] THEN ['origen'] ELSE ['host'] END, {{name: x}})]) AS node              UNWIND f AS x              RETURN node[x.o], node[x.d], apoc.create.vRelationship(node[x.o], x.c, {{count: x.n, resultado: x.res, primero: x.p, ultimo: x.u}}, node[x.d]) AS acceso",
            wh = wh,
            ol = list(origins)
        )
    } else {
        format!("MATCH p=(a:host)-[r]->(b:host) WHERE {} RETURN p LIMIT 500", wh)
    }
}
