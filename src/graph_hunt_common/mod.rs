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

pub mod account;
pub mod algos;
pub mod engine;
pub mod hostmap;
pub mod record;
pub mod report;
pub mod resolve;
pub mod schema;
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
///
/// The result is UTC. A time written with an offset is converted (it used
/// to be cut off: `22:00:00-05:00` was read as 22:00 UTC, five hours
/// early, and could land on the wrong side of the cutoff); a time with no
/// zone is UTC, as every masstin parser writes it.
pub fn parse_ts(s: &str) -> Option<NaiveDateTime> {
    let mut t = s.trim().to_string();
    if let Some(i) = t.find('[') { t.truncate(i); }
    // `2026-09-23 15:35:09` (a space where ISO has a T: masstin's older
    // parsers and many custom rules write it) and `... UTC` after the time
    // are the same instants; refused here, those rows were out of the hunt
    // and of the viewer while `merge` and the loaders read them
    let upper = t.to_ascii_uppercase();
    if let Some(cut) = upper.strip_suffix(" UTC").or_else(|| upper.strip_suffix(" GMT")) {
        t.truncate(cut.len());
        t = t.trim_end().to_string();
    }
    if t.len() >= 19 && t.as_bytes()[10] == b' ' && t.as_bytes()[4] == b'-' && t.as_bytes()[13] == b':' {
        t.replace_range(10..11, "T");
        // `15:35:09 +0200` -> `15:35:09+0200`
        if let Some(i) = t[11..].find(' ') {
            t.remove(11 + i);
        }
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&t) {
        return Some(dt.naive_utc());
    }
    // an offset without the colon ("+0100")
    for f in ["%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%dT%H:%M:%S%z"] {
        if let Ok(dt) = chrono::DateTime::parse_from_str(&t, f) {
            return Some(dt.naive_utc());
        }
    }
    let t = t.trim_end_matches('Z');
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(t, f) {
            return Some(dt);
        }
    }
    crate::timefmt::parse_fallback(s)
}

/// The UTC instant of a `time_created` cell that the loaders cannot store
/// as it is written: one with an offset other than zero (`22:00:00-05:00`)
/// or with its zone in words (`15:35:09.123 UTC`, as Cortex gives it).
/// `Some("2026-10-20T03:00:00")` (with the fraction, to the microsecond,
/// when there is one), or None when the cell is fine as it is (UTC, with
/// `Z`, `+00:00` or no zone) or is not a time.
/// An IPv6 address in the one spelling the hunt uses for it, in upper case:
/// `fd00:cdc:a:0:1:0:0:28` and `FD00:CDC:A:0:1::28` are the same address and
/// must be the same node. An IPv4-mapped address is its IPv4 address. `None`
/// for anything that is not an IPv6 address written whole (a name, an IPv4
/// address, an address with a zone or a port), which is left as it is.
///
/// The loaders call it on every host and address cell so a loaded graph
/// names an address as graph-hunt-csv does (`engine::clean_host`).
pub(crate) fn canonical_ipv6(cell: &str) -> Option<String> {
    let v6 = cell.trim().parse::<std::net::Ipv6Addr>().ok()?;
    Some(match v6.to_ipv4_mapped() {
        Some(v4) => v4.to_string(),
        None => v6.to_string().to_uppercase(),
    })
}

/// The domain a row gives for its account, as the loaders store it on the
/// edge: the one the name itself carries after `@` (`alice@dev.corp`) when
/// it has one, else the row's domain column. The edge's relationship type is
/// the bare name, so without this the domain of such an account was lost and
/// the hunt over a loaded graph named `ALICE` what graph-hunt-csv names
/// `ALICE@DEV`.
pub(crate) fn edge_domain(user: &str, domain_column: &str) -> String {
    match user.trim().rsplit('\\').next().unwrap_or(user).split_once('@') {
        Some((_, d)) if !d.trim().is_empty() => d.trim().to_string(),
        _ => domain_column.to_string(),
    }
}

pub fn utc_if_rewritten(raw: &str) -> Option<String> {
    let t = raw.trim();
    let upper = t.to_ascii_uppercase();
    let in_words = upper.ends_with(" UTC") || upper.ends_with(" GMT");
    let iso = t.replacen(' ', "T", 1);
    let offset = chrono::DateTime::parse_from_rfc3339(&iso)
        .or_else(|_| chrono::DateTime::parse_from_str(&iso, "%Y-%m-%dT%H:%M:%S%.f%z"))
        .map(|d| d.offset().local_minus_utc() != 0)
        .unwrap_or(false);
    if !in_words && !offset {
        return None;
    }
    let dt = parse_ts(t)?;
    use chrono::Timelike;
    Some(if dt.nanosecond() == 0 { dt.format("%Y-%m-%dT%H:%M:%S").to_string() } else { dt.format("%Y-%m-%dT%H:%M:%S%.6f").to_string() })
}

/// `--database` as the driver takes it. `localhost:7687` works bare, but
/// an address (`127.0.0.1:7687`, `10.0.0.5:7687`) was refused as a
/// "relative URL without a base": a value without a scheme gets `bolt://`.
pub fn bolt_uri(database: &str) -> String {
    let d = database.trim();
    if d.contains("://") { d.to_string() } else { format!("bolt://{}", d) }
}

#[cfg(test)]
mod bolt_uri_tests {
    #[test]
    fn a_value_without_a_scheme_gets_bolt() {
        assert_eq!(super::bolt_uri("127.0.0.1:7687"), "bolt://127.0.0.1:7687");
        assert_eq!(super::bolt_uri(" localhost:7687 "), "bolt://localhost:7687");
        assert_eq!(super::bolt_uri("bolt://db:7687"), "bolt://db:7687");
        assert_eq!(super::bolt_uri("neo4j+s://x.databases.neo4j.io"), "neo4j+s://x.databases.neo4j.io");
    }
}

#[cfg(test)]
mod utc_if_rewritten_tests {
    use super::utc_if_rewritten;

    #[test]
    fn only_the_cells_that_need_it_are_rewritten() {
        for fine in ["2026-10-19T22:00:00Z", "2026-10-19T22:00:00.123456Z", "2026-10-19T22:00:00+00:00", "2026-10-19 22:00:00", "2026-10-19T22:00:00.1234567", "not a time", ""] {
            assert_eq!(utc_if_rewritten(fine), None, "{}", fine);
        }
        assert_eq!(utc_if_rewritten("2026-10-19T22:00:00-05:00").as_deref(), Some("2026-10-20T03:00:00"));
        assert_eq!(utc_if_rewritten("2026-10-19T22:00:00.5+02:00").as_deref(), Some("2026-10-19T20:00:00.500000"));
        assert_eq!(utc_if_rewritten("2026-10-19 22:00:00 +0200").as_deref(), Some("2026-10-19T20:00:00"));
        assert_eq!(utc_if_rewritten("2026-10-19 22:00:00.123 UTC").as_deref(), Some("2026-10-19T22:00:00.123000"));
        assert_eq!(utc_if_rewritten("2026-10-19 22:00:00 utc").as_deref(), Some("2026-10-19T22:00:00"));
    }
}

#[cfg(test)]
mod parse_ts_tests {
    use super::parse_ts;

    fn at(s: &str) -> String {
        parse_ts(s).map(|d| d.format("%Y-%m-%dT%H:%M:%S%.3f").to_string()).unwrap_or_default()
    }

    #[test]
    fn a_space_for_the_t_and_a_zone_in_words() {
        assert_eq!(at("2026-09-23 15:35:09"), "2026-09-23T15:35:09.000");
        assert_eq!(at("2026-09-23 15:35:09.250"), "2026-09-23T15:35:09.250");
        assert_eq!(at("2026-09-23 15:35:09 UTC"), "2026-09-23T15:35:09.000");
        assert_eq!(at("2026-09-23 15:35:09.250 utc"), "2026-09-23T15:35:09.250");
        assert_eq!(at("2026-09-23T15:35:09 UTC"), "2026-09-23T15:35:09.000");
        assert_eq!(at("2026-09-23 15:35:09 +0200"), "2026-09-23T13:35:09.000");
        assert_eq!(at("2026-09-23 15:35:09+02:00"), "2026-09-23T13:35:09.000");
        assert_eq!(at("2026-09-23 15:35:09Z"), "2026-09-23T15:35:09.000");
        // what is not a time stays refused
        assert_eq!(at("2026-09-23 "), "");
        assert_eq!(at("ñññññññññññññññññññññ"), "");
    }

    #[test]
    fn an_offset_is_applied_not_cut_off() {
        // the same instant, written four ways
        assert_eq!(at("2026-10-20T03:00:00Z"), "2026-10-20T03:00:00.000");
        assert_eq!(at("2026-10-19T22:00:00-05:00"), "2026-10-20T03:00:00.000");
        assert_eq!(at("2026-10-20T04:00:00+01:00"), "2026-10-20T03:00:00.000");
        assert_eq!(at("2026-10-20T04:00:00+0100"), "2026-10-20T03:00:00.000");
        // what the backends store
        assert_eq!(at("2026-09-23T15:35:09.336951Z"), "2026-09-23T15:35:09.336");
        assert_eq!(at("2026-09-23T15:35:09+00:00"), "2026-09-23T15:35:09.000");
        assert_eq!(at("2026-09-23T15:35:09.000000"), "2026-09-23T15:35:09.000");
        assert_eq!(at("2026-09-23T15:35:09+02:00[Europe/Madrid]"), "2026-09-23T13:35:09.000");
        assert_eq!(at("not a time"), "");
    }
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
        w.push(account::cypher_condition(a, &|s| q(s)));
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
