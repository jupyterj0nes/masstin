// Shared pieces of graph-hunt used by both backends (Neo4j + GDS in
// `graph_hunt_neo4j`, Memgraph + MAGE in `graph_hunt`).
//
// Everything here speaks plain Cypher through neo4rs; the only dialect
// difference that matters is the temporal constructor (`datetime()` on
// Neo4j, `localDateTime()` on Memgraph) and whether APOC is available for
// Browser-ready virtual-graph snippets. Both are carried by `Dialect`.
//
// Contents:
//   * Finding            — the unit every detector emits
//   * edge predicates    — "authenticated login with an account", "failed",
//                          "counts as a time series" (lastlog excluded)
//   * new detectors      — origin-fanout, failed-sweep, probe-then-success
//   * periodicity        — demote (origin, account) pairs that behave like a
//                          scheduled job AND already existed before the cutoff
//   * coverage check     — warn when the cutoff leaves a log source with too
//                          little baseline
//   * report             — per-pattern aggregation, cross-detector
//                          corroboration, CSV

use chrono::NaiveDateTime;
use neo4rs::*;
use std::collections::{HashMap, HashSet};

pub mod report;

// ───────────────────────────── Finding ──────────────────────────────────────

/// One detector hit. `origin` is the source host of the activity (for
/// host-level detectors such as pagerank-spike it is the host itself);
/// `account` is the relationship type (the user) when the finding is about
/// a single account, empty otherwise. `events` is how many graph edges the
/// finding summarises.
#[derive(Debug, Clone, Default)]
pub struct Finding {
    pub detector: &'static str,
    pub host: String,
    pub origin: String,
    pub account: String,
    pub time_window: String,
    pub score: f64,
    pub events: u64,
    pub summary: String,
    pub cypher_snippet: String,
}

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

/// Successful login with a real account. Graphs loaded by masstin versions
/// that did not store `event_type` are treated as all-success (the old
/// behaviour) through `coalesce`.
pub fn auth_ok(v: &str) -> String {
    format!(
        "(coalesce({v}.event_type, 'SUCCESSFUL_LOGON') <> 'FAILED_LOGON' AND NOT type({v}) IN {na})",
        v = v,
        na = NO_ACCOUNT_TYPES
    )
}

/// Failed login (any account, including none).
pub fn failed(v: &str) -> String {
    format!("coalesce({}.event_type, '') = 'FAILED_LOGON'", v)
}

/// Edges that form a time series. lastlog holds one "last login" record per
/// account: it proves a relationship existed, it says nothing about how
/// often, so it is excluded from frequency counts.
pub fn is_series(v: &str) -> String {
    format!("coalesce({}.log_source, '') <> 'lastlog'", v)
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

/// A query to paste into Neo4j Browser / Memgraph Lab that shows the
/// activity behind a finding. On Neo4j it returns an APOC *virtual* graph:
/// one node per host, one relationship per (origin, account, destination,
/// result) carrying `count`, `resultado`, `primero`, `ultimo`. Virtual nodes
/// matter: with real nodes the Browser's "connect result nodes" pulls every
/// historical relationship between the hosts (tens of thousands for a
/// scheduler) and hangs.
pub fn browser_snippet(
    d: &Dialect,
    origin: &str,
    dest: Option<&str>,
    account: Option<&str>,
    from: &str,
    to: Option<&str>,
) -> String {
    let mut w = vec![format!("r.time >= {}", d.t(from))];
    if let Some(t) = to { w.push(format!("r.time <= {}", d.t(t))); }
    if let Some(x) = dest { w.push(format!("b.name = '{}'", q(x))); }
    if let Some(a) = account { w.push(format!("type(r) = '{}'", q(a))); }
    let wh = w.join(" AND ");
    if d.apoc {
        format!(
            "MATCH (a:host {{name: '{o}'}})-[r]->(b:host) WHERE {wh} \
             WITH a.name AS o, b.name AS d, type(r) AS c, r.event_type AS res, count(*) AS n, \
             toString(min(r.time)) AS p, toString(max(r.time)) AS u \
             WITH collect({{o: o, d: d, c: c, res: res, n: n, p: p, u: u}}) AS f \
             WITH f, apoc.coll.toSet([x IN f | x.o] + [x IN f | x.d]) AS names \
             WITH f, apoc.map.fromLists(names, [x IN names | apoc.create.vNode(CASE WHEN x = '{o}' THEN ['origen'] ELSE ['host'] END, {{name: x}})]) AS node \
             UNWIND f AS x \
             RETURN node[x.o], node[x.d], apoc.create.vRelationship(node[x.o], x.c, {{count: x.n, resultado: x.res, primero: x.p, ultimo: x.u}}, node[x.d]) AS acceso",
            o = q(origin),
            wh = wh
        )
    } else {
        format!(
            "MATCH p=(a:host {{name: '{}'}})-[r]->(b:host) WHERE {} RETURN p LIMIT 500",
            q(origin),
            wh
        )
    }
}

// ─────────────────────────── shared baseline facts ──────────────────────────

/// Facts about the baseline that the shared detectors need, independent of
/// each backend's own `Baseline` struct.
pub struct BaselineFacts {
    pub cutoff: String,
    /// Origins with ANY edge before the cutoff (success, failure, lastlog).
    pub known_origins: HashSet<String>,
    /// Destinations each origin reached with an authenticated login before
    /// the cutoff.
    pub dests_by_origin: HashMap<String, HashSet<String>>,
    /// Accounts (relationship types, no-account types excluded) each origin
    /// used before the cutoff, success or failure.
    pub accounts_by_origin: HashMap<String, HashSet<String>>,
}

pub async fn fetch_baseline_facts(graph: &Graph, d: &Dialect, cutoff: &str) -> neo4rs::Result<BaselineFacts> {
    let qs = format!(
        "MATCH (a:host)-[r]->(b:host) WHERE r.time < {t}
         RETURN a.name AS o, type(r) AS acct, b.name AS d,
                count(CASE WHEN {ok} THEN 1 END) AS ok",
        t = d.t(cutoff),
        ok = auth_ok("r"),
    );
    let mut known_origins = HashSet::new();
    let mut dests_by_origin: HashMap<String, HashSet<String>> = HashMap::new();
    let mut accounts_by_origin: HashMap<String, HashSet<String>> = HashMap::new();
    let mut s = graph.execute(query(&qs)).await?;
    while let Some(row) = s.next().await? {
        let o: String = row.get("o").unwrap_or_default();
        let acct: String = row.get("acct").unwrap_or_default();
        let dst: String = row.get("d").unwrap_or_default();
        let ok: i64 = row.get("ok").unwrap_or(0);
        if o.is_empty() { continue; }
        known_origins.insert(o.clone());
        if ok > 0 {
            dests_by_origin.entry(o.clone()).or_default().insert(dst);
        }
        if !is_no_account(&acct) {
            accounts_by_origin.entry(o).or_default().insert(acct);
        }
    }
    Ok(BaselineFacts { cutoff: cutoff.to_string(), known_origins, dests_by_origin, accounts_by_origin })
}

// ─────────────────────────── origin-fanout ──────────────────────────────────

const FANOUT_MIN_NEW_DESTS: usize = 3;
const BURST_WINDOW_SECS: i64 = 60;

/// One row per origin that, in the window, logged in successfully to at
/// least FANOUT_MIN_NEW_DESTS destinations it had never reached before.
/// This is the question an analyst asks first ("who suddenly went
/// everywhere?") and the per-edge detectors cannot answer: they emit one
/// row per destination with a flat score, so a 20-host fan-out drowns in
/// the per-edge noise.
///
/// Score (range 1.0 – 3.0):
///   1.0 base
/// + 1.0 if the origin has no event of any kind before the cutoff,
///   otherwise 0.5 × (fraction of its window destinations that are new)
/// + 0.5 × min(new destinations / 10, 1)                   (breadth)
/// + 0.5 × min(max new destinations first reached within 60 s / 10, 1) (burst)
pub async fn origin_fanout(graph: &Graph, d: &Dialect, bf: &BaselineFacts) -> Vec<Finding> {
    let qs = format!(
        "MATCH (a:host)-[r]->(b:host) WHERE r.time >= {t} AND {ok}
         RETURN a.name AS o, b.name AS dst, type(r) AS acct, count(*) AS n,
                toString(min(r.time)) AS first, toString(max(r.time)) AS last",
        t = d.t(&bf.cutoff),
        ok = auth_ok("r"),
    );
    struct Agg { dests: HashMap<String, NaiveDateTime>, accts: HashSet<String>, n: u64, first: String, last: String }
    let mut per: HashMap<String, Agg> = HashMap::new();
    let mut s = match graph.execute(query(&qs)).await {
        Ok(s) => s,
        Err(e) => { eprintln!("  [origin-fanout] query failed: {}", e); return Vec::new(); }
    };
    loop {
        match s.next().await {
            Ok(Some(row)) => {
                let o: String = row.get("o").unwrap_or_default();
                let dst: String = row.get("dst").unwrap_or_default();
                let acct: String = row.get("acct").unwrap_or_default();
                let n: i64 = row.get("n").unwrap_or(0);
                let first: String = row.get("first").unwrap_or_default();
                let last: String = row.get("last").unwrap_or_default();
                if o.is_empty() { continue; }
                let a = per.entry(o).or_insert(Agg { dests: HashMap::new(), accts: HashSet::new(), n: 0, first: first.clone(), last: last.clone() });
                if let Some(ft) = parse_ts(&first) {
                    let e = a.dests.entry(dst).or_insert(ft);
                    if ft < *e { *e = ft; }
                }
                a.accts.insert(acct);
                a.n += n.max(0) as u64;
                if first < a.first { a.first = first; }
                if last > a.last { a.last = last; }
            }
            Ok(None) => break,
            Err(e) => { eprintln!("  [origin-fanout] row read failed: {}", e); break; }
        }
    }

    let empty = HashSet::new();
    let mut out = Vec::new();
    for (o, a) in per {
        let known_dests = bf.dests_by_origin.get(&o).unwrap_or(&empty);
        let mut new: Vec<(&String, &NaiveDateTime)> = a.dests.iter().filter(|(dst, _)| !known_dests.contains(*dst)).collect();
        if new.len() < FANOUT_MIN_NEW_DESTS { continue; }
        new.sort_by_key(|(_, t)| **t);
        // largest number of new destinations first reached inside any 60 s window
        let times: Vec<NaiveDateTime> = new.iter().map(|(_, t)| **t).collect();
        let mut burst = 0usize;
        let mut j = 0usize;
        for i in 0..times.len() {
            while (times[i] - times[j]).num_seconds() > BURST_WINDOW_SECS { j += 1; }
            burst = burst.max(i - j + 1);
        }
        let never_seen = !bf.known_origins.contains(&o);
        let frac_new = new.len() as f64 / a.dests.len() as f64;
        let novelty = if never_seen { 1.0 } else { 0.5 * frac_new };
        let breadth = 0.5 * (new.len() as f64 / 10.0).min(1.0);
        let burst_s = 0.5 * (burst as f64 / 10.0).min(1.0);
        let score = 1.0 + novelty + breadth + burst_s;
        let mut accts: Vec<&String> = a.accts.iter().collect();
        accts.sort();
        let mut names: Vec<String> = new.iter().map(|(dst, _)| dst.to_string()).collect();
        names.sort();
        let summary = format!(
            "{o} logged in successfully to {nd} destination(s) it had never reached before ({tot} in the window, {ev} logins), \
             accounts [{ac}]. {bu} new destination(s) first reached within {w} s. Origin {seen}. New: [{list}].",
            o = o,
            nd = new.len(),
            tot = a.dests.len(),
            ev = a.n,
            ac = accts.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
            bu = burst,
            w = BURST_WINDOW_SECS,
            seen = if never_seen { "has no event of any kind before the cutoff" } else { "was already active before the cutoff" },
            list = names.join(", "),
        );
        out.push(Finding {
            detector: "origin-fanout",
            host: o.clone(),
            origin: o.clone(),
            account: String::new(),
            time_window: format!("{} .. {}", a.first, a.last),
            score,
            events: a.n,
            summary,
            cypher_snippet: browser_snippet(d, &o, None, None, &bf.cutoff, None),
        });
    }
    out
}

// ─────────────────────────── failed-sweep ───────────────────────────────────

const SWEEP_MIN_DESTS: usize = 3;
const SWEEP_MIN_FAILS: u64 = 100;

/// Failed and unauthenticated attempts are kept out of every structural
/// detector (they are not connectivity: a scanner "reaching" 20 hosts
/// reached none). They are reported here instead, one row per origin.
/// Score 0.3 – 0.8: below any authenticated anomaly on purpose.
pub async fn failed_sweep(graph: &Graph, d: &Dialect, bf: &BaselineFacts) -> Vec<Finding> {
    let qs = format!(
        "MATCH (a:host)-[r]->(b:host) WHERE r.time >= {t} AND {f}
         RETURN a.name AS o, b.name AS dst, type(r) AS acct, count(*) AS n,
                toString(min(r.time)) AS first, toString(max(r.time)) AS last",
        t = d.t(&bf.cutoff),
        f = failed("r"),
    );
    struct Agg { dests: HashSet<String>, accts: HashSet<String>, n: u64, first: String, last: String }
    let mut per: HashMap<String, Agg> = HashMap::new();
    let mut s = match graph.execute(query(&qs)).await {
        Ok(s) => s,
        Err(e) => { eprintln!("  [failed-sweep] query failed: {}", e); return Vec::new(); }
    };
    while let Ok(Some(row)) = s.next().await {
        let o: String = row.get("o").unwrap_or_default();
        if o.is_empty() { continue; }
        let first: String = row.get("first").unwrap_or_default();
        let last: String = row.get("last").unwrap_or_default();
        let n: i64 = row.get("n").unwrap_or(0);
        let a = per.entry(o).or_insert(Agg { dests: HashSet::new(), accts: HashSet::new(), n: 0, first: first.clone(), last: last.clone() });
        a.dests.insert(row.get("dst").unwrap_or_default());
        a.accts.insert(row.get("acct").unwrap_or_default());
        a.n += n.max(0) as u64;
        if first < a.first { a.first = first; }
        if last > a.last { a.last = last; }
    }
    let mut out = Vec::new();
    for (o, a) in per {
        if a.dests.len() < SWEEP_MIN_DESTS && a.n < SWEEP_MIN_FAILS { continue; }
        let never_seen = !bf.known_origins.contains(&o);
        let score = 0.3 + if never_seen { 0.2 } else { 0.0 } + 0.3 * (a.dests.len() as f64 / 20.0).min(1.0);
        let mut accts: Vec<&String> = a.accts.iter().collect();
        accts.sort();
        let summary = format!(
            "{o}: {n} failed / unauthenticated attempts against {nd} destination(s), accounts tried [{ac}]. Origin {seen}.",
            o = o, n = a.n, nd = a.dests.len(),
            ac = accts.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
            seen = if never_seen { "has no event of any kind before the cutoff" } else { "was already active before the cutoff" },
        );
        out.push(Finding {
            detector: "failed-sweep",
            host: o.clone(),
            origin: o.clone(),
            account: String::new(),
            time_window: format!("{} .. {}", a.first, a.last),
            score,
            events: a.n,
            summary,
            cypher_snippet: browser_snippet(d, &o, None, None, &bf.cutoff, None),
        });
    }
    out
}

// ─────────────────────────── probe-then-success ─────────────────────────────

const PROBE_WINDOW_HOURS: i64 = 6;

/// Same origin: failed or unauthenticated attempts, then within
/// PROBE_WINDOW_HOURS a successful login with an account that was NOT among
/// the ones that failed. The shape of "try, get refused, come back with a
/// working credential". Score 1.5, +0.5 when the origin has no event of any
/// kind before the cutoff.
pub async fn probe_then_success(graph: &Graph, d: &Dialect, bf: &BaselineFacts) -> Vec<Finding> {
    let qs = format!(
        "MATCH (a:host)-[r]->(b:host) WHERE r.time >= {t}
         RETURN a.name AS o, type(r) AS acct,
                CASE WHEN {f} THEN 'F' ELSE 'S' END AS res,
                count(*) AS n, collect(DISTINCT b.name) AS dests,
                toString(min(r.time)) AS first",
        t = d.t(&bf.cutoff),
        f = failed("r"),
    );
    // origin -> (failures: acct -> (first, dests, n), successes: acct -> (first, dests, n))
    type Side = HashMap<String, (NaiveDateTime, Vec<String>, i64)>;
    let mut per: HashMap<String, (Side, Side)> = HashMap::new();
    let mut s = match graph.execute(query(&qs)).await {
        Ok(s) => s,
        Err(e) => { eprintln!("  [probe-then-success] query failed: {}", e); return Vec::new(); }
    };
    while let Ok(Some(row)) = s.next().await {
        let o: String = row.get("o").unwrap_or_default();
        let acct: String = row.get("acct").unwrap_or_default();
        let res: String = row.get("res").unwrap_or_default();
        let n: i64 = row.get("n").unwrap_or(0);
        let dests: Vec<String> = row.get("dests").unwrap_or_default();
        let first: String = row.get("first").unwrap_or_default();
        let ft = match parse_ts(&first) { Some(t) => t, None => continue };
        if o.is_empty() { continue; }
        let e = per.entry(o).or_default();
        if res == "F" {
            e.0.insert(acct, (ft, dests, n));
        } else if !is_no_account(&acct) {
            e.1.insert(acct, (ft, dests, n));
        }
    }
    let mut out = Vec::new();
    let empty = HashSet::new();
    for (o, (fails, succ)) in per {
        if fails.is_empty() || succ.is_empty() { continue; }
        // A probe needs a refused NAMED account (`test`, a guessed user).
        // Unauthenticated connections alone (`_UNKNOWN_`) precede ordinary
        // logins all the time — key exchange, agents trying methods — and
        // would flag every automation account.
        let named_fails: Vec<NaiveDateTime> = fails.iter().filter(|(a, _)| !is_no_account(a)).map(|(_, v)| v.0).collect();
        if named_fails.is_empty() { continue; }
        let first_fail = *named_fails.iter().min().unwrap();
        let never_seen = !bf.known_origins.contains(&o);
        let used_before = bf.accounts_by_origin.get(&o).unwrap_or(&empty);
        // successes with an account that never failed, starting after the
        // first failure and within the window
        let mut hits: Vec<(&String, &(NaiveDateTime, Vec<String>, i64))> = succ
            .iter()
            .filter(|(acct, v)| {
                !fails.contains_key(*acct)
                    && v.0 > first_fail
                    && (v.0 - first_fail).num_hours() < PROBE_WINDOW_HOURS
                    // the working account must be new for this origin (or the
                    // origin itself new): a known job account is not a find
                    && (never_seen || !used_before.contains(*acct))
            })
            .collect();
        if hits.is_empty() { continue; }
        hits.sort_by_key(|(_, v)| v.0);
        let score = 1.5 + if never_seen { 0.5 } else { 0.0 };
        let mut fail_desc: Vec<String> = fails
            .iter()
            .map(|(a, v)| format!("{} x{} on {} host(s) from {}", a, v.2, v.1.len(), v.0.format("%Y-%m-%d %H:%M:%S")))
            .collect();
        fail_desc.sort();
        let succ_desc: Vec<String> = hits
            .iter()
            .map(|(a, v)| format!("{} x{} on {} host(s) from {}", a, v.2, v.1.len(), v.0.format("%Y-%m-%d %H:%M:%S")))
            .collect();
        let gap = (hits[0].1 .0 - first_fail).num_minutes();
        let ev: i64 = fails.values().map(|v| v.2).sum::<i64>() + hits.iter().map(|(_, v)| v.2).sum::<i64>();
        let summary = format!(
            "{o}: refused attempts [{f}], then {gap} min later successful logins with a different account [{s}]. Origin {seen}.",
            o = o, f = fail_desc.join("; "), gap = gap, s = succ_desc.join("; "),
            seen = if never_seen { "has no event of any kind before the cutoff" } else { "was already active before the cutoff" },
        );
        let last = hits.iter().map(|(_, v)| v.0).max().unwrap();
        out.push(Finding {
            detector: "probe-then-success",
            host: o.clone(),
            origin: o.clone(),
            account: String::new(),
            time_window: format!("{} .. {}", first_fail.format("%Y-%m-%dT%H:%M:%S"), last.format("%Y-%m-%dT%H:%M:%S")),
            score,
            events: ev.max(0) as u64,
            summary,
            cypher_snippet: browser_snippet(d, &o, None, None, &bf.cutoff, None),
        });
    }
    out
}

// ─────────────────────────── periodicity ────────────────────────────────────

const PERIODIC_MIN_DAYS: usize = 3;
const PERIODIC_TOD_SD_SECS: f64 = 900.0;
const PERIODIC_RATE_CV: f64 = 0.10;
const PERIODIC_MIN_DAILY: f64 = 24.0;
pub const PERIODIC_FACTOR: f64 = 0.3;

/// (origin, account) pairs that, in the window, behave like a scheduled job
/// AND were already active from that origin before the cutoff:
///   * seen on >= 3 distinct days, and
///   * either the time of day is nearly constant (sd < 15 min: a daily
///     job) or the daily volume is nearly constant (CV < 10% over the
///     interior days, >= 24/day: a probe every N minutes).
/// A new periodic job (a freshly planted cron) is NOT demoted: the pair
/// must already exist in the baseline.
pub async fn periodic_pairs(graph: &Graph, d: &Dialect, bf: &BaselineFacts) -> HashSet<(String, String)> {
    let qs = format!(
        "MATCH (a:host)-[r]->(:host) WHERE r.time >= {t}
         WITH a.name AS o, type(r) AS acct,
              r.time.year * 10000 + r.time.month * 100 + r.time.day AS day,
              r.time.hour * 3600 + r.time.minute * 60 + r.time.second AS tod
         RETURN o, acct, day, count(*) AS n, sum(tod) AS s, sum(tod * tod) AS ss",
        t = d.t(&bf.cutoff)
    );
    struct Agg { days: Vec<(i64, f64)>, n: f64, s: f64, ss: f64 }
    let mut per: HashMap<(String, String), Agg> = HashMap::new();
    let mut st = match graph.execute(query(&qs)).await {
        Ok(s) => s,
        Err(e) => { eprintln!("  [periodicity] query failed: {}", e); return HashSet::new(); }
    };
    while let Ok(Some(row)) = st.next().await {
        let o: String = row.get("o").unwrap_or_default();
        let acct: String = row.get("acct").unwrap_or_default();
        let day: i64 = row.get("day").unwrap_or(0);
        let n: i64 = row.get("n").unwrap_or(0);
        let s: f64 = row.get::<i64>("s").map(|v| v as f64).or_else(|| row.get::<f64>("s")).unwrap_or(0.0);
        let ss: f64 = row.get::<i64>("ss").map(|v| v as f64).or_else(|| row.get::<f64>("ss")).unwrap_or(0.0);
        let a = per.entry((o, acct)).or_insert(Agg { days: Vec::new(), n: 0.0, s: 0.0, ss: 0.0 });
        a.days.push((day, n as f64));
        a.n += n as f64;
        a.s += s;
        a.ss += ss;
    }
    let mut out = HashSet::new();
    for ((o, acct), mut a) in per {
        if a.days.len() < PERIODIC_MIN_DAYS { continue; }
        let known = if is_no_account(&acct) {
            bf.known_origins.contains(&o)
        } else {
            bf.accounts_by_origin.get(&o).map(|s| s.contains(&acct)).unwrap_or(false)
        };
        if !known { continue; }
        let mean = a.s / a.n;
        let sd = ((a.ss / a.n) - mean * mean).max(0.0).sqrt();
        a.days.sort_by_key(|x| x.0);
        let interior: Vec<f64> = if a.days.len() > 2 { a.days[1..a.days.len() - 1].iter().map(|x| x.1).collect() } else { Vec::new() };
        let rate_regular = if interior.len() >= 1 {
            let m = interior.iter().sum::<f64>() / interior.len() as f64;
            let v = interior.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / interior.len() as f64;
            m >= PERIODIC_MIN_DAILY && (v.sqrt() / m) < PERIODIC_RATE_CV
        } else { false };
        if sd < PERIODIC_TOD_SD_SECS || rate_regular {
            out.insert((o, acct));
        }
    }
    out
}

/// Demote findings that describe periodic, pre-existing activity. A
/// per-account finding matches its (origin, account); an origin-level
/// finding (no account) is demoted only when every account the origin
/// used in the window is periodic.
pub async fn apply_periodicity(graph: &Graph, d: &Dialect, bf: &BaselineFacts, findings: &mut [Finding]) {
    let periodic = periodic_pairs(graph, d, bf).await;
    if periodic.is_empty() { return; }
    let mut accts_by_origin: HashMap<String, HashSet<String>> = HashMap::new();
    for (o, a) in &periodic { accts_by_origin.entry(o.clone()).or_default().insert(a.clone()); }
    // all window accounts per origin
    let qs = format!(
        "MATCH (a:host)-[r]->(:host) WHERE r.time >= {} RETURN a.name AS o, collect(DISTINCT type(r)) AS accts",
        d.t(&bf.cutoff)
    );
    let mut window_accts: HashMap<String, HashSet<String>> = HashMap::new();
    if let Ok(mut s) = graph.execute(query(&qs)).await {
        while let Ok(Some(row)) = s.next().await {
            let o: String = row.get("o").unwrap_or_default();
            let a: Vec<String> = row.get("accts").unwrap_or_default();
            window_accts.insert(o, a.into_iter().collect());
        }
    }
    let mut demoted = 0usize;
    for f in findings.iter_mut() {
        if f.origin.is_empty() { continue; }
        let hit = if !f.account.is_empty() {
            periodic.contains(&(f.origin.clone(), f.account.clone()))
        } else {
            match (window_accts.get(&f.origin), accts_by_origin.get(&f.origin)) {
                (Some(all), Some(per)) => !all.is_empty() && all.iter().all(|a| per.contains(a)),
                _ => false,
            }
        };
        if hit {
            f.score *= PERIODIC_FACTOR;
            f.summary.push_str(" [periodic: same pattern daily and already present before the cutoff — demoted]");
            demoted += 1;
        }
    }
    crate::banner::print_phase_detail(
        "Periodicity:",
        &format!("{} (origin, account) pairs look scheduled and pre-existing; {} finding(s) demoted x{}", periodic.len(), demoted, PERIODIC_FACTOR),
    );
}

// ─────────────────────────── coverage ───────────────────────────────────────

const MIN_BASELINE_DAYS: i64 = 14;

/// Warn when the cutoff leaves a log source with little or no baseline on
/// some destinations. Novelty is only meaningful against data that could
/// have shown the same thing: if `secure` starts two days before the
/// cutoff, every sshd-only fact in the window looks "new" simply because
/// the rotation that would have held its history is gone. Uses the
/// `log_source` edge property (graphs loaded by older versions have none:
/// the check is skipped). "Covered since" = first day of the most recent
/// run of days with no gap > 7 days. lastlog (one record per account) and
/// btmp (failures only, sparse by nature) are excluded.
pub async fn check_coverage(graph: &Graph, d: &Dialect, cutoff: chrono::DateTime<chrono::Utc>) -> neo4rs::Result<()> {
    let _ = d;
    let qs = "MATCH ()-[r]->(b:host)
              WHERE r.log_source IS NOT NULL AND NOT r.log_source IN ['', 'lastlog', 'btmp']
              RETURN b.name AS dst, r.log_source AS src,
                     collect(DISTINCT r.time.year * 10000 + r.time.month * 100 + r.time.day) AS days";
    let mut stream = graph.execute(query(qs)).await?;
    let mut per_src: HashMap<String, Vec<(String, chrono::NaiveDate)>> = HashMap::new();
    let mut any = false;
    while let Some(row) = stream.next().await? {
        any = true;
        let dst: String = row.get("dst").unwrap_or_default();
        let src: String = row.get("src").unwrap_or_default();
        let raw: Vec<i64> = row.get("days").unwrap_or_default();
        let mut days: Vec<chrono::NaiveDate> = raw
            .iter()
            .filter_map(|v| chrono::NaiveDate::from_ymd_opt((*v / 10000) as i32, ((*v / 100) % 100) as u32, (*v % 100) as u32))
            .collect();
        days.sort();
        days.dedup();
        let mut start = match days.last() { Some(d) => *d, None => continue };
        for w in days.windows(2).rev() {
            if (w[1] - w[0]).num_days() > 7 { break; }
            start = w[0];
        }
        per_src.entry(src).or_default().push((dst, start));
    }
    if !any {
        crate::banner::print_phase_detail(
            "Coverage:",
            "edges carry no log_source (graph loaded by an older masstin) — coverage check skipped",
        );
        return Ok(());
    }
    let cut = cutoff.date_naive();
    let mut srcs: Vec<&String> = per_src.keys().collect();
    srcs.sort();
    for src in srcs {
        let list = &per_src[src];
        let mut shortl: Vec<(String, i64)> = list
            .iter()
            .map(|(h, s)| (h.clone(), (cut - *s).num_days()))
            .filter(|(_, days)| *days < MIN_BASELINE_DAYS)
            .collect();
        let earliest = list.iter().map(|(_, s)| *s).min();
        let latest = list.iter().map(|(_, s)| *s).max();
        let range = match (earliest, latest) {
            (Some(a), Some(b)) if a == b => format!("since {}", a),
            (Some(a), Some(b)) => format!("since {} .. {}", a, b),
            _ => String::new(),
        };
        if shortl.is_empty() {
            crate::banner::print_phase_detail(
                "Coverage:",
                &format!("{:<9} {} host(s), {} — baseline >= {} days everywhere", src, list.len(), range, MIN_BASELINE_DAYS),
            );
        } else {
            shortl.sort_by_key(|(_, d)| *d);
            let sample: Vec<String> = shortl
                .iter()
                .take(6)
                .map(|(h, d)| if *d <= 0 { format!("{} (none)", h) } else { format!("{} ({}d)", h, d) })
                .collect();
            crate::banner::print_warning(&format!(
                "Coverage: {} has < {} days of baseline on {} of {} host(s) ({}): {}{}. \
                 Anything seen only in {} on those hosts will look novel for lack of history.",
                src, MIN_BASELINE_DAYS, shortl.len(), list.len(), range,
                sample.join(", "), if shortl.len() > 6 { ", ..." } else { "" }, src
            ));
        }
    }
    Ok(())
}

