// graph-hunt statistical engine (both backends).
//
// Design: docs/graph-hunt-statistics.md. In short:
//   1. Pull every edge once (per-event rows for logins and named failures,
//      per-day aggregates for pre-auth touches and unnamed failures).
//   2. Fold IP and host name into one machine when the co-occurrence
//      resolution is significant (resolve.rs).
//   3. Leave-one-day-out reference: on a baseline day a fact is new when it
//      occurs on no other baseline day, on a window day when it occurs on
//      no baseline day. Baseline days give the null, window days the
//      observations; every statistic is computed the same way for both.
//   4. Comparability: novelty is pooled over destinations with at most the
//      observation's reference days (conservative); counts are compared
//      day by day on the destinations both days could show.
//   5. Empirical p-values, Simes within evidence family, Fisher across
//      families, Benjamini-Hochberg across machines.
//   6. CSV: findings, campaign groups, not-evaluable destinations.

use super::algos::{self, DiGraph};
use super::resolve::{self, Obs};
use super::stats;
use super::{is_no_account, parse_ts, Dialect, NO_ACCOUNT_TYPES};
use chrono::{DateTime, Utc};
use neo4rs::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;

const OTHER: u8 = 0;
const OK: u8 = 1;
const FAIL: u8 = 2;
const PRE: u8 = 3;

pub struct Settings {
    pub cutoff: DateTime<Utc>,
    /// optional end of the window (events after it are ignored), e.g. to
    /// check calibration on a period without the incident
    pub end: Option<DateTime<Utc>>,
    pub alpha: f64,
    pub only: HashSet<String>,
    pub skip: HashSet<String>,
}

impl Settings {
    fn enabled(&self, det: &str) -> bool {
        if !self.only.is_empty() {
            return self.only.contains(det);
        }
        !self.skip.contains(det)
    }
}

/// Detector names accepted by --skip-detectors / --only-detectors. Each
/// origin-level one is a coordinate of the origin-day profile; the two
/// centrality ones form the host-day profile.
pub const DETECTORS: &[&str] = &[
    "origin-fanout",
    "cred-rotation",
    "novel-edge",
    "community-bridge",
    "failed-sweep",
    "preauth-sweep",
    "probe-then-success",
    "rare-logon-type",
    "chain-motif",
    "pagerank-spike",
    "betweenness-spike",
];

// ───────────────────────────── interning ────────────────────────────────────

#[derive(Default)]
struct Interner {
    map: HashMap<String, u32>,
    names: Vec<String>,
}

impl Interner {
    fn id(&mut self, s: &str) -> u32 {
        if let Some(&i) = self.map.get(s) {
            return i;
        }
        let i = self.names.len() as u32;
        self.map.insert(s.to_string(), i);
        self.names.push(s.to_string());
        i
    }
    fn name(&self, i: u32) -> &str {
        &self.names[i as usize]
    }
}

fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

fn class_of(et: &str, eid: &str, acct: &str) -> u8 {
    if eid == "SSH_PREAUTH" {
        PRE
    } else if et == "FAILED_LOGON" {
        FAIL
    } else if is_no_account(acct) {
        OTHER
    } else {
        OK
    }
}

/// An account the parser could only name by uid (auditd `id=` without a
/// passwd entry): `uid:1101` in the CSV, `UID_1101` once the loader turns
/// it into a relationship type. Not a name, so never "a new account".
fn is_uid_account(a: &str) -> bool {
    let rest = if a.len() > 4 && (a[..4].eq_ignore_ascii_case("uid:") || a[..4].eq_ignore_ascii_case("uid_")) { &a[4..] } else { return false };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

struct RawRow {
    t: i64,
    /// log family (secure, wtmp, audit, journal, btmp, evtx...)
    fam: u32,
    o: u32,
    d: u32,
    a: u32,
    et: u32,
    cls: u8,
    lt: u32,
    cov: (bool, bool),
    n: u64,
}

struct Corpus {
    /// node name -> (cov_ok, cov_fail) log-file spans written by the loader
    cov: HashMap<String, (Vec<i64>, Vec<i64>)>,
    fams: Interner,
    nodes: Interner,
    accts: Interner,
    lts: Interner,
    ets: Interner,
    rows: Vec<RawRow>,
}

async fn pull(graph: &Graph) -> neo4rs::Result<Corpus> {
    let mut c = Corpus { cov: HashMap::new(), fams: Interner::default(), nodes: Interner::default(), accts: Interner::default(), lts: Interner::default(), ets: Interner::default(), rows: Vec::new() };
    let aggregated = format!(
        "(coalesce(r.event_id, '') = 'SSH_PREAUTH' OR (coalesce(r.event_type, '') = 'FAILED_LOGON' AND type(r) IN {na}))",
        na = NO_ACCOUNT_TYPES
    );
    let qa = format!(
        "MATCH (a:host)-[r]->(b:host) WHERE NOT {agg}
         RETURN a.name AS o, b.name AS d, type(r) AS acct, coalesce(r.event_type, '') AS et,
                coalesce(r.event_id, '') AS eid, coalesce(toString(r.logon_type), '') AS lt,
                coalesce(r.log_source, '') AS src, toString(r.time) AS t,
                toInteger(coalesce(r.count, 1)) AS c",
        agg = aggregated
    );
    let qb = format!(
        "MATCH (a:host)-[r]->(b:host) WHERE {agg}
         WITH a.name AS o, b.name AS d, type(r) AS acct, coalesce(r.event_type, '') AS et,
              coalesce(r.event_id, '') AS eid, coalesce(r.log_source, '') AS src,
              r.time.year * 10000 + r.time.month * 100 + r.time.day AS dk,
              sum(toInteger(coalesce(r.count, 1))) AS c, min(r.time) AS t0
         RETURN o, d, acct, et, eid, '' AS lt, src, toString(t0) AS t, c",
        agg = aggregated
    );
    for q in [qa, qb] {
        let mut s = graph.execute(query(&q)).await?;
        while let Some(row) = s.next().await? {
            let o: String = row.get("o").unwrap_or_default();
            let d: String = row.get("d").unwrap_or_default();
            if o.is_empty() || d.is_empty() {
                continue;
            }
            let acct: String = row.get("acct").unwrap_or_default();
            let et: String = row.get("et").unwrap_or_default();
            let eid: String = row.get("eid").unwrap_or_default();
            let lt: String = row.get("lt").unwrap_or_default();
            let src: String = row.get("src").unwrap_or_default();
            let ts: String = row.get("t").unwrap_or_default();
            let n: i64 = row.get("c").unwrap_or(1);
            let t = match parse_ts(&ts) {
                Some(x) => x.and_utc().timestamp(),
                None => continue,
            };
            let cls = class_of(&et, &eid, &acct);
            let r = RawRow {
                t,
                fam: c.fams.id(&src),
                o: c.nodes.id(&o),
                d: c.nodes.id(&d),
                a: c.accts.id(&acct),
                et: c.ets.id(&et),
                cls,
                lt: c.lts.id(&lt),
                cov: super::coverage_kinds(&src),
                n: n.max(1) as u64,
            };
            c.rows.push(r);
        }
    }
    let mut s = graph
        .execute(query("MATCH (h:host) RETURN h.name AS n, coalesce(h.cov_ok, []) AS ok, coalesce(h.cov_fail, []) AS fail"))
        .await?;
    while let Some(row) = s.next().await? {
        let n: String = row.get("n").unwrap_or_default();
        let ok: Vec<i64> = row.get("ok").unwrap_or_default();
        let fail: Vec<i64> = row.get("fail").unwrap_or_default();
        c.cov.insert(n, (ok, fail));
    }
    Ok(c)
}

// ───────────────────────────── reference ────────────────────────────────────
//
// Leave-one-day-out. On a baseline day D a fact is "new" when it occurs on
// no OTHER baseline day; on a window day it is new when it occurs on no
// baseline day. Both judge a day against (almost) the same amount of
// reference, so baseline days are a fair null for window days wherever they
// fall in the calendar.

const F_TRIPLE: u8 = 1;
const F_ACCT_DST: u8 = 2;
const F_DST_ORIGIN: u8 = 4;
const F_ACCT_ORIGIN: u8 = 8;
const F_NO_HISTORY: u8 = 16;

/// Distinct baseline days an item occurs on.
#[derive(Clone, Copy)]
struct DayCount {
    n: u32,
    first: i32,
    last: i32,
}

struct DayIndex<K: std::hash::Hash + Eq> {
    m: HashMap<K, DayCount>,
}

impl<K: std::hash::Hash + Eq> DayIndex<K> {
    fn new() -> Self {
        DayIndex { m: HashMap::new() }
    }
    fn add(&mut self, k: K, day: i32) {
        match self.m.get_mut(&k) {
            Some(c) => {
                if c.last != day {
                    c.n += 1;
                    c.last = day;
                }
            }
            None => {
                self.m.insert(k, DayCount { n: 1, first: day, last: day });
            }
        }
    }
    /// New on `day`: baseline day -> occurs on no other baseline day;
    /// window day -> occurs on no baseline day.
    fn is_new(&self, k: &K, day: i32, baseline: bool) -> bool {
        match self.m.get(k) {
            None => true,
            Some(c) => baseline && c.n == 1 && c.first == day,
        }
    }
}

struct TripleDay {
    day: i32,
    o: u32,
    d: u32,
    a: u32,
    /// OK / FAIL / PRE
    cls: u8,
    /// log families the connection was seen in (bit per family id)
    fams: u64,
    flags: u8,
    /// reference days of the destination (its other covered baseline days)
    k: usize,
    n: u64,
    t0: i64,
    t1: i64,
}

/// Everything one origin did on one day, as raw facts; the statistics are
/// computed from it for whichever destination set is being compared.
#[derive(Default)]
struct OriginDay {
    new_dsts: BTreeSet<u32>,
    /// (account, destination) where the account is new for this origin
    new_acct_uses: BTreeSet<(u32, u32)>,
    /// (account, destination) where the account never logged in to it
    new_ad: BTreeSet<(u32, u32)>,
    /// new destinations outside the origin's Louvain community
    cross_dsts: BTreeSet<u32>,
    fail_dsts: BTreeSet<u32>,
    pre_dsts: BTreeSet<u32>,
    ok_dsts: BTreeSet<u32>,
    refused: BTreeSet<(u32, u32, i64)>,
    newacct_success: Vec<(u32, i64)>,
    /// (destination, -ln share of logins with a logon type at most this rare, logon type)
    lt_surprise: Vec<(u32, f64, u32)>,
    /// (B, C, gap s): this origin opened a new login to B, then B opened a new one to C
    chains: Vec<(u32, u32, i64)>,
    ok_secs: Vec<f64>,
    fail_n: u64,
    pre_n: u64,
    t0: i64,
    t1: i64,
    no_history: bool,
}

struct OkEvent {
    t: i64,
    day: i32,
    o: u32,
    d: u32,
    pair_new: bool,
}

/// a - b, with differences at the level of floating-point rounding (n
/// accumulated operations on values of this size) treated as zero: a
/// betweenness that "changes" by 1e-17 has not changed.
fn clean_delta(a: f64, b: f64, n: usize) -> f64 {
    let d = a - b;
    if d.abs() <= (n.max(1) as f64) * f64::EPSILON * a.abs().max(b.abs()) {
        0.0
    } else {
        d
    }
}

fn day_of(t: i64) -> i32 {
    t.div_euclid(86_400) as i32
}

fn day_str(day: i32) -> String {
    chrono::DateTime::from_timestamp(day as i64 * 86_400, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

fn ts_str(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

// ── joint test ──
//
// Statistic: T(x) = sum over coordinates of -ln(share of null points at
// least as high in that coordinate), only for coordinates above zero. It
// is calibrated empirically: p = (1 + #null points with T >= T(x)) /
// (1 + N), the null points' own T being computed leaving themselves out.
// Valid for exchangeable days whatever the dependence between coordinates
// (dependence only costs power). The number of null points at least as
// high in EVERY coordinate is reported alongside as a plain-language check.

struct JointNull {
    /// per coordinate, null values ascending
    cols: Vec<Vec<f64>>,
    /// null T values ascending
    t_sorted: Vec<f64>,
    n: usize,
    rows: Vec<Vec<f64>>,
}

fn surprise(col: &[f64], v: f64, n: usize, self_in_null: bool) -> f64 {
    if v <= 0.0 {
        return 0.0;
    }
    let ge = col.len() - col.partition_point(|x| *x < v) - if self_in_null { 1 } else { 0 };
    -stats::empirical_p(ge, n.saturating_sub(if self_in_null { 1 } else { 0 })).ln()
}

impl JointNull {
    fn new(rows: Vec<Vec<f64>>) -> Self {
        let n = rows.len();
        let dims = rows.first().map(|r| r.len()).unwrap_or(0);
        let cols: Vec<Vec<f64>> = (0..dims)
            .map(|k| {
                let mut v: Vec<f64> = rows.iter().map(|r| r[k]).collect();
                v.sort_by(|a, b| a.partial_cmp(b).unwrap());
                v
            })
            .collect();
        let mut t_sorted: Vec<f64> = rows.iter().map(|r| (0..dims).map(|k| surprise(&cols[k], r[k], n, true)).sum()).collect();
        t_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        JointNull { cols, t_sorted, n, rows }
    }
    /// (p, T, #null points at least as high in every coordinate)
    fn test(&self, x: &[f64]) -> (f64, f64, usize) {
        let t: f64 = x.iter().enumerate().map(|(k, v)| surprise(&self.cols[k], *v, self.n, false)).sum();
        let ge = self.t_sorted.len() - self.t_sorted.partition_point(|v| *v < t - 1e-12);
        let dom = self.rows.iter().filter(|r| r.iter().zip(x).all(|(a, b)| a >= b)).count();
        (stats::empirical_p(ge, self.n), t, dom)
    }
    /// (p, T, 0): the joint test without the all-coordinates dominance count
    fn test_fast(&self, x: &[f64]) -> (f64, f64, usize) {
        let t: f64 = x.iter().enumerate().map(|(k, v)| surprise(&self.cols[k], *v, self.n, false)).sum();
        let ge = self.t_sorted.len() - self.t_sorted.partition_point(|v| *v < t - 1e-12);
        (stats::empirical_p(ge, self.n), t, 0)
    }
    /// marginal (count at least as high, share) for one coordinate
    fn marginal(&self, k: usize, v: f64) -> (usize, f64) {
        let ge = self.cols[k].len() - self.cols[k].partition_point(|x| *x < v);
        (ge, stats::empirical_p(ge, self.n))
    }
}

// ───────────────────────────── output rows ──────────────────────────────────

/// One connection of the report: (origin, destination, account, result)
/// on one day, with how unusual it is and why.
struct Conn {
    p: f64,
    q: f64,
    tstat: f64,
    day: i32,
    first: i64,
    last: i64,
    origin: String,
    dest: String,
    account: String,
    result: &'static str,
    events: u64,
    logs: String,
    why: String,
    campaign: String,
    cypher: String,
    evaluable: bool,
}

// ───────────────────────────── main entry ───────────────────────────────────

pub async fn run(graph: &Graph, dialect: &Dialect, cfg: &Settings, output: Option<&str>) {
    let clock = std::time::Instant::now();
    crate::banner::print_phase("3", "4", "Reading the graph...");
    let corpus = match pull(graph).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Masstin - Error: reading edges failed: {}", e);
            return;
        }
    };
    crate::banner::print_phase_result(&format!(
        "{} edge rows, {} nodes, {} accounts ({:.1}s)",
        corpus.rows.len(),
        corpus.nodes.names.len(),
        corpus.accts.names.len(),
        clock.elapsed().as_secs_f64()
    ));
    crate::banner::print_phase("4", "4", "Computing statistics...");
    let mut corpus = corpus;
    if let Some(end) = cfg.end {
        let e = end.timestamp();
        corpus.rows.retain(|r| r.t <= e);
        crate::banner::print_phase_detail("Window end:", &format!("{} (later events ignored)", end.to_rfc3339()));
    }
    let (rows, summary_lines, alpha) = analyse(&corpus, dialect, cfg);
    for l in &summary_lines {
        crate::banner::print_phase_detail("", l);
    }
    if let Err(e) = write_csv(&rows, alpha, output) {
        eprintln!("Masstin - Error: cannot write findings CSV: {}", e);
        return;
    }
    crate::banner::print_phase_detail("Done:", &format!("{} rows in {:.1}s", rows.len(), clock.elapsed().as_secs_f64()));
}

struct Entities {
    names: Interner,
    aliases: Vec<BTreeSet<String>>,
    of_node: Vec<u32>,
}

fn build_entities(c: &Corpus, alpha: f64) -> (Entities, HashMap<String, resolve::Resolution>) {
    let obs = c.rows.iter().filter(|r| r.cls == OK || r.cls == FAIL).filter(|r| !is_no_account(c.accts.name(r.a))).map(|r| {
        let src = c.nodes.name(r.o);
        Obs {
            dst: c.nodes.name(r.d),
            account: c.accts.name(r.a),
            outcome: c.ets.name(r.et),
            sec: r.t,
            source: src,
            source_is_ip: looks_like_ip(src),
        }
    });
    let res = resolve::resolve_ip_names(obs, alpha);
    let mut names = Interner::default();
    let mut aliases: Vec<BTreeSet<String>> = Vec::new();
    let mut of_node = Vec::with_capacity(c.nodes.names.len());
    for n in &c.nodes.names {
        let label = match res.get(n) {
            Some(r) => r.name.clone(),
            None => n.clone(),
        };
        let id = names.id(&label);
        if aliases.len() <= id as usize {
            aliases.push(BTreeSet::new());
        }
        aliases[id as usize].insert(n.clone());
        of_node.push(id);
    }
    (Entities { names, aliases, of_node }, res)
}

fn entity_label(e: &Entities, id: u32) -> String {
    let name = e.names.name(id);
    let others: Vec<&String> = e.aliases[id as usize].iter().filter(|a| a.as_str() != name).collect();
    if others.is_empty() {
        name.to_string()
    } else {
        format!("{} [{}]", name, others.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" "))
    }
}

/// Coordinates of the origin-day profile, in order. The detector name is
/// used for the component rows and for --skip/--only.
const COORDS: [(&str, &str); 10] = [
    ("origin-fanout", "destinations reached for the first time"),
    ("cred-rotation", "accounts used for the first time from this origin"),
    ("novel-edge", "account-destination combinations never seen"),
    ("community-bridge", "new destinations outside the origin's Louvain community"),
    ("failed-sweep", "destinations with failed attempts"),
    ("preauth-sweep", "destinations touched without authenticating (SSH pre-auth)"),
    ("probe-then-success", "refused named attempts followed the same day by a login with an account new for this origin"),
    ("no-history", "origin has no event of any kind in the baseline"),
    ("rare-logon-type", "rarest logon type used, -ln(share of the destination's logins with a type at most this rare)"),
    ("chain-motif", "fastest new-login chain started, 1 / (1 + seconds between the two hops)"),
];

type Pred<'a> = &'a dyn Fn(u32) -> bool;

/// Profile of one origin-day restricted to the destinations `ok` (login
/// coverage) and `fail` (failure coverage) accept.
fn profile(o: &OriginDay, ok: Pred, fail: Pred, enabled: &[bool; 10]) -> [f64; 10] {
    let mut v = [0.0f64; 10];
    v[0] = o.new_dsts.iter().filter(|d| ok(**d)).count() as f64;
    v[1] = o.new_acct_uses.iter().filter(|(_, d)| ok(*d)).map(|(a, _)| *a).collect::<BTreeSet<u32>>().len() as f64;
    v[2] = o.new_ad.iter().filter(|(_, d)| ok(*d)).count() as f64;
    v[3] = o.cross_dsts.iter().filter(|d| ok(**d)).count() as f64;
    v[4] = o.fail_dsts.iter().filter(|d| fail(**d)).count() as f64;
    v[5] = o.pre_dsts.iter().filter(|d| fail(**d)).count() as f64;
    v[6] = match o.newacct_success.iter().filter(|(d, _)| ok(*d)).map(|(_, t)| *t).max() {
        Some(last) => o.refused.iter().filter(|(d, _, t)| fail(*d) && *t < last).map(|(d, a, _)| (*d, *a)).collect::<BTreeSet<(u32, u32)>>().len() as f64,
        None => 0.0,
    };
    v[7] = if o.no_history { 1.0 } else { 0.0 };
    v[8] = o.lt_surprise.iter().filter(|(d, _, _)| ok(*d)).map(|(_, s, _)| *s).fold(0.0, f64::max);
    v[9] = o.chains.iter().filter(|(b, _, _)| ok(*b)).map(|(_, _, g)| 1.0 / (1.0 + *g as f64)).fold(0.0, f64::max);
    for (i, e) in enabled.iter().enumerate() {
        if !e {
            v[i] = 0.0;
        }
    }
    v
}

fn active(o: &OriginDay, ok: Pred, fail: Pred) -> bool {
    o.ok_dsts.iter().any(|d| ok(*d)) || o.fail_dsts.iter().any(|d| fail(*d)) || o.pre_dsts.iter().any(|d| fail(*d))
}

/// Days a list of flattened [s0, e0, s1, e1, ...] spans touches.
fn span_days(spans: &[i64]) -> BTreeSet<i32> {
    let mut out = BTreeSet::new();
    for pair in spans.chunks(2) {
        if pair.len() == 2 && pair[1] >= pair[0] {
            for d in day_of(pair[0])..=day_of(pair[1]) {
                out.insert(d);
            }
        }
    }
    out
}

fn analyse(c: &Corpus, dialect: &Dialect, cfg: &Settings) -> (Vec<Conn>, Vec<String>, f64) {
    let mut lines = Vec::new();
    let alpha = cfg.alpha;
    let (ents, res) = build_entities(c, alpha);
    lines.push(format!(
        "Machines: {} graph nodes -> {} machines ({} IP(s) folded into a host name: unanimous same-login evidence, chance coincidence significant at FDR {})",
        c.nodes.names.len(),
        ents.names.names.len(),
        res.len(),
        alpha
    ));
    let ne = ents.names.names.len();
    let cutoff_ts = cfg.cutoff.timestamp();
    let cutoff_day = day_of(cutoff_ts);
    if cutoff_ts % 86_400 != 0 {
        lines.push(format!("Note: cutoff is not at 00:00 UTC; the whole day {} belongs to the window", day_str(cutoff_day)));
    }
    let is_base = |day: i32| day < cutoff_day;
    let enabled: [bool; 10] = {
        let mut e = [true; 10];
        for (i, (det, _)) in COORDS.iter().enumerate() {
            if *det != "no-history" {
                e[i] = cfg.enabled(det);
            }
        }
        e
    };

    struct Ev {
        t: i64,
        day: i32,
        o: u32,
        d: u32,
        a: u32,
        cls: u8,
        lt: u32,
        n: u64,
        fam: u32,
    }
    let mut evs: Vec<Ev> = c
        .rows
        .iter()
        .map(|r| Ev { t: r.t, day: day_of(r.t), o: ents.of_node[r.o as usize], d: ents.of_node[r.d as usize], a: r.a, cls: r.cls, lt: r.lt, n: r.n, fam: r.fam })
        .collect();
    evs.sort_by_key(|e| e.t);
    let base_days: BTreeSet<i32> = evs.iter().map(|e| e.day).filter(|d| is_base(*d)).collect();
    let win_days: BTreeSet<i32> = evs.iter().map(|e| e.day).filter(|d| !is_base(*d)).collect();

    // ── coverage per destination machine: log-file spans from the loader,
    //    or (older graphs) the days with events ──
    let mut cov_ok: HashMap<u32, BTreeSet<i32>> = HashMap::new();
    let mut cov_fail: HashMap<u32, BTreeSet<i32>> = HashMap::new();
    let mut spans_used = false;
    for (node, (ok, fail)) in &c.cov {
        if let Some(&nid) = c.nodes.map.get(node) {
            let e = ents.of_node[nid as usize];
            if !ok.is_empty() || !fail.is_empty() {
                spans_used = true;
            }
            cov_ok.entry(e).or_default().extend(span_days(ok));
            cov_fail.entry(e).or_default().extend(span_days(fail));
        }
    }
    if !spans_used {
        for r in &c.rows {
            let d = ents.of_node[r.d as usize];
            let day = day_of(r.t);
            if r.cov.0 {
                cov_ok.entry(d).or_default().insert(day);
            }
            if r.cov.1 {
                cov_fail.entry(d).or_default().insert(day);
            }
        }
        lines.push("Coverage: graph has no log-file spans (loaded by an older masstin); using days with events".to_string());
    }
    let covered = |m: &HashMap<u32, BTreeSet<i32>>, d: u32, day: i32| m.get(&d).map(|s| s.contains(&day)).unwrap_or(false);
    let kref = |m: &HashMap<u32, BTreeSet<i32>>, d: u32| m.get(&d).map(|s| s.range(..cutoff_day).count()).unwrap_or(0);

    // ── panel: destinations covered on every day from S to the cutoff; S
    //    maximises (panel size x null days) ──
    let bd: Vec<i32> = base_days.iter().copied().collect();
    let dsts: Vec<u32> = cov_ok.keys().copied().collect();
    let mut best = (0usize, cutoff_day);
    {
        // for each destination and kind, the first day of its last
        // uninterrupted run of covered days that reaches the cutoff
        let run_starts = |m: &HashMap<u32, BTreeSet<i32>>| -> Vec<i32> {
            let mut v = Vec::new();
            for s in m.values() {
                if !s.contains(&(cutoff_day - 1)) {
                    continue;
                }
                let mut st = cutoff_day - 1;
                while s.contains(&(st - 1)) {
                    st -= 1;
                }
                v.push(st);
            }
            v
        };
        let rs_ok = run_starts(&cov_ok);
        let rs_fail = run_starts(&cov_fail);
        // S maximises the information of the worse-served kind of evidence:
        // min(login panel, failure panel) x null days. A sum would let a
        // long login history buy out the failure panel (and with it the
        // failed-sweep / pre-auth / probe signals) almost entirely.
        for (k, s) in bd.iter().enumerate() {
            let size = rs_ok.iter().filter(|st| **st <= *s).count().min(rs_fail.iter().filter(|st| **st <= *s).count());
            let cells = size * (bd.len() - k);
            if cells > best.0 {
                best = (cells, *s);
            }
        }
    }
    let s_day = best.1;
    let in_run = |m: &HashMap<u32, BTreeSet<i32>>, d: u32| -> bool {
        match m.get(&d) {
            Some(s) => (s_day..cutoff_day).all(|x| s.contains(&x)),
            None => false,
        }
    };
    let panel_ok: HashSet<u32> = dsts.iter().copied().filter(|d| in_run(&cov_ok, *d)).collect();
    let panel_fail: HashSet<u32> = cov_fail.keys().copied().filter(|d| in_run(&cov_fail, *d)).collect();
    let null_days: Vec<i32> = bd.iter().copied().filter(|d| *d >= s_day).collect();
    lines.push(format!(
        "Panel: {} destination(s) with continuous login coverage and {} with failure coverage from {} to the cutoff; {} baseline day(s) form the null; reference for novelty = all {} baseline day(s) with data, leave-one-day-out",
        panel_ok.len(),
        panel_fail.len(),
        day_str(s_day),
        null_days.len(),
        base_days.len()
    ));

    // ── baseline item indexes ──
    let mut ix_triple: DayIndex<(u32, u32, u32)> = DayIndex::new();
    // (origin, destination, account, result): the connection itself
    let mut ix_conn: DayIndex<(u32, u32, u32, u8)> = DayIndex::new();
    let mut ix_pair: DayIndex<(u32, u32)> = DayIndex::new();
    let mut ix_ad: DayIndex<(u32, u32)> = DayIndex::new();
    let mut ix_oa: DayIndex<(u32, u32)> = DayIndex::new();
    let mut ix_org: DayIndex<u32> = DayIndex::new();
    let mut lt_base: HashMap<u32, HashMap<u32, u64>> = HashMap::new();
    let mut lt_day: HashMap<(i32, u32), HashMap<u32, u64>> = HashMap::new();
    for e in evs.iter().filter(|e| is_base(e.day)) {
        ix_org.add(e.o, e.day);
        if e.cls == OK || e.cls == FAIL || e.cls == PRE {
            ix_conn.add((e.o, e.d, e.a, e.cls), e.day);
        }
        match e.cls {
            OK => {
                ix_triple.add((e.o, e.d, e.a), e.day);
                ix_pair.add((e.o, e.d), e.day);
                ix_ad.add((e.a, e.d), e.day);
                ix_oa.add((e.o, e.a), e.day);
                *lt_base.entry(e.d).or_default().entry(e.lt).or_insert(0) += e.n;
                *lt_day.entry((e.day, e.d)).or_default().entry(e.lt).or_insert(0) += e.n;
            }
            FAIL => {
                if !is_no_account(c.accts.name(e.a)) {
                    ix_oa.add((e.o, e.a), e.day);
                }
            }
            _ => {}
        }
    }

    // ── reference graphs (baseline pairs; on a baseline day without the
    //    pairs unique to it) for Louvain and centrality ──
    let want_comm = enabled[3];
    let want_central = cfg.enabled("pagerank-spike") || cfg.enabled("betweenness-spike");
    let base_pairs: Vec<(usize, usize)> = ix_pair.m.keys().filter(|(o, d)| o != d).map(|(o, d)| (*o as usize, *d as usize)).collect();
    let mut unique_by_day: BTreeMap<i32, HashSet<(usize, usize)>> = BTreeMap::new();
    for ((o, d), c0) in &ix_pair.m {
        if o != d && c0.n == 1 {
            unique_by_day.entry(c0.first).or_default().insert((*o as usize, *d as usize));
        }
    }
    let nodes_of = |edges: &[(usize, usize)]| -> HashSet<usize> { edges.iter().flat_map(|(a, b)| [*a, *b]).collect() };
    let g_base = DiGraph::from_edges(ne, &base_pairs);
    let base_nodes = nodes_of(&base_pairs);
    let comm_base = if want_comm { algos::louvain(&g_base) } else { Vec::new() };
    let m_base = if want_central { Some((algos::pagerank(&g_base), algos::betweenness(&g_base))) } else { None };
    let mut comm_day: HashMap<i32, (Vec<usize>, HashSet<usize>)> = HashMap::new();
    let mut delta_day: HashMap<i32, (Vec<f64>, Vec<f64>)> = HashMap::new();
    for (day, uniq) in &unique_by_day {
        let need_c = want_comm;
        let need_m = want_central && *day >= s_day;
        if !need_c && !need_m {
            continue;
        }
        let r: Vec<(usize, usize)> = base_pairs.iter().copied().filter(|p| !uniq.contains(p)).collect();
        let g = DiGraph::from_edges(ne, &r);
        if need_c {
            comm_day.insert(*day, (algos::louvain(&g), nodes_of(&r)));
        }
        if need_m {
            let (pb, bb) = m_base.as_ref().unwrap();
            let (pr, bc) = (algos::pagerank(&g), algos::betweenness(&g));
            delta_day.insert(*day, (pb.iter().zip(&pr).map(|(a, b)| clean_delta(*a, *b, ne)).collect(), bb.iter().zip(&bc).map(|(a, b)| clean_delta(*a, *b, ne * ne)).collect()));
        }
    }

    // ── per-day facts ──
    let mut triples: Vec<TripleDay> = Vec::new();
    let mut origin_days: BTreeMap<(i32, u32), OriginDay> = BTreeMap::new();
    let mut ok_events: Vec<OkEvent> = Vec::new();
    let mut pairs_by_day: BTreeMap<i32, BTreeSet<(u32, u32)>> = BTreeMap::new();
    let mut i = 0usize;
    while i < evs.len() {
        let day = evs[i].day;
        let mut j = i;
        while j < evs.len() && evs[j].day == day {
            j += 1;
        }
        let b = is_base(day);
        let today = &evs[i..j];
        let (cm, cnodes): (&Vec<usize>, &HashSet<usize>) = match (b, comm_day.get(&day)) {
            (true, Some(x)) => (&x.0, &x.1),
            _ => (&comm_base, &base_nodes),
        };
        let mut tri: HashMap<(u32, u32, u32, u8), (u64, i64, i64, u64)> = HashMap::new();
        let mut ltc: HashMap<(u32, u32, u32), u64> = HashMap::new();
        for e in today.iter().filter(|e| e.cls == OK || e.cls == FAIL || e.cls == PRE) {
            let x = tri.entry((e.o, e.d, e.a, e.cls)).or_insert((0, e.t, e.t, 0));
            x.0 += e.n;
            x.2 = e.t;
            x.3 |= 1u64 << e.fam.min(63);
            if e.cls == OK {
                *ltc.entry((e.o, e.d, e.lt)).or_insert(0) += e.n;
            }
        }
        for ((o, d, a, cls), (n, t0, t1, fams)) in tri {
            let an = c.accts.name(a);
            let named = !is_no_account(an) && !is_uid_account(an);
            let mut f = 0u8;
            // the connection itself (same origin, destination, account and
            // result) seen on another baseline day is habitual: nothing
            // about it is new, whatever else happens that day
            let conn_new = ix_conn.is_new(&(o, d, a, cls), day, b);
            if conn_new && (cls != OK || ix_triple.is_new(&(o, d, a), day, b)) {
                f |= F_TRIPLE;
            }
            if named && ix_ad.is_new(&(a, d), day, b) {
                f |= F_ACCT_DST;
            }
            if ix_pair.is_new(&(o, d), day, b) {
                f |= F_DST_ORIGIN;
            }
            if named && ix_oa.is_new(&(o, a), day, b) {
                f |= F_ACCT_ORIGIN;
            }
            if ix_org.is_new(&o, day, b) {
                f |= F_NO_HISTORY;
            }
            let k = if b { kref(&cov_ok, d).saturating_sub(1) } else { kref(&cov_ok, d) };
            triples.push(TripleDay { day, o, d, a, cls, fams, flags: f, k, n, t0, t1 });
        }
        for e in today {
            let od = origin_days
                .entry((day, e.o))
                .or_insert_with(|| OriginDay { t0: e.t, no_history: ix_org.is_new(&e.o, day, b), ..Default::default() });
            od.t1 = e.t;
            match e.cls {
                OK => {
                    od.ok_dsts.insert(e.d);
                    let pnew = ix_pair.is_new(&(e.o, e.d), day, b);
                    if pnew && e.o != e.d {
                        od.new_dsts.insert(e.d);
                        if want_comm && cnodes.contains(&(e.o as usize)) && cnodes.contains(&(e.d as usize)) && cm[e.o as usize] != cm[e.d as usize] {
                            od.cross_dsts.insert(e.d);
                        }
                    }
                    pairs_by_day.entry(day).or_default().insert((e.o, e.d));
                    let an = c.accts.name(e.a);
                    if !is_uid_account(an) {
                        if ix_oa.is_new(&(e.o, e.a), day, b) {
                            od.new_acct_uses.insert((e.a, e.d));
                            od.newacct_success.push((e.d, e.t));
                        }
                        if ix_ad.is_new(&(e.a, e.d), day, b) {
                            od.new_ad.insert((e.a, e.d));
                        }
                    }
                    od.ok_secs.push(e.t.rem_euclid(86_400) as f64);
                    ok_events.push(OkEvent { t: e.t, day, o: e.o, d: e.d, pair_new: pnew });
                }
                FAIL => {
                    od.fail_dsts.insert(e.d);
                    od.fail_n += e.n;
                    let an = c.accts.name(e.a);
                    if !is_no_account(an) && !is_uid_account(an) {
                        od.refused.insert((e.d, e.a, e.t));
                    }
                }
                PRE => {
                    od.pre_dsts.insert(e.d);
                    od.pre_n += e.n;
                }
                _ => {}
            }
        }
        // logon-type rarity against the destination's other baseline days
        for ((o, d, lt), _) in ltc {
            let base = lt_base.get(&d);
            let minus = if b { lt_day.get(&(day, d)) } else { None };
            let refc = |t: u32| -> u64 {
                base.and_then(|m| m.get(&t)).copied().unwrap_or(0).saturating_sub(minus.and_then(|m| m.get(&t)).copied().unwrap_or(0))
            };
            let types: Vec<u32> = base.map(|m| m.keys().copied().collect()).unwrap_or_default();
            let tot: u64 = types.iter().map(|t| refc(*t)).sum();
            if tot == 0 {
                continue;
            }
            let n_obs = refc(lt);
            let tail: u64 = types.iter().map(|t| refc(*t)).filter(|v| *v <= n_obs).sum();
            let share = stats::empirical_p(tail as usize, tot as usize);
            if let Some(od) = origin_days.get_mut(&(day, o)) {
                od.lt_surprise.push((d, -share.ln(), lt));
            }
        }
        i = j;
    }
    // chains: A opened a new login to B, then B opened a new login to C
    if enabled[9] {
        let mut out_new: HashMap<u32, Vec<(i64, u32)>> = HashMap::new();
        for e in ok_events.iter().filter(|e| e.pair_new) {
            out_new.entry(e.o).or_default().push((e.t, e.d));
        }
        for v in out_new.values_mut() {
            v.sort();
        }
        for e in ok_events.iter().filter(|e| e.pair_new) {
            let v = match out_new.get(&e.d) {
                Some(v) => v,
                None => continue,
            };
            let k = v.partition_point(|(t, _)| *t <= e.t);
            if let Some((t2, cc)) = v[k..].iter().find(|(_, cc)| *cc != e.o && *cc != e.d).copied() {
                if is_base(e.day) && t2 >= cutoff_ts {
                    continue;
                }
                if let Some(od) = origin_days.get_mut(&(e.day, e.o)) {
                    od.chains.push((e.d, cc, t2 - e.t));
                }
            }
        }
    }

    let names = |set: &mut dyn Iterator<Item = u32>| -> String {
        let mut v: Vec<String> = set.map(|d| ents.names.name(d).to_string()).collect();
        v.sort();
        v.dedup();
        v.join(" ")
    };
    let alias_list = |id: u32| -> Vec<String> { ents.aliases[id as usize].iter().cloned().collect() };
    let dest_nodes = |ids: &mut dyn Iterator<Item = u32>| -> Vec<String> { ids.flat_map(|d| ents.aliases[d as usize].iter().cloned().collect::<Vec<_>>()).collect() };
    let day_from = |day: i32| ts_str(day as i64 * 86_400);
    let day_to = |day: i32| ts_str((day as i64 + 1) * 86_400);

    // ═════════════ connection-level test ═════════════
    //
    // The unit is one connection: (origin, destination, account, result)
    // on one day. Each is described by what is new about it and by the
    // context it happened in; it is compared with the connections of the
    // same result (login OK / failed / unauthenticated) on the baseline
    // days, on the destinations both days could show.

    // window-day centrality deltas (baseline graph + the day's logins)
    let mut win_delta: HashMap<i32, (Vec<f64>, Vec<f64>)> = HashMap::new();
    if let Some((pb, bb)) = m_base.as_ref() {
        for wday in &win_days {
            let mut e: Vec<(usize, usize)> = base_pairs.clone();
            if let Some(ps) = pairs_by_day.get(wday) {
                e.extend(ps.iter().filter(|(o, d)| o != d).map(|(o, d)| (*o as usize, *d as usize)));
            }
            let g = DiGraph::from_edges(ne, &e);
            let (pr, bc) = (algos::pagerank(&g), algos::betweenness(&g));
            win_delta.insert(
                *wday,
                (
                    pr.iter().zip(pb).map(|(a, b)| clean_delta(*a, *b, ne)).collect(),
                    bc.iter().zip(bb).map(|(a, b)| clean_delta(*a, *b, ne * ne)).collect(),
                ),
            );
        }
    }
    let use_pr = cfg.enabled("pagerank-spike");
    let use_bc = cfg.enabled("betweenness-spike");
    let cen = |day: i32, d: u32| -> (f64, f64) {
        let src = if is_base(day) { delta_day.get(&day) } else { win_delta.get(&day) };
        match src {
            Some((p, b)) => (if use_pr { p[d as usize].max(0.0) } else { 0.0 }, if use_bc { b[d as usize].max(0.0) } else { 0.0 }),
            None => (0.0, 0.0),
        }
    };
    let on = |det: &str| cfg.enabled(det);
    let empty_od = OriginDay::default();
    // connection features, for the destinations `okp` / `failp` accept
    let features = |t: &TripleDay, okp: Pred, failp: Pred, cache: &mut HashMap<(i32, u32), [f64; 10]>| -> [f64; 15] {
        let mut v = [0.0f64; 15];
        // a habitual connection is not unusual, whatever its context
        if t.flags & F_TRIPLE == 0 {
            v[4] = 0.0;
            return v;
        }
        let od = origin_days.get(&(t.day, t.o)).unwrap_or(&empty_od);
        let ctx = *cache.entry((t.day, t.o)).or_insert_with(|| profile(od, okp, failp, &enabled));
        let f = t.flags;
        let bit = |m: u8| if f & m != 0 { 1.0 } else { 0.0 };
        if on("novel-edge") {
            v[0] = bit(F_TRIPLE);
            v[1] = bit(F_ACCT_DST);
        }
        if on("origin-fanout") {
            v[2] = bit(F_DST_ORIGIN);
            v[5] = ctx[0];
        }
        if on("cred-rotation") {
            v[3] = bit(F_ACCT_ORIGIN);
            v[6] = ctx[1];
        }
        v[4] = bit(F_NO_HISTORY);
        v[7] = ctx[4];
        v[8] = ctx[5];
        v[9] = ctx[6];
        if t.cls == OK {
            if on("community-bridge") && od.cross_dsts.contains(&t.d) {
                v[10] = 1.0;
            }
            if on("rare-logon-type") {
                v[11] = od.lt_surprise.iter().filter(|(d, _, _)| *d == t.d).map(|(_, s, _)| *s).fold(0.0, f64::max);
            }
            if on("chain-motif") {
                v[12] = od.chains.iter().filter(|(b, _, _)| *b == t.d).map(|(_, _, g)| 1.0 / (1.0 + *g as f64)).fold(0.0, f64::max);
            }
            let (dp, db) = cen(t.day, t.d);
            v[13] = dp;
            v[14] = db;
        }
        v
    };
    struct Tested<'a> {
        t: &'a TripleDay,
        x: [f64; 15],
        p: f64,
        tstat: f64,
        n_null: usize,
        marg: Vec<(usize, f64)>,
    }
    let mut tested: Vec<Tested> = Vec::new();
    let mut not_eval: Vec<&TripleDay> = Vec::new();
    for wday in &win_days {
        let pw_ok: HashSet<u32> = panel_ok.iter().copied().filter(|d| covered(&cov_ok, *d, *wday)).collect();
        let pw_fail: HashSet<u32> = panel_fail.iter().copied().filter(|d| covered(&cov_fail, *d, *wday)).collect();
        let okp = |d: u32| pw_ok.contains(&d);
        let failp = |d: u32| pw_fail.contains(&d);
        let on_panel = |t: &TripleDay| if t.cls == OK { okp(t.d) } else { failp(t.d) };
        for cls in [OK, FAIL, PRE] {
            let mut cache: HashMap<(i32, u32), [f64; 10]> = HashMap::new();
            let null_rows: Vec<Vec<f64>> = triples
                .iter()
                .filter(|t| t.cls == cls && is_base(t.day) && t.day >= s_day && on_panel(t))
                .map(|t| features(t, &okp, &failp, &mut cache).to_vec())
                .collect();
            let jn = JointNull::new(null_rows);
            for t in triples.iter().filter(|t| t.cls == cls && t.day == *wday) {
                if !on_panel(t) {
                    not_eval.push(t);
                    continue;
                }
                let x = features(t, &okp, &failp, &mut cache);
                let (p, tstat, _) = jn.test_fast(&x);
                let marg: Vec<(usize, f64)> = (0..15).map(|k| if x[k] > 0.0 { jn.marginal(k, x[k]) } else { (jn.n, 1.0) }).collect();
                tested.push(Tested { t, x, p, tstat, n_null: jn.n, marg });
            }
        }
    }
    let qs = stats::benjamini_hochberg(&tested.iter().map(|x| x.p).collect::<Vec<_>>());
    let n_sig = qs.iter().filter(|q| **q <= alpha).count();
    lines.push(format!(
        "Connections: {} tested (origin, destination, account, result, day) against {} baseline day(s); {} significant at FDR {} (Benjamini-Hochberg); {} on destinations without comparable coverage",
        tested.len(),
        null_days.len(),
        n_sig,
        alpha,
        not_eval.len()
    ));

    // ── campaigns (origins with no history sharing a new account) ──
    let mut campaign_of: HashMap<u32, String> = HashMap::new();
    {
        let pop_set: HashSet<u32> = panel_ok.iter().copied().filter(|d| win_days.iter().any(|w| covered(&cov_ok, *d, *w))).collect();
        let mut nod: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
        let mut noa: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
        for ((day, o), od) in &origin_days {
            if is_base(*day) || ix_org.m.contains_key(o) {
                continue;
            }
            nod.entry(*o).or_default().extend(od.new_dsts.iter().copied().filter(|d| pop_set.contains(d)));
            noa.entry(*o).or_default().extend(od.new_acct_uses.iter().map(|(a, _)| *a));
        }
        let cand: Vec<u32> = nod.iter().filter(|(_, s)| !s.is_empty()).map(|(o, _)| *o).collect();
        let pop = pop_set.len() as u64;
        let mut pairs: Vec<(u32, u32, f64, usize, BTreeSet<u32>)> = Vec::new();
        for x in 0..cand.len() {
            for y in x + 1..cand.len() {
                let (a, b) = (cand[x], cand[y]);
                let shared: BTreeSet<u32> = noa[&a].intersection(&noa[&b]).copied().collect();
                if shared.is_empty() {
                    continue;
                }
                let (da, db) = (&nod[&a], &nod[&b]);
                let k = da.intersection(db).count();
                pairs.push((a, b, stats::hypergeom_upper(pop, da.len() as u64, db.len() as u64, k as u64), k, shared));
            }
        }
        let pq = stats::benjamini_hochberg(&pairs.iter().map(|p| p.2).collect::<Vec<_>>());
        let mut n_camp = 0usize;
        for (k, pr) in pairs.iter().enumerate() {
            if pq[k] > alpha {
                continue;
            }
            n_camp += 1;
            let acc = pr.4.iter().map(|a| c.accts.name(*a)).collect::<Vec<_>>().join(" ");
            for (me, other, mine) in [(pr.0, pr.1, &nod[&pr.0]), (pr.1, pr.0, &nod[&pr.1])] {
                let txt = format!(
                    "with {}: both never seen before, same new account {}, {} of its {} new destinations shared (exact test p = {:.1e}, q = {:.1e})",
                    entity_label(&ents, other),
                    acc,
                    pr.3,
                    mine.len(),
                    pr.2,
                    pq[k]
                );
                let e = campaign_of.entry(me).or_default();
                if !e.is_empty() {
                    e.push_str("; ");
                }
                e.push_str(&txt);
            }
        }
        lines.push(format!("Campaigns: {} candidate pair(s) sharing a new account, {} significant", pairs.len(), n_camp));
    }

    // ── report rows ──
    let result_name = |cls: u8| match cls {
        OK => "login OK",
        FAIL => "login FAILED",
        PRE => "connection without authentication (SSH pre-auth)",
        _ => "other",
    };
    let class_name = |cls: u8| match cls {
        OK => "successful logins",
        FAIL => "failed logins",
        _ => "unauthenticated connections",
    };
    let fam_list = |m: u64| -> String {
        let mut v: Vec<&str> = (0..64u32).filter(|i| m & (1u64 << i) != 0).filter_map(|i| c.fams.names.get(i as usize).map(|s| s.as_str())).filter(|s| !s.is_empty()).collect();
        v.sort();
        v.join(" ")
    };
    let mut out: Vec<Conn> = Vec::new();
    for (i, tt) in tested.iter().enumerate() {
        let t = tt.t;
        let od = origin_days.get(&(t.day, t.o)).unwrap_or(&empty_od);
        let mut why: Vec<String> = Vec::new();
        let base = |k: usize| format!("{} of {} baseline {}", tt.marg[k].0, tt.n_null, class_name(t.cls));
        let x = &tt.x;
        if x[4] > 0.0 {
            why.push(format!("origin never seen before ({} from origins never seen before)", base(4)));
        } else {
            if x[2] > 0.0 {
                why.push(format!("origin never connected to this destination before ({})", base(2)));
            }
            if x[3] > 0.0 {
                why.push(format!("account never used by this origin before ({})", base(3)));
            }
        }
        if x[1] > 0.0 {
            why.push(format!("account never logged in to this destination before ({})", base(1)));
        }
        if x[0] > 0.0 && x[1] == 0.0 && x[2] == 0.0 && x[3] == 0.0 && x[4] == 0.0 {
            why.push(format!("this origin/account/destination combination never seen, each part known ({})", base(0)));
        }
        if x[5] > 0.0 {
            why.push(format!("that day the origin reached {} destinations for the first time ({} at least as many)", x[5], base(5)));
        }
        if x[6] > 0.0 {
            why.push(format!("that day the origin used {} account(s) new to it ({} at least as many)", x[6], base(6)));
        }
        if x[7] > 0.0 {
            why.push(format!("that day the origin failed to log in on {} destination(s) ({} at least as many)", x[7], base(7)));
        }
        if x[8] > 0.0 {
            why.push(format!("that day the origin touched {} destination(s) without authenticating ({} at least as many)", x[8], base(8)));
        }
        if x[9] > 0.0 {
            why.push(format!("that day the origin had {} refused named attempt(s) before logging in with an account new to it ({} at least as many)", x[9], base(9)));
        }
        if x[10] > 0.0 {
            why.push(format!("destination outside the origin's usual group of hosts (Louvain community; {})", base(10)));
        }
        if x[11] > 0.0 {
            let lt = od.lt_surprise.iter().filter(|(d, _, _)| *d == t.d).max_by(|a, b| a.1.partial_cmp(&b.1).unwrap()).map(|x| c.lts.name(x.2)).unwrap_or("");
            why.push(format!("logon type {} is rare on this destination ({} at least as rare)", lt, base(11)));
        }
        if x[12] > 0.0 {
            if let Some((_, cc, g)) = od.chains.iter().filter(|(b, _, _)| *b == t.d).min_by_key(|x| x.2) {
                why.push(format!("{} s later the destination opened a new login to {} ({} with a chain at least as fast)", g, ents.names.name(*cc), base(12)));
            }
        }
        if x[13] > 0.0 || x[14] > 0.0 {
            why.push(format!("the destination's centrality rose that day (PageRank +{:.3}, betweenness +{:.5}; {} / {} at least as high)", x[13], x[14], base(13), base(14)));
        }
        if why.is_empty() {
            why.push("nothing new: a connection like the usual ones".into());
        }
        let acct = c.accts.name(t.a);
        out.push(Conn {
            p: tt.p,
            q: qs[i],
            tstat: tt.tstat,
            day: t.day,
            first: t.t0,
            last: t.t1,
            origin: entity_label(&ents, t.o),
            dest: entity_label(&ents, t.d),
            account: if is_no_account(acct) { String::new() } else { acct.to_string() },
            result: result_name(t.cls),
            events: t.n,
            logs: fam_list(t.fams),
            why: why.join("; "),
            campaign: campaign_of.get(&t.o).cloned().unwrap_or_default(),
            cypher: super::browser_snippet_multi(
                dialect,
                &alias_list(t.o),
                &alias_list(t.d),
                if is_no_account(acct) { None } else { Some(acct) },
                &ts_str(t.t0 - 1),
                Some(&ts_str(t.t1 + 1)),
            ),
            evaluable: true,
        });
    }
    for t in not_eval {
        let acct = c.accts.name(t.a);
        let k = kref(&cov_ok, t.d);
        out.push(Conn {
            p: f64::NAN,
            q: f64::NAN,
            tstat: f64::NAN,
            day: t.day,
            first: t.t0,
            last: t.t1,
            origin: entity_label(&ents, t.o),
            dest: entity_label(&ents, t.d),
            account: if is_no_account(acct) { String::new() } else { acct.to_string() },
            result: result_name(t.cls),
            events: t.n,
            logs: fam_list(t.fams),
            why: format!(
                "not evaluated: the destination has {} covered baseline day(s) and no continuous coverage from {} to the cutoff, so nothing there can be judged new or habitual",
                k,
                day_str(s_day)
            ),
            campaign: campaign_of.get(&t.o).cloned().unwrap_or_default(),
            cypher: super::browser_snippet_multi(
                dialect,
                &alias_list(t.o),
                &alias_list(t.d),
                if is_no_account(acct) { None } else { Some(acct) },
                &ts_str(t.t0 - 1),
                Some(&ts_str(t.t1 + 1)),
            ),
            evaluable: false,
        });
    }
    // most unusual first: p, then combined surprise, then volume
    out.sort_by(|a, b| {
        (!a.evaluable)
            .cmp(&!b.evaluable)
            .then(nan_last(a.p).partial_cmp(&nan_last(b.p)).unwrap())
            .then(nan_last(-a.tstat).partial_cmp(&nan_last(-b.tstat)).unwrap())
            .then(a.first.cmp(&b.first))
    });
    (out, lines, alpha)
}

fn nan_last(x: f64) -> f64 {
    if x.is_nan() {
        f64::INFINITY
    } else {
        x
    }
}

fn fmt_p(p: f64) -> String {
    if p.is_nan() {
        String::new()
    } else {
        format!("{:.3e}", p)
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn write_csv(rows: &[Conn], alpha: f64, output: Option<&str>) -> std::io::Result<()> {
    let mut buf = String::from(
        "rank,significant,p_value,q_value,day,first_seen_utc,last_seen_utc,origin,destination,account,result,events,logs,why_unusual,campaign,cypher_snippet
",
    );
    for (k, r) in rows.iter().enumerate() {
        let sig = if !r.evaluable {
            "not evaluated"
        } else if r.q <= alpha {
            "yes"
        } else {
            "no"
        };
        buf.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}
",
            k + 1,
            sig,
            fmt_p(r.p),
            fmt_p(r.q),
            day_str(r.day),
            ts_str(r.first),
            ts_str(r.last),
            csv_escape(&r.origin),
            csv_escape(&r.dest),
            csv_escape(&r.account),
            r.result,
            r.events,
            csv_escape(&r.logs),
            csv_escape(&r.why),
            csv_escape(&r.campaign),
            csv_escape(&r.cypher),
        ));
    }
    match output {
        Some(path) => std::fs::File::create(path)?.write_all(buf.as_bytes()),
        None => {
            print!("{}", buf);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn joint_extreme_gets_floor_p() {
        // 99 ordinary null points, observation beyond all of them in two
        // coordinates at once
        let rows: Vec<Vec<f64>> = (0..99).map(|i| vec![(i % 5) as f64, (i % 3) as f64]).collect();
        let jn = JointNull::new(rows);
        let (p, _, dom) = jn.test(&[10.0, 10.0]);
        assert!((p - 1.0 / 100.0).abs() < 1e-12);
        assert_eq!(dom, 0);
        // an ordinary point is not significant
        let (p2, _, _) = jn.test(&[1.0, 1.0]);
        assert!(p2 > 0.3);
    }
    #[test]
    fn dayindex_leave_one_out() {
        let mut ix: DayIndex<u32> = DayIndex::new();
        ix.add(7, 100);
        ix.add(8, 100);
        ix.add(8, 101);
        assert!(ix.is_new(&7, 100, true)); // only on day 100
        assert!(!ix.is_new(&8, 100, true)); // also on 101
        assert!(!ix.is_new(&7, 105, false)); // window: seen in baseline
        assert!(ix.is_new(&9, 105, false));
    }
}
