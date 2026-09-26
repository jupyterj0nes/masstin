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
    nodes: Interner,
    accts: Interner,
    lts: Interner,
    ets: Interner,
    rows: Vec<RawRow>,
}

async fn pull(graph: &Graph) -> neo4rs::Result<Corpus> {
    let mut c = Corpus { cov: HashMap::new(), nodes: Interner::default(), accts: Interner::default(), lts: Interner::default(), ets: Interner::default(), rows: Vec::new() };
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
    /// marginal (count at least as high, share) for one coordinate
    fn marginal(&self, k: usize, v: f64) -> (usize, f64) {
        let ge = self.cols[k].len() - self.cols[k].partition_point(|x| *x < v);
        (ge, stats::empirical_p(ge, self.n))
    }
}

// ───────────────────────────── output rows ──────────────────────────────────

struct Row {
    section: &'static str,
    /// decision (joint test that counts for the machine), component (one
    /// coordinate of it, univariate tail), detail (per-login novelty)
    role: &'static str,
    /// machine p (Fisher of family Simes) and BH q; NaN when not tested
    mp: f64,
    mq: f64,
    entity: u32,
    detector: &'static str,
    p: f64,
    day: i32,
    hosts: String,
    account: String,
    events: u64,
    window: String,
    summary: String,
    snippet: String,
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
    let (rows, summary_lines, labels, alpha) = analyse(&corpus, dialect, cfg);
    for l in &summary_lines {
        crate::banner::print_phase_detail("", l);
    }
    if let Err(e) = write_csv(&rows, &labels, alpha, output) {
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

fn analyse(c: &Corpus, dialect: &Dialect, cfg: &Settings) -> (Vec<Row>, Vec<String>, Vec<String>, f64) {
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
    }
    let mut evs: Vec<Ev> = c
        .rows
        .iter()
        .map(|r| Ev { t: r.t, day: day_of(r.t), o: ents.of_node[r.o as usize], d: ents.of_node[r.d as usize], a: r.a, cls: r.cls, lt: r.lt, n: r.n })
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
    let mut ix_pair: DayIndex<(u32, u32)> = DayIndex::new();
    let mut ix_ad: DayIndex<(u32, u32)> = DayIndex::new();
    let mut ix_oa: DayIndex<(u32, u32)> = DayIndex::new();
    let mut ix_org: DayIndex<u32> = DayIndex::new();
    let mut lt_base: HashMap<u32, HashMap<u32, u64>> = HashMap::new();
    let mut lt_day: HashMap<(i32, u32), HashMap<u32, u64>> = HashMap::new();
    for e in evs.iter().filter(|e| is_base(e.day)) {
        ix_org.add(e.o, e.day);
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
            delta_day.insert(*day, (pb.iter().zip(&pr).map(|(a, b)| a - b).collect(), bb.iter().zip(&bc).map(|(a, b)| a - b).collect()));
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
        let mut tri: HashMap<(u32, u32, u32), (u64, i64, i64)> = HashMap::new();
        let mut ltc: HashMap<(u32, u32, u32), u64> = HashMap::new();
        for e in today.iter().filter(|e| e.cls == OK) {
            let x = tri.entry((e.o, e.d, e.a)).or_insert((0, e.t, e.t));
            x.0 += e.n;
            x.2 = e.t;
            *ltc.entry((e.o, e.d, e.lt)).or_insert(0) += e.n;
        }
        for ((o, d, a), (n, t0, t1)) in tri {
            let uid = is_uid_account(c.accts.name(a));
            let mut f = 0u8;
            if ix_triple.is_new(&(o, d, a), day, b) {
                f |= F_TRIPLE;
            }
            if !uid && ix_ad.is_new(&(a, d), day, b) {
                f |= F_ACCT_DST;
            }
            if ix_pair.is_new(&(o, d), day, b) {
                f |= F_DST_ORIGIN;
            }
            if !uid && ix_oa.is_new(&(o, a), day, b) {
                f |= F_ACCT_ORIGIN;
            }
            if ix_org.is_new(&o, day, b) {
                f |= F_NO_HISTORY;
            }
            let k = if b { kref(&cov_ok, d).saturating_sub(1) } else { kref(&cov_ok, d) };
            triples.push(TripleDay { day, o, d, a, flags: f, k, n, t0, t1 });
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

    let mut tests: Vec<(u32, f64)> = Vec::new();
    let mut rows: Vec<Row> = Vec::new();

    // ── origin-day joint test, per window day on that day's panel ──
    let mut null_od: Vec<&OriginDay> = Vec::new();
    for ((day, _), od) in &origin_days {
        if is_base(*day) && *day >= s_day {
            null_od.push(od);
        }
    }
    for wday in &win_days {
        let pw_ok: HashSet<u32> = panel_ok.iter().copied().filter(|d| covered(&cov_ok, *d, *wday)).collect();
        let pw_fail: HashSet<u32> = panel_fail.iter().copied().filter(|d| covered(&cov_fail, *d, *wday)).collect();
        let okp = |d: u32| pw_ok.contains(&d);
        let failp = |d: u32| pw_fail.contains(&d);
        let jn = JointNull::new(null_od.iter().filter(|o| active(o, &okp, &failp)).map(|o| profile(o, &okp, &failp, &enabled).to_vec()).collect());
        for ((_, oid), o) in origin_days.range((*wday, 0)..=(*wday, u32::MAX)) {
            if !active(o, &okp, &failp) {
                continue;
            }
            let x = profile(o, &okp, &failp, &enabled);
            let (p, tstat, dx) = jn.test(&x);
            tests.push((*oid, p));
            if x.iter().all(|v| *v == 0.0) {
                continue;
            }
            let mut parts: Vec<String> = Vec::new();
            for k in 0..10 {
                if x[k] > 0.0 {
                    let (ge, tail) = jn.marginal(k, x[k]);
                    let val = if k >= 8 { format!("{:.3}", x[k]) } else { format!("{}", x[k] as u64) };
                    parts.push(format!("{} = {} ({} of {} baseline origin-days at least as high)", COORDS[k].0, val, ge, jn.n));
                    // component row
                    let (hosts, dn, acc): (Vec<u32>, Vec<String>, String) = match k {
                        0 => {
                            let v: Vec<u32> = o.new_dsts.iter().copied().filter(|d| okp(*d)).collect();
                            let a: BTreeSet<&str> = o.new_acct_uses.iter().filter(|(_, d)| okp(*d)).map(|(a, _)| c.accts.name(*a)).collect();
                            (v.clone(), dest_nodes(&mut v.into_iter()), a.into_iter().collect::<Vec<_>>().join(" "))
                        }
                        1 => {
                            let v: Vec<u32> = o.new_acct_uses.iter().filter(|(_, d)| okp(*d)).map(|(_, d)| *d).collect();
                            let a: BTreeSet<&str> = o.new_acct_uses.iter().filter(|(_, d)| okp(*d)).map(|(a, _)| c.accts.name(*a)).collect();
                            (v.clone(), dest_nodes(&mut v.into_iter()), a.into_iter().collect::<Vec<_>>().join(" "))
                        }
                        2 => {
                            let v: Vec<u32> = o.new_ad.iter().filter(|(_, d)| okp(*d)).map(|(_, d)| *d).collect();
                            let a: BTreeSet<&str> = o.new_ad.iter().filter(|(_, d)| okp(*d)).map(|(a, _)| c.accts.name(*a)).collect();
                            (v.clone(), dest_nodes(&mut v.into_iter()), a.into_iter().collect::<Vec<_>>().join(" "))
                        }
                        3 => {
                            let v: Vec<u32> = o.cross_dsts.iter().copied().filter(|d| okp(*d)).collect();
                            (v.clone(), dest_nodes(&mut v.into_iter()), String::new())
                        }
                        4 => {
                            let v: Vec<u32> = o.fail_dsts.iter().copied().filter(|d| failp(*d)).collect();
                            (v.clone(), dest_nodes(&mut v.into_iter()), String::new())
                        }
                        5 => {
                            let v: Vec<u32> = o.pre_dsts.iter().copied().filter(|d| failp(*d)).collect();
                            (v.clone(), dest_nodes(&mut v.into_iter()), String::new())
                        }
                        6 => {
                            let v: Vec<u32> = o.refused.iter().map(|(d, _, _)| *d).filter(|d| failp(*d)).collect();
                            let a: BTreeSet<&str> = o.refused.iter().map(|(_, a, _)| c.accts.name(*a)).chain(o.new_acct_uses.iter().map(|(a, _)| c.accts.name(*a))).collect();
                            (v.clone(), dest_nodes(&mut v.into_iter()), a.into_iter().collect::<Vec<_>>().join(" "))
                        }
                        8 => {
                            let best = o.lt_surprise.iter().filter(|(d, _, _)| okp(*d)).fold(None, |acc: Option<&(u32, f64, u32)>, x| match acc {
                                Some(a) if a.1 >= x.1 => Some(a),
                                _ => Some(x),
                            });
                            match best {
                                Some((d, _, lt)) => (vec![*d], alias_list(*d), format!("logon type {}", c.lts.name(*lt))),
                                None => (Vec::new(), Vec::new(), String::new()),
                            }
                        }
                        9 => {
                            let best = o.chains.iter().filter(|(b, _, _)| okp(*b)).min_by_key(|x| x.2);
                            match best {
                                Some((b, cc, g)) => (vec![*b, *cc], alias_list(*b), format!("{} -> {} in {} s", ents.names.name(*b), ents.names.name(*cc), g)),
                                None => (Vec::new(), Vec::new(), String::new()),
                            }
                        }
                        _ => (Vec::new(), Vec::new(), String::new()),
                    };
                    if k == 7 {
                        continue;
                    }
                    let n_ev = match k {
                        4 => o.fail_n,
                        5 => o.pre_n,
                        _ => x[k].round() as u64,
                    };
                    rows.push(Row {
                        mp: f64::NAN,
                        mq: f64::NAN,
                        section: "finding",
                        entity: *oid,
                        detector: COORDS[k].0,
                        role: "component",
                        p: tail,
                        day: *wday,
                        hosts: names(&mut hosts.iter().copied()),
                        account: acc,
                        events: n_ev,
                        window: format!("{} .. {}", ts_str(o.t0), ts_str(o.t1)),
                        summary: format!(
                            "{}: {} {} on {}. {} of {} baseline origin-days reached at least as much on the same panel.",
                            entity_label(&ents, *oid), val, COORDS[k].1, day_str(*wday), ge, jn.n
                        ),
                        snippet: super::browser_snippet_multi(dialect, &alias_list(*oid), &dn, None, &day_from(*wday), Some(&day_to(*wday))),
                    });
                }
            }
            let mut summary = format!(
                "{} on {} ({}): {}. Joint test: combined surprise {:.1}; {} of {} baseline origin-days scored at least as high, {} were at least as high in every one of these respects at once.",
                entity_label(&ents, *oid),
                day_str(*wday),
                if o.no_history { "origin has no event of any kind in the baseline" } else { "origin already active in the baseline" },
                parts.join("; "),
                tstat,
                ((p * (jn.n as f64 + 1.0)).round() as usize).saturating_sub(1),
                jn.n,
                dx
            );
            if o.ok_secs.len() >= 2 {
                let (r, pr) = stats::rayleigh(&o.ok_secs);
                summary.push_str(&format!(" Time of day of its logins: mean resultant length {:.2}, Rayleigh p = {:.2e}.", r, pr));
            }
            let all_dsts: BTreeSet<u32> = o.ok_dsts.iter().chain(o.fail_dsts.iter()).chain(o.pre_dsts.iter()).copied().filter(|d| okp(*d) || failp(*d)).collect();
            rows.push(Row {
                mp: f64::NAN,
                mq: f64::NAN,
                section: "finding",
                entity: *oid,
                detector: "origin-profile",
                role: "decision",
                p,
                day: *wday,
                hosts: names(&mut o.new_dsts.iter().copied().filter(|d| okp(*d))),
                account: o.new_acct_uses.iter().map(|(a, _)| c.accts.name(*a)).collect::<BTreeSet<&str>>().into_iter().collect::<Vec<_>>().join(" "),
                events: 0,
                window: format!("{} .. {}", ts_str(o.t0), ts_str(o.t1)),
                summary,
                snippet: super::browser_snippet_multi(dialect, &alias_list(*oid), &dest_nodes(&mut all_dsts.into_iter()), None, &day_from(*wday), Some(&day_to(*wday))),
            });
        }
    }

    // ── host-day centrality joint test (panel hosts) ──
    if want_central {
        let (pb, bb) = m_base.as_ref().unwrap();
        let mut act: BTreeMap<i32, BTreeSet<u32>> = BTreeMap::new();
        for e in &ok_events {
            act.entry(e.day).or_default().insert(e.d);
        }
        let use_pr = cfg.enabled("pagerank-spike");
        let use_bc = cfg.enabled("betweenness-spike");
        let mut null: Vec<Vec<f64>> = Vec::new();
        for day in &null_days {
            if let Some(hs) = act.get(day) {
                for h in hs.iter().filter(|h| panel_ok.contains(h)) {
                    let (dp, db) = match delta_day.get(day) {
                        Some(d) => (d.0[*h as usize], d.1[*h as usize]),
                        None => (0.0, 0.0),
                    };
                    null.push(vec![if use_pr { dp } else { 0.0 }, if use_bc { db } else { 0.0 }]);
                }
            }
        }
        let jn = JointNull::new(null);
        for wday in &win_days {
            let mut e: Vec<(usize, usize)> = base_pairs.clone();
            if let Some(ps) = pairs_by_day.get(wday) {
                e.extend(ps.iter().filter(|(o, d)| o != d).map(|(o, d)| (*o as usize, *d as usize)));
            }
            let g = DiGraph::from_edges(ne, &e);
            let (pr, bc) = (algos::pagerank(&g), algos::betweenness(&g));
            if let Some(hs) = act.get(wday) {
                for h in hs.iter().filter(|h| panel_ok.contains(h) && covered(&cov_ok, **h, *wday)) {
                    let x = vec![if use_pr { pr[*h as usize] - pb[*h as usize] } else { 0.0 }, if use_bc { bc[*h as usize] - bb[*h as usize] } else { 0.0 }];
                    let (p, _t, dx) = jn.test(&x);
                    tests.push((*h, p));
                    if x[0] > 0.0 || x[1] > 0.0 {
                        rows.push(Row {
                            mp: f64::NAN,
                            mq: f64::NAN,
                            section: "finding",
                            entity: *h,
                            detector: "centrality-profile",
                            role: "decision",
                            p,
                            day: *wday,
                            hosts: ents.names.name(*h).to_string(),
                            account: String::new(),
                            events: 0,
                            window: day_str(*wday),
                            summary: format!(
                                "{}: when the day's logins are added to the baseline graph, PageRank (mean 1) changes by {:.4} and betweenness (normalised) by {:.5}. Joint test over baseline host-days (each day removed from the graph and added back): {} of {} scored at least as high; {} rose at least as much in both.",
                                entity_label(&ents, *h), x[0], x[1], ((p * (jn.n as f64 + 1.0)).round() as usize).saturating_sub(1), jn.n, dx
                            ),
                            snippet: String::new(),
                        });
                    }
                }
            }
        }
        lines.push(format!("Centrality: {} baseline host-day(s) in the null", jn.n));
    }

    // ── novel-edge detail (descriptive): novelty profile per login triple,
    //    pooled over destinations with at most the observation's reference
    //    days ──
    if enabled[2] {
        let mut by_pat: Vec<Vec<usize>> = vec![Vec::new(); 32];
        for t in triples.iter().filter(|t| is_base(t.day)) {
            by_pat[t.flags as usize].push(t.k);
        }
        for v in by_pat.iter_mut() {
            v.sort_unstable();
        }
        let count = |f: u8, k: usize| -> (usize, usize) {
            let mut ge = 0usize;
            let mut all = 0usize;
            for (p, v) in by_pat.iter().enumerate() {
                let n = v.partition_point(|x| *x <= k);
                all += n;
                if (p as u8) & f == f {
                    ge += n;
                }
            }
            (ge, all)
        };
        let mut agg: BTreeMap<(u32, i32, u32, u8), (Vec<u32>, u64, i64, i64, usize)> = BTreeMap::new();
        for t in triples.iter().filter(|t| !is_base(t.day) && t.k >= 1 && t.flags & F_TRIPLE != 0) {
            let x = agg.entry((t.o, t.day, t.a, t.flags)).or_insert((Vec::new(), 0, t.t0, t.t1, usize::MAX));
            x.0.push(t.d);
            x.1 += t.n;
            x.2 = x.2.min(t.t0);
            x.3 = x.3.max(t.t1);
            x.4 = x.4.min(t.k);
        }
        for ((o, day, a, f), (ds, n, t0, t1, kmin)) in agg {
            let (ge, all) = count(f, kmin);
            let mut what = Vec::new();
            if f & F_NO_HISTORY != 0 {
                what.push("origin has no event of any kind in the baseline");
            } else {
                if f & F_ACCT_ORIGIN != 0 {
                    what.push("account never used by this origin");
                }
                if f & F_DST_ORIGIN != 0 {
                    what.push("destination never reached by this origin");
                }
            }
            if f & F_ACCT_DST != 0 {
                what.push("account never logged in to this destination");
            }
            if what.is_empty() {
                what.push("combination never seen, each part known");
            }
            rows.push(Row {
                mp: f64::NAN,
                mq: f64::NAN,
                section: "finding",
                entity: o,
                detector: "novel-edge",
                role: "detail",
                p: stats::empirical_p(ge, all),
                day,
                hosts: names(&mut ds.iter().copied()),
                account: c.accts.name(a).to_string(),
                events: n,
                window: format!("{} .. {}", ts_str(t0), ts_str(t1)),
                summary: format!(
                    "{} logged in as {} to {} destination(s) for the first time: {}. Among baseline login-days on destinations with at most {} reference day(s), {} of {} were at least this new.",
                    entity_label(&ents, o), c.accts.name(a), ds.len(), what.join("; "), kmin, ge, all
                ),
                snippet: super::browser_snippet_multi(dialect, &alias_list(o), &dest_nodes(&mut ds.iter().copied()), Some(c.accts.name(a)), &day_from(day), Some(&day_to(day))),
            });
        }
    }

    // ── per machine: Simes over its decision tests; BH across machines ──
    let mut per_entity: BTreeMap<u32, Vec<f64>> = BTreeMap::new();
    for (e, p) in &tests {
        per_entity.entry(*e).or_default().push(*p);
    }
    let ent_ids: Vec<u32> = per_entity.keys().copied().collect();
    let ent_p: Vec<f64> = ent_ids.iter().map(|e| stats::simes(&per_entity[e])).collect();
    let ent_q = stats::benjamini_hochberg(&ent_p);
    let pq: HashMap<u32, (f64, f64)> = ent_ids.iter().enumerate().map(|(k, e)| (*e, (ent_p[k], ent_q[k]))).collect();
    let n_sig = ent_q.iter().filter(|q| **q <= alpha).count();
    lines.push(format!(
        "Tests: {} joint test(s) over {} machine(s); {} machine(s) significant at FDR {} (Simes per machine, Benjamini-Hochberg across machines)",
        tests.len(),
        ent_ids.len(),
        n_sig,
        alpha
    ));

    // ── campaigns ──
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
                let p = stats::hypergeom_upper(pop, da.len() as u64, db.len() as u64, k as u64);
                pairs.push((a, b, p, k, shared));
            }
        }
        let qs = stats::benjamini_hochberg(&pairs.iter().map(|p| p.2).collect::<Vec<_>>());
        let mut parent: HashMap<u32, u32> = HashMap::new();
        fn find(p: &mut HashMap<u32, u32>, x: u32) -> u32 {
            let y = *p.get(&x).unwrap_or(&x);
            if y == x {
                return x;
            }
            let r = find(p, y);
            p.insert(x, r);
            r
        }
        let mut sig: Vec<usize> = Vec::new();
        for (k, pr) in pairs.iter().enumerate() {
            if qs[k] <= alpha {
                let (ra, rb) = (find(&mut parent, pr.0), find(&mut parent, pr.1));
                if ra != rb {
                    parent.insert(ra, rb);
                }
                sig.push(k);
            }
        }
        let mut groups: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        for k in &sig {
            let r = find(&mut parent, pairs[*k].0);
            groups.entry(r).or_default().push(*k);
        }
        for (_, ks) in groups {
            let mut members: BTreeSet<u32> = BTreeSet::new();
            let mut accts: BTreeSet<u32> = BTreeSet::new();
            let mut qmax: f64 = 0.0;
            for k in &ks {
                let pr = &pairs[*k];
                members.insert(pr.0);
                members.insert(pr.1);
                accts.extend(pr.4.iter().copied());
                qmax = qmax.max(qs[*k]);
            }
            let detail: Vec<String> = ks
                .iter()
                .map(|k| {
                    let pr = &pairs[*k];
                    format!(
                        "{} & {}: {} common new destinations of {} / {} (p = {:.2e})",
                        ents.names.name(pr.0), ents.names.name(pr.1), pr.3, nod[&pr.0].len(), nod[&pr.1].len(), pr.2
                    )
                })
                .collect();
            let m0 = *members.iter().next().unwrap();
            rows.push(Row {
                mp: f64::NAN,
                mq: f64::NAN,
                section: "campaign",
                entity: m0,
                detector: "campaign",
                role: "grouping",
                p: qmax,
                day: cutoff_day,
                hosts: members.iter().map(|m| entity_label(&ents, *m)).collect::<Vec<_>>().join(" | "),
                account: accts.iter().map(|a| c.accts.name(*a)).collect::<Vec<_>>().join(" "),
                events: members.len() as u64,
                window: String::new(),
                summary: format!(
                    "Origins with no event in the baseline that share new account(s) and reach overlapping destinations beyond chance (exact hypergeometric test over {} panel destinations, Benjamini-Hochberg across {} candidate pair(s); p_value = largest q): {}. Grouping only; nodes are not merged and scores are unchanged.",
                    pop,
                    pairs.len(),
                    detail.join("; ")
                ),
                snippet: String::new(),
            });
        }
        lines.push(format!("Campaigns: {} candidate pair(s) sharing a new account, {} significant", pairs.len(), sig.len()));
    }

    // ── not evaluable: window logins to destinations outside the panel ──
    {
        let mut ner: BTreeMap<u32, (BTreeSet<u32>, BTreeSet<u32>, u64, i32)> = BTreeMap::new();
        for t in triples.iter().filter(|t| !is_base(t.day) && !(panel_ok.contains(&t.d) && covered(&cov_ok, t.d, t.day))) {
            let x = ner.entry(t.d).or_insert((BTreeSet::new(), BTreeSet::new(), 0, t.day));
            if t.flags & F_TRIPLE != 0 {
                x.0.insert(t.o);
                x.1.insert(t.a);
            }
            x.2 += t.n;
            x.3 = x.3.min(t.day);
        }
        for (d, (origins, accts, n, d0)) in ner {
            let k = kref(&cov_ok, d);
            let first = cov_ok.get(&d).and_then(|s| s.iter().next().copied());
            let reason = if k == 0 {
                format!("has no login coverage on any baseline day (first covered day {})", first.map(day_str).unwrap_or_else(|| "none".into()))
            } else {
                format!("has {} covered baseline day(s) but not continuously from {} to the cutoff", k, day_str(s_day))
            };
            rows.push(Row {
                mp: f64::NAN,
                mq: f64::NAN,
                section: "not-evaluable",
                entity: d,
                detector: "not-evaluable",
                role: "",
                p: f64::NAN,
                day: d0,
                hosts: ents.names.name(d).to_string(),
                account: accts.iter().map(|a| c.accts.name(*a)).collect::<Vec<_>>().join(" "),
                events: n,
                window: String::new(),
                summary: format!(
                    "{} {}: its window logins are left out of the tests. New origins there: {}.",
                    ents.names.name(d),
                    reason,
                    if origins.is_empty() { "none".to_string() } else { origins.iter().map(|o| entity_label(&ents, *o)).collect::<Vec<_>>().join(", ") }
                ),
                snippet: String::new(),
            });
        }
    }

    for r in rows.iter_mut() {
        if r.section == "finding" {
            if let Some((p, q)) = pq.get(&r.entity) {
                r.mp = *p;
                r.mq = *q;
            }
        }
    }
    let sec_rank = |s: &str| match s {
        "campaign" => 0,
        "finding" => 1,
        _ => 2,
    };
    let role_rank = |s: &str| match s {
        "decision" => 0,
        "component" => 1,
        _ => 2,
    };
    rows.sort_by(|a, b| {
        sec_rank(a.section)
            .cmp(&sec_rank(b.section))
            .then(nan_last(a.mq).partial_cmp(&nan_last(b.mq)).unwrap())
            .then(ents.names.name(a.entity).cmp(ents.names.name(b.entity)))
            .then(role_rank(a.role).cmp(&role_rank(b.role)))
            .then(nan_last(a.p).partial_cmp(&nan_last(b.p)).unwrap())
    });
    let labels: Vec<String> = (0..ne as u32).map(|i| entity_label(&ents, i)).collect();
    (rows, lines, labels, alpha)
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

fn write_csv(rows: &[Row], labels: &[String], alpha: f64, output: Option<&str>) -> std::io::Result<()> {
    let mut buf = String::from(
        "section,rank,machine,machine_p,machine_q,significant,detector,role,p_value,day,hosts,account,events,time_window,summary,cypher_snippet
",
    );
    for (k, r) in rows.iter().enumerate() {
        let machine = if r.section == "campaign" { r.hosts.clone() } else { labels.get(r.entity as usize).cloned().unwrap_or_default() };
        let sig = if r.section != "finding" {
            ""
        } else if r.mq <= alpha {
            "yes"
        } else {
            "no"
        };
        buf.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}
",
            r.section,
            k + 1,
            csv_escape(&machine),
            fmt_p(r.mp),
            fmt_p(r.mq),
            sig,
            r.detector,
            r.role,
            fmt_p(r.p),
            day_str(r.day),
            csv_escape(&r.hosts),
            csv_escape(&r.account),
            r.events,
            csv_escape(&r.window),
            csv_escape(&r.summary),
            csv_escape(&r.snippet),
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
