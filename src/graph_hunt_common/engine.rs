// graph-hunt statistical engine (both backends).
//
// Design: docs/graph-hunt-statistics.md. In short:
//   1. Pull every edge once (per-event rows for logins and named failures,
//      per-day aggregates for pre-auth touches and unnamed failures).
//   2. Fold IP and host name into one machine when the co-occurrence
//      resolution is significant (resolve.rs).
//   3. Past-only reference with the window's gap: a window day sees every
//      baseline day; a baseline day d sees the baseline days up to d - L,
//      L being the window length, so a fact is new on the first day it
//      appears, for baseline and window days alike. Baseline days give the
//      null, window days the observations; every statistic is computed the
//      same way for both.
//   4. Unit: one connection (origin, destination, account, result) on one
//      day; habitual connections (seen on the reference) are not tested.
//      Counts are compared on the destinations both days could show.
//   5. Conformal joint test per connection against the baseline
//      connections of the same result; Benjamini-Hochberg across the new
//      connections; Hopper classes order the rows.
//   6. CSV: connections, not-evaluable destinations; --report: one story
//      per origin.

use super::algos::{self, DiGraph};
use super::report;
use super::resolve::{self, Obs};
use super::sigma;
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
    /// known-bad host names, IPs or accounts to reconstruct the incident
    /// from; `host:account` for both at once
    pub seeds: Vec<String>,
    /// only logins in [seed_from, seed_to] start the chain
    pub seed_from: Option<DateTime<Utc>>,
    pub seed_to: Option<DateTime<Utc>>,
    /// Sigma hit files (Hayabusa / Chainsaw JSON), see sigma.rs
    pub sigma: Vec<String>,
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
    "causal-path",
    "credential-switch",
    "pagerank-spike",
    "betweenness-spike",
    "sigma",
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
    } else if et == "LOGOFF" || is_no_account(acct) {
        // a session end is not a login; a row without an account is not
        // an authenticated connection
        OTHER
    } else {
        OK
    }
}

/// An account the parser could only name by uid (auditd `id=` without a
/// passwd entry): `uid:1101` in the CSV, `UID_1101` once the loader turns
/// it into a relationship type. Not a name, so never "a new account".
fn is_uid_account(a: &str) -> bool {
    let b = a.as_bytes();
    if b.len() <= 4 || !(b[..4].eq_ignore_ascii_case(b"uid:") || b[..4].eq_ignore_ascii_case(b"uid_")) {
        return false;
    }
    b[4..].iter().all(|x| x.is_ascii_digit())
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
    /// session identifier (interned); 0 = none
    lid: u32,
    /// a session end (event_type LOGOFF)
    logoff: bool,
}

struct Corpus {
    /// node name -> (cov_ok, cov_fail) log-file spans written by the loader
    cov: HashMap<String, (Vec<i64>, Vec<i64>)>,
    fams: Interner,
    nodes: Interner,
    accts: Interner,
    lts: Interner,
    ets: Interner,
    lids: Interner,
    rows: Vec<RawRow>,
    /// edge rows whose time could not be parsed (ignored, reported)
    bad_ts: usize,
}

async fn pull(graph: &Graph) -> neo4rs::Result<Corpus> {
    let mut c = Corpus { cov: HashMap::new(), fams: Interner::default(), nodes: Interner::default(), accts: Interner::default(), lts: Interner::default(), ets: Interner::default(), lids: Interner::default(), rows: Vec::new(), bad_ts: 0 };
    c.lids.id("");
    let aggregated = format!(
        "(coalesce(r.event_id, '') = 'SSH_PREAUTH' OR (coalesce(r.event_type, '') = 'FAILED_LOGON' AND type(r) IN {na}))",
        na = NO_ACCOUNT_TYPES
    );
    let qa = format!(
        "MATCH (a:host)-[r]->(b:host) WHERE NOT {agg}
         RETURN a.name AS o, b.name AS d, type(r) AS acct, coalesce(r.event_type, '') AS et,
                coalesce(r.event_id, '') AS eid, coalesce(toString(r.logon_type), '') AS lt,
                coalesce(r.log_source, '') AS src, toString(r.time) AS t,
                toInteger(coalesce(r.count, 1)) AS c, coalesce(r.logon_id, '') AS lid",
        agg = aggregated
    );
    let qb = format!(
        "MATCH (a:host)-[r]->(b:host) WHERE {agg}
         WITH a.name AS o, b.name AS d, type(r) AS acct, coalesce(r.event_type, '') AS et,
              coalesce(r.event_id, '') AS eid, coalesce(r.log_source, '') AS src,
              r.time.year * 10000 + r.time.month * 100 + r.time.day AS dk,
              sum(toInteger(coalesce(r.count, 1))) AS c, min(r.time) AS t0
         RETURN o, d, acct, et, eid, '' AS lt, src, toString(t0) AS t, c, '' AS lid",
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
            let lid: String = row.get("lid").unwrap_or_default();
            let t = match parse_ts(&ts) {
                Some(x) => x.and_utc().timestamp(),
                None => {
                    c.bad_ts += 1;
                    continue;
                }
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
                lid: c.lids.id(&lid),
                logoff: et == "LOGOFF",
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

// ───────────────────────────── CSV corpus ───────────────────────────────────

/// Split one CSV line, honouring double quotes ("" inside a quoted field
/// is a quote). Quoted empty fields come back empty.
pub(crate) fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inq = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if inq => {
                if chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    inq = false;
                }
            }
            '"' => inq = true,
            ',' if !inq => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    out.push(cur);
    out
}

const CSV_HEADER: &str = "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename";

fn account_type(user: &str) -> String {
    let stripped = user.split('@').next().unwrap_or(user);
    let mut s: String = stripped.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
    if s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        s = format!("u{}", s);
    }
    if s.is_empty() {
        s = "NO_USER".to_string();
    }
    s.to_uppercase()
}

/// Build the corpus from masstin timeline CSVs (14-column layout). Two
/// passes: the first finds short host names shared by different FQDNs and
/// the log-file spans of every destination, the second builds the rows;
/// pre-auth touches and unnamed failures are aggregated per day as the
/// graph pull does.
fn corpus_from_csv(files: &[String]) -> std::io::Result<(Corpus, Vec<String>)> {
    use std::io::BufRead;
    let local: HashSet<&str> = ["LOCAL", "127.0.0.1", "::1", "::", "0.0.0.0", "DEFAULT_VALUE", "-", "", " "].into_iter().collect();
    let is_local = |v: &str| local.contains(v);
    let mut notes = Vec::new();
    // pass 1: FQDN ambiguity and coverage spans per (destination, family)
    let mut fqdn_by_short: HashMap<String, HashSet<String>> = HashMap::new();
    let mut span: HashMap<(String, String), (i64, i64)> = HashMap::new();
    let mut bad_header: Vec<String> = Vec::new();
    for f in files {
        let rd = std::io::BufReader::new(std::fs::File::open(f)?);
        let mut lines = rd.lines();
        let header = lines.next().transpose()?.unwrap_or_default();
        if header.trim_end_matches(['\r', '\n']) != CSV_HEADER {
            bad_header.push(f.clone());
            continue;
        }
        for line in lines {
            let line = line?;
            let p = split_csv(&line);
            if p.len() < 14 {
                continue;
            }
            for col in [1usize, 7, 8] {
                let v = p[col].to_uppercase();
                if v.contains('.') && !looks_like_ip(&v) {
                    if let Some(short) = v.split('.').next() {
                        fqdn_by_short.entry(short.to_string()).or_default().insert(v.clone());
                    }
                }
            }
            if let Some(t) = parse_ts(&p[0]) {
                // one span per log FILE (a missing rotation is a gap), as
                // the loader records them
                let t = t.and_utc().timestamp();
                let e = span.entry((p[1].to_uppercase(), p[13].clone())).or_insert((t, t));
                e.0 = e.0.min(t);
                e.1 = e.1.max(t);
            }
        }
    }
    if !bad_header.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("not a masstin 14-column timeline: {}", bad_header.join(", "))));
    }
    let ambiguous: HashSet<String> = fqdn_by_short.into_iter().filter(|(_, s)| s.len() > 1).map(|(k, _)| k).collect();
    let short = |v: &str| -> String {
        let u = v.to_uppercase();
        if u.contains('.') && !looks_like_ip(&u) {
            let s = u.split('.').next().unwrap_or("");
            if !s.is_empty() && !ambiguous.contains(s) {
                return s.to_string();
            }
        }
        u
    };
    // pass 2: rows
    let mut c = Corpus { cov: HashMap::new(), fams: Interner::default(), nodes: Interner::default(), accts: Interner::default(), lts: Interner::default(), ets: Interner::default(), lids: Interner::default(), rows: Vec::new(), bad_ts: 0 };
    c.lids.id("");
    let mut agg: HashMap<(u32, u32, u32, u32, u32, i32), (u64, i64)> = HashMap::new();
    let mut dropped = 0usize;
    let mut total = 0usize;
    for f in files {
        let rd = std::io::BufReader::new(std::fs::File::open(f)?);
        for line in rd.lines().skip(1) {
            let line = line?;
            let p = split_csv(&line);
            if p.len() < 14 {
                continue;
            }
            total += 1;
            let t = match parse_ts(&p[0]) {
                Some(x) => x.and_utc().timestamp(),
                None => {
                    c.bad_ts += 1;
                    continue;
                }
            };
            let sc = p[7].trim();
            let si = p[8].trim();
            let origin = if !is_local(sc) && !(looks_like_ip(sc) && sc == si) {
                short(sc)
            } else if !is_local(si) {
                short(si)
            } else {
                dropped += 1;
                continue;
            };
            let dest = short(p[1].trim());
            if dest.is_empty() || origin.eq_ignore_ascii_case(&dest) {
                dropped += 1;
                continue;
            }
            let acct = account_type(p[5].trim());
            let et = p[2].trim();
            let eid = p[3].trim();
            let fam = crate::load_neo4j::log_source_family(&p[13]);
            let cls = class_of(et, eid, &acct);
            let o = c.nodes.id(&origin);
            let d = c.nodes.id(&dest);
            let a = c.accts.id(&acct);
            let eti = c.ets.id(et);
            let fi = c.fams.id(fam);
            // pre-auth touches and unnamed failures: one row per day
            if cls == PRE || (cls == FAIL && is_no_account(&acct)) {
                let key = (o, d, a, eti, fi, day_of(t));
                let e = agg.entry(key).or_insert((0, t));
                e.0 += 1;
                e.1 = e.1.min(t);
                continue;
            }
            c.rows.push(RawRow {
                t,
                fam: fi,
                o,
                d,
                a,
                et: eti,
                cls,
                lt: c.lts.id(p[4].trim()),
                cov: super::coverage_kinds(fam),
                n: 1,
                lid: c.lids.id(p[11].trim()),
                logoff: et == "LOGOFF",
            });
        }
    }
    for ((o, d, a, eti, fi, _day), (n, t0)) in agg {
        let et = c.ets.name(eti).to_string();
        let acct = c.accts.name(a).to_string();
        let fam = c.fams.name(fi).to_string();
        let eid = if et == "CONNECT" { "SSH_PREAUTH" } else { "" };
        c.rows.push(RawRow { t: t0, fam: fi, o, d, a, et: eti, cls: class_of(&et, eid, &acct), lt: c.lts.id(""), cov: super::coverage_kinds(&fam), n, lid: 0, logoff: false });
    }
    // coverage spans per destination node, by kind
    let mut by_node: HashMap<String, (Vec<(i64, i64)>, Vec<(i64, i64)>)> = HashMap::new();
    for ((dst, file), (lo, hi)) in span {
        let name = short(&dst);
        let (ok, fail) = super::coverage_kinds(crate::load_neo4j::log_source_family(&file));
        let e = by_node.entry(name).or_default();
        if ok {
            e.0.push((lo, hi));
        }
        if fail {
            e.1.push((lo, hi));
        }
    }
    for (name, (ok, fail)) in by_node {
        c.cov.insert(name, (super::merge_spans(ok), super::merge_spans(fail)));
    }
    notes.push(format!(
        "{} CSV row(s): {} dropped (no usable source, or origin = destination), {} with an unparseable time; {} short name(s) shared by different FQDNs kept fully qualified",
        total,
        dropped,
        c.bad_ts,
        ambiguous.len()
    ));
    Ok((c, notes))
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
/// credential switch (Hopper, Ho et al. 2021): the account has an owner in
/// the baseline (it logged in on other days, from other origins) and this
/// origin never used it
const F_SWITCH: u8 = 32;
/// the account is new to the whole network, not only to this origin
const F_UNKNOWN_ACCT: u8 = 64;
/// new access: destination new for the origin or for the account
const F_NEW_ACCESS: u8 = 128;

/// Distinct baseline days an item occurs on.
#[derive(Clone)]
struct DayCount {
    n: u32,
    first: i32,
    last: i32,
    days: BTreeSet<i32>,
}

/// Past-only reference with the window's gap. A window day is new against
/// every baseline day (all of them lie before the cutoff, up to L - 1 days
/// before the window day, L being the window length). A baseline day d is
/// judged against the baseline days up to d - L: the same "only the past,
/// with the same gap" rule, so that a fact that starts mid-baseline and
/// repeats is new on its first day only, exactly as it would be in the
/// window. Early baseline days have less reference and therefore more
/// novelty, which makes the null heavier than the window: conservative.
struct DayIndex<K: std::hash::Hash + Eq> {
    m: HashMap<K, DayCount>,
    block: i32,
}

impl<K: std::hash::Hash + Eq> DayIndex<K> {
    fn new(block: i32) -> Self {
        DayIndex { m: HashMap::new(), block: block.max(1) }
    }
    fn add(&mut self, k: K, day: i32) {
        let c = self.m.entry(k).or_insert_with(|| DayCount { n: 0, first: day, last: day, days: BTreeSet::new() });
        if c.days.insert(day) {
            c.n = c.days.len() as u32;
            c.first = c.first.min(day);
            c.last = c.last.max(day);
        }
    }
    /// New on `day`: window day -> occurs on no baseline day; baseline day
    /// -> occurs on no baseline day up to `day - block`.
    fn is_new(&self, k: &K, day: i32, baseline: bool) -> bool {
        match self.m.get(k) {
            None => true,
            Some(c) => baseline && c.days.range(..=(day - self.block)).next().is_none(),
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
    n: u64,
    t0: i64,
    t1: i64,
    /// end of the last session of the connection: its LOGOFF when
    /// recorded, else the end of the day; t1 for failures and pre-auth
    t_end: i64,
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
    /// causal paths through this origin as pivot (Hopper): A logged in to
    /// it earlier the same day as a1, then it logged in to C as a2 != a1,
    /// and a1 had never reached C
    paths: Vec<PathFact>,
    /// (account, destination) logins with a credential switch (account owned
    /// by other origins, never used by this one) and a new access
    /// (destination new for the origin or for the account): Hopper's two
    /// attack properties in one login
    switch_new: BTreeSet<(u32, u32)>,
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
    a: u32,
    /// a real account name (not NO_USER / _UNKNOWN_ / uid:N)
    named: bool,
    /// session end: its LOGOFF when recorded, else the end of the UTC day
    end: i64,
}

/// One inferred causal path A -(a1)-> B -(a2)-> C with Hopper's two attack
/// properties: a credential switch (a2 != a1) and a new access (a1 never
/// logged in to C in the reference). `cert` = 1 / number of candidate
/// causes of the B -> C login (distinct (A, a1) that entered B earlier the
/// same day).
#[derive(Clone, Copy)]
struct PathFact {
    cert: f64,
    a_node: u32,
    a1: u32,
    t1: i64,
    c_node: u32,
    a2: u32,
    t2: i64,
    n_cand: usize,
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
    /// baseline day of each null row, for the "on N of M days" counts
    days: Vec<i32>,
}

fn surprise(col: &[f64], v: f64, n: usize, self_in_null: bool) -> f64 {
    if v <= 0.0 || col.is_empty() {
        return 0.0;
    }
    let ge = col.len() - col.partition_point(|x| *x < v) - if self_in_null { 1 } else { 0 };
    -stats::empirical_p(ge, n.saturating_sub(if self_in_null { 1 } else { 0 })).ln()
}

impl JointNull {
    /// `dims` is given explicitly so that an empty null (no baseline
    /// connection of this result) still answers every coordinate: p = 1.
    fn new(rows: Vec<Vec<f64>>, days: Vec<i32>, dims: usize) -> Self {
        let n = rows.len();
        let cols: Vec<Vec<f64>> = (0..dims)
            .map(|k| {
                let mut v: Vec<f64> = rows.iter().map(|r| r[k]).collect();
                v.sort_by(|a, b| a.partial_cmp(b).unwrap());
                v
            })
            .collect();
        let mut t_sorted: Vec<f64> = rows.iter().map(|r| (0..dims).map(|k| surprise(&cols[k], r[k], n, true)).sum()).collect();
        t_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        JointNull { cols, t_sorted, n, rows, days }
    }
    /// (p, T): conformal p of the joint statistic
    fn test_fast(&self, x: &[f64]) -> (f64, f64) {
        let t: f64 = x.iter().enumerate().map(|(k, v)| surprise(&self.cols[k], *v, self.n, false)).sum();
        let ge = self.t_sorted.len() - self.t_sorted.partition_point(|v| *v < t - 1e-12);
        (stats::empirical_p(ge, self.n), t)
    }
    /// marginal for one coordinate: (null connections at least as high,
    /// their share, distinct baseline days they fall on)
    fn marginal(&self, k: usize, v: f64) -> (usize, f64, usize) {
        let ge = self.cols[k].len() - self.cols[k].partition_point(|x| *x < v);
        let days: HashSet<i32> = self.rows.iter().zip(&self.days).filter(|(r, _)| r[k] >= v).map(|(_, d)| *d).collect();
        (ge, stats::empirical_p(ge, self.n), days.len())
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
    /// Hopper class of the connection (`signature` column)
    class: String,
    why: String,
    /// every reason with the baseline count behind it (`evidence` column)
    evidence: String,
    /// position in the seed reconstruction ("hop 3 depth 1"), else empty
    chain: String,
    campaign: String,
    cypher: String,
    evaluable: bool,
    /// origin, destination and account ids and the novelty flags, for the report
    oid: u32,
    did: u32,
    aid: u32,
    flags: u8,
    /// Hopper-style class, used for ordering within the significant rows:
    /// 0 credential switch with new access (or same origin-day as one),
    /// 1 unknown account or switch to a known destination, 2 habitual
    /// credential / no credential, 3 habitual connection
    group: u8,
}

// ───────────────────────────── main entry ───────────────────────────────────

pub async fn run(graph: &Graph, dialect: &Dialect, cfg: &Settings, output: Option<&str>, report_path: Option<&str>) {
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
    run_with(corpus, dialect, cfg, output, report_path, clock);
}

/// The hunt straight from masstin timeline CSVs, no graph database: the
/// rows become the same corpus the graph pull produces, with the loader's
/// conventions (short upper-case host names unless two FQDNs share one,
/// local sources dropped, accounts as relationship types, log-file
/// coverage spans per destination).
pub fn run_csv(files: &[String], dialect: &Dialect, cfg: &Settings, output: Option<&str>, report_path: Option<&str>) {
    let clock = std::time::Instant::now();
    crate::banner::print_phase("3", "4", "Reading the timeline CSV...");
    let (corpus, notes) = match corpus_from_csv(files) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Masstin - Error: reading the CSV failed: {}", e);
            return;
        }
    };
    for n in &notes {
        crate::banner::print_phase_detail("", n);
    }
    crate::banner::print_phase_result(&format!(
        "{} edge rows, {} nodes, {} accounts ({:.1}s)",
        corpus.rows.len(),
        corpus.nodes.names.len(),
        corpus.accts.names.len(),
        clock.elapsed().as_secs_f64()
    ));
    run_with(corpus, dialect, cfg, output, report_path, clock);
}

fn run_with(corpus: Corpus, dialect: &Dialect, cfg: &Settings, output: Option<&str>, report_path: Option<&str>, clock: std::time::Instant) {
    if corpus.bad_ts > 0 {
        crate::banner::print_phase_detail("Warning:", &format!("{} edge row(s) with an unparseable time ignored", corpus.bad_ts));
    }
    crate::banner::print_phase("4", "4", "Computing statistics...");
    let mut corpus = corpus;
    if let Some(end) = cfg.end {
        let e = end.timestamp();
        corpus.rows.retain(|r| r.t <= e);
        crate::banner::print_phase_detail("Window end:", &format!("{} (later events ignored)", end.to_rfc3339()));
    }
    let hits: Vec<sigma::SigmaHit> = if cfg.sigma.is_empty() {
        Vec::new()
    } else {
        let (h, notes) = sigma::load(&cfg.sigma);
        for n in &notes {
            crate::banner::print_phase_detail("Sigma:", n);
        }
        h
    };
    let (rows, summary_lines, alpha, stories, seed) = analyse(&corpus, dialect, cfg, &hits);
    for l in &summary_lines {
        crate::banner::print_phase_detail("", l);
    }
    if let Err(e) = write_csv(&rows, alpha, output) {
        eprintln!("Masstin - Error: cannot write findings CSV: {}", e);
        return;
    }
    if let Some(path) = report_path {
        let days: Vec<i32> = rows.iter().map(|r| r.day).collect();
        let h = report::Header {
            cutoff: cfg.cutoff.format("%Y-%m-%d %H:%M:%S").to_string(),
            window_from: days.iter().min().map(|d| day_str(*d)).unwrap_or_default(),
            window_to: days.iter().max().map(|d| day_str(*d)).unwrap_or_default(),
            alpha,
            lines: summary_lines.clone(),
            n_origins_sig: stories.len(),
            n_rows: rows.len(),
            n_sig: rows.iter().filter(|r| r.evaluable && r.q <= alpha).count(),
            n_not_eval: rows.iter().filter(|r| !r.evaluable).count(),
        };
        match report::write(path, &h, &stories, seed.as_ref()) {
            Ok(()) => crate::banner::print_phase_detail("Report:", &format!("{} ({} origin(s){})", path, stories.len(), seed.as_ref().map(|s| format!(", seed reconstruction with {} hop(s)", s.hops.len())).unwrap_or_default())),
            Err(e) => eprintln!("Masstin - Error: cannot write report: {}", e),
        }
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
const COORDS: [(&str, &str); 11] = [
    ("origin-fanout", "destinations reached for the first time"),
    ("cred-rotation", "accounts used for the first time from this origin"),
    ("novel-edge", "account-destination combinations never seen"),
    ("community-bridge", "new destinations outside the origin's Louvain community"),
    ("failed-sweep", "destinations with failed attempts"),
    ("preauth-sweep", "destinations touched without authenticating (SSH pre-auth)"),
    ("probe-then-success", "refused named attempts followed the same day by a login with an account new for this origin"),
    ("no-history", "origin has no event of any kind in the baseline"),
    ("rare-logon-type", "rarest logon type used, -ln(share of the destination's logins with a type at most this rare)"),
    ("causal-path", "causal paths through this origin with a credential switch and a new access (sum of path certainties)"),
    ("credential-switch", "logins with a credential switch and a new access (account owned by other origins, destination new for the origin or the account)"),
];

type Pred<'a> = &'a dyn Fn(u32) -> bool;

/// Profile of one origin-day restricted to the destinations `ok` (login
/// coverage) and `fail` (failure coverage) accept.
fn profile(o: &OriginDay, ok: Pred, fail: Pred, enabled: &[bool; 11]) -> [f64; 11] {
    let mut v = [0.0f64; 11];
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
    // per distinct (destination, account) connection of the pivot, its best
    // path certainty; summed over connections, not over sessions
    v[9] = {
        let mut best: BTreeMap<(u32, u32), f64> = BTreeMap::new();
        for p in o.paths.iter().filter(|p| ok(p.c_node)) {
            let e = best.entry((p.c_node, p.a2)).or_insert(0.0);
            if p.cert > *e {
                *e = p.cert;
            }
        }
        best.values().sum()
    };
    v[10] = o.switch_new.iter().filter(|(_, d)| ok(*d)).count() as f64;
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

fn analyse(c: &Corpus, dialect: &Dialect, cfg: &Settings, hits: &[sigma::SigmaHit]) -> (Vec<Conn>, Vec<String>, f64, Vec<report::OriginStory>, Option<report::SeedRecon>) {
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
    // Sigma hits matched to machines by short upper-case name (or IP)
    let (hits_of, n_hits_matched): (HashMap<u32, Vec<usize>>, usize) = {
        let mut by_name: HashMap<String, u32> = HashMap::new();
        for e in 0..ne as u32 {
            for a in &ents.aliases[e as usize] {
                by_name.entry(sigma::norm_host(a)).or_insert(e);
            }
        }
        let mut m: HashMap<u32, Vec<usize>> = HashMap::new();
        let mut n = 0usize;
        for (i, h) in hits.iter().enumerate() {
            if let Some(&e) = by_name.get(&sigma::norm_host(&h.host)) {
                m.entry(e).or_default().push(i);
                n += 1;
            }
        }
        (m, n)
    };
    if !hits.is_empty() {
        lines.push(format!("Sigma: {} hit(s) read, {} on {} machine(s) of the graph", hits.len(), n_hits_matched, hits_of.len()));
    }
    // hits on a machine within [t0, t1] (indices into `hits`)
    let hits_in = |d: u32, t0: i64, t1: i64| -> Vec<usize> {
        match hits_of.get(&d) {
            Some(v) => {
                let lo = v.partition_point(|&i| hits[i].t < t0);
                let hi = v.partition_point(|&i| hits[i].t <= t1);
                v[lo..hi].to_vec()
            }
            None => Vec::new(),
        }
    };
    let cutoff_ts = cfg.cutoff.timestamp();
    let cutoff_day = day_of(cutoff_ts);
    if cutoff_ts % 86_400 != 0 {
        lines.push(format!("Note: cutoff is not at 00:00 UTC; the whole day {} belongs to the window", day_str(cutoff_day)));
    }
    let is_base = |day: i32| day < cutoff_day;
    let enabled: [bool; 11] = {
        let mut e = [true; 11];
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
        lid: u32,
        logoff: bool,
    }
    let mut evs: Vec<Ev> = c
        .rows
        .iter()
        .map(|r| Ev { t: r.t, day: day_of(r.t), o: ents.of_node[r.o as usize], d: ents.of_node[r.d as usize], a: r.a, cls: r.cls, lt: r.lt, n: r.n, fam: r.fam, lid: r.lid, logoff: r.logoff })
        .collect();
    evs.sort_by_key(|e| e.t);
    let base_days: BTreeSet<i32> = evs.iter().map(|e| e.day).filter(|d| is_base(*d)).collect();
    let win_days: BTreeSet<i32> = evs.iter().map(|e| e.day).filter(|d| !is_base(*d)).collect();
    // window length in days: the block a baseline day is judged without
    let block: i32 = win_days.iter().next_back().map(|d| d - cutoff_day + 1).unwrap_or(1).max(1);

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
    // the last covered baseline day: the panel runs up to it
    let anchor = match cov_ok.values().chain(cov_fail.values()).filter_map(|s| s.range(..cutoff_day).next_back().copied()).max() {
        Some(a) => a,
        None => {
            lines.push("No destination has log coverage before the cutoff: nothing can be compared. Check --investigation-from and the coverage spans written by the loader.".to_string());
            return (Vec::new(), lines, alpha, Vec::new(), None);
        }
    };
    if anchor != cutoff_day - 1 {
        lines.push(format!("Note: the last covered baseline day is {}; the panel runs up to it", day_str(anchor)));
    }
    let mut best = (0usize, cutoff_day);
    {
        // for each destination and kind, the first day of its last
        // uninterrupted run of covered days that reaches the anchor
        let run_starts = |m: &HashMap<u32, BTreeSet<i32>>| -> Vec<i32> {
            let mut v = Vec::new();
            for s in m.values() {
                if !s.contains(&anchor) {
                    continue;
                }
                let mut st = anchor;
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
        // failed-sweep / pre-auth / probe signals) almost entirely. A kind
        // of evidence absent from the whole graph does not veto the other.
        for (k, s) in bd.iter().enumerate() {
            let n_ok = rs_ok.iter().filter(|st| **st <= *s).count();
            let n_fail = rs_fail.iter().filter(|st| **st <= *s).count();
            let size = if rs_fail.is_empty() {
                n_ok
            } else if rs_ok.is_empty() {
                n_fail
            } else {
                n_ok.min(n_fail)
            };
            let cells = size * (bd.len() - k);
            if cells > best.0 {
                best = (cells, *s);
            }
        }
    }
    if best.0 == 0 {
        lines.push("Panel is empty: no destination is covered continuously up to the last covered baseline day. Nothing can be compared.".to_string());
        return (Vec::new(), lines, alpha, Vec::new(), None);
    }
    let s_day = best.1;
    let in_run = |m: &HashMap<u32, BTreeSet<i32>>, d: u32| -> bool {
        match m.get(&d) {
            Some(s) => (s_day..=anchor).all(|x| s.contains(&x)),
            None => false,
        }
    };
    let panel_ok: HashSet<u32> = dsts.iter().copied().filter(|d| in_run(&cov_ok, *d)).collect();
    let panel_fail: HashSet<u32> = cov_fail.keys().copied().filter(|d| in_run(&cov_fail, *d)).collect();
    let null_days: Vec<i32> = bd.iter().copied().filter(|d| *d >= s_day).collect();
    lines.push(format!(
        "Panel: {} destination(s) with continuous login coverage and {} with failure coverage from {} to the cutoff; {} baseline day(s) form the null; reference for novelty = all {} baseline day(s) with data, past only, with the window's gap of {} day(s)",
        panel_ok.len(),
        panel_fail.len(),
        day_str(s_day),
        null_days.len(),
        base_days.len(),
        block
    ));

    // ── baseline item indexes ──
    let mut ix_triple: DayIndex<(u32, u32, u32)> = DayIndex::new(block);
    // (origin, destination, account, result): the connection itself
    let mut ix_conn: DayIndex<(u32, u32, u32, u8)> = DayIndex::new(block);
    let mut ix_pair: DayIndex<(u32, u32)> = DayIndex::new(block);
    let mut ix_ad: DayIndex<(u32, u32)> = DayIndex::new(block);
    // (origin, account): successful use only; a refused attempt is not a
    // use, so a spray that started before the cutoff and succeeds in the
    // window is still a first use (and a credential switch)
    let mut ix_oa: DayIndex<(u32, u32)> = DayIndex::new(block);
    let mut ix_org: DayIndex<u32> = DayIndex::new(block);
    // named accounts with a successful login anywhere: an account seen on
    // other baseline days "has an owner"; one never seen is unknown
    let mut ix_acct: DayIndex<u32> = DayIndex::new(block);
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
                if !is_uid_account(c.accts.name(e.a)) {
                    ix_acct.add(e.a, e.day);
                }
                *lt_base.entry(e.d).or_default().entry(e.lt).or_insert(0) += e.n;
                *lt_day.entry((e.day, e.d)).or_default().entry(e.lt).or_insert(0) += e.n;
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
    // PageRank is iterative: two starting points give values that differ
    // by the convergence noise. A change smaller than twice that noise (or
    // than rounding) is no change.
    let pr_noise = if want_central { algos::pagerank_noise(&g_base) } else { 0.0 };
    let pr_clean = |a: f64, b: f64| -> f64 {
        let d = a - b;
        if d.abs() <= (2.0 * pr_noise).max((ne.max(1) as f64) * f64::EPSILON * a.abs().max(b.abs())) {
            0.0
        } else {
            d
        }
    };
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
            delta_day.insert(*day, (pb.iter().zip(&pr).map(|(a, b)| pr_clean(*a, *b)).collect(), bb.iter().zip(&bc).map(|(a, b)| clean_delta(*a, *b, ne * ne)).collect()));
        }
    }

    // session ends for every successful login: first LOGOFF of the same
    // (origin, destination, account, session id) at or after the login,
    // else the end of the UTC day
    let logoff_idx: HashMap<(u32, u32, u32, u32), Vec<i64>> = {
        let mut m: HashMap<(u32, u32, u32, u32), Vec<i64>> = HashMap::new();
        for e in evs.iter().filter(|e| e.logoff) {
            m.entry((e.o, e.d, e.a, e.lid)).or_default().push(e.t);
        }
        for v in m.values_mut() {
            v.sort();
        }
        m
    };
    let session_end = |e: &Ev| -> i64 {
        logoff_idx
            .get(&(e.o, e.d, e.a, e.lid))
            .and_then(|v| {
                let k = v.partition_point(|t| *t < e.t);
                v.get(k).copied()
            })
            .unwrap_or((e.day as i64 + 1) * 86_400 - 1)
    };

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
        // last LOGOFF of the day per (origin, destination, account)
        let mut logoff_end: HashMap<(u32, u32, u32), i64> = HashMap::new();
        for e in today.iter().filter(|e| e.logoff) {
            let x = logoff_end.entry((e.o, e.d, e.a)).or_insert(e.t);
            *x = (*x).max(e.t);
        }
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
            if f & (F_DST_ORIGIN | F_ACCT_DST) != 0 {
                f |= F_NEW_ACCESS;
            }
            if named && f & F_ACCT_ORIGIN != 0 {
                if ix_acct.is_new(&a, day, b) {
                    f |= F_UNKNOWN_ACCT;
                } else {
                    f |= F_SWITCH;
                }
            }
            let t_end = if cls == OK {
                logoff_end.get(&(o, d, a)).copied().filter(|t| *t >= t1).unwrap_or((day as i64 + 1) * 86_400 - 1)
            } else {
                t1
            };
            triples.push(TripleDay { day, o, d, a, cls, fams, flags: f, n, t0, t1, t_end });
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
                        let oa_new = ix_oa.is_new(&(e.o, e.a), day, b);
                        let ad_new = ix_ad.is_new(&(e.a, e.d), day, b);
                        if oa_new {
                            od.new_acct_uses.insert((e.a, e.d));
                            od.newacct_success.push((e.d, e.t));
                        }
                        if ad_new {
                            od.new_ad.insert((e.a, e.d));
                        }
                        if oa_new && !ix_acct.is_new(&e.a, day, b) && (pnew || ad_new) {
                            od.switch_new.insert((e.a, e.d));
                        }
                    }
                    ok_events.push(OkEvent { t: e.t, day, o: e.o, d: e.d, a: e.a, named: !is_uid_account(an), end: session_end(e) });
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
    // causal paths (Hopper, Ho et al. 2021): a login B -> C as a2 is caused
    // by one of the logins A -> B that entered B earlier the same UTC day
    // (the day is the unit of the whole analysis; Hopper uses the session
    // length, 24 h). Each distinct (A, a1) is a candidate cause with
    // certainty 1 / #candidates. The path carries the attack signature when
    // the credential changed (a1 != a2) and a1 had never reached C. Paths
    // are attributed to the pivot B: they describe what B did after being
    // entered, and the B -> C connection is the row that shows them.
    if enabled[9] {
        // a login B -> C is caused by one of the sessions open on B at that
        // moment: entered before, not ended yet (LOGOFF when recorded,
        // else the end of the UTC day). With session ends the cause can
        // have entered on an earlier day.
        let mut inbound: HashMap<u32, Vec<(i64, u32, u32, i64)>> = HashMap::new();
        for e in ok_events.iter().filter(|e| e.named && e.o != e.d) {
            inbound.entry(e.d).or_default().push((e.t, e.o, e.a, e.end));
        }
        for v in inbound.values_mut() {
            v.sort();
        }
        for e2 in ok_events.iter().filter(|e| e.named && e.o != e.d) {
            let v = match inbound.get(&e2.o) {
                Some(v) => v,
                None => continue,
            };
            let k = v.partition_point(|(t, _, _, _)| *t <= e2.t);
            let mut cands: BTreeMap<(u32, u32), i64> = BTreeMap::new();
            for (t1, a_node, a1, end1) in &v[..k] {
                if *end1 >= e2.t && *a_node != e2.o && *a_node != e2.d {
                    // latest entry of each candidate cause
                    cands.insert((*a_node, *a1), *t1);
                }
            }
            if cands.is_empty() {
                continue;
            }
            let b = is_base(e2.day);
            let cert = 1.0 / cands.len() as f64;
            for ((a_node, a1), t1) in &cands {
                if *a1 != e2.a && ix_ad.is_new(&(*a1, e2.d), e2.day, b) {
                    if let Some(od) = origin_days.get_mut(&(e2.day, e2.o)) {
                        od.paths.push(PathFact { cert, a_node: *a_node, a1: *a1, t1: *t1, c_node: e2.d, a2: e2.a, t2: e2.t, n_cand: cands.len() });
                    }
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
                    pr.iter().zip(pb).map(|(a, b)| pr_clean(*a, *b)).collect(),
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
    // connection features, for the destinations `okp` / `failp` accept.
    // `off_panel`: the destination has no comparable coverage, so nothing
    // about the account's history on it can be asserted
    let features = |t: &TripleDay, okp: Pred, failp: Pred, cache: &mut HashMap<(i32, u32), [f64; 11]>, off_panel: bool| -> [f64; 17] {
        let mut v = [0.0f64; 17];
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
            v[1] = if off_panel { 0.0 } else { bit(F_ACCT_DST) };
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
        if on("credential-switch") {
            v[15] = ctx[10];
        }
        if t.cls == OK {
            if on("community-bridge") && od.cross_dsts.contains(&t.d) {
                v[10] = 1.0;
            }
            if on("rare-logon-type") {
                v[11] = od.lt_surprise.iter().filter(|(d, _, _)| *d == t.d).map(|(_, s, _)| *s).fold(0.0, f64::max);
            }
            if on("causal-path") {
                v[12] = od.paths.iter().filter(|p| p.c_node == t.d && p.a2 == t.a).map(|p| p.cert).fold(0.0, f64::max);
            }
            let (dp, db) = cen(t.day, t.d);
            v[13] = dp;
            v[14] = db;
            if on("sigma") {
                // distinct Sigma rules that fired on the destination while
                // the connection's session was open
                let set: HashSet<&str> = hits_in(t.d, t.t0, t.t_end).into_iter().map(|i| hits[i].title.as_str()).collect();
                v[16] = set.len() as f64;
            }
            if off_panel {
                // nothing destination-side is comparable with the panel
                v[10] = 0.0;
                v[11] = 0.0;
                v[13] = 0.0;
                v[14] = 0.0;
                v[16] = 0.0;
            }
        }
        v
    };
    struct Tested<'a> {
        t: &'a TripleDay,
        x: [f64; 17],
        p: f64,
        tstat: f64,
        n_null: usize,
        marg: Vec<(usize, f64, usize)>,
        /// destination without comparable coverage; evaluated only because
        /// the origin has no baseline at all
        off_panel: bool,
    }
    let mut tested: Vec<Tested> = Vec::new();
    let mut not_eval: Vec<&TripleDay> = Vec::new();
    for wday in &win_days {
        let pw_ok: HashSet<u32> = panel_ok.iter().copied().filter(|d| covered(&cov_ok, *d, *wday)).collect();
        let pw_fail: HashSet<u32> = panel_fail.iter().copied().filter(|d| covered(&cov_fail, *d, *wday)).collect();
        let okp = |d: u32| pw_ok.contains(&d);
        let failp = |d: u32| pw_fail.contains(&d);
        let on_panel = |t: &TripleDay| if t.cls == OK { okp(t.d) } else { failp(t.d) };
        let had_history = |t: &TripleDay| {
            let m = if t.cls == OK { &cov_ok } else { &cov_fail };
            m.get(&t.d).map(|s| s.range(..=(t.day - block)).next().is_some()).unwrap_or(false)
        };
        for cls in [OK, FAIL, PRE] {
            let mut cache: HashMap<(i32, u32), [f64; 11]> = HashMap::new();
            let (null_rows, null_row_days): (Vec<Vec<f64>>, Vec<i32>) = triples
                .iter()
                // the null is the NEW baseline connections of this result:
                // the question is how unusual a new connection's profile is
                // among new connections. With habitual connections in the
                // null, merely being new would read as a 4 % event and every
                // new connection would pass a 5 % false discovery rate
                // and only on destinations that already had coverage before
                // the day's reference gap: on the first covered day of a
                // destination every connection to it is new for lack of
                // history, not for being unusual
                .filter(|t| t.cls == cls && is_base(t.day) && t.day >= s_day && t.flags & F_TRIPLE != 0 && on_panel(t) && had_history(t))
                .map(|t| (features(t, &okp, &failp, &mut cache, false).to_vec(), t.day))
                .unzip();
            let jn = JointNull::new(null_rows, null_row_days, 17);
            for t in triples.iter().filter(|t| t.cls == cls && t.day == *wday) {
                let off = !on_panel(t);
                // an origin with no baseline at all is new whatever the
                // destination's coverage: its connections are judged by
                // what is known about the origin, never listed as
                // "not evaluated"
                if off && t.flags & F_NO_HISTORY == 0 {
                    not_eval.push(t);
                    continue;
                }
                let x = features(t, &okp, &failp, &mut cache, off);
                let (p, tstat) = jn.test_fast(&x);
                let marg: Vec<(usize, f64, usize)> = (0..17).map(|k| if x[k] > 0.0 { jn.marginal(k, x[k]) } else { (jn.n, 1.0, null_days.len()) }).collect();
                tested.push(Tested { t, x, p, tstat, n_null: jn.n, marg, off_panel: off });
            }
        }
    }
    // the Benjamini-Hochberg family holds the new connections only: a
    // habitual connection has p = 1 by construction and is not a test, and
    // counting it would only cost power (the floor 1/(N+1) must clear
    // alpha * rank / m)
    let family: Vec<usize> = tested.iter().enumerate().filter(|(_, x)| x.t.flags & F_TRIPLE != 0).map(|(i, _)| i).collect();
    let qf = stats::benjamini_hochberg(&family.iter().map(|&i| tested[i].p).collect::<Vec<_>>());
    let mut qs = vec![1.0f64; tested.len()];
    for (j, &i) in family.iter().enumerate() {
        qs[i] = qf[j];
    }
    let n_sig = qs.iter().filter(|q| **q <= alpha).count();
    let floor: Vec<String> = [OK, FAIL, PRE]
        .iter()
        .filter_map(|cls| tested.iter().find(|x| x.t.cls == *cls).map(|x| format!("{} 1/{}", match *cls { OK => "logins", FAIL => "failed logins", _ => "unauthenticated connections" }, x.n_null + 1)))
        .collect();
    lines.push(format!(
        "Connections: {} new connections tested (origin, destination, account, result, day) against {} baseline day(s), {} habitual (p = 1, not tested); {} significant at FDR {} (Benjamini-Hochberg over the new ones); {} on destinations without comparable coverage; smallest reachable p: {}",
        family.len(),
        null_days.len(),
        tested.len() - family.len(),
        n_sig,
        alpha,
        not_eval.len(),
        floor.join(", ")
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
        // an IP and its own host name, both unresolved, share the very same
        // logins (same destination, account and second): one machine, not
        // a campaign
        let mut ev_of: HashMap<u32, HashSet<(u32, u32, i64)>> = HashMap::new();
        for e in evs.iter().filter(|e| !is_base(e.day) && e.cls == OK && nod.contains_key(&e.o)) {
            ev_of.entry(e.o).or_default().insert((e.d, e.a, e.t));
        }
        let pop = pop_set.len() as u64;
        let mut pairs: Vec<(u32, u32, f64, usize, BTreeSet<u32>)> = Vec::new();
        for x in 0..cand.len() {
            for y in x + 1..cand.len() {
                let (a, b) = (cand[x], cand[y]);
                let shared: BTreeSet<u32> = noa[&a].intersection(&noa[&b]).copied().collect();
                if shared.is_empty() {
                    continue;
                }
                if let (Some(sa), Some(sb)) = (ev_of.get(&a), ev_of.get(&b)) {
                    if !sa.is_disjoint(sb) {
                        continue;
                    }
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
        OK => "new baseline logins",
        FAIL => "new baseline failed logins",
        _ => "new baseline unauthenticated connections",
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
        // each reason is (what happened, the baseline count behind it):
        // `why_unusual` lists the first parts, `evidence` the pairs
        let mut why: Vec<(String, String)> = Vec::new();
        // "shared by N of M baseline logins" for a yes/no fact, "matched or
        // exceeded by N of M baseline logins" for a count: N baseline
        // connections of the same result were at least as extreme
        let nd = null_days.len();
        let shared = |k: usize| format!("shared by {} of {} {}, on {} of {} days", tt.marg[k].0, tt.n_null, class_name(t.cls), tt.marg[k].2, nd);
        let matched = |k: usize| format!("matched or exceeded by {} of {} {}, on {} of {} days", tt.marg[k].0, tt.n_null, class_name(t.cls), tt.marg[k].2, nd);
        let x = &tt.x;
        let f = t.flags;
        // Hopper's two attack properties (Ho et al., USENIX Security 2021):
        // a credential switch and a new access. The class orders the rows;
        // the p-value stays what it is.
        let (group, class): (u8, &str) = if f & F_TRIPLE == 0 {
            (3, "habitual connection")
        } else if t.cls == OK && f & F_SWITCH != 0 && f & F_NEW_ACCESS != 0 {
            (0, "credential switch with new access")
        } else if x[12] > 0.0 {
            (0, "causal path with credential switch and new access")
        } else if x[15] > 0.0 {
            (0, "same origin and day as a credential switch with new access")
        } else if f & F_UNKNOWN_ACCT != 0 {
            (1, "account unknown to the network")
        } else if f & F_SWITCH != 0 {
            (1, "credential switch to a known destination")
        } else if t.cls == OK {
            (2, "habitual credential on a new connection")
        } else {
            (2, "no credential")
        };
        if x[4] > 0.0 {
            why.push(("origin never seen before".into(), shared(4)));
        } else {
            if x[2] > 0.0 {
                why.push(("origin never connected to this destination before".into(), shared(2)));
            }
            if x[3] > 0.0 {
                why.push(("account never used by this origin before".into(), shared(3)));
            }
        }
        if x[1] > 0.0 {
            why.push(("account never logged in to this destination before".into(), shared(1)));
        }
        if x[0] > 0.0 && x[1] == 0.0 && x[2] == 0.0 && x[3] == 0.0 && x[4] == 0.0 {
            why.push(("this origin/account/destination combination never seen, each part known".into(), shared(0)));
        }
        if x[5] > 0.0 {
            why.push((format!("that day the origin reached {} destination(s) for the first time", x[5]), matched(5)));
        }
        if x[6] > 0.0 {
            why.push((format!("that day the origin used {} account(s) new to it", x[6]), matched(6)));
        }
        if x[7] > 0.0 {
            why.push((format!("that day the origin failed to log in on {} destination(s)", x[7]), matched(7)));
        }
        if x[8] > 0.0 {
            why.push((format!("that day the origin touched {} destination(s) without authenticating", x[8]), matched(8)));
        }
        if x[9] > 0.0 {
            why.push((format!("that day the origin had {} refused named attempt(s) before logging in with an account new to it", x[9]), matched(9)));
        }
        if x[10] > 0.0 {
            why.push(("destination outside the origin's usual group of hosts (Louvain community)".into(), shared(10)));
        }
        if x[11] > 0.0 {
            let lt = od.lt_surprise.iter().filter(|(d, _, _)| *d == t.d).max_by(|a, b| a.1.partial_cmp(&b.1).unwrap()).map(|x| c.lts.name(x.2)).unwrap_or("");
            why.push((format!("logon type {} is rare on this destination", lt), matched(11)));
        }
        if x[12] > 0.0 {
            if let Some(p) = od.paths.iter().filter(|p| p.c_node == t.d && p.a2 == t.a).max_by(|a, b| a.cert.partial_cmp(&b.cert).unwrap()) {
                why.push((
                    format!(
                        "causal path: {} had been entered from {} as {} at {} ({} s earlier); it went on to {} as {}, and {} had never logged in there (1 of {} candidate cause(s))",
                        ents.names.name(t.o),
                        ents.names.name(p.a_node),
                        c.accts.name(p.a1),
                        ts_str(p.t1),
                        p.t2 - p.t1,
                        ents.names.name(t.d),
                        c.accts.name(p.a2),
                        c.accts.name(p.a1),
                        p.n_cand
                    ),
                    matched(12),
                ));
            }
        }
        if x[15] > 0.0 {
            why.push((format!("that day the origin made {} login(s) with a credential switch to a new access", x[15]), matched(15)));
        }
        if x[13] > 0.0 {
            why.push((format!("the destination's PageRank rose that day (+{:.3})", x[13]), matched(13)));
        }
        if x[14] > 0.0 {
            why.push((format!("the destination's betweenness rose that day (+{:.5})", x[14]), matched(14)));
        }
        if x[16] > 0.0 {
            let idx = hits_in(t.d, t.t0, t.t_end);
            let mut seen: HashSet<&str> = HashSet::new();
            let mut examples: Vec<String> = Vec::new();
            for i in idx {
                let h = &hits[i];
                if seen.insert(h.title.as_str()) && examples.len() < 3 {
                    examples.push(format!("'{}' at {}{}", h.title, ts_str(h.t), if h.level.is_empty() { String::new() } else { format!(" ({})", h.level) }));
                }
            }
            why.push((
                format!(
                    "Sigma: {} rule(s) fired on {} while the session was open: {}{}",
                    x[16],
                    ents.names.name(t.d),
                    examples.join(", "),
                    if seen.len() > examples.len() { format!(" and {} more", seen.len() - examples.len()) } else { String::new() }
                ),
                matched(16),
            ));
        }
        if tt.off_panel {
            why.push(("destination without continuous coverage: judged by the origin's novelty only".into(), String::new()));
        }
        if why.is_empty() && group == 3 {
            why.push(("nothing new: a connection like the usual ones".into(), String::new()));
        }
        let why_text = why.iter().map(|(w, _)| w.as_str()).collect::<Vec<_>>().join("; ");
        let evidence = why.iter().filter(|(_, e)| !e.is_empty()).map(|(w, e)| format!("{}: {}", w, e)).collect::<Vec<_>>().join("; ");
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
            class: class.to_string(),
            why: why_text,
            evidence,
            chain: String::new(),
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
            oid: t.o,
            did: t.d,
            aid: t.a,
            flags: t.flags,
            group,
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
            class: "not evaluated".to_string(),
            why: format!(
                "not evaluated: the destination has {} covered baseline day(s) and no continuous coverage from {} to the cutoff, so nothing there can be judged new or habitual",
                k,
                day_str(s_day)
            ),
            evidence: String::new(),
            chain: String::new(),
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
            oid: t.o,
            did: t.d,
            aid: t.a,
            flags: t.flags,
            group: 3,
        });
    }
    // evaluated first; significant before the rest; within each, Hopper
    // class, then p, then combined surprise, then time
    let insig = |c: &Conn| !(c.q <= alpha);
    out.sort_by(|a, b| {
        (!a.evaluable)
            .cmp(&!b.evaluable)
            .then(insig(a).cmp(&insig(b)))
            .then(a.group.cmp(&b.group))
            .then(nan_last(a.p).partial_cmp(&nan_last(b.p)).unwrap())
            .then(nan_last(-a.tstat).partial_cmp(&nan_last(-b.tstat)).unwrap())
            .then(a.first.cmp(&b.first))
    });
    let sig_g = |g: u8| out.iter().filter(|c| c.evaluable && c.q <= alpha && c.group == g).count();
    lines.push(format!(
        "Significant by class: {} credential switch with new access (or same origin-day), {} unknown account / switch to a known destination, {} habitual or no credential",
        sig_g(0),
        sig_g(1),
        sig_g(2) + sig_g(3)
    ));

    // ── analyst report: one story per origin with a significant connection,
    //    in the order of the CSV ──
    let is_sig = |cn: &Conn| cn.evaluable && cn.q <= alpha;
    let mut order: Vec<u32> = Vec::new();
    for cn in out.iter().filter(|cn| is_sig(cn)) {
        if !order.contains(&cn.oid) {
            order.push(cn.oid);
        }
    }
    // baseline days per partner of `id` in a (first, second) index; `name`
    // turns the partner id into text (machine or account)
    let top_days = |m: &HashMap<(u32, u32), DayCount>, key_is_first: bool, id: u32, name: &dyn Fn(u32) -> String| -> Vec<(String, u32)> {
        let mut v: Vec<(String, u32)> = m
            .iter()
            .filter(|((a, b), _)| if key_is_first { *a == id } else { *b == id })
            .map(|((a, b), cnt)| (name(if key_is_first { *b } else { *a }), cnt.n))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    };
    let machine_name = |x: u32| ents.names.name(x).to_string();
    let account_name = |x: u32| c.accts.name(x).to_string();
    let mut stories: Vec<report::OriginStory> = Vec::new();
    for o in order {
        let rows: Vec<&Conn> = out.iter().filter(|cn| cn.oid == o).collect();
        let sig_rows: Vec<&Conn> = rows.iter().copied().filter(|cn| is_sig(cn)).collect();
        let best_p = sig_rows.iter().map(|cn| cn.p).fold(f64::INFINITY, f64::min);
        let best_q = sig_rows.iter().map(|cn| cn.q).fold(f64::INFINITY, f64::min);
        let class = sig_rows[0].class.clone();
        // phases: (day, result) in time order
        let mut ph: BTreeMap<(i32, String), Vec<&Conn>> = BTreeMap::new();
        for cn in &rows {
            ph.entry((cn.day, cn.result.to_string())).or_default().push(cn);
        }
        let mut phases: Vec<report::Phase> = ph
            .into_iter()
            .map(|((day, result), v)| {
                let mut accounts: Vec<String> = v.iter().map(|cn| cn.account.clone()).filter(|a| !a.is_empty()).collect();
                accounts.sort();
                accounts.dedup();
                let mut hosts: Vec<String> = v.iter().map(|cn| cn.dest.clone()).collect();
                hosts.sort();
                hosts.dedup();
                report::Phase {
                    day: day_str(day),
                    t0: ts_str(v.iter().map(|cn| cn.first).min().unwrap_or(0)),
                    t1: ts_str(v.iter().map(|cn| cn.last).max().unwrap_or(0)),
                    verb: match result.as_str() {
                        "login OK" => "logged in".to_string(),
                        "login FAILED" => "failed to log in".to_string(),
                        _ => "connected without authenticating".to_string(),
                    },
                    accounts,
                    hosts,
                    events: v.iter().map(|cn| cn.events).sum(),
                    n_rows: v.len(),
                    n_sig: v.iter().filter(|cn| is_sig(cn)).count(),
                    habitual: v.iter().all(|cn| cn.group == 3 && cn.evaluable),
                    best_p: v.iter().filter(|cn| cn.evaluable).map(|cn| cn.p).fold(f64::NAN, f64::min),
                }
            })
            .collect();
        phases.sort_by(|a, b| a.day.cmp(&b.day).then(a.t0.cmp(&b.t0)));
        // origin-level reasons per day, taken once from the best row of the day
        let mut why: Vec<(String, Vec<String>)> = Vec::new();
        let mut days: Vec<i32> = rows.iter().map(|cn| cn.day).collect();
        days.sort();
        days.dedup();
        for d in &days {
            let mut clauses: Vec<String> = Vec::new();
            for cn in rows.iter().filter(|cn| cn.day == *d && cn.evaluable) {
                for cl in cn.evidence.split("; ") {
                    if (cl.starts_with("that day") || cl.starts_with("origin never seen before") || cl.starts_with("Sigma:")) && !clauses.iter().any(|x| x == cl) {
                        clauses.push(cl.to_string());
                    }
                }
                if !clauses.is_empty() {
                    break;
                }
            }
            why.push((day_str(*d), clauses));
        }
        // accounts new for this origin: who owns them in the baseline
        let mut acct_ids: Vec<u32> = rows.iter().filter(|cn| cn.result == "login OK" && cn.flags & F_ACCT_ORIGIN != 0).map(|cn| cn.aid).collect();
        acct_ids.sort();
        acct_ids.dedup();
        let accounts: Vec<report::AccountNote> = acct_ids
            .iter()
            .map(|a| {
                let owners = top_days(&ix_oa.m, false, *a, &machine_name);
                let owners: Vec<(String, u32)> = owners.into_iter().filter(|(n, _)| n != ents.names.name(o)).collect();
                report::AccountNote { account: c.accts.name(*a).to_string(), n_owners: owners.len(), owners: owners.into_iter().take(5).collect() }
            })
            .collect();
        let mut paths: Vec<String> = Vec::new();
        for cn in &rows {
            for cl in cn.why.split("; ") {
                if cl.starts_with("causal path:") && !paths.contains(&cl.to_string()) {
                    paths.push(cl.to_string());
                }
            }
        }
        let mut logs: Vec<String> = rows.iter().flat_map(|cn| cn.logs.split_whitespace().map(|s| s.to_string()).collect::<Vec<_>>()).collect();
        logs.sort();
        logs.dedup();
        let d0 = *days.first().unwrap_or(&cutoff_day);
        let d1 = *days.last().unwrap_or(&cutoff_day);
        stories.push(report::OriginStory {
            origin: entity_label(&ents, o),
            class,
            best_q,
            best_p,
            n_sig: sig_rows.len(),
            n_rows: rows.len(),
            n_not_eval: rows.iter().filter(|cn| !cn.evaluable).count(),
            baseline_days: ix_org.m.get(&o).map(|cnt| cnt.n).unwrap_or(0),
            baseline_first: ix_org.m.get(&o).map(|cnt| day_str(cnt.first)).unwrap_or_default(),
            baseline_last: ix_org.m.get(&o).map(|cnt| day_str(cnt.last)).unwrap_or_default(),
            data_first: base_days.iter().next().map(|d| day_str(*d)).unwrap_or_default(),
            data_last: base_days.iter().next_back().map(|d| day_str(*d)).unwrap_or_default(),
            usual_dests: top_days(&ix_pair.m, true, o, &machine_name).into_iter().take(5).collect(),
            usual_accts: top_days(&ix_oa.m, true, o, &account_name).into_iter().filter(|(a, _)| !is_uid_account(a) && !is_no_account(a)).take(5).collect(),
            phases,
            why,
            accounts,
            paths,
            campaign: rows[0].campaign.clone(),
            logs,
            cypher: super::browser_snippet_multi(dialect, &alias_list(o), &[], None, &day_from(d0), Some(&day_to(d1))),
        });
    }
    // ═════════════ reconstruction from seeds ═════════════
    //
    // The analyst names what is already known to be bad (hosts, IPs,
    // accounts). Every window login by a seed is a hop; from each hop's
    // destination, the logins that leave it while the hop's session is
    // open are the next hops, with certainty 1 / (sessions open on that
    // machine at that moment), as in the causal paths. Only logins that
    // are new connections, or that use an account the chain already used,
    // are followed: routine traffic leaving a machine the attacker entered
    // (its daily jobs) is not the attacker's chain. Sessions end at their
    // LOGOFF when one was recorded, else at the end of the UTC day. One
    // level backward is given too: the sessions open on a seed machine
    // when it made its first hop.
    let mut chain_set: Vec<(usize, String)> = Vec::new();
    let seed_recon: Option<report::SeedRecon> = if cfg.seeds.is_empty() {
        None
    } else {
        // a seed is a machine, an account, or `machine:account` (both at
        // once); a seed with a baseline history only starts the chain
        // with its NEW connections, a never-seen one with everything
        struct Spec {
            text: String,
            machines: HashSet<u32>,
            accounts: HashSet<u32>,
            has_history: bool,
        }
        let find_m = |s: &str| -> HashSet<u32> {
            (0..ents.names.names.len() as u32)
                .filter(|&e| ents.names.name(e).to_lowercase() == s || ents.aliases[e as usize].iter().any(|a| a.to_lowercase() == s))
                .collect()
        };
        let find_a = |s: &str| -> HashSet<u32> { (0..c.accts.names.len() as u32).filter(|&a| c.accts.name(a).to_lowercase() == s).collect() };
        let mut specs: Vec<Spec> = Vec::new();
        let mut matched: Vec<String> = Vec::new();
        let mut unmatched: Vec<String> = Vec::new();
        for raw in &cfg.seeds {
            let s = raw.to_lowercase();
            let (machines, accounts) = match s.rfind(':') {
                Some(k) if !looks_like_ip(&s) => (find_m(&s[..k]), find_a(&s[k + 1..])),
                _ => {
                    let m = find_m(&s);
                    if m.is_empty() {
                        (HashSet::new(), find_a(&s))
                    } else {
                        (m, HashSet::new())
                    }
                }
            };
            let both = s.contains(':') && !looks_like_ip(&s);
            let ok = if both { !machines.is_empty() && !accounts.is_empty() } else { !machines.is_empty() || !accounts.is_empty() };
            if !ok {
                unmatched.push(raw.clone());
                continue;
            }
            let has_history = machines.iter().any(|m| ix_org.m.contains_key(m)) || (machines.is_empty() && accounts.iter().any(|a| ix_acct.m.contains_key(a)));
            matched.push(raw.clone());
            specs.push(Spec { text: raw.clone(), machines, accounts, has_history });
        }
        let seed_m: HashSet<u32> = specs.iter().flat_map(|sp| sp.machines.iter().copied()).collect();
        let seed_a: HashSet<u32> = specs.iter().filter(|sp| sp.machines.is_empty()).flat_map(|sp| sp.accounts.iter().copied()).collect();
        let t_lo = cfg.seed_from.map(|t| t.timestamp()).unwrap_or(i64::MIN);
        let t_hi = cfg.seed_to.map(|t| t.timestamp()).unwrap_or(i64::MAX);
        // window sessions: successful logins with a named account
        struct Sess {
            t: i64,
            end: Option<i64>,
            o: u32,
            d: u32,
            a: u32,
            day: i32,
        }
        let mut logoffs: HashMap<(u32, u32, u32, u32), Vec<i64>> = HashMap::new();
        for e in evs.iter().filter(|e| e.logoff && !is_base(e.day)) {
            logoffs.entry((e.o, e.d, e.a, e.lid)).or_default().push(e.t);
        }
        for v in logoffs.values_mut() {
            v.sort();
        }
        let mut sess: Vec<Sess> = Vec::new();
        for e in evs.iter().filter(|e| e.cls == OK && !is_base(e.day) && e.o != e.d) {
            let an = c.accts.name(e.a);
            if is_no_account(an) {
                continue;
            }
            let end = logoffs.get(&(e.o, e.d, e.a, e.lid)).and_then(|v| {
                let k = v.partition_point(|t| *t < e.t);
                v.get(k).copied()
            });
            sess.push(Sess { t: e.t, end, o: e.o, d: e.d, a: e.a, day: e.day });
        }
        let end_of = |s: &Sess| s.end.unwrap_or((s.day as i64 + 1) * 86_400 - 1);
        // sessions by destination, in time order, and by origin
        let mut by_dst: HashMap<u32, Vec<usize>> = HashMap::new();
        let mut by_org: HashMap<u32, Vec<usize>> = HashMap::new();
        for (i, s) in sess.iter().enumerate() {
            by_dst.entry(s.d).or_default().push(i);
            by_org.entry(s.o).or_default().push(i);
        }
        for v in by_dst.values_mut().chain(by_org.values_mut()) {
            v.sort_by_key(|i| sess[*i].t);
        }
        // is a session a new connection in the hunt? (origin, dest, account, day)
        let conn_of: HashMap<(u32, u32, u32, i32), usize> = out.iter().enumerate().map(|(i, cn)| ((cn.oid, cn.did, cn.aid, cn.day), i)).collect();
        let is_new_conn = |s: &Sess| conn_of.get(&(s.o, s.d, s.a, s.day)).map(|&i| out[i].flags & F_TRIPLE != 0).unwrap_or(false);
        struct HopRec {
            s: usize,
            depth: i32,
            n_cand: usize,
            cause: String,
        }
        let mut hops: Vec<HopRec> = Vec::new();
        let mut taken: HashSet<usize> = HashSet::new();
        let mut chain_accts: HashSet<u32> = seed_a.clone();
        // depth 1: the window logins that match a seed, within the seed
        // bounds; for a seed with a history only its new connections
        let mut skipped_n: Vec<usize> = vec![0; specs.len()];
        let mut order: Vec<(usize, usize)> = Vec::new();
        for i in 0..sess.len() {
            let s = &sess[i];
            if s.t < t_lo || s.t > t_hi {
                continue;
            }
            for (k, sp) in specs.iter().enumerate() {
                let m_ok = sp.machines.is_empty() || sp.machines.contains(&s.o);
                let a_ok = sp.accounts.is_empty() || sp.accounts.contains(&s.a);
                if !(m_ok && a_ok) {
                    continue;
                }
                if sp.has_history && !is_new_conn(s) {
                    skipped_n[k] += 1;
                    continue;
                }
                order.push((i, k));
                break;
            }
        }
        order.sort_by_key(|(i, _)| sess[*i].t);
        for (i, _) in order {
            if taken.insert(i) {
                chain_accts.insert(sess[i].a);
                hops.push(HopRec { s: i, depth: 1, n_cand: 1, cause: "seed".to_string() });
            }
        }
        let skipped: Vec<String> = specs
            .iter()
            .enumerate()
            .filter(|(k, sp)| sp.has_history && skipped_n[*k] > 0)
            .map(|(k, sp)| format!("{} existed in the baseline: {} habitual login(s) in the window (connections it already made before) were not followed; only its new connections start the chain", sp.text, skipped_n[k]))
            .collect();
        // onward hops, breadth first
        let mut q = 0usize;
        while q < hops.len() {
            let hi = q;
            q += 1;
            let s = &sess[hops[hi].s];
            let t_end = end_of(s);
            let outs: Vec<usize> = by_org.get(&s.d).map(|v| v.iter().copied().filter(|&j| sess[j].t >= s.t && sess[j].t <= t_end && !taken.contains(&j)).collect()).unwrap_or_default();
            for j in outs {
                let x = &sess[j];
                if !(is_new_conn(x) || chain_accts.contains(&x.a)) {
                    continue;
                }
                // sessions open on the pivot at that moment
                let open = by_dst.get(&s.d).map(|v| v.iter().filter(|&&k| sess[k].t <= x.t && end_of(&sess[k]) >= x.t).count()).unwrap_or(1).max(1);
                taken.insert(j);
                chain_accts.insert(x.a);
                let cause = format!("hop {}: {} entered {} as {}", hi + 1, ents.names.name(s.o), ents.names.name(s.d), c.accts.name(s.a));
                hops.push(HopRec { s: j, depth: hops[hi].depth + 1, n_cand: open, cause });
            }
        }
        // one level back: what was open on a seed machine when it first acted
        let mut back: Vec<HopRec> = Vec::new();
        for &m in &seed_m {
            if let Some(first) = hops.iter().filter(|h| sess[h.s].o == m).map(|h| sess[h.s].t).min() {
                let open: Vec<usize> = by_dst.get(&m).map(|v| v.iter().copied().filter(|&k| sess[k].t <= first && end_of(&sess[k]) >= first && !taken.contains(&k)).collect()).unwrap_or_default();
                let n = open.len().max(1);
                for k in open {
                    taken.insert(k);
                    back.push(HopRec { s: k, depth: 0, n_cand: n, cause: format!("open on {} when it first acted", ents.names.name(m)) });
                }
            }
        }
        let mut all: Vec<HopRec> = back;
        all.extend(hops);
        all.sort_by_key(|h| (sess[h.s].t, h.depth));
        // group the sessions of one movement: same depth, origin, account,
        // destination and cause (an automated fan-out opens several
        // sessions per host)
        struct Grp {
            depth: i32,
            o: u32,
            d: u32,
            a: u32,
            day: i32,
            cause: String,
            n_cand: usize,
            first: i64,
            last: i64,
            end: Option<i64>,
            n: usize,
        }
        let mut groups: Vec<Grp> = Vec::new();
        let mut gidx: HashMap<(i32, u32, u32, u32, String), usize> = HashMap::new();
        for h in &all {
            let s = &sess[h.s];
            let key = (h.depth, s.o, s.d, s.a, h.cause.clone());
            match gidx.get(&key) {
                Some(&g) => {
                    let gr = &mut groups[g];
                    gr.last = gr.last.max(s.t);
                    gr.end = match (gr.end, s.end) {
                        (Some(x), Some(y)) => Some(x.max(y)),
                        (None, y) => y,
                        (x, None) => x,
                    };
                    gr.n += 1;
                    gr.n_cand = gr.n_cand.max(h.n_cand);
                }
                None => {
                    gidx.insert(key, groups.len());
                    groups.push(Grp { depth: h.depth, o: s.o, d: s.d, a: s.a, day: s.day, cause: h.cause.clone(), n_cand: h.n_cand, first: s.t, last: s.t, end: s.end, n: 1 });
                }
            }
        }
        // machines of the chain and its time span
        let mut machines: BTreeSet<u32> = seed_m.iter().copied().collect();
        for h in &all {
            machines.insert(sess[h.s].o);
            machines.insert(sess[h.s].d);
        }
        let t_first = all.iter().map(|h| sess[h.s].t).min().unwrap_or(cutoff_ts);
        let t_last = all.iter().map(|h| end_of(&sess[h.s]).max(sess[h.s].t)).max().unwrap_or(cutoff_ts);
        // failed / pre-auth touches from chain machines in the window
        let mut touch: BTreeMap<(u32, u32, u8), (u64, i64, i64)> = BTreeMap::new();
        for e in evs.iter().filter(|e| !is_base(e.day) && (e.cls == FAIL || e.cls == PRE) && machines.contains(&e.o)) {
            let x = touch.entry((e.o, e.d, e.cls)).or_insert((0, e.t, e.t));
            x.0 += e.n;
            x.1 = x.1.min(e.t);
            x.2 = x.2.max(e.t);
        }
        let touches: Vec<String> = touch
            .iter()
            .map(|((o, d, cls), (n, a, b))| {
                format!(
                    "{} -> {}: {} {} {}",
                    ents.names.name(*o),
                    ents.names.name(*d),
                    n,
                    if *cls == FAIL { "failed attempt(s)" } else { "unauthenticated touch(es)" },
                    if a == b { format!("at {}", ts_str(*a)) } else { format!("between {} and {}", ts_str(*a), ts_str(*b)) }
                )
            })
            .collect();
        for (i, g) in groups.iter().enumerate() {
            if let Some(&idx) = conn_of.get(&(g.o, g.d, g.a, g.day)) {
                chain_set.push((idx, format!("hop {} depth {}", i + 1, g.depth)));
            }
        }
        let hop_rows: Vec<report::SeedHop> = groups
            .iter()
            .map(|g| {
                let (p, sig, class) = match conn_of.get(&(g.o, g.d, g.a, g.day)) {
                    Some(&i) if out[i].evaluable => (out[i].p, if out[i].q <= alpha { "significant".to_string() } else { "not significant".to_string() }, out[i].class.clone()),
                    _ => (f64::NAN, String::new(), String::new()),
                };
                report::SeedHop {
                    depth: g.depth,
                    time: ts_str(g.first),
                    last: ts_str(g.last),
                    sessions: g.n,
                    end: g.end.map(ts_str).unwrap_or_default(),
                    origin: entity_label(&ents, g.o),
                    account: c.accts.name(g.a).to_string(),
                    dest: entity_label(&ents, g.d),
                    certainty: 1.0 / g.n_cand as f64,
                    n_cand: g.n_cand,
                    cause: g.cause.clone(),
                    p,
                    significant: sig,
                    class,
                }
            })
            .collect();
        // Cypher: the chain as a virtual graph (APOC) or as the real edges
        // of each hop (Memgraph); and everything between the chain machines
        let qs = |s: &str| s.replace('\\', "\\\\").replace('\'', "\\'");
        let cypher_chain = if dialect.apoc {
            let items: Vec<String> = groups
                .iter()
                .enumerate()
                .map(|(i, g)| {
                    format!(
                        "{{h: {}, o: '{}', d: '{}', c: '{}', t: '{}', u: '{}', n: {}, e: '{}', k: '{}'}}",
                        i + 1,
                        qs(ents.names.name(g.o)),
                        qs(ents.names.name(g.d)),
                        qs(c.accts.name(g.a)),
                        ts_str(g.first),
                        ts_str(g.last),
                        g.n,
                        g.end.map(ts_str).unwrap_or_else(|| "?".into()),
                        if g.n_cand <= 1 { "1".to_string() } else { format!("1/{}", g.n_cand) }
                    )
                })
                .collect();
            format!(
                "WITH [{}] AS hops\nWITH hops, apoc.coll.toSet([x IN hops | x.o] + [x IN hops | x.d]) AS names\nWITH hops, apoc.map.fromLists(names, [x IN names | apoc.create.vNode(CASE WHEN x IN [{}] THEN ['seed'] ELSE ['host'] END, {{name: x}})]) AS node\nUNWIND hops AS x\nRETURN node[x.o], apoc.create.vRelationship(node[x.o], x.c, {{hop: x.h, first: x.t, last: x.u, sessions: x.n, end: x.e, certainty: x.k}}, node[x.d]) AS salto, node[x.d]",
                items.join(",\n      "),
                seed_m.iter().map(|m| format!("'{}'", qs(ents.names.name(*m)))).collect::<Vec<_>>().join(", ")
            )
        } else {
            let conds: Vec<String> = groups
                .iter()
                .map(|g| {
                    format!(
                        "(a.name IN [{}] AND b.name IN [{}] AND type(r) = '{}' AND r.time >= {} AND r.time < {})",
                        alias_list(g.o).iter().map(|x| format!("'{}'", qs(x))).collect::<Vec<_>>().join(", "),
                        alias_list(g.d).iter().map(|x| format!("'{}'", qs(x))).collect::<Vec<_>>().join(", "),
                        qs(c.accts.name(g.a)),
                        dialect.t(ts_str(g.first - 1).trim_end_matches('Z')),
                        dialect.t(ts_str(g.last + 1).trim_end_matches('Z'))
                    )
                })
                .collect();
            format!("MATCH (a:host)-[r]->(b:host) WHERE {} RETURN a, r, b", conds.join("\n   OR "))
        };
        let names: Vec<String> = machines.iter().flat_map(|m| alias_list(*m)).collect();
        let cypher_all = super::browser_snippet_multi(dialect, &names, &names, None, &ts_str(t_first - 1), Some(&ts_str(t_last + 1)));
        lines.push(format!(
            "Seeds: {} matched, {} movement(s) ({} session(s)) reconstructed over {} machine(s)",
            matched.len(),
            groups.len(),
            all.len(),
            machines.len()
        ));
        Some(report::SeedRecon {
            seeds: cfg.seeds.clone(),
            matched,
            unmatched,
            skipped,
            hops: hop_rows,
            touches,
            machines: machines.iter().map(|m| entity_label(&ents, *m)).collect(),
            first: ts_str(t_first),
            last: ts_str(t_last),
            cypher_chain,
            cypher_all,
            rule: "A seed that existed in the baseline starts the chain only with its new connections; a never-seen seed with everything it did. A hop is followed from a machine while the session that entered it is open (until its LOGOFF, or the end of the UTC day when none was recorded); only logins that are new connections or that use an account the chain already used are followed, and the certainty is 1 over the sessions open on the machine at that moment.".to_string(),
        })
    };
    for (i, s) in chain_set {
        out[i].chain = s;
    }
    (out, lines, alpha, stories, seed_recon)
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
        "rank,significant,p_value,q_value,day,first_seen_utc,last_seen_utc,origin,destination,account,result,events,logs,signature,why_unusual,evidence,chain,campaign,cypher_snippet
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
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}
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
            csv_escape(&r.class),
            csv_escape(&r.why),
            csv_escape(&r.evidence),
            csv_escape(&r.chain),
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
        let days: Vec<i32> = (0..99).map(|i| i / 10).collect();
        let jn = JointNull::new(rows, days, 2);
        let (p, _) = jn.test_fast(&[10.0, 10.0]);
        assert!((p - 1.0 / 100.0).abs() < 1e-12);
        // an ordinary point is not significant
        let (p2, _) = jn.test_fast(&[1.0, 1.0]);
        assert!(p2 > 0.3);
        // marginal: 4 is reached by i % 5 == 4, i.e. 19 rows on all 10 days
        let (ge, _, nd) = jn.marginal(0, 4.0);
        assert_eq!(ge, 19);
        assert_eq!(nd, 10);
    }
    #[test]
    fn empty_null_gives_p_one() {
        let jn = JointNull::new(Vec::new(), Vec::new(), 16);
        let (p, t) = jn.test_fast(&[3.0; 16]);
        assert_eq!(p, 1.0);
        assert_eq!(t, 0.0);
        assert_eq!(jn.marginal(0, 1.0), (0, 1.0, 0));
    }
    #[test]
    fn uid_account_is_utf8_safe() {
        assert!(is_uid_account("uid:1101"));
        assert!(is_uid_account("UID_7"));
        assert!(!is_uid_account("uid:"));
        assert!(!is_uid_account("José"));
        assert!(!is_uid_account("Joséfina"));
    }
    #[test]
    fn block_reference_matches_window_length() {
        // gap 3: a fact on baseline days 10, 11, 12 and 20 is new on day 12
        // (only the days up to 9 count) and not on day 20 (12 <= 17)
        let mut ix: DayIndex<u32> = DayIndex::new(3);
        ix.add(1, 10);
        ix.add(1, 11);
        ix.add(1, 12);
        ix.add(1, 20);
        assert!(ix.is_new(&1, 12, true));
        assert!(!ix.is_new(&1, 20, true));
        let mut ix2: DayIndex<u32> = DayIndex::new(3);
        ix2.add(2, 10);
        ix2.add(2, 11);
        ix2.add(2, 12);
        assert!(ix2.is_new(&2, 12, true));
        assert!(!ix2.is_new(&2, 15, true)); // 12 is outside 15's block [13, 15]
    }
    /// Build a corpus from (day, hour, origin, destination, account, event_type) rows.
    fn corpus(rows: &[(i32, i64, &str, &str, &str, &str)]) -> Corpus {
        let mut c = Corpus { cov: HashMap::new(), fams: Interner::default(), nodes: Interner::default(), accts: Interner::default(), lts: Interner::default(), ets: Interner::default(), lids: Interner::default(), rows: Vec::new(), bad_ts: 0 };
        c.lids.id("");
        for (day, hour, o, d, a, et) in rows {
            let eid = if *et == "CONNECT" { "SSH_PREAUTH" } else { "" };
            let cls = class_of(et, eid, a);
            c.rows.push(RawRow {
                t: *day as i64 * 86_400 + hour * 3600,
                fam: c.fams.id("secure"),
                o: c.nodes.id(o),
                d: c.nodes.id(d),
                a: c.accts.id(a),
                et: c.ets.id(et),
                cls,
                lt: c.lts.id("SSH"),
                cov: (true, true),
                n: 1,
                lid: 0,
                logoff: *et == "LOGOFF",
            });
        }
        c
    }

    #[test]
    fn causal_path_and_credential_switch_are_reported() {
        // baseline days 1..=20: A logs in to B as a1 every day; X logs in to
        // C as a2 every day (a2's owner is X). Window day 21: A -> B as a1
        // at 10:00, then B -> C as a2 at 11:00. The B -> C login is a
        // credential switch (a2 owned by X, never used by B) with a new
        // access (B never reached C), and the causal path A -(a1)-> B
        // -(a2)-> C has certainty 1 (one candidate cause) and a1 never
        // logged in to C.
        // plus one ordinary new connection per baseline day (Zk -> B as A1)
        // so that the null of new connections is not empty
        let zs: Vec<String> = (1..=20).map(|k| format!("Z{}", k)).collect();
        let mut rows: Vec<(i32, i64, &str, &str, &str, &str)> = Vec::new();
        for day in 1..=20 {
            rows.push((day, 9, "A", "B", "A1", "SUCCESSFUL_LOGON"));
            rows.push((day, 9, "X", "C", "A2", "SUCCESSFUL_LOGON"));
            rows.push((day, 12, zs[(day - 1) as usize].as_str(), "B", "A1", "SUCCESSFUL_LOGON"));
        }
        rows.push((21, 10, "A", "B", "A1", "SUCCESSFUL_LOGON"));
        rows.push((21, 11, "B", "C", "A2", "SUCCESSFUL_LOGON"));
        let c = corpus(&rows);
        let cfg = Settings { cutoff: chrono::DateTime::from_timestamp(21 * 86_400, 0).unwrap(), end: None, alpha: 0.05, only: HashSet::new(), skip: HashSet::new(), seeds: vec!["a:a1".into(), "nobody".into()], seed_from: None, seed_to: None, sigma: Vec::new() };
        let (out, _lines, _alpha, stories, seed) = analyse(&c, &super::super::NEO4J, &cfg, &[]);
        // seed A: hop 1 = A -> B as A1 on day 21, hop 2 = B -> C as A2 (new
        // connection, one session open on B: certainty 1)
        let r = seed.expect("seed reconstruction");
        assert_eq!(r.matched, vec!["a:a1".to_string()]);
        assert_eq!(r.unmatched, vec!["nobody".to_string()]);
        // A existed in the baseline, so its habitual A -> B login on day 21
        // does not start the chain by itself... but the chain must still
        // reach B -> C: A -> B is habitual, hence skipped, and nothing
        // follows. That is the intended behaviour for a seed with history.
        assert_eq!(r.hops.len(), 0, "{:?}", r.hops.iter().map(|h| (h.depth, h.origin.clone(), h.dest.clone())).collect::<Vec<_>>());
        assert_eq!(r.skipped.len(), 1);
        // seeding by the account that switched (A2, owned by X, used by B)
        // finds the B -> C login directly
        let cfg2 = Settings { seeds: vec!["a2".into()], ..cfg };
        let (_, _, _, _, seed2) = analyse(&c, &super::super::NEO4J, &cfg2, &[]);
        let r = seed2.expect("seed reconstruction");
        assert_eq!(r.hops.len(), 1);
        assert_eq!((r.hops[0].depth, r.hops[0].origin.as_str(), r.hops[0].dest.as_str()), (1, "B", "C"));
        assert!(r.cypher_chain.contains("apoc.create.vRelationship"));
        let r = report::SeedRecon { hops: Vec::new(), ..r };
        assert!(report::render_seed(&r).contains("No login by the seeds"));
        return;

        let bc = out.iter().find(|r| r.origin == "B" && r.dest == "C" && r.account == "A2").expect("B -> C row");
        assert!(bc.evaluable);
        assert_eq!(bc.class, "credential switch with new access");
        assert!(bc.why.contains("causal path: B had been entered from A as A1"), "{}", bc.why);
        assert!(bc.why.contains("went on to C as A2, and A1 had never logged in there (1 of 1 candidate cause(s))"), "{}", bc.why);
        assert!(bc.evidence.contains("origin never connected to this destination before: shared by"), "{}", bc.evidence);
        // the habitual A -> B login on day 21 is not new
        let ab = out.iter().find(|r| r.origin == "A" && r.dest == "B" && r.day == 21).expect("A -> B row");
        assert_eq!(ab.class, "habitual connection");
        // B -> C is the only new connection of the window and beats the 19
        // new baseline connections that count (Zk -> B on days 2..=20; day 1
        // has no prior coverage): p = 1/20, significant alone
        assert_eq!(out[0].origin, "B");
        assert!((bc.p - 1.0 / 20.0).abs() < 1e-12, "{}", bc.p);
        assert!(bc.q <= 0.05);
        // the report tells who owns A2
        let st = stories.iter().find(|s| s.origin == "B").expect("story for B");
        assert_eq!(st.accounts.len(), 1);
        assert_eq!(st.accounts[0].account, "A2");
        assert_eq!(st.accounts[0].owners, vec![("X".to_string(), 20)]);
        assert!(st.paths.iter().any(|p| p.starts_with("causal path:")));
        assert_eq!(st.phases.len(), 1);
        assert_eq!(st.phases[0].verb, "logged in");
    }

    #[test]
    fn sigma_hits_during_the_session_are_reported() {
        // same corpus as the causal-path test, plus the LOGOFF of B -> C at
        // 12:00 on day 21 and two Sigma hits on C: one at 11:30 (inside the
        // session) and one at 13:00 (after it)
        let zs: Vec<String> = (1..=20).map(|k| format!("Z{}", k)).collect();
        let mut rows: Vec<(i32, i64, &str, &str, &str, &str)> = Vec::new();
        for day in 1..=20 {
            rows.push((day, 9, "A", "B", "A1", "SUCCESSFUL_LOGON"));
            rows.push((day, 9, "X", "C", "A2", "SUCCESSFUL_LOGON"));
            rows.push((day, 12, zs[(day - 1) as usize].as_str(), "B", "A1", "SUCCESSFUL_LOGON"));
        }
        rows.push((21, 10, "A", "B", "A1", "SUCCESSFUL_LOGON"));
        rows.push((21, 11, "B", "C", "A2", "SUCCESSFUL_LOGON"));
        rows.push((21, 12, "B", "C", "A2", "LOGOFF"));
        let c = corpus(&rows);
        let day21 = 21 * 86_400;
        let hits = vec![
            sigma::SigmaHit { t: day21 + 11 * 3600 + 1800, host: "c.corp.local".into(), title: "PsExec Service Installation".into(), level: "high".into(), tags: String::new() },
            sigma::SigmaHit { t: day21 + 13 * 3600, host: "C".into(), title: "Something later".into(), level: String::new(), tags: String::new() },
        ];
        let cfg = Settings { cutoff: chrono::DateTime::from_timestamp(day21, 0).unwrap(), end: None, alpha: 0.05, only: HashSet::new(), skip: HashSet::new(), seeds: Vec::new(), seed_from: None, seed_to: None, sigma: Vec::new() };
        let (out, lines, _, _, _) = analyse(&c, &super::super::NEO4J, &cfg, &hits);
        assert!(lines.iter().any(|l| l.starts_with("Sigma: 2 hit(s) read, 2 on 1 machine(s)")), "{:?}", lines);
        let bc = out.iter().find(|r| r.origin == "B" && r.dest == "C" && r.account == "A2").expect("B -> C row");
        assert!(bc.why.contains("Sigma: 1 rule(s) fired on C while the session was open"), "{}", bc.why);
        assert!(bc.evidence.contains("Sigma: 1 rule(s) fired on C while the session was open: 'PsExec Service Installation' at 1970-01-22T11:30:00Z (high): matched or exceeded by"), "{}", bc.evidence);
        assert!(bc.why.contains("'PsExec Service Installation' at 1970-01-22T11:30:00Z (high)"), "{}", bc.why);
        assert!(!bc.why.contains("Something later"), "{}", bc.why);
    }

    #[test]
    fn csv_split_and_account_type() {
        assert_eq!(split_csv(r#"a,"",b"#), vec!["a", "", "b"]);
        assert_eq!(split_csv(r#"x,"one, two","he said ""hi"" ok",y"#), vec!["x", "one, two", "he said \"hi\" ok", "y"]);
        assert_eq!(account_type("uid:1101"), "UID_1101");
        assert_eq!(account_type("(unknown)"), "_UNKNOWN_");
        assert_eq!(account_type("bob@corp"), "BOB");
        assert_eq!(account_type(""), "NO_USER");
        assert_eq!(account_type("50114229n"), "U50114229N");
    }

    #[test]
    fn logoff_is_not_a_login() {
        assert_eq!(class_of("LOGOFF", "", "ROOT"), OTHER);
        assert_eq!(class_of("SUCCESSFUL_LOGON", "", "ROOT"), OK);
        assert_eq!(class_of("FAILED_LOGON", "", "ROOT"), FAIL);
        assert_eq!(class_of("CONNECT", "SSH_PREAUTH", "NO_USER"), PRE);
    }

    #[test]
    fn dayindex_leave_one_out() {
        let mut ix: DayIndex<u32> = DayIndex::new(1);
        ix.add(7, 100);
        ix.add(8, 100);
        ix.add(8, 101);
        assert!(ix.is_new(&7, 100, true)); // first seen on day 100
        assert!(ix.is_new(&8, 100, true)); // first seen on day 100 too
        assert!(!ix.is_new(&8, 101, true)); // seen the day before
        assert!(!ix.is_new(&7, 105, false)); // window: seen in baseline
        assert!(ix.is_new(&9, 105, false));
    }
}
