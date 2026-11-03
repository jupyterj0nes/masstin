//! Time-respecting paths and reach, the questions a Cypher catalogue used
//! to answer, computed on the store's time-ordered adjacency.
//!
//! A path from A to B is a chain of logins where every hop happens after
//! the previous one, no later than `max_gap` seconds after it, and no host
//! is entered twice. The search is a depth-first walk over each host's
//! outgoing edges, which are sorted by time, so the candidates of the next
//! hop start at a binary search and everything earlier is skipped.
//!
//! The forward cone is the earliest-arrival traversal: every host the
//! origin could have reached from `t0`, with the hop and the login that
//! got there first; the backward cone is the same towards a destination,
//! walking the incoming edges back in time.

use std::collections::{HashMap, HashSet, VecDeque};

use super::store::{Edge, Store, R_OK};

#[derive(Clone, Debug)]
pub struct PathQuery {
    pub origin: u32,
    pub dest: u32,
    /// first hop at or after this time
    pub from: Option<i64>,
    /// last hop at or before this time
    pub to: Option<i64>,
    pub max_hops: usize,
    /// seconds a hop may wait after the previous one
    pub max_gap: i64,
    pub max_paths: usize,
    /// which results count as a hop (logon OK, FAILED, logoff, connect)
    pub results: [bool; 4],
    /// leave out machine accounts (`NAME$`)
    pub skip_machine_accounts: bool,
}

impl Default for PathQuery {
    fn default() -> Self {
        PathQuery { origin: 0, dest: 0, from: None, to: None, max_hops: 6, max_gap: 86_400, max_paths: 50, results: [true, false, false, false], skip_machine_accounts: true }
    }
}

#[derive(Clone, Debug)]
pub struct Path {
    /// store edge indices, in order
    pub edges: Vec<u32>,
}

impl Path {
    pub fn hops(&self) -> usize {
        self.edges.len()
    }
    pub fn span(&self, s: &Store) -> i64 {
        let a = s.edges[self.edges[0] as usize].t;
        let b = s.edges[*self.edges.last().unwrap() as usize].t;
        b - a
    }
}

fn hop_ok(s: &Store, e: &Edge, q: &PathQuery) -> bool {
    if !q.results[e.result as usize] {
        return false;
    }
    if q.skip_machine_accounts && s.users.name(e.user).ends_with('$') {
        return false;
    }
    true
}

/// Every time-respecting path from `origin` to `dest`, shortest first,
/// then earliest to complete.
pub fn find_paths(s: &Store, q: &PathQuery) -> Vec<Path> {
    let mut out: Vec<Path> = Vec::new();
    if q.origin == q.dest || q.max_hops == 0 {
        return out;
    }
    let mut visited: HashSet<u32> = HashSet::new();
    visited.insert(q.origin);
    let mut chain: Vec<u32> = Vec::new();
    // iterative DFS: (host, earliest time for the next hop, latest time, depth)
    let mut budget = 2_000_000usize;
    dfs(s, q, q.origin, q.from.unwrap_or(i64::MIN), q.to.unwrap_or(i64::MAX), &mut visited, &mut chain, &mut out, &mut budget);
    out.sort_by(|a, b| a.hops().cmp(&b.hops()).then_with(|| a.span(s).cmp(&b.span(s))).then_with(|| s.edges[a.edges[0] as usize].t.cmp(&s.edges[b.edges[0] as usize].t)));
    // the same route with the same accounts (two rows of one logon, a
    // retry a second later) is one path: the earliest stays
    let mut seen: HashSet<Vec<(u32, u32, u32)>> = HashSet::new();
    out.retain(|p| seen.insert(p.edges.iter().map(|&ei| { let e = &s.edges[ei as usize]; (e.src, e.dst, e.user) }).collect()));
    out.truncate(q.max_paths);
    out
}

#[allow(clippy::too_many_arguments)]
fn dfs(s: &Store, q: &PathQuery, host: u32, not_before: i64, not_after: i64, visited: &mut HashSet<u32>, chain: &mut Vec<u32>, out: &mut Vec<Path>, budget: &mut usize) {
    if chain.len() >= q.max_hops || out.len() >= q.max_paths * 4 || *budget == 0 {
        return;
    }
    let edges = s.out_adj.of(host);
    // first edge at or after `not_before` (edges of a host are in time order)
    let start = edges.partition_point(|&ei| s.edges[ei as usize].t < not_before);
    for &ei in &edges[start..] {
        *budget = budget.saturating_sub(1);
        if *budget == 0 {
            return;
        }
        let e = &s.edges[ei as usize];
        if e.t > not_after {
            break;
        }
        if !hop_ok(s, e, q) || visited.contains(&e.dst) {
            continue;
        }
        chain.push(ei);
        if e.dst == q.dest {
            out.push(Path { edges: chain.clone() });
        } else {
            visited.insert(e.dst);
            let next_after = (e.t + 1).max(not_before);
            let window_end = (e.t + q.max_gap).min(not_after);
            dfs(s, q, e.dst, next_after, window_end, visited, chain, out, budget);
            visited.remove(&e.dst);
        }
        chain.pop();
    }
}

/// A host in a cone: how far from the seed, when it was first reached,
/// through which login.
#[derive(Clone, Copy, Debug)]
pub struct Reach {
    pub hop: usize,
    pub t: i64,
    pub via: Option<u32>,
}

/// Earliest-arrival traversal from `origin` starting at `from`: every host
/// a chain of logins could have reached, each hop no later than `max_gap`
/// after the previous one.
pub fn forward_cone(s: &Store, origin: u32, from: i64, q: &PathQuery) -> HashMap<u32, Reach> {
    let mut best: HashMap<u32, Reach> = HashMap::new();
    best.insert(origin, Reach { hop: 0, t: from, via: None });
    let mut queue: VecDeque<u32> = VecDeque::new();
    queue.push_back(origin);
    while let Some(h) = queue.pop_front() {
        let r = best[&h];
        if r.hop >= q.max_hops {
            continue;
        }
        let edges = s.out_adj.of(h);
        let not_before = if r.hop == 0 { r.t } else { r.t + 1 };
        let not_after = if r.hop == 0 { q.to.unwrap_or(i64::MAX) } else { (r.t + q.max_gap).min(q.to.unwrap_or(i64::MAX)) };
        let start = edges.partition_point(|&ei| s.edges[ei as usize].t < not_before);
        for &ei in &edges[start..] {
            let e = &s.edges[ei as usize];
            if e.t > not_after {
                break;
            }
            if !hop_ok(s, e, q) {
                continue;
            }
            let better = match best.get(&e.dst) {
                None => true,
                Some(b) => e.t < b.t,
            };
            if better {
                best.insert(e.dst, Reach { hop: r.hop + 1, t: e.t, via: Some(ei) });
                queue.push_back(e.dst);
            }
        }
    }
    best
}

/// The same towards `dest`, back in time from `to`: every host from which
/// a chain of logins could have reached it.
pub fn backward_cone(s: &Store, dest: u32, to: i64, q: &PathQuery) -> HashMap<u32, Reach> {
    let mut best: HashMap<u32, Reach> = HashMap::new();
    best.insert(dest, Reach { hop: 0, t: to, via: None });
    let mut queue: VecDeque<u32> = VecDeque::new();
    queue.push_back(dest);
    while let Some(h) = queue.pop_front() {
        let r = best[&h];
        if r.hop >= q.max_hops {
            continue;
        }
        let edges = s.in_adj.of(h);
        let not_after = if r.hop == 0 { r.t } else { r.t - 1 };
        let not_before = if r.hop == 0 { q.from.unwrap_or(i64::MIN) } else { (r.t - q.max_gap).max(q.from.unwrap_or(i64::MIN)) };
        // walk the latest first
        let end = edges.partition_point(|&ei| s.edges[ei as usize].t <= not_after);
        for &ei in edges[..end].iter().rev() {
            let e = &s.edges[ei as usize];
            if e.t < not_before {
                break;
            }
            if !hop_ok(s, e, q) {
                continue;
            }
            let better = match best.get(&e.src) {
                None => true,
                Some(b) => e.t > b.t,
            };
            if better {
                best.insert(e.src, Reach { hop: r.hop + 1, t: e.t, via: Some(ei) });
                queue.push_back(e.src);
            }
        }
    }
    best
}

/// The canned questions: short tables over a set of edges (the view's).
pub struct Question {
    pub title: &'static str,
    pub columns: [&'static str; 3],
    pub rows: Vec<(String, String, String)>,
}

pub fn questions(s: &Store, edges: &[u32], top: usize) -> Vec<Question> {
    let mut out = Vec::new();
    let name = |h: u32| s.hosts.name(h).to_string();
    // fan-out: destinations per origin (logons that succeeded)
    let mut fanout: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut fanin: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut acct_origins: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut fails: HashMap<(u32, u32), (u64, Option<i64>)> = HashMap::new();
    let mut first_host: HashMap<u32, i64> = HashMap::new();
    let mut first_acct: HashMap<u32, (i64, u32)> = HashMap::new();
    for &ei in edges {
        let e = &s.edges[ei as usize];
        if e.result == R_OK {
            fanout.entry(e.src).or_default().insert(e.dst);
            fanin.entry(e.dst).or_default().insert(e.src);
            if !s.users.name(e.user).is_empty() && !s.users.name(e.user).ends_with('$') {
                acct_origins.entry(e.user).or_default().insert(e.src);
            }
        }
        let f = fails.entry((e.src, e.dst)).or_insert((0, None));
        if e.result == super::store::R_FAIL {
            f.0 += 1;
        } else if e.result == R_OK && f.0 > 0 && f.1.is_none() {
            f.1 = Some(e.t);
        }
        for h in [e.src, e.dst] {
            first_host.entry(h).and_modify(|t| *t = (*t).min(e.t)).or_insert(e.t);
        }
        first_acct.entry(e.user).and_modify(|x| if e.t < x.0 { *x = (e.t, e.src) }).or_insert((e.t, e.src));
    }
    let mut v: Vec<(String, String, String)> = fanout.iter().map(|(h, d)| (name(*h), d.len().to_string(), d.iter().take(6).map(|&x| name(x)).collect::<Vec<_>>().join(", "))).collect();
    v.sort_by(|a, b| b.1.parse::<usize>().unwrap().cmp(&a.1.parse::<usize>().unwrap()).then(a.0.cmp(&b.0)));
    v.truncate(top);
    out.push(Question { title: "Origins reaching the most destinations", columns: ["origin", "destinations", "which"], rows: v });
    let mut v: Vec<(String, String, String)> = fanin.iter().map(|(h, d)| (name(*h), d.len().to_string(), d.iter().take(6).map(|&x| name(x)).collect::<Vec<_>>().join(", "))).collect();
    v.sort_by(|a, b| b.1.parse::<usize>().unwrap().cmp(&a.1.parse::<usize>().unwrap()).then(a.0.cmp(&b.0)));
    v.truncate(top);
    out.push(Question { title: "Destinations reached from the most origins", columns: ["destination", "origins", "which"], rows: v });
    let mut v: Vec<(String, String, String)> = acct_origins.iter().filter(|(_, o)| o.len() > 1).map(|(u, o)| (s.users.name(*u).to_string(), o.len().to_string(), o.iter().take(6).map(|&x| name(x)).collect::<Vec<_>>().join(", "))).collect();
    v.sort_by(|a, b| b.1.parse::<usize>().unwrap().cmp(&a.1.parse::<usize>().unwrap()).then(a.0.cmp(&b.0)));
    v.truncate(top);
    out.push(Question { title: "Accounts used from several origins", columns: ["account", "origins", "which"], rows: v });
    let mut v: Vec<(String, String, String)> = fails.iter().filter(|(_, (n, ok))| *n > 0 && ok.is_some()).map(|((a, b), (n, ok))| (format!("{} -> {}", name(*a), name(*b)), n.to_string(), super::query::fmt_time(ok.unwrap()))).collect();
    v.sort_by(|a, b| b.1.parse::<u64>().unwrap().cmp(&a.1.parse::<u64>().unwrap()).then(a.0.cmp(&b.0)));
    v.truncate(top);
    out.push(Question { title: "Failures followed by a logon", columns: ["connection", "failures", "logon at"], rows: v });
    let mut v: Vec<(String, String, String)> = first_host.iter().map(|(h, t)| (name(*h), super::query::fmt_time(*t), String::new())).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v.truncate(top);
    out.push(Question { title: "Hosts seen latest for the first time", columns: ["host", "first seen", ""], rows: v });
    let mut v: Vec<(String, String, String)> = first_acct.iter().filter(|(u, _)| !s.users.name(**u).is_empty()).map(|(u, (t, src))| (s.users.name(*u).to_string(), super::query::fmt_time(*t), name(*src))).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v.truncate(top);
    out.push(Question { title: "Accounts seen latest for the first time", columns: ["account", "first seen", "from"], rows: v });
    out
}

/// Degree, PageRank and betweenness of the hosts of a set of edges.
pub struct Rank {
    pub host: u32,
    pub inn: usize,
    pub out: usize,
    pub pagerank: f64,
    pub betweenness: f64,
}

pub fn ranking(s: &Store, edges: &[u32]) -> Vec<Rank> {
    use crate::graph_hunt_common::algos;
    let mut hosts: Vec<u32> = Vec::new();
    let mut index: HashMap<u32, usize> = HashMap::new();
    let mut pairs: HashSet<(usize, usize)> = HashSet::new();
    let mut inn: HashMap<u32, usize> = HashMap::new();
    let mut out: HashMap<u32, usize> = HashMap::new();
    for &ei in edges {
        let e = &s.edges[ei as usize];
        for h in [e.src, e.dst] {
            if !index.contains_key(&h) {
                index.insert(h, hosts.len());
                hosts.push(h);
            }
        }
        if e.src != e.dst && pairs.insert((index[&e.src], index[&e.dst])) {
            *out.entry(e.src).or_insert(0) += 1;
            *inn.entry(e.dst).or_insert(0) += 1;
        }
    }
    let links: Vec<(usize, usize)> = pairs.into_iter().collect();
    let g = algos::DiGraph::from_edges(hosts.len(), &links);
    let pr = algos::pagerank(&g);
    let bc = algos::betweenness(&g);
    let mut v: Vec<Rank> = hosts.iter().enumerate().map(|(i, &h)| Rank { host: h, inn: inn.get(&h).copied().unwrap_or(0), out: out.get(&h).copied().unwrap_or(0), pagerank: pr.get(i).copied().unwrap_or(0.0), betweenness: bc.get(i).copied().unwrap_or(0.0) }).collect();
    v.sort_by(|a, b| b.pagerank.partial_cmp(&a.pagerank).unwrap_or(std::cmp::Ordering::Equal));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csv_out;

    fn row(day: u32, hour: u32, src: &str, dst: &str, user: &str, et: &str) -> String {
        format!("2026-01-{:02}T{:02}:00:00Z,{},{},4624,3,{},CORP,,{},,,0x{},,Security.evtx{}", day, hour, dst, et, user, src, hour, csv_out::EMPTY_TAIL)
    }

    fn store() -> (Store, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("masstin-paths-{}.csv", std::process::id()));
        let lines = vec![
            csv_out::HEADER.to_string(),
            row(1, 9, "10.0.0.5", "WS01", "alice", "SUCCESSFUL_LOGON"),
            row(1, 9, "10.0.0.5", "WS01", "alice", "SUCCESSFUL_LOGON"),
            row(1, 10, "WS01", "SRV01", "alice", "SUCCESSFUL_LOGON"),
            row(1, 11, "SRV01", "DC01", "admin", "SUCCESSFUL_LOGON"),
            // too early to follow: before the hop into SRV01
            row(1, 8, "SRV01", "DC01", "admin", "SUCCESSFUL_LOGON"),
            // a failure, not a hop by default
            row(1, 12, "WS01", "DC01", "alice", "FAILED_LOGON"),
            // a machine account, skipped by default
            row(1, 13, "WS01", "DC01", "WS01$", "SUCCESSFUL_LOGON"),
            // a day later: beyond a 6 h gap
            row(2, 20, "DC01", "FS01", "admin", "SUCCESSFUL_LOGON"),
        ];
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        (Store::load(&[path.to_string_lossy().to_string()], 0.05).unwrap(), path)
    }

    #[test]
    fn paths_respect_time_gap_and_filters() {
        let (s, path) = store();
        let h = |n: &str| s.hosts.get(n).unwrap();
        let mut q = PathQuery { origin: h("10.0.0.5"), dest: h("DC01"), ..Default::default() };
        q.max_gap = 6 * 3600;
        let p = find_paths(&s, &q);
        assert_eq!(p.len(), 1, "{:?}", p);
        assert_eq!(p[0].hops(), 3);
        let names: Vec<String> = p[0].edges.iter().map(|&ei| s.hosts.name(s.edges[ei as usize].dst).to_string()).collect();
        assert_eq!(names, vec!["WS01", "SRV01", "DC01"]);
        // allowing failures and machine accounts adds the two short paths
        q.results = [true, true, false, false];
        q.skip_machine_accounts = false;
        let p = find_paths(&s, &q);
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].hops(), 2);
        // FS01 is only reachable with a long gap
        let mut q2 = PathQuery { origin: h("10.0.0.5"), dest: h("FS01"), ..Default::default() };
        q2.max_gap = 6 * 3600;
        assert!(find_paths(&s, &q2).is_empty());
        q2.max_gap = 48 * 3600;
        assert_eq!(find_paths(&s, &q2).len(), 1);
        // cones
        let f = forward_cone(&s, h("10.0.0.5"), 0, &q2);
        assert_eq!(f[&h("FS01")].hop, 4);
        assert_eq!(f[&h("SRV01")].hop, 2);
        let strict = PathQuery { origin: h("10.0.0.5"), dest: h("DC01"), max_gap: 6 * 3600, ..Default::default() };
        let b = backward_cone(&s, h("DC01"), i64::MAX, &strict);
        assert!(b.contains_key(&h("10.0.0.5")));
        assert_eq!(b[&h("WS01")].hop, 2);
        let qs = questions(&s, &(0..s.edges.len() as u32).collect::<Vec<_>>(), 5);
        assert_eq!(qs[0].rows[0].0, "WS01");
        assert!(qs[3].rows.iter().any(|r| r.0 == "WS01 -> DC01"));
        let r = ranking(&s, &(0..s.edges.len() as u32).collect::<Vec<_>>());
        assert_eq!(r.len(), 5);
        let _ = std::fs::remove_file(path);
    }
}
