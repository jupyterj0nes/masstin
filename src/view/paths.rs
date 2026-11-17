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

use super::store::{is_machine_account, Edge, Store, R_OK};

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
    if q.skip_machine_accounts && is_machine_account(s.users.name(e.user)) {
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

/// Every host a chain of logins could have reached from `origin`, starting
/// at `from`, each hop no later than `max_gap` after the one before it.
pub fn forward_cone(s: &Store, origin: u32, from: i64, q: &PathQuery) -> HashMap<u32, Reach> {
    cone(s, origin, from, q, true).0
}

/// The same towards `dest`, back in time from `to`: every host from which
/// a chain of logins could have reached it.
pub fn backward_cone(s: &Store, dest: u32, to: i64, q: &PathQuery) -> HashMap<u32, Reach> {
    cone(s, dest, to, q, false).0
}

/// The cone of `seed`, forward in time or back, and the logins that
/// support it besides each host's own (see below).
///
/// The logins are walked in the order of time, and a host keeps EVERY
/// arrival that can still be continued, not its first one only: a login
/// out of a host is a hop when some arrival came before it and no more
/// than `max_gap` earlier. (Keeping the first arrival alone, a host
/// entered at 09:00 and again at 17:00 could not be left at 17:30 with a
/// gap of an hour, and everything reached from there was missing from the
/// cone.) A host's `Reach` is its first arrival, as before; when the hop
/// into it left a host through a LATER arrival than that host's first, the
/// login of that arrival is given too, so what is drawn holds together.
pub fn cone(s: &Store, seed: u32, t0: i64, q: &PathQuery, forward: bool) -> (HashMap<u32, Reach>, Vec<u32>) {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    // time as the walk runs it: as it is forward, negated backward
    let tau = |t: i64| if forward { t } else { t.saturating_neg() };
    let limit: i64 = if forward { q.to.unwrap_or(i64::MAX) } else { q.from.map(|f| f.saturating_neg()).unwrap_or(i64::MAX) };
    let adj = |h: u32| -> &[u32] {
        if forward { s.out_adj.of(h) } else { s.in_adj.of(h) }
    };
    // the k-th login of a host in walk order (the lists are in time order)
    let nth = |h: u32, k: usize| -> Option<u32> {
        let l = adj(h);
        if k >= l.len() {
            None
        } else if forward {
            Some(l[k])
        } else {
            Some(l[l.len() - 1 - k])
        }
    };
    let etau = |ei: u32| tau(s.edges[ei as usize].t);
    // the first login of a host, in walk order, at or after `x`
    let first_at = |h: u32, x: i64| -> usize {
        let l = adj(h);
        if forward {
            l.partition_point(|&ei| s.edges[ei as usize].t < x)
        } else {
            l.len() - l.partition_point(|&ei| s.edges[ei as usize].t <= x.saturating_neg())
        }
    };
    struct Host {
        /// the next login to look at, in walk order
        next: usize,
        /// no login after this can be a hop (the last arrival plus the gap)
        until: i64,
        /// arrivals that can still be continued: (time, hops, login), in
        /// time order and with more hops the later they are (one that is
        /// later and no shorter than another is never the better choice)
        arrivals: VecDeque<(i64, usize, u32)>,
        queued: bool,
    }
    let mut best: HashMap<u32, Reach> = HashMap::new();
    best.insert(seed, Reach { hop: 0, t: t0, via: None });
    let mut support: HashSet<u32> = HashSet::new();
    let mut hosts: HashMap<u32, Host> = HashMap::new();
    let mut heap: BinaryHeap<Reverse<(i64, u32)>> = BinaryHeap::new();
    let start = first_at(seed, tau(t0));
    hosts.insert(seed, Host { next: start, until: limit, arrivals: VecDeque::new(), queued: false });
    if let Some(ei) = nth(seed, start) {
        heap.push(Reverse((etau(ei), seed)));
        hosts.get_mut(&seed).unwrap().queued = true;
    }
    while let Some(Reverse((_, h))) = heap.pop() {
        // this host's next login, and what it can continue
        let (ei, hops, enabling) = {
            let host = hosts.get_mut(&h).unwrap();
            host.queued = false;
            let Some(ei) = nth(h, host.next) else { continue };
            let te = etau(ei);
            if te > limit || (h != seed && te > host.until) {
                // nothing more from here until another arrival
                continue;
            }
            host.next += 1;
            if h == seed {
                (ei, 0usize, None)
            } else {
                while host.arrivals.front().map_or(false, |a| a.0 < te.saturating_sub(q.max_gap)) {
                    host.arrivals.pop_front();
                }
                // the oldest arrival before this login is the one with the fewest hops
                match host.arrivals.iter().find(|a| a.0 < te) {
                    Some(a) => (ei, a.1, Some(a.2)),
                    None => {
                        if let Some(n) = nth(h, host.next) {
                            heap.push(Reverse((etau(n), h)));
                            host.queued = true;
                        }
                        continue;
                    }
                }
            }
        };
        let e = &s.edges[ei as usize];
        let te = etau(ei);
        let v = if forward { e.dst } else { e.src };
        if v != seed && v != h && hops < q.max_hops && hop_ok(s, e, q) {
            if !best.contains_key(&v) {
                best.insert(v, Reach { hop: hops + 1, t: e.t, via: Some(ei) });
                if let Some(en) = enabling {
                    if best.get(&h).and_then(|r| r.via) != Some(en) {
                        support.insert(en);
                    }
                }
            }
            let first_next = first_at(v, te.saturating_add(1));
            let hv = hosts.entry(v).or_insert(Host { next: 0, until: i64::MIN, arrivals: VecDeque::new(), queued: false });
            while hv.arrivals.back().map_or(false, |a| a.1 >= hops + 1) {
                hv.arrivals.pop_back();
            }
            hv.arrivals.push_back((te, hops + 1, ei));
            hv.until = hv.until.max(te.saturating_add(q.max_gap));
            if !hv.queued {
                hv.next = hv.next.max(first_next);
                if let Some(n) = nth(v, hv.next) {
                    heap.push(Reverse((etau(n), v)));
                    hv.queued = true;
                }
            }
        }
        let host = hosts.get_mut(&h).unwrap();
        if !host.queued {
            if let Some(n) = nth(h, host.next) {
                heap.push(Reverse((etau(n), h)));
                host.queued = true;
            }
        }
    }
    let mut support: Vec<u32> = support.into_iter().collect();
    support.sort_unstable();
    (best, support)
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
            if !s.users.name(e.user).is_empty() && !is_machine_account(s.users.name(e.user)) {
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

    /// A host entered twice: what it reaches after its SECOND arrival is in
    /// the cone, forward and back, and the cone is every host a path
    /// search finds and no other.
    #[test]
    fn a_cone_follows_every_arrival_not_the_first_one() {
        let path = std::env::temp_dir().join(format!("masstin-cone-{}.csv", std::process::id()));
        let row = |day: u32, hour: u32, src: &str, dst: &str| format!("2026-01-{:02}T{:02}:00:00Z,{},SUCCESSFUL_LOGON,4624,3,ana,CORP,,{},,,0x{}{},,Security.evtx,,,,,", day, hour, dst, src, day, hour);
        let body = [
            crate::csv_out::HEADER.to_string(),
            row(5, 9, "10.0.0.1", "B"),
            // eight hours later A enters B again, and B goes on within the hour
            row(5, 17, "10.0.0.1", "B"),
            row(5, 18, "B", "C"),
            row(5, 19, "C", "D"),
            // too late after anything: never part of the cone
            row(9, 9, "D", "E"),
            // another way into C, a day before, that leads nowhere in time
            row(4, 9, "X", "C"),
        ]
        .join("\n");
        std::fs::write(&path, format!("{}\n", body)).unwrap();
        let s = Store::load(&[path.to_string_lossy().to_string()], 0.05).unwrap();
        let h = |n: &str| s.hosts.get(n).unwrap();
        let name = |id: &u32| s.hosts.name(*id).to_string();
        let q = PathQuery { origin: h("10.0.0.1"), dest: h("D"), max_gap: 2 * 3600, ..Default::default() };
        let (f, support) = cone(&s, h("10.0.0.1"), 0, &q, true);
        let mut reached: Vec<String> = f.keys().map(name).collect();
        reached.sort();
        assert_eq!(reached, ["10.0.0.1", "B", "C", "D"]);
        assert_eq!((f[&h("B")].hop, f[&h("C")].hop, f[&h("D")].hop), (1, 2, 3));
        // B is shown by its first arrival; the one that let it go on is given too
        assert_eq!(s.edges[f[&h("B")].via.unwrap() as usize].t % 86_400, 9 * 3600);
        assert_eq!(support.len(), 1);
        assert_eq!(s.edges[support[0] as usize].t % 86_400, 17 * 3600);
        // what the path search finds is in the cone
        assert_eq!(find_paths(&s, &q).len(), 1);
        // back from D: the same chain, and X (a day early) is not on it
        let (b, _) = cone(&s, h("D"), i64::MAX, &q, false);
        let mut from: Vec<String> = b.keys().map(name).collect();
        from.sort();
        assert_eq!(from, ["10.0.0.1", "B", "C", "D"]);
        assert_eq!((b[&h("C")].hop, b[&h("B")].hop, b[&h("10.0.0.1")].hop), (1, 2, 3));
        // one hop at most: only what the seed touches itself
        let one = PathQuery { max_hops: 1, ..PathQuery { origin: h("10.0.0.1"), dest: h("D"), max_gap: 2 * 3600, ..Default::default() } };
        assert_eq!(cone(&s, h("10.0.0.1"), 0, &one, true).0.len(), 2);
        // a window that ends before the second arrival: B alone
        let early = PathQuery { to: Some(s.edges[f[&h("B")].via.unwrap() as usize].t + 3600), ..PathQuery { origin: h("10.0.0.1"), dest: h("D"), max_gap: 2 * 3600, ..Default::default() } };
        assert_eq!(cone(&s, h("10.0.0.1"), 0, &early, true).0.len(), 2);
        let _ = std::fs::remove_file(path);
    }

    /// On a real timeline (`MASSTIN_CONE_FIXTURE=<timeline.csv>`, and
    /// `MASSTIN_CONE_ORIGINS=a,b`): every host the path search reaches from
    /// an origin is in that origin's cone, and the other way round.
    #[test]
    fn the_cone_is_what_the_path_search_reaches() {
        let Ok(file) = std::env::var("MASSTIN_CONE_FIXTURE") else { return };
        let s = Store::load(&[file], 0.05).unwrap();
        let origins = std::env::var("MASSTIN_CONE_ORIGINS").unwrap_or_default();
        for o in origins.split(',').filter(|o| !o.is_empty()) {
            let origin = s.hosts.get(o).unwrap_or_else(|| panic!("no host {}", o));
            for (hops, gap) in [(2usize, 3600i64), (3, 6 * 3600), (4, 24 * 3600)] {
                let q = PathQuery { origin, dest: origin, max_hops: hops, max_gap: gap, ..Default::default() };
                let (reach, _) = cone(&s, origin, s.t_min, &q, true);
                let (mut both, mut only_paths, mut only_cone) = (0usize, 0usize, 0usize);
                for d in 0..s.hosts.len() as u32 {
                    if d == origin {
                        continue;
                    }
                    let found = !find_paths(&s, &PathQuery { dest: d, max_paths: 1, ..q.clone() }).is_empty();
                    match (found, reach.contains_key(&d)) {
                        (true, true) => both += 1,
                        (true, false) => only_paths += 1,
                        (false, true) => only_cone += 1,
                        _ => {}
                    }
                }
                println!("{} hops<={} gap={}h: cone {} hosts; with a path {}; a path but not in the cone {}; in the cone without a path found {}", o, hops, gap / 3600, reach.len() - 1, both, only_paths, only_cone);
                assert_eq!(only_paths, 0, "{}: hosts with a path that the cone misses", o);
            }
        }
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
        // the same hosts whichever way the cone is asked for
        assert_eq!(cone(&s, h("10.0.0.5"), 0, &q2, true).0.len(), f.len());
        let qs = questions(&s, &(0..s.edges.len() as u32).collect::<Vec<_>>(), 5);
        assert_eq!(qs[0].rows[0].0, "WS01");
        assert!(qs[3].rows.iter().any(|r| r.0 == "WS01 -> DC01"));
        let r = ranking(&s, &(0..s.edges.len() as u32).collect::<Vec<_>>());
        assert_eq!(r.len(), 5);
        let _ = std::fs::remove_file(path);
    }
}
