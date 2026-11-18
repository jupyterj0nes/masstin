//! Time-respecting paths and reach, the questions a Cypher catalogue used
//! to answer, computed on the store's time-ordered adjacency.
//!
//! A path from A to B is a chain of logins where every hop happens after
//! the previous one, no later than `max_gap` seconds after it, and no host
//! is entered twice. Asked **by session**, the hop out of a host is tied to
//! the session the hop into it opened, by that session's logon ID, in
//! either of two ways: the host has its own record of that session
//! connecting to the next host (a 4648, an auditd `connect`: the session
//! MADE the hop), or the hop leaves while the session is still open,
//! between its logon and its logoff, which the timeline pairs by logon ID
//! (a logon whose logoff the timeline does not have cannot be followed
//! that way, unless the gap is asked for in its place). The search is a depth-first walk over each host's
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
    /// the next hop is tied to the session the hop before opened, instead
    /// of leaving within `max_gap` of it: the session is recorded to have
    /// made it, or it leaves while the session is open
    pub by_session: bool,
    /// by session: a logon with no logoff in the timeline is followed for
    /// `max_gap` (instead of not at all)
    pub gap_without_session: bool,
    /// the only logins that may be a hop, by store edge; `None`: any
    pub only: Option<std::rc::Rc<Vec<bool>>>,
    /// only the first of the two ways of `by_session`: every hop was MADE
    /// by the session the hop before opened, by the record of the host in
    /// between. Leaving while the session is open is not enough
    pub launched: bool,
}

impl Default for PathQuery {
    fn default() -> Self {
        PathQuery { origin: 0, dest: 0, from: None, to: None, max_hops: 6, max_gap: 86_400, max_paths: 50, results: [true, false, false, false], skip_machine_accounts: true, by_session: false, gap_without_session: false, only: None, launched: false }
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

fn hop_ok(s: &Store, ei: u32, e: &Edge, q: &PathQuery) -> bool {
    if !q.results[e.result as usize] {
        return false;
    }
    if let Some(only) = &q.only {
        if !only.get(ei as usize).copied().unwrap_or(false) {
            return false;
        }
    }
    if q.skip_machine_accounts && is_machine_account(s.users.name(e.user)) {
        return false;
    }
    true
}

/// How long after hop `ei` the next one may leave; `None`: it cannot be
/// followed by its time alone (by session, and the timeline has no logoff
/// for it; or only what a session is recorded to have made is asked for).
fn window(s: &Store, q: &PathQuery, ei: u32) -> Option<i64> {
    if q.launched {
        return None;
    }
    if !q.by_session {
        return Some(q.max_gap);
    }
    match s.session_of(ei) {
        Some(d) => Some(d),
        None if q.gap_without_session => Some(q.max_gap),
        None => None,
    }
}

/// Whether the records of what a session made are part of the question
/// (and the timeline has any).
fn by_records(s: &Store, q: &PathQuery) -> bool {
    (q.by_session || q.launched) && s.launches > 0
}

/// Every time-respecting path from `origin` to `dest`, shortest first,
/// then the quickest to complete, then the earliest.
pub fn find_paths(s: &Store, q: &PathQuery) -> Vec<Path> {
    search(s, q).0
}

/// How many chains one length of the search may try before it gives up.
const BUDGET: usize = 2_000_000;

/// The paths, and whether the search was cut short (so many chains to try
/// that some length was not walked to its end: there may be more paths).
///
/// One length at a time, the shortest first: a search that walked every
/// length at once and stopped when it had enough would keep the first
/// chains it met, which are the earliest, not the shortest.
pub fn search(s: &Store, q: &PathQuery) -> (Vec<Path>, bool) {
    let mut out: Vec<Path> = Vec::new();
    let mut cut = false;
    if q.origin == q.dest || q.max_hops == 0 || q.max_paths == 0 {
        return (out, cut);
    }
    // the same route with the same accounts (two rows of one logon, a
    // retry a second later) is one path: the quickest stays
    let mut seen: HashSet<Vec<(u32, u32, u32)>> = HashSet::new();
    for hops in 1..=q.max_hops {
        let mut found: Vec<Path> = Vec::new();
        let mut visited: HashSet<u32> = HashSet::from([q.origin]);
        let mut chain: Vec<u32> = Vec::new();
        let mut budget = BUDGET;
        let room = q.max_paths.saturating_mul(20).saturating_add(1000);
        dfs(s, q, hops, room, q.origin, None, &mut visited, &mut chain, &mut found, &mut budget);
        cut |= budget == 0;
        found.sort_by(|a, b| a.span(s).cmp(&b.span(s)).then_with(|| s.edges[a.edges[0] as usize].t.cmp(&s.edges[b.edges[0] as usize].t)).then_with(|| a.edges.cmp(&b.edges)));
        for p in found {
            if seen.insert(p.edges.iter().map(|&ei| { let e = &s.edges[ei as usize]; (e.src, e.dst, e.user) }).collect()) {
                out.push(p);
            }
        }
        if out.len() >= q.max_paths {
            break;
        }
    }
    out.truncate(q.max_paths);
    (out, cut)
}

/// The chains of exactly `hops` logins from `host` to the destination.
/// `into` is the hop that entered `host` (none at the origin): the logins
/// that can follow it are the ones inside its window (the gap, or its
/// session) and, by session, the ones its session is recorded to have made.
#[allow(clippy::too_many_arguments)]
fn dfs(s: &Store, q: &PathQuery, hops: usize, room: usize, host: u32, into: Option<u32>, visited: &mut HashSet<u32>, chain: &mut Vec<u32>, out: &mut Vec<Path>, budget: &mut usize) {
    if chain.len() >= hops || out.len() >= room || *budget == 0 {
        return;
    }
    let edges = s.out_adj.of(host);
    let end = q.to.unwrap_or(i64::MAX);
    // inside the window: from the moment after the hop in, as long as it lasts
    let (lo, hi) = match into {
        None => (q.from.unwrap_or(i64::MIN), end),
        Some(i) => {
            let t = s.edges[i as usize].t;
            match window(s, q, i) {
                Some(w) => (t + 1, t.saturating_add(w).min(end)),
                None => (1, 0),
            }
        }
    };
    if lo <= hi {
        // (edges of a host are in time order)
        let start = edges.partition_point(|&ei| s.edges[ei as usize].t < lo);
        for &ei in &edges[start..] {
            if s.edges[ei as usize].t > hi || !take(s, q, hops, room, ei, visited, chain, out, budget) {
                break;
            }
        }
    }
    // made by the session, whenever its own record says
    if let Some(i) = into.filter(|_| by_records(s, q)) {
        let after = s.edges[i as usize].t + 1;
        let mut tried: Vec<u32> = Vec::new();
        for &(t, dst) in s.launches_of(i) {
            let (from, to) = ((t - 5).max(after), (t + 300).min(end));
            let start = edges.partition_point(|&ei| s.edges[ei as usize].t < from);
            for &ei in &edges[start..] {
                let e = &s.edges[ei as usize];
                if e.t > to {
                    break;
                }
                // (not one the window already gave)
                if e.dst != dst || (lo <= e.t && e.t <= hi) || tried.contains(&ei) || !s.launched_by(i, ei) {
                    continue;
                }
                tried.push(ei);
                if !take(s, q, hops, room, ei, visited, chain, out, budget) {
                    return;
                }
            }
        }
    }
}

/// One login tried as the next hop of the chain; false when the search
/// has to stop (nothing left to spend, or enough found).
#[allow(clippy::too_many_arguments)]
fn take(s: &Store, q: &PathQuery, hops: usize, room: usize, ei: u32, visited: &mut HashSet<u32>, chain: &mut Vec<u32>, out: &mut Vec<Path>, budget: &mut usize) -> bool {
    *budget = budget.saturating_sub(1);
    if *budget == 0 || out.len() >= room {
        return false;
    }
    let e = &s.edges[ei as usize];
    let last = chain.len() + 1 == hops;
    // the last hop enters the destination and no other does
    if last != (e.dst == q.dest) || visited.contains(&e.dst) || !hop_ok(s, ei, e, q) {
        return true;
    }
    chain.push(ei);
    if last {
        out.push(Path { edges: chain.clone() });
    } else {
        visited.insert(e.dst);
        dfs(s, q, hops, room, e.dst, Some(ei), visited, chain, out, budget);
        visited.remove(&e.dst);
    }
    chain.pop();
    true
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
        /// arrivals that can still be continued: (time, hops, login, the
        /// last moment it can be continued), in time order; one that is
        /// later, no shorter and lasts no less than another replaces it
        arrivals: VecDeque<(i64, usize, u32, i64)>,
        /// every arrival, by what a record ties it to a login by (by
        /// session, when the timeline has records of what sessions made):
        /// forward its logon ID, backward the host it goes to
        tied: HashMap<u64, Vec<(i64, usize, u32)>>,
        queued: bool,
    }
    let records = by_records(s, q);
    let mut best: HashMap<u32, Reach> = HashMap::new();
    best.insert(seed, Reach { hop: 0, t: t0, via: None });
    let mut support: HashSet<u32> = HashSet::new();
    let mut hosts: HashMap<u32, Host> = HashMap::new();
    let mut heap: BinaryHeap<Reverse<(i64, u32)>> = BinaryHeap::new();
    let start = first_at(seed, tau(t0));
    hosts.insert(seed, Host { next: start, until: limit, arrivals: VecDeque::new(), tied: HashMap::new(), queued: false });
    if let Some(ei) = nth(seed, start) {
        heap.push(Reverse((etau(ei), seed)));
        hosts.get_mut(&seed).unwrap().queued = true;
    }
    // the arrivals of the moment being walked: (host, time, hops, login).
    // They wait until every login of that moment is done: one of them may
    // replace an older arrival that a login of this very moment still needs
    let mut arriving: Vec<(u32, i64, usize, u32)> = Vec::new();
    loop {
        if !arriving.is_empty() && heap.peek().map_or(true, |r| (r.0).0 > arriving[0].1) {
            for (v, te, hops, ei) in arriving.drain(..) {
                let first_next = first_at(v, te.saturating_add(1));
                let hv = hosts.entry(v).or_insert(Host { next: 0, until: i64::MIN, arrivals: VecDeque::new(), tied: HashMap::new(), queued: false });
                let expiry = if q.by_session && !forward { i64::MAX } else { window(s, q, ei).map_or(te, |w| te.saturating_add(w)) };
                while hv.arrivals.back().map_or(false, |a| a.1 >= hops && a.3 <= expiry) {
                    hv.arrivals.pop_back();
                }
                hv.arrivals.push_back((te, hops, ei, expiry));
                hv.until = hv.until.max(expiry);
                if records {
                    // a record may tie it to a login at any later moment
                    let key = if forward { s.logon_key(ei) } else { s.edges[ei as usize].dst as u64 + 1 };
                    if key != 0 {
                        hv.tied.entry(key).or_default().push((te, hops, ei));
                    }
                    hv.until = i64::MAX;
                }
                if !hv.queued {
                    hv.next = hv.next.max(first_next);
                    if let Some(n) = nth(v, hv.next) {
                        heap.push(Reverse((etau(n), v)));
                        hv.queued = true;
                    }
                }
            }
            continue;
        }
        let Some(Reverse((_, h))) = heap.pop() else { break };
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
                host.arrivals.retain(|a| a.3 >= te);
                // walking back by session, it is THIS login's session that
                // must hold the hop already found out of the host
                let back = if q.by_session && !forward { window(s, q, ei).unwrap_or(-1) } else { i64::MAX };
                // of the arrivals this login can continue, the one with the fewest hops:
                // the ones whose window it is in...
                let mut from: Option<(usize, u32)> = if q.launched { None } else { host.arrivals.iter().filter(|a| a.0 < te && te.saturating_sub(a.0) <= back).min_by_key(|a| a.1).map(|a| (a.1, a.2)) };
                // ...and the ones a record of the host says made it (forward:
                // the sessions recorded to have connected to where this login
                // goes; backward: the hops out this login's session is
                // recorded to have made)
                if records && !host.tied.is_empty() {
                    let keys: Vec<u64> = if forward { s.launchers_of(ei) } else { s.launches_of(ei).iter().map(|r| r.1 as u64 + 1).collect() };
                    for k in keys {
                        for a in host.tied.get(&k).map_or(&[][..], |v| v.as_slice()) {
                            if a.0 < te && from.map_or(true, |f| a.1 < f.0) && if forward { s.launched_by(a.2, ei) } else { s.launched_by(ei, a.2) } {
                                from = Some((a.1, a.2));
                            }
                        }
                    }
                }
                match from {
                    Some(a) => (ei, a.0, Some(a.1)),
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
        if v != seed && v != h && hops < q.max_hops && hop_ok(s, ei, e, q) {
            if !best.contains_key(&v) {
                best.insert(v, Reach { hop: hops + 1, t: e.t, via: Some(ei) });
                if let Some(en) = enabling {
                    if best.get(&h).and_then(|r| r.via) != Some(en) {
                        support.insert(en);
                    }
                }
            }
            arriving.push((v, te, hops + 1, ei));
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

    /// The gap is between one hop and the next, not from the first hop to
    /// every other; by session, a hop leaves while the session before it is
    /// open; and the logins allowed are the only hops.
    #[test]
    fn the_gap_is_per_hop_and_sessions_chain() {
        let path = std::env::temp_dir().join(format!("masstin-sess-{}.csv", std::process::id()));
        let row = |hour: u32, src: &str, dst: &str, user: &str, et: &str, id: &str| format!("2026-01-05T{:02}:00:00Z,{},{},4624,3,{},CORP,,{},,,{},,Security.evtx,,,,,", hour, dst, et, user, src, id);
        let body = [
            crate::csv_out::HEADER.to_string(),
            row(1, "10.0.0.1", "B", "ana", "SUCCESSFUL_LOGON", "0xb1"),
            // five hours after each hop: inside a gap of six, hop by hop
            row(6, "B", "C", "ana", "SUCCESSFUL_LOGON", "0xc1"),
            row(11, "C", "D", "bob", "SUCCESSFUL_LOGON", "0xd1"),
            // the session on B ends at 08:00 (a logoff has no origin), the one on C at 07:00
            row(8, "", "B", "ana", "LOGOFF", "0xb1"),
            row(7, "", "C", "ana", "LOGOFF", "0xc1"),
        ]
        .join("\n");
        std::fs::write(&path, format!("{}\n", body)).unwrap();
        let s = Store::load(&[path.to_string_lossy().to_string()], 0.05).unwrap();
        let h = |n: &str| s.hosts.get(n).unwrap();
        assert_eq!((s.logons, s.sessions_known), (3, 2));
        let q = PathQuery { origin: h("10.0.0.1"), dest: h("D"), max_gap: 6 * 3600, ..Default::default() };
        // 01:00 -> 06:00 -> 11:00: each within six hours of the one before
        assert_eq!(find_paths(&s, &q).len(), 1);
        assert_eq!(find_paths(&s, &PathQuery { max_gap: 4 * 3600, ..q.clone() }).len(), 0);
        // by session: B is left at 06:00 inside its session (01:00 to 08:00)...
        let sess = PathQuery { by_session: true, ..q.clone() };
        assert_eq!(find_paths(&s, &PathQuery { dest: h("C"), ..sess.clone() }).len(), 1);
        // ...but C is left at 11:00, four hours after its session ended
        assert_eq!(find_paths(&s, &sess).len(), 0);
        let reach = |q: &PathQuery, fwd: bool| -> Vec<String> {
            let seed = if fwd { q.origin } else { q.dest };
            let mut v: Vec<String> = cone(&s, seed, if fwd { 0 } else { i64::MAX }, q, fwd).0.keys().map(|k| s.hosts.name(*k).to_string()).collect();
            v.sort();
            v
        };
        assert_eq!(reach(&sess, true), ["10.0.0.1", "B", "C"]);
        assert_eq!(reach(&q, true), ["10.0.0.1", "B", "C", "D"]);
        // back from C by session: B, and the address that entered B
        assert_eq!(reach(&PathQuery { dest: h("C"), ..sess.clone() }, false), ["10.0.0.1", "B", "C"]);
        // back from D by session: C alone (the hop out of C was after its session)
        assert_eq!(reach(&sess, false), ["C", "D"]);
        assert_eq!(reach(&q, false), ["10.0.0.1", "B", "C", "D"]);
        // only ana's logins: D is bob's
        let ana: Vec<bool> = s.edges.iter().map(|e| s.users.name(e.user).starts_with("ana")).collect();
        let only = PathQuery { only: Some(std::rc::Rc::new(ana)), ..q.clone() };
        assert_eq!(find_paths(&s, &only).len(), 0);
        assert_eq!(find_paths(&s, &PathQuery { dest: h("C"), ..only.clone() }).len(), 1);
        assert_eq!(reach(&only, true), ["10.0.0.1", "B", "C"]);
        let _ = std::fs::remove_file(path);
    }

    /// A logon with no logoff in the timeline: not followed by session,
    /// unless the gap is asked for in its place.
    #[test]
    fn a_session_without_its_logoff_needs_the_gap() {
        let path = std::env::temp_dir().join(format!("masstin-sess2-{}.csv", std::process::id()));
        let row = |hour: u32, src: &str, dst: &str, id: &str| format!("2026-01-05T{:02}:00:00Z,{},SUCCESSFUL_LOGON,4624,3,ana,CORP,,{},,,{},,Security.evtx,,,,,", hour, dst, src, id);
        let body = [crate::csv_out::HEADER.to_string(), row(1, "10.0.0.1", "B", "0xb1"), row(2, "B", "C", "0xc1")].join("\n");
        std::fs::write(&path, format!("{}\n", body)).unwrap();
        let s = Store::load(&[path.to_string_lossy().to_string()], 0.05).unwrap();
        let h = |n: &str| s.hosts.get(n).unwrap();
        assert_eq!(s.sessions_known, 0);
        let q = PathQuery { origin: h("10.0.0.1"), dest: h("C"), by_session: true, ..Default::default() };
        assert_eq!(find_paths(&s, &q).len(), 0);
        assert_eq!(find_paths(&s, &PathQuery { gap_without_session: true, ..q.clone() }).len(), 1);
        assert_eq!(cone(&s, q.origin, 0, &q, true).0.len(), 2);
        assert_eq!(cone(&s, q.origin, 0, &PathQuery { gap_without_session: true, ..q.clone() }, true).0.len(), 3);
        let _ = std::fs::remove_file(path);
    }

    /// A small timeline made by chance: six hosts, three accounts (one a
    /// machine's), every result, sessions with and without their logoff,
    /// and few distinct moments so that many rows share one.
    fn chance_store(seed: u64, tag: &str) -> (Store, std::path::PathBuf) {
        let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let mut next = |n: u64| -> u64 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (x >> 33) % n
        };
        let hosts = ["HA", "HB", "HC", "HD", "HE", "HF"];
        let users = ["ana", "bob", "HB$"];
        let kinds = ["SUCCESSFUL_LOGON", "SUCCESSFUL_LOGON", "SUCCESSFUL_LOGON", "SUCCESSFUL_LOGON", "FAILED_LOGON", "CONNECT", "LOGOFF"];
        let stamp = |slot: u64| chrono::DateTime::from_timestamp(1_767_225_600 + slot as i64 * 1800, 0).unwrap().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut lines = vec![crate::csv_out::HEADER.to_string()];
        let rows = 14 + next(22);
        for i in 0..rows {
            let (a, mut b) = (next(6) as usize, next(6) as usize);
            if a == b {
                b = (b + 1) % 6;
            }
            let slot = next(30);
            let kind = kinds[next(7) as usize];
            let user = users[next(3) as usize];
            lines.push(format!("{},{},{},4624,3,{},CORP,,{},,,0x{:x},,Security.evtx,,,,,", stamp(slot), hosts[b], kind, user, hosts[a], 0x100 + i));
            // its logoff (no origin, as Windows writes it), for some
            if kind == "SUCCESSFUL_LOGON" && next(3) > 0 {
                lines.push(format!("{},{},LOGOFF,4634,3,{},CORP,,,,,0x{:x},,Security.evtx,,,,,", stamp(slot + next(9)), hosts[b], user, 0x100 + i));
            }
            // what that session did next, by the record of the host it is on
            // (a 4648 with the session's logon ID), with the logon it ends in or without it
            if kind == "SUCCESSFUL_LOGON" && next(2) == 0 {
                let mut to = next(6) as usize;
                if to == b {
                    to = (to + 1) % 6;
                }
                let at = slot + 1 + next(3);
                lines.push(format!("{},{},CONNECT,4648,3,{},CORP,{},,,,0x{:x},,Security.evtx,,,,,", stamp(at), hosts[to], user, hosts[b], 0x100 + i));
                if next(4) > 0 {
                    lines.push(format!("{},{},SUCCESSFUL_LOGON,4624,3,{},CORP,,{},,,0x{:x},,Security.evtx,,,,,", stamp(at), hosts[to], user, hosts[b], 0x9000 + i));
                }
            }
        }
        let path = std::env::temp_dir().join(format!("masstin-chance-{}-{}-{}.csv", tag, std::process::id(), seed));
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        (Store::load(&[path.to_string_lossy().to_string()], 0.05).unwrap(), path)
    }

    /// Whether a login may be a hop, written again here from what the
    /// options mean (not from the code that is tested).
    fn may_hop(s: &Store, q: &PathQuery, ei: usize) -> bool {
        let e = &s.edges[ei];
        q.results[e.result as usize]
            && q.only.as_ref().map_or(true, |o| o[ei])
            && !(q.skip_machine_accounts && s.users.name(e.user).split('@').next().unwrap().ends_with('$'))
            && q.to.map_or(true, |t| e.t <= t)
            && q.from.map_or(true, |f| e.t >= f)
    }

    /// Whether login `b` can follow login `a`: out of the host `a` entered,
    /// later, and within the gap, or inside the session `a` opened.
    fn follows(s: &Store, q: &PathQuery, a: usize, b: usize) -> bool {
        let (ea, eb) = (&s.edges[a], &s.edges[b]);
        if eb.src != ea.dst || eb.t <= ea.t {
            return false;
        }
        // made by the session: some record written from the host in between,
        // with the logon ID of `a`, of a connection to where `b` goes, when
        // `b` goes, while the session of `a` is open (when its end is known)
        let made = {
            let id = s.logon_key(a as u32);
            let open_until = s.session_of(a as u32).map(|d| ea.t + d + 5);
            id != 0
                && (0..s.edges.len()).any(|r| {
                    let er = &s.edges[r];
                    matches!(s.event_ids.name(er.event_id), "4648" | "AUDIT_CONNECT")
                        && s.logon_key(r as u32) == id
                        && er.src == ea.dst
                        && er.dst == eb.dst
                        && er.t >= ea.t
                        && open_until.map_or(true, |u| er.t <= u)
                        && eb.t >= er.t - 5
                        && eb.t <= er.t + 300
                })
        };
        if q.launched {
            return made;
        }
        if q.by_session && made {
            return true;
        }
        let room = if !q.by_session {
            Some(q.max_gap)
        } else {
            match s.session_of(a as u32) {
                Some(d) => Some(d),
                None => q.gap_without_session.then_some(q.max_gap),
            }
        };
        room.map_or(false, |r| eb.t - ea.t <= r)
    }

    /// Every path there is, by trying every chain: the routes (origin,
    /// destination and account of each hop) with their number of hops.
    fn every_route(s: &Store, q: &PathQuery) -> HashMap<Vec<(u32, u32, u32)>, usize> {
        fn walk(s: &Store, q: &PathQuery, chain: &mut Vec<usize>, seen: &mut Vec<u32>, out: &mut HashMap<Vec<(u32, u32, u32)>, usize>) {
            let last = *chain.last().unwrap();
            if s.edges[last].dst == q.dest {
                out.insert(chain.iter().map(|&i| (s.edges[i].src, s.edges[i].dst, s.edges[i].user)).collect(), chain.len());
                return;
            }
            if chain.len() >= q.max_hops {
                return;
            }
            for b in 0..s.edges.len() {
                if may_hop(s, q, b) && follows(s, q, last, b) && !seen.contains(&s.edges[b].dst) {
                    chain.push(b);
                    seen.push(s.edges[b].dst);
                    walk(s, q, chain, seen, out);
                    seen.pop();
                    chain.pop();
                }
            }
        }
        let mut out = HashMap::new();
        if q.origin == q.dest || q.max_hops == 0 {
            return out;
        }
        for a in 0..s.edges.len() {
            if s.edges[a].src == q.origin && may_hop(s, q, a) {
                walk(s, q, &mut vec![a], &mut vec![q.origin, s.edges[a].dst], &mut out);
            }
        }
        out
    }

    /// Every host a chain of logins reaches from the seed (or that reaches
    /// it), by trying every chain; a chain may pass a host twice.
    fn every_reach(s: &Store, q: &PathQuery, seed: u32, forward: bool) -> HashSet<u32> {
        let n = s.edges.len();
        let far = |i: usize| if forward { s.edges[i].dst } else { s.edges[i].src };
        let near = |i: usize| if forward { s.edges[i].src } else { s.edges[i].dst };
        let usable = |i: usize| may_hop(s, q, i) && far(i) != seed;
        let mut done = vec![false; n];
        let mut level: Vec<usize> = (0..n).filter(|&i| near(i) == seed && usable(i)).collect();
        let mut hosts: HashSet<u32> = HashSet::from([seed]);
        for _ in 0..q.max_hops {
            let mut after = Vec::new();
            for &a in &level {
                if std::mem::replace(&mut done[a], true) {
                    continue;
                }
                hosts.insert(far(a));
                for b in 0..n {
                    let chained = if forward { follows(s, q, a, b) } else { follows(s, q, b, a) };
                    if !done[b] && usable(b) && chained {
                        after.push(b);
                    }
                }
            }
            level = after;
        }
        hosts
    }

    /// The search against every chain there is, on timelines made by
    /// chance, with every option in every combination: the same paths, in
    /// order of length, and the same cones forward and back.
    #[test]
    fn the_search_finds_what_trying_every_chain_finds() {
        let mut checked = (0usize, 0usize, 0usize);
        // paths whose every hop the session before it is recorded to have made
        let mut made = 0usize;
        for seed in 0..60u64 {
            let (s, path) = chance_store(seed, "all");
            let h = |n: &str| s.hosts.get(n);
            let (Some(o), Some(d)) = (h("HA"), h("HD")) else {
                let _ = std::fs::remove_file(path);
                continue;
            };
            let ana: std::rc::Rc<Vec<bool>> = std::rc::Rc::new(s.edges.iter().map(|e| s.users.name(e.user).to_lowercase().starts_with("ana")).collect());
            let mid = (s.t_min + s.t_max) / 2;
            for combo in 0..(2 * 3 * 3 * 2 * 2 * 3 * 3 * 2) {
                let mut c = combo;
                let mut pick = |n: usize| -> usize {
                    let k = c % n;
                    c /= n;
                    k
                };
                let q = PathQuery {
                    origin: o,
                    dest: d,
                    skip_machine_accounts: pick(2) == 0,
                    results: [[true, false, false, false], [true, true, false, true], [true, true, true, true]][pick(3)],
                    max_hops: [1, 2, 5][pick(3)],
                    max_gap: [3600, 6 * 3600][pick(2)],
                    only: [None, Some(ana.clone())][pick(2)].clone(),
                    from: [None, Some(mid), Some(s.t_min + 3600)][pick(3)],
                    to: [None, Some(mid), Some(s.t_max - 3600)][pick(3)],
                    by_session: false,
                    gap_without_session: false,
                    launched: false,
                    max_paths: 100_000,
                };
                let chain = pick(2);
                for mode in 0..4 {
                    // the session modes on half the combinations (they share the rest)
                    if mode > 0 && chain == 0 {
                        continue;
                    }
                    let q = PathQuery { by_session: mode == 1 || mode == 2, gap_without_session: mode == 2, launched: mode == 3, ..q.clone() };
                    if mode == 3 {
                        made += every_route(&s, &q).len();
                    }
                    let want = every_route(&s, &q);
                    let (got, cut) = search(&s, &q);
                    assert!(!cut);
                    let got_routes: HashMap<Vec<(u32, u32, u32)>, usize> = got.iter().map(|p| (p.edges.iter().map(|&ei| { let e = &s.edges[ei as usize]; (e.src, e.dst, e.user) }).collect(), p.hops())).collect();
                    assert_eq!(got_routes.len(), got.len(), "seed {} combo {} mode {}: a route twice", seed, combo, mode);
                    assert_eq!(got_routes, want, "seed {} combo {} mode {}: {:?}", seed, combo, mode, q);
                    assert!(got.windows(2).all(|w| w[0].hops() <= w[1].hops()), "seed {} combo {}: not shortest first", seed, combo);
                    // every path found holds, hop by hop
                    for p in &got {
                        assert!(p.edges.iter().all(|&e| may_hop(&s, &q, e as usize)));
                        assert!(p.edges.windows(2).all(|w| follows(&s, &q, w[0] as usize, w[1] as usize)));
                    }
                    // a few of them: the shortest ones
                    if want.len() > 2 {
                        let few = find_paths(&s, &PathQuery { max_paths: 2, ..q.clone() });
                        let mut lens: Vec<usize> = want.values().copied().collect();
                        lens.sort();
                        assert_eq!(few.iter().map(|p| p.hops()).collect::<Vec<_>>(), lens[..2], "seed {} combo {} mode {}: the two shortest", seed, combo, mode);
                    }
                    checked.0 += 1;
                    checked.1 += want.len();
                    // the cones
                    for forward in [true, false] {
                        let seed_host = if forward { o } else { d };
                        let t0 = if forward { q.from.unwrap_or(i64::MIN) } else { q.to.unwrap_or(i64::MAX) };
                        let got: HashSet<u32> = cone(&s, seed_host, t0, &q, forward).0.keys().copied().collect();
                        let want = every_reach(&s, &q, seed_host, forward);
                        let names = |v: &HashSet<u32>| { let mut n: Vec<&str> = v.iter().map(|x| s.hosts.name(*x)).collect(); n.sort(); n.join(" ") };
                        assert_eq!(names(&got), names(&want), "seed {} combo {} mode {} forward {}: {:?}", seed, combo, mode, forward, q);
                        checked.2 += want.len() - 1;
                    }
                }
            }
            let _ = std::fs::remove_file(path);
        }
        println!("{} searches checked: {} paths, {} hosts in cones", checked.0, checked.1, checked.2);
        println!("{} of the paths with every hop made by the session before it", made);
        assert!(checked.1 > 5_000 && checked.2 > 20_000 && made > 200, "{:?} {}", checked, made);
    }

    /// So many chains that a length is not walked to its end: the search
    /// says it was cut short; and a path that is there is still found
    /// among thousands of rows of the same logins, once.
    #[test]
    fn a_search_too_wide_says_it_was_cut_short() {
        let path = std::env::temp_dir().join(format!("masstin-wide-{}.csv", std::process::id()));
        let mut lines = vec![crate::csv_out::HEADER.to_string()];
        let stamp = |sec: u32| format!("2026-01-05T{:02}:{:02}:{:02}Z", sec / 3600, (sec / 60) % 60, sec % 60);
        for i in 0..1800u32 {
            lines.push(format!("{},B,SUCCESSFUL_LOGON,4624,3,ana,CORP,,10.0.0.1,,,0x{:x},,Security.evtx,,,,,", stamp(i), i + 1));
            lines.push(format!("{},C,SUCCESSFUL_LOGON,4624,3,ana,CORP,,B,,,0x{:x},,Security.evtx,,,,,", stamp(3000 + i), 9000 + i));
        }
        // D is entered from C, and E from nowhere that is reached
        lines.push(format!("{},D,SUCCESSFUL_LOGON,4624,3,ana,CORP,,C,,,0xfff1,,Security.evtx,,,,,", stamp(6000)));
        lines.push(format!("{},E,SUCCESSFUL_LOGON,4624,3,ana,CORP,,Z,,,0xfff2,,Security.evtx,,,,,", stamp(6100)));
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let s = Store::load(&[path.to_string_lossy().to_string()], 0.05).unwrap();
        let h = |n: &str| s.hosts.get(n).unwrap();
        // 1,800 x 1,800 chains reach C before any could go on to E
        let (found, cut) = search(&s, &PathQuery { origin: h("10.0.0.1"), dest: h("E"), ..Default::default() });
        assert!(found.is_empty() && cut);
        // to C in two hops: thousands of rows, one route, and nothing left unwalked
        let (found, cut) = search(&s, &PathQuery { origin: h("10.0.0.1"), dest: h("C"), max_hops: 2, ..Default::default() });
        assert_eq!((found.len(), found[0].hops(), cut), (1, 2, false));
        // to D, three hops: found, as one path
        let (found, _) = search(&s, &PathQuery { origin: h("10.0.0.1"), dest: h("D"), ..Default::default() });
        assert_eq!((found.len(), found[0].hops()), (1, 3));
        let _ = std::fs::remove_file(path);
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
