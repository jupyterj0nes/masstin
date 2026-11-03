//! What the viewer shows: the filter the analyst set, and the graph it
//! selects from the store (one drawn edge per origin, destination, account
//! and result; a pair of hosts with many accounts between them collapsed
//! into one edge that says how many).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::store::{Edge, Pattern, Store, H_BASELINE, H_CANDIDATE, H_HABITUAL, H_NOT_EVALUATED, H_SIGNIFICANT};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum View {
    /// the connections the hunt marked significant or candidate
    Findings,
    /// a host's neighbourhood, `hops` away
    Around,
    /// everything the other filters let through
    All,
}

/// The analyst's filter. Text fields hold what was typed; `compile`
/// turns them into patterns and times once per query.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Filter {
    pub view: View,
    pub around: String,
    pub hops: usize,
    pub host: String,
    pub user: String,
    pub logon_type: String,
    /// logon OK, logon FAILED, logoff, connect
    pub results: [bool; 4],
    /// none, significant, candidate, habitual, not evaluated, baseline
    pub hunt: [bool; 6],
    /// none, suspicious, confirmed, benign
    pub verdict: [bool; 4],
    pub from: String,
    pub to: String,
    pub limit: usize,
}

impl Default for Filter {
    fn default() -> Self {
        Filter {
            view: View::Findings,
            around: String::new(),
            hops: 1,
            host: String::new(),
            user: String::new(),
            logon_type: String::new(),
            results: [true, true, false, true],
            hunt: [true; 6],
            verdict: [true; 4],
            from: String::new(),
            to: String::new(),
            limit: 600,
        }
    }
}

/// `2026-01-05 10:00:00`, `2026-01-05T10:00`, `2026-01-05` -> epoch seconds.
pub fn parse_time(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let mut t = s.replacen(' ', "T", 1);
    if t.len() == 10 {
        t.push_str("T00:00:00");
    } else if t.len() == 16 {
        t.push_str(":00");
    }
    crate::graph_hunt_common::parse_ts(&t).map(|n| n.and_utc().timestamp())
}

pub fn fmt_time(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_default()
}

struct Compiled {
    hosts: Vec<Pattern>,
    users: Vec<Pattern>,
    logon_types: Vec<Pattern>,
    around: Vec<Pattern>,
    from: Option<i64>,
    to: Option<i64>,
}

impl Filter {
    fn compile(&self) -> Compiled {
        Compiled {
            hosts: Pattern::parse_list(&self.host),
            users: Pattern::parse_list(&self.user),
            logon_types: Pattern::parse_list(&self.logon_type),
            around: Pattern::parse_list(&self.around),
            from: parse_time(&self.from),
            to: parse_time(&self.to),
        }
    }

    fn keeps(&self, c: &Compiled, s: &Store, e: &Edge) -> bool {
        if !self.results[e.result as usize] {
            return false;
        }
        if self.view == View::Findings {
            if e.hunt != H_SIGNIFICANT && e.hunt != H_CANDIDATE {
                return false;
            }
        } else if !self.hunt[e.hunt as usize] {
            return false;
        }
        if !self.verdict[e.verdict as usize] {
            return false;
        }
        if !c.users.is_empty() && !Pattern::any(&c.users, s.users.name(e.user)) {
            return false;
        }
        if !c.logon_types.is_empty() && !Pattern::any(&c.logon_types, s.logon_types.name(e.logon_type)) {
            return false;
        }
        if !c.hosts.is_empty() {
            let hit = |h: u32| s.aliases[h as usize].iter().any(|a| Pattern::any(&c.hosts, a));
            if !hit(e.src) && !hit(e.dst) {
                return false;
            }
        }
        true
    }

    /// The store's edges the filter selects, in time order.
    pub fn select(&self, s: &Store) -> Vec<u32> {
        let c = self.compile();
        if self.view == View::Around {
            let seeds = s.hosts_matching(&c.around);
            let set = s.neighbourhood(&seeds, self.hops.max(1), c.from, c.to);
            s.edges_of(&set, c.from, c.to).into_iter().filter(|&ei| self.keeps(&c, s, &s.edges[ei as usize])).collect()
        } else {
            s.in_window(c.from, c.to).iter().copied().filter(|&ei| self.keeps(&c, s, &s.edges[ei as usize])).collect()
        }
    }
}

/// Order of attention of the hunt states: significant first.
pub fn hunt_rank(h: u8) -> u8 {
    match h {
        H_SIGNIFICANT => 0,
        H_CANDIDATE => 1,
        H_NOT_EVALUATED => 2,
        H_HABITUAL => 3,
        H_BASELINE => 4,
        _ => 5,
    }
}

/// A drawn edge: one connection, or the accounts between two hosts folded.
pub struct GEdge {
    pub src: u32,
    pub dst: u32,
    /// account id, or None when several accounts are folded into this edge
    pub user: Option<u32>,
    pub users: Vec<u32>,
    pub result: u8,
    pub count: u64,
    pub first: i64,
    pub last: i64,
    pub hunt: u8,
    pub hunt_q: f32,
    pub why: u32,
    pub verdicts: [u32; 4],
    pub logon_types: Vec<u32>,
    pub event_ids: Vec<u32>,
    pub src_is_ip: bool,
    /// the store edges behind it, in time order
    pub rows: Vec<u32>,
    /// index in `GraphView::events` of its first row (for the replay)
    pub first_event: usize,
}

impl GEdge {
    /// The verdict most rows carry, if any.
    pub fn verdict(&self) -> u8 {
        (1..4).filter(|&v| self.verdicts[v] > 0).max_by_key(|&v| self.verdicts[v]).map(|v| v as u8).unwrap_or(0)
    }
}

/// What a host looks like from its traffic, for the shapes by role.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// receives Kerberos ticket traffic (4768 / 4769 / 4770 / 4771)
    DomainController,
    /// an address outside the private ranges
    External,
    /// mostly a destination
    Server,
    /// mostly an origin
    Workstation,
    Other,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Role::DomainController => "domain controller",
            Role::External => "external address",
            Role::Server => "server",
            Role::Workstation => "workstation",
            Role::Other => "host",
        }
    }
}

/// Whether an address is outside RFC 1918 / link-local / loopback space.
pub fn is_public_ip(s: &str) -> bool {
    match s.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => !(v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])),
        Ok(std::net::IpAddr::V6(v6)) => !(v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80),
        Err(_) => false,
    }
}

pub struct GNode {
    pub host: u32,
    pub inn: u64,
    pub out: u64,
    pub hunt_rank: u8,
    pub first_event: usize,
    pub role: Role,
}

pub struct GraphView {
    pub nodes: Vec<GNode>,
    pub edges: Vec<GEdge>,
    pub node_of_host: HashMap<u32, usize>,
    /// every selected store edge, in time order
    pub events: Vec<u32>,
    /// drawn edge of each event
    pub edge_of_event: Vec<u32>,
    pub connections: usize,
    pub truncated: bool,
}

impl GraphView {
    pub fn empty() -> GraphView {
        GraphView { nodes: Vec::new(), edges: Vec::new(), node_of_host: HashMap::new(), events: Vec::new(), edge_of_event: Vec::new(), connections: 0, truncated: false }
    }

    /// Hosts with more than this many accounts between them are drawn as
    /// one edge.
    pub const FOLD_ABOVE: usize = 6;

    pub fn build(s: &Store, f: &Filter) -> GraphView {
        let selected = f.select(s);
        struct Agg {
            count: u64,
            first: i64,
            last: i64,
            hunt: u8,
            q: f32,
            why: u32,
            verdicts: [u32; 4],
            lts: HashSet<u32>,
            eids: HashSet<u32>,
            src_is_ip: bool,
            rows: Vec<u32>,
        }
        let mut agg: HashMap<(u32, u32, u32, u8), Agg> = HashMap::new();
        for &ei in &selected {
            let e = &s.edges[ei as usize];
            let a = agg.entry((e.src, e.dst, e.user, e.result)).or_insert(Agg { count: 0, first: e.t, last: e.t, hunt: e.hunt, q: e.hunt_q, why: e.why, verdicts: [0; 4], lts: HashSet::new(), eids: HashSet::new(), src_is_ip: e.src_is_ip, rows: Vec::new() });
            a.count += 1;
            a.first = a.first.min(e.t);
            a.last = a.last.max(e.t);
            if hunt_rank(e.hunt) < hunt_rank(a.hunt) || (e.hunt == a.hunt && e.hunt_q < a.q) {
                a.hunt = e.hunt;
                a.q = e.hunt_q;
                a.why = e.why;
            }
            a.verdicts[e.verdict as usize] += 1;
            a.lts.insert(e.logon_type);
            a.eids.insert(e.event_id);
            a.rows.push(ei);
        }
        let connections = agg.len();
        let mut list: Vec<((u32, u32, u32, u8), Agg)> = agg.into_iter().collect();
        list.sort_by(|a, b| hunt_rank(a.1.hunt).cmp(&hunt_rank(b.1.hunt)).then_with(|| b.1.count.cmp(&a.1.count)).then_with(|| a.1.first.cmp(&b.1.first)).then_with(|| a.0.cmp(&b.0)));
        let truncated = list.len() > f.limit;
        list.truncate(f.limit);
        // fold the accounts of a busy pair
        let mut by_pair: HashMap<(u32, u32, u8), Vec<usize>> = HashMap::new();
        for (i, ((src, dst, _, result), _)) in list.iter().enumerate() {
            by_pair.entry((*src, *dst, *result)).or_default().push(i);
        }
        let mut edges: Vec<GEdge> = Vec::new();
        let mut folded: HashSet<usize> = HashSet::new();
        let mut pairs: Vec<((u32, u32, u8), Vec<usize>)> = by_pair.into_iter().collect();
        pairs.sort_by_key(|(k, _)| *k);
        for ((src, dst, result), idx) in pairs {
            if idx.len() <= Self::FOLD_ABOVE {
                continue;
            }
            let mut g = GEdge { src, dst, user: None, users: Vec::new(), result, count: 0, first: i64::MAX, last: i64::MIN, hunt: 0, hunt_q: f32::NAN, why: 0, verdicts: [0; 4], logon_types: Vec::new(), event_ids: Vec::new(), src_is_ip: false, rows: Vec::new(), first_event: usize::MAX };
            let mut lts = HashSet::new();
            let mut eids = HashSet::new();
            let mut first = true;
            for &i in &idx {
                let ((_, _, user, _), a) = &list[i];
                folded.insert(i);
                g.users.push(*user);
                g.count += a.count;
                g.first = g.first.min(a.first);
                g.last = g.last.max(a.last);
                if first || hunt_rank(a.hunt) < hunt_rank(g.hunt) || (a.hunt == g.hunt && a.q < g.hunt_q) {
                    g.hunt = a.hunt;
                    g.hunt_q = a.q;
                    g.why = a.why;
                }
                first = false;
                for k in 0..4 {
                    g.verdicts[k] += a.verdicts[k];
                }
                lts.extend(a.lts.iter().copied());
                eids.extend(a.eids.iter().copied());
                g.src_is_ip |= a.src_is_ip;
                g.rows.extend(a.rows.iter().copied());
            }
            g.users.sort_by_key(|&u| s.users.name(u).to_uppercase());
            g.logon_types = lts.into_iter().collect();
            g.event_ids = eids.into_iter().collect();
            g.rows.sort_unstable_by_key(|&ei| (s.edges[ei as usize].t, ei));
            edges.push(g);
        }
        for (i, ((src, dst, user, result), a)) in list.into_iter().enumerate() {
            if folded.contains(&i) {
                continue;
            }
            edges.push(GEdge { src, dst, user: Some(user), users: vec![user], result, count: a.count, first: a.first, last: a.last, hunt: a.hunt, hunt_q: a.q, why: a.why, verdicts: a.verdicts, logon_types: a.lts.into_iter().collect(), event_ids: a.eids.into_iter().collect(), src_is_ip: a.src_is_ip, rows: a.rows, first_event: usize::MAX });
        }
        for g in &mut edges {
            g.logon_types.sort_by_key(|&i| s.logon_types.name(i).to_string());
            g.event_ids.sort_by_key(|&i| s.event_ids.name(i).to_string());
        }
        // the replay: every drawn row in time order, and which edge it belongs to
        let mut edge_of_row: HashMap<u32, u32> = HashMap::new();
        for (gi, g) in edges.iter().enumerate() {
            for &r in &g.rows {
                edge_of_row.insert(r, gi as u32);
            }
        }
        let mut events: Vec<u32> = edge_of_row.keys().copied().collect();
        events.sort_unstable_by_key(|&ei| (s.edges[ei as usize].t, ei));
        let edge_of_event: Vec<u32> = events.iter().map(|r| edge_of_row[r]).collect();
        for (k, &g) in edge_of_event.iter().enumerate() {
            let e = &mut edges[g as usize];
            if e.first_event == usize::MAX {
                e.first_event = k;
            }
        }
        // nodes
        let mut hosts: HashMap<u32, GNode> = HashMap::new();
        let mut kerberos: HashSet<u32> = HashSet::new();
        for g in &edges {
            let n = hosts.entry(g.src).or_insert(GNode { host: g.src, inn: 0, out: 0, hunt_rank: 255, first_event: usize::MAX, role: Role::Other });
            n.out += g.count;
            n.hunt_rank = n.hunt_rank.min(hunt_rank(g.hunt));
            n.first_event = n.first_event.min(g.first_event);
            let n = hosts.entry(g.dst).or_insert(GNode { host: g.dst, inn: 0, out: 0, hunt_rank: 255, first_event: usize::MAX, role: Role::Other });
            n.inn += g.count;
            n.hunt_rank = n.hunt_rank.min(hunt_rank(g.hunt));
            n.first_event = n.first_event.min(g.first_event);
            if g.event_ids.iter().any(|&k| matches!(s.event_ids.name(k), "4768" | "4769" | "4770" | "4771")) {
                kerberos.insert(g.dst);
            }
        }
        for n in hosts.values_mut() {
            let name = s.hosts.name(n.host);
            n.role = if kerberos.contains(&n.host) {
                Role::DomainController
            } else if is_public_ip(name) {
                Role::External
            } else if n.inn >= 5 && n.inn >= 3 * n.out {
                Role::Server
            } else if n.out > n.inn {
                Role::Workstation
            } else {
                Role::Other
            };
        }
        let mut nodes: Vec<GNode> = hosts.into_values().collect();
        nodes.sort_by_key(|n| n.host);
        let node_of_host: HashMap<u32, usize> = nodes.iter().enumerate().map(|(i, n)| (n.host, i)).collect();
        GraphView { nodes, edges, node_of_host, events, edge_of_event, connections, truncated }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csv_out;

    fn row(day: u32, hour: u32, src: &str, dst: &str, user: &str, et: &str, tail: &str) -> String {
        format!("2026-01-{:02}T{:02}:00:00Z,{},{},4624,3,{},CORP,,{},,,0x{},,Security.evtx{}", day, hour, dst, et, user, src, hour, tail)
    }

    fn store() -> (Store, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("masstin-query-{}.csv", std::process::id()));
        let mut lines = vec![csv_out::HEADER.to_string()];
        for d in 1..=3 {
            lines.push(row(d, 9, "10.0.0.5", "SRV01", "alice", "SUCCESSFUL_LOGON", ",habitual,1,nothing new,,"));
        }
        lines.push(row(4, 10, "10.0.0.9", "SRV01", "mallory", "SUCCESSFUL_LOGON", ",significant,1.000e-3,origin never seen before,,"));
        lines.push(row(4, 11, "SRV01", "WS02", "mallory", "FAILED_LOGON", ",candidate,2.000e-1,new,,"));
        for k in 0..8 {
            lines.push(row(4, 12, "10.0.0.9", "WS03", &format!("spray{}", k), "FAILED_LOGON", ",candidate,5.000e-1,spray,,"));
        }
        std::fs::write(&path, format!("{}
", lines.join("
"))).unwrap();
        (Store::load(&[path.to_string_lossy().to_string()], 0.05).unwrap(), path)
    }

    #[test]
    fn findings_neighbourhood_and_folding() {
        let (s, path) = store();
        let f = Filter::default();
        let g = GraphView::build(&s, &f);
        // findings: the significant login, the candidate failure, the spray folded into one edge
        assert_eq!(g.edges.len(), 3, "{:?}", g.edges.iter().map(|e| (e.src, e.dst, e.users.len())).collect::<Vec<_>>());
        let folded = g.edges.iter().find(|e| e.user.is_none()).expect("a folded edge");
        assert_eq!(folded.users.len(), 8);
        assert_eq!(folded.count, 8);
        assert_eq!(g.events.len(), 10);
        assert!(g.edges.iter().all(|e| e.first_event < g.events.len()));

        let mut all = Filter::default();
        all.view = View::All;
        let g = GraphView::build(&s, &all);
        assert_eq!(g.events.len(), 13);

        let mut around = Filter::default();
        around.view = View::Around;
        around.around = "WS02".into();
        around.hunt = [true; 6];
        let g = GraphView::build(&s, &around);
        assert_eq!(g.nodes.len(), 2);
        around.hops = 2;
        let g = GraphView::build(&s, &around);
        assert!(g.nodes.len() >= 3);

        let mut user = Filter::default();
        user.view = View::All;
        user.user = "mall*".into();
        let g = GraphView::build(&s, &user);
        assert_eq!(g.events.len(), 2);

        let mut window = Filter::default();
        window.view = View::All;
        window.from = "2026-01-04".into();
        window.to = "2026-01-04 10:30".into();
        let g = GraphView::build(&s, &window);
        assert_eq!(g.events.len(), 1);
        let _ = std::fs::remove_file(path);
    }
}
