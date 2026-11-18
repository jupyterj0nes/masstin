//! The timeline in memory, for the viewer.
//!
//! One `Edge` per CSV row that names an origin and a destination (the
//! same rule graph-hunt applies: a row without a usable source, or whose
//! origin is its destination, is counted and left out). Hosts are the
//! machines graph-hunt sees: upper-case short names, an IP folded into the
//! name the same-login test gives it. Everything the viewer filters on is
//! an interned integer; strings live once. Adjacency is a CSR per host
//! (edges out, edges in) with the edges of each host in time order, so a
//! host's activity in a window is a binary search.
//!
//! The CSV stays the truth: a mark (verdict, notes) updates the edge here
//! and rewrites the file's tail for that row; a file that changed on disk
//! under us is reloaded whole.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, Seek, SeekFrom, Write};
use std::path::Path;

use crate::csv_out::{self, Layout};
use crate::graph_hunt_common::engine::{ambiguous_short_names, base_prefix_len, clean_host, ip_names_for_csv, replace_file, row_key, short_name, split_csv_into};
use crate::graph_hunt_common::parse_ts;

pub const R_OK: u8 = 0;
pub const R_FAIL: u8 = 1;
pub const R_LOGOFF: u8 = 2;
pub const R_CONNECT: u8 = 3;
pub const RESULT_NAMES: [&str; 4] = ["logon OK", "logon FAILED", "logoff", "connect"];

pub const H_NONE: u8 = 0;
pub const H_SIGNIFICANT: u8 = 1;
pub const H_CANDIDATE: u8 = 2;
pub const H_HABITUAL: u8 = 3;
pub const H_NOT_EVALUATED: u8 = 4;
pub const H_BASELINE: u8 = 5;
pub const HUNT_NAMES: [&str; 6] = ["", csv_out::HUNT_SIGNIFICANT, csv_out::HUNT_CANDIDATE, csv_out::HUNT_HABITUAL, csv_out::HUNT_NOT_EVALUATED, csv_out::HUNT_BASELINE];

pub const V_NONE: u8 = 0;
pub const VERDICT_NAMES: [&str; 4] = ["", "suspicious", "confirmed", "benign"];

pub fn hunt_code(s: &str) -> u8 {
    HUNT_NAMES.iter().position(|n| *n == s).map(|i| i as u8).unwrap_or(H_NONE)
}

pub fn verdict_code(s: &str) -> u8 {
    VERDICT_NAMES.iter().position(|n| *n == s).map(|i| i as u8).unwrap_or(V_NONE)
}

/// What a row is for the graph. A Kerberos ticket (4768 a TGT, 4769 a
/// service ticket, 4770 a renewal) or an NTLM validation (4776) that
/// succeeded is an authentication AT the domain controller, not a logon
/// session ON it: the account proved who it is there, on its way to
/// somewhere else. It is a connection with no logon in it, whatever the
/// timeline calls it (timelines write it as a successful logon). A failed
/// one (4771, a 4768 / 4769 / 4776 with an error) stays a failure.
fn result_code(event_type: &str, event_id: &str) -> u8 {
    if event_type == "SUCCESSFUL_LOGON" && matches!(event_id, "4768" | "4769" | "4770" | "4776") {
        return R_CONNECT;
    }
    match event_type {
        "SUCCESSFUL_LOGON" => R_OK,
        "FAILED_LOGON" => R_FAIL,
        "LOGOFF" => R_LOGOFF,
        _ => R_CONNECT,
    }
}

/// A computer account, by its name: `WS01$`, with its domain or not
/// (`WS01$@CORP`).
pub fn is_machine_account(account: &str) -> bool {
    account.split('@').next().unwrap_or(account).ends_with('$')
}

#[derive(Default)]
pub struct Interner {
    map: HashMap<String, u32>,
    pub names: Vec<String>,
}

impl Interner {
    pub fn id(&mut self, s: &str) -> u32 {
        if let Some(&i) = self.map.get(s) {
            return i;
        }
        let i = self.names.len() as u32;
        self.map.insert(s.to_string(), i);
        self.names.push(s.to_string());
        i
    }
    pub fn get(&self, s: &str) -> Option<u32> {
        self.map.get(s).copied()
    }
    pub fn name(&self, i: u32) -> &str {
        &self.names[i as usize]
    }
    pub fn len(&self) -> usize {
        self.names.len()
    }
}

#[derive(Clone, Copy)]
pub struct Edge {
    pub t: i64,
    pub src: u32,
    pub dst: u32,
    pub user: u32,
    pub logon_type: u32,
    pub event_id: u32,
    pub why: u32,
    pub line: u32,
    /// `hunt_score`, 0 to 100; NaN when the row carries none
    pub score: f32,
    pub file: u16,
    pub result: u8,
    pub hunt: u8,
    pub verdict: u8,
    /// the row named the origin by address, not by name
    pub src_is_ip: bool,
}

/// Compressed adjacency: `items[offsets[h]..offsets[h+1]]` are the edge
/// indices of host `h`, in time order.
pub struct Csr {
    offsets: Vec<u32>,
    items: Vec<u32>,
}

impl Csr {
    fn build(n: usize, pairs: impl Iterator<Item = (u32, u32)>, edges: &[Edge]) -> Csr {
        let mut pairs: Vec<(u32, u32)> = pairs.collect();
        pairs.sort_unstable_by_key(|(h, e)| (*h, edges[*e as usize].t, *e));
        let mut offsets = vec![0u32; n + 1];
        for (h, _) in &pairs {
            offsets[*h as usize + 1] += 1;
        }
        for i in 0..n {
            offsets[i + 1] += offsets[i];
        }
        Csr { offsets, items: pairs.into_iter().map(|(_, e)| e).collect() }
    }
    pub fn of(&self, h: u32) -> &[u32] {
        let a = self.offsets[h as usize] as usize;
        let b = self.offsets[h as usize + 1] as usize;
        &self.items[a..b]
    }
}

pub struct FileInfo {
    pub path: String,
    pub layout: Layout,
    pub rows: usize,
    pub len: u64,
    pub mtime: Option<std::time::SystemTime>,
    /// byte offset of every data line (index 0 = first row after the header)
    offsets: Vec<u64>,
    /// first and one-past-last edge index of this file in `edges`
    edge_range: (u32, u32),
}

pub struct Store {
    pub files: Vec<FileInfo>,
    pub hosts: Interner,
    /// raw names folded into each host (its own name included)
    pub aliases: Vec<Vec<String>>,
    pub users: Interner,
    pub logon_types: Interner,
    pub event_ids: Interner,
    pub whys: Interner,
    /// in file order, lines ascending within a file
    pub edges: Vec<Edge>,
    /// edge indices by time
    pub by_time: Vec<u32>,
    pub out_adj: Csr,
    pub in_adj: Csr,
    pub notes: HashMap<(u16, u32), String>,
    pub rows_total: usize,
    pub rows_without_origin: usize,
    pub rows_bad_time: usize,
    pub t_min: i64,
    pub t_max: i64,
    /// per edge: the seconds the session that logon opened lasted (its
    /// logoff on the same host with the same logon ID, the first after it);
    /// `u32::MAX` when the timeline does not say
    session: Vec<u32>,
    /// successful logons, and how many of them have their session
    pub logons: usize,
    pub sessions_known: usize,
    /// per edge: its logon ID as a number to pair by (0: none)
    lid: Vec<u64>,
    /// what a session did on the network, by the source's own record of
    /// it (a Windows 4648, an auditd `connect`): (the host the session is
    /// on, its logon ID) -> (time, destination), in time order
    launched: HashMap<(u32, u64), Vec<(i64, u32)>>,
    /// the same records by where they go: (origin, destination) ->
    /// (time, the logon ID of the session), in time order
    launch_at: HashMap<(u32, u32), Vec<(i64, u64)>>,
    /// how many such records the timeline has
    pub launches: usize,
    /// per account: a number for its bare name (`ana` of `ana@CORP`,
    /// `CORP\ana`, `Ana@WS01`), so the same person's accounts are told to
    /// be one along a chain
    user_keys: Vec<u32>,
}

/// The name of an account without its domain or machine, in lower case:
/// `ana` for `ana@CORP`, `CORP\ana`, `Ana`.
pub fn bare_account(account: &str) -> String {
    let a = account.trim();
    let a = a.rsplit('\\').next().unwrap_or(a);
    a.split('@').next().unwrap_or(a).to_lowercase()
}

/// A row written from the ORIGIN of a connection, whose logon ID is the
/// one of the session on the origin that made it: a Windows 4648 (explicit
/// credentials used by a process of that session) and an auditd `connect`
/// record of a login session.
fn is_launch_record(event_id: &str) -> bool {
    matches!(event_id, "4648" | "AUDIT_CONNECT")
}

/// A logon ID as a number to pair by; 0 when the row has none.
fn logon_id_key(cell: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let t = cell.trim();
    let digits = t.trim_start_matches("0x").trim_start_matches("0X").trim_start_matches('0');
    if t.is_empty() || t == "-" || digits.is_empty() {
        return 0;
    }
    let mut h = std::collections::hash_map::DefaultHasher::new();
    t.to_ascii_lowercase().hash(&mut h);
    h.finish() | 1
}

impl Store {
    /// Read the timelines. `alpha` is the false discovery rate of the
    /// IP -> name test (the one graph-hunt and the loaders use).
    pub fn load(paths: &[String], alpha: f64) -> std::io::Result<Store> {
        Self::load_with(paths, alpha, &[])
    }

    /// The same, with the analyst's merges: each `(from, into)` makes
    /// `from` part of `into` (after the hunt's own address folding), chains
    /// followed to their end.
    pub fn load_with(paths: &[String], alpha: f64, merges: &[(String, String)]) -> std::io::Result<Store> {
        let ambiguous = ambiguous_short_names(paths)?;
        let resolved: HashMap<String, (String, u32, f64)> = ip_names_for_csv(paths, alpha).unwrap_or_default();
        let mut manual: HashMap<String, String> = merges.iter().map(|(f, i)| (f.trim().to_uppercase(), i.trim().to_uppercase())).filter(|(f, i)| !f.is_empty() && !i.is_empty() && f != i).collect();
        // follow chains: A -> B, B -> C gives A -> C
        for _ in 0..16 {
            let mut changed = false;
            let snapshot = manual.clone();
            for (_, into) in manual.iter_mut() {
                if let Some(next) = snapshot.get(into) {
                    if next != into {
                        *into = next.clone();
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        let mut hosts = Interner::default();
        let mut aliases: Vec<Vec<String>> = Vec::new();
        // `full`: the name as the file writes it (`SRV01.corp.example`), so the
        // host answers to it too wherever a host is named (a search, a
        // neighbourhood, `--focus`); empty when the row gives none
        // the host a raw name is, by its label
        let label_of = |raw: &str| -> String {
            let label = resolved.get(raw).map(|r| r.0.as_str()).unwrap_or(raw);
            // a machine account named as a computer (`PTR-SRV01$`) is that computer
            let label = label.strip_suffix('$').filter(|l| !l.is_empty()).unwrap_or(label);
            manual.get(&label.to_uppercase()).map(String::as_str).unwrap_or(label).to_string()
        };
        let mut host_of = |raw: &str, full: &str, hosts: &mut Interner| -> u32 {
            let label = label_of(raw);
            let label = label.as_str();
            let id = hosts.id(label);
            if aliases.len() <= id as usize {
                aliases.push(vec![label.to_string()]);
            }
            if !aliases[id as usize].iter().any(|a| a == raw) {
                aliases[id as usize].push(raw.to_string());
            }
            if !full.is_empty() && !aliases[id as usize].iter().any(|a| a.eq_ignore_ascii_case(full)) {
                aliases[id as usize].push(full.to_string());
            }
            id
        };
        let mut users = Interner::default();
        // An account is its name and its domain (graph_hunt_common::account):
        // the Administrator of a domain is not the local one of a machine,
        // and `Administrator@PARTNER.TEST` is the one of PARTNER. In any
        // case; shown as first written, `Administrator@PARTNER`.
        let mut user_of: HashMap<String, u32> = HashMap::new();
        let mut logon_types = Interner::default();
        let mut event_ids = Interner::default();
        let mut whys = Interner::default();
        whys.id("");
        let mut edges: Vec<Edge> = Vec::new();
        // the logon ID of each edge, and every logoff that carries one (most
        // have no origin and are no edge): (host label, logon ID, time)
        let mut edge_lid: Vec<u64> = Vec::new();
        let mut logoff_hosts = Interner::default();
        let mut logoffs: Vec<(u32, u64, i64)> = Vec::new();
        let mut notes = HashMap::new();
        let mut files = Vec::new();
        let (mut rows_total, mut rows_without_origin, mut rows_bad_time) = (0usize, 0usize, 0usize);
        for (fi, path) in paths.iter().enumerate() {
            let meta = std::fs::metadata(path)?;
            let mut rd = std::io::BufReader::with_capacity(1 << 20, std::fs::File::open(path)?);
            let mut header = String::new();
            rd.read_line(&mut header)?;
            let layout = Layout::of(&header).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}: not a masstin timeline", path)))?;
            let idx = layout.base_indices();
            let header_has_q = csv_out::header_has_q(&header);
            let first_edge = edges.len() as u32;
            let mut offsets: Vec<u64> = Vec::new();
            let mut pos = header.len() as u64;
            let mut line = String::new();
            let mut rows = 0usize;
            loop {
                let n = csv_out::read_record(&mut rd, &mut line)?;
                if n == 0 {
                    break;
                }
                let at = pos;
                pos += n as u64;
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    continue;
                }
                let line_no = offsets.len() as u32;
                offsets.push(at);
                rows += 1;
                rows_total += 1;
                let mut p: Vec<Cow<str>> = Vec::with_capacity(20);
                split_csv_into(trimmed, &mut p);
                let b: Vec<Cow<str>> = idx.iter().map(|i| i.and_then(|i| p.get(i)).cloned().unwrap_or(Cow::Borrowed(""))).collect();
                if b.len() < 14 || p.len() < layout.columns().min(12) {
                    rows_without_origin += 1;
                    continue;
                }
                let t = match parse_ts(&b[0]) {
                    Some(x) => x.and_utc().timestamp(),
                    None => {
                        rows_bad_time += 1;
                        continue;
                    }
                };
                let lid = logon_id_key(&b[11]);
                if lid != 0 && result_code(b[2].trim(), b[3].trim()) == R_LOGOFF {
                    let host = short_name(&clean_host(&b[1]), &ambiguous);
                    if !host.is_empty() {
                        logoffs.push((logoff_hosts.id(&label_of(&host)), lid, t));
                    }
                }
                let (origin, dest, _acct, _cls) = match row_key(&b, &ambiguous) {
                    Some(k) => k,
                    None => {
                        rows_without_origin += 1;
                        continue;
                    }
                };
                let sc = b[7].trim();
                let src_is_ip = sc.is_empty() || sc == "-" || crate::load_neo4j::looks_like_ip(sc);
                // the fully qualified name of each end, when the row has one
                // and it is the name the end was keyed by
                let full_of = |cell: &str, keyed: &str| -> String {
                    let c = clean_host(cell).to_uppercase();
                    if c.contains('.') && c.parse::<std::net::IpAddr>().is_err() && short_name(&c, &ambiguous) == keyed { c } else { String::new() }
                };
                let src = host_of(&origin, &full_of(&b[7], &origin), &mut hosts);
                let dst = host_of(&dest, &full_of(&b[1], &dest), &mut hosts);
                let (hunt, score, why, verdict) = if layout == Layout::V19 && p.len() >= 19 {
                    let h = hunt_code(p[14].trim());
                    let q: f32 = csv_out::score_of_text(&p[15], header_has_q).map(|s| s as f32).unwrap_or(f32::NAN);
                    let w = whys.id(p[16].trim());
                    let v = verdict_code(p[17].trim());
                    let n = p[18].trim();
                    if !n.is_empty() {
                        notes.insert((fi as u16, line_no), n.to_string());
                    }
                    (h, q, w, v)
                } else {
                    (H_NONE, f32::NAN, 0, V_NONE)
                };
                edge_lid.push(lid);
                edges.push(Edge {
                    t,
                    src,
                    dst,
                    user: {
                        let shown = crate::graph_hunt_common::account::account_shown(&b[5], &b[6], &dest);
                        match user_of.get(&shown.to_lowercase()) {
                            Some(&u) => u,
                            None => {
                                let u = users.id(&shown);
                                user_of.insert(shown.to_lowercase(), u);
                                u
                            }
                        }
                    },
                    logon_type: logon_types.id(b[4].trim()),
                    event_id: event_ids.id(b[3].trim()),
                    why,
                    line: line_no,
                    score,
                    file: fi as u16,
                    result: result_code(b[2].trim(), b[3].trim()),
                    hunt,
                    verdict,
                    src_is_ip,
                });
            }
            files.push(FileInfo { path: path.clone(), layout, rows, len: meta.len(), mtime: meta.modified().ok(), offsets, edge_range: (first_edge, edges.len() as u32) });
        }
        let mut by_time: Vec<u32> = (0..edges.len() as u32).collect();
        by_time.sort_unstable_by_key(|&i| (edges[i as usize].t, i));
        let n = hosts.len();
        let out_adj = Csr::build(n, edges.iter().enumerate().map(|(i, e)| (e.src, i as u32)), &edges);
        let in_adj = Csr::build(n, edges.iter().enumerate().map(|(i, e)| (e.dst, i as u32)), &edges);
        let t_min = by_time.first().map(|&i| edges[i as usize].t).unwrap_or(0);
        let t_max = by_time.last().map(|&i| edges[i as usize].t).unwrap_or(0);
        // each logon's session: its logoff is the first one after it on the
        // same host with the same logon ID
        let host_id: Vec<Option<u32>> = logoff_hosts.names.iter().map(|n| hosts.get(n)).collect();
        let mut ends: Vec<(u32, u64, i64)> = logoffs.into_iter().filter_map(|(h, id, t)| host_id[h as usize].map(|h| (h, id, t))).collect();
        ends.sort_unstable();
        let mut session = vec![u32::MAX; edges.len()];
        let (mut logons, mut sessions_known) = (0usize, 0usize);
        for (i, e) in edges.iter().enumerate() {
            if e.result != R_OK {
                continue;
            }
            logons += 1;
            let id = edge_lid[i];
            if id == 0 {
                continue;
            }
            let k = ends.partition_point(|x| *x < (e.dst, id, e.t));
            if let Some(&(h, l, end)) = ends.get(k) {
                if h == e.dst && l == id {
                    session[i] = (end - e.t).clamp(0, u32::MAX as i64 - 1) as u32;
                    sessions_known += 1;
                }
            }
        }
        // what each session is recorded to have connected to
        let mut launched: HashMap<(u32, u64), Vec<(i64, u32)>> = HashMap::new();
        let mut launches = 0usize;
        for (i, e) in edges.iter().enumerate() {
            if edge_lid[i] != 0 && e.src != e.dst && is_launch_record(event_ids.name(e.event_id)) {
                launched.entry((e.src, edge_lid[i])).or_default().push((e.t, e.dst));
                launches += 1;
            }
        }
        for v in launched.values_mut() {
            v.sort_unstable();
        }
        let mut launch_at: HashMap<(u32, u32), Vec<(i64, u64)>> = HashMap::new();
        for ((src, id), records) in &launched {
            for &(t, dst) in records {
                launch_at.entry((*src, dst)).or_default().push((t, *id));
            }
        }
        for v in launch_at.values_mut() {
            v.sort_unstable();
        }
        let mut bare = Interner::default();
        let user_keys: Vec<u32> = users.names.iter().map(|n| bare.id(&bare_account(n))).collect();
        Ok(Store { files, hosts, aliases, users, logon_types, event_ids, whys, edges, by_time, out_adj, in_adj, notes, rows_total, rows_without_origin, rows_bad_time, t_min, t_max, session, logons, sessions_known, lid: edge_lid, launched, launch_at, launches, user_keys })
    }

    /// The number of an account's bare name: equal for the accounts of one
    /// name, whatever their domain or machine.
    pub fn user_key(&self, user: u32) -> u32 {
        self.user_keys.get(user as usize).copied().unwrap_or(u32::MAX)
    }

    /// The logon ID of an edge, as the number it is paired by (0: none).
    pub fn logon_key(&self, edge: u32) -> u64 {
        self.lid.get(edge as usize).copied().unwrap_or(0)
    }

    /// Whether the hop `next` (out of the host that `into` entered) was
    /// made by the session `into` opened, by that host's own record of it:
    /// a 4648 or an auditd `connect` with the logon ID of `into`, to the
    /// host `next` enters, at the moment of `next` (the record is written
    /// as the connection is made: up to five minutes before the logon it
    /// ends in, for a password typed by hand, and never after it but for
    /// the clocks of two machines), and inside the session.
    /// What the session `into` opened is recorded to have connected to,
    /// by the host it is on: (time, destination), in time order.
    pub fn launches_of(&self, into: u32) -> &[(i64, u32)] {
        let id = self.logon_key(into);
        if id == 0 {
            return &[];
        }
        self.launched.get(&(self.edges[into as usize].dst, id)).map_or(&[], |v| v.as_slice())
    }

    /// The logon IDs of the sessions on the origin of `next` that are
    /// recorded to have connected to where it goes, when it goes.
    pub fn launchers_of(&self, next: u32) -> Vec<u64> {
        let e = &self.edges[next as usize];
        let Some(records) = self.launch_at.get(&(e.src, e.dst)) else { return Vec::new() };
        let from = records.partition_point(|r| r.0 < e.t - 300);
        records[from..].iter().take_while(|r| r.0 <= e.t + 5).map(|r| r.1).collect()
    }

    pub fn launched_by(&self, into: u32, next: u32) -> bool {
        let (a, b) = (&self.edges[into as usize], &self.edges[next as usize]);
        let id = self.logon_key(into);
        if id == 0 || b.src != a.dst {
            return false;
        }
        let Some(records) = self.launched.get(&(a.dst, id)) else { return false };
        let end = self.session_of(into).map_or(i64::MAX, |d| a.t.saturating_add(d).saturating_add(5));
        records.iter().any(|&(t, dst)| dst == b.dst && t >= a.t && t <= end && b.t >= t - 5 && b.t <= t + 300)
    }

    /// How long the session a logon opened lasted, in seconds, when the
    /// timeline has its logoff (paired by logon ID on the host logged on to).
    pub fn session_of(&self, edge: u32) -> Option<i64> {
        self.session.get(edge as usize).filter(|d| **d != u32::MAX).map(|d| *d as i64)
    }

    /// Whether a file changed on disk since it was read (or written here).
    pub fn changed(&self) -> bool {
        self.files.iter().any(|f| match std::fs::metadata(&f.path) {
            Ok(m) => m.len() != f.len || m.modified().ok() != f.mtime,
            Err(_) => true,
        })
    }

    /// Edge indices with `t` in [from, to], in time order.
    pub fn in_window(&self, from: Option<i64>, to: Option<i64>) -> &[u32] {
        let lo = match from {
            Some(f) => self.by_time.partition_point(|&i| self.edges[i as usize].t < f),
            None => 0,
        };
        let hi = match to {
            Some(t) => self.by_time.partition_point(|&i| self.edges[i as usize].t <= t),
            None => self.by_time.len(),
        };
        &self.by_time[lo..hi.max(lo)]
    }

    /// Hosts within `hops` of `seeds`, following edges in both directions
    /// (edges outside [from, to] are not followed).
    pub fn neighbourhood(&self, seeds: &[u32], hops: usize, from: Option<i64>, to: Option<i64>) -> HashSet<u32> {
        let mut seen: HashSet<u32> = seeds.iter().copied().collect();
        let mut queue: VecDeque<(u32, usize)> = seeds.iter().map(|&s| (s, 0)).collect();
        let inside = |e: &Edge| from.map_or(true, |f| e.t >= f) && to.map_or(true, |t| e.t <= t);
        while let Some((h, d)) = queue.pop_front() {
            if d >= hops {
                continue;
            }
            for &ei in self.out_adj.of(h).iter().chain(self.in_adj.of(h).iter()) {
                let e = &self.edges[ei as usize];
                if !inside(e) {
                    continue;
                }
                for other in [e.src, e.dst] {
                    if seen.insert(other) {
                        queue.push_back((other, d + 1));
                    }
                }
            }
        }
        seen
    }

    /// Edge indices between hosts of `set` (both ends in it), in time
    /// order, within the window.
    pub fn edges_of(&self, set: &HashSet<u32>, from: Option<i64>, to: Option<i64>) -> Vec<u32> {
        let mut v: Vec<u32> = Vec::new();
        for &h in set {
            v.extend(self.out_adj.of(h).iter().copied());
            v.extend(self.in_adj.of(h).iter().copied());
        }
        v.sort_unstable();
        v.dedup();
        v.retain(|&ei| {
            let e = &self.edges[ei as usize];
            set.contains(&e.src) && set.contains(&e.dst) && from.map_or(true, |f| e.t >= f) && to.map_or(true, |t| e.t <= t)
        });
        v.sort_unstable_by_key(|&ei| (self.edges[ei as usize].t, ei));
        v
    }

    /// Hosts whose name or any alias matches the patterns.
    pub fn hosts_matching(&self, pats: &[Pattern]) -> Vec<u32> {
        (0..self.hosts.len() as u32).filter(|&h| self.aliases[h as usize].iter().any(|a| Pattern::any(pats, a))).collect()
    }

    /// The edge of a file row, if the row is one.
    pub fn edge_at(&self, file: u16, line: u32) -> Option<usize> {
        let (a, b) = self.files.get(file as usize)?.edge_range;
        let slice = &self.edges[a as usize..b as usize];
        let k = slice.partition_point(|e| e.line < line);
        if k < slice.len() && slice[k].line == line {
            Some(a as usize + k)
        } else {
            None
        }
    }

    /// How many data rows a file has (every row, with an origin or not).
    pub fn file_rows(&self, file: u16) -> usize {
        self.files.get(file as usize).map_or(0, |f| f.offsets.len())
    }

    /// A row as the file has it, in the 19 columns of `csv_out::HEADER`:
    /// the 14 event columns and the hunt's and the analyst's tail (empty
    /// when the file has none; an older layout is laid out as 19).
    pub fn raw_row(&self, file: u16, line: u32) -> std::io::Result<Vec<String>> {
        let f = self.files.get(file as usize).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"))?;
        let at = *f.offsets.get(line as usize).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such row"))?;
        let mut fh = std::fs::File::open(&f.path)?;
        fh.seek(SeekFrom::Start(at))?;
        let mut rd = std::io::BufReader::new(fh);
        let mut text = String::new();
        csv_out::read_record(&mut rd, &mut text)?;
        let trimmed = text.trim_end_matches(['\r', '\n']);
        let mut p: Vec<Cow<str>> = Vec::with_capacity(20);
        split_csv_into(trimmed, &mut p);
        let fields: Vec<&str> = p.iter().map(|c| c.as_ref()).collect();
        Ok(f.layout.to_v19(&fields))
    }

    /// What the rows of a file say of a hunt it carries: rows with a hunt
    /// state, those significant, the last day with `baseline` rows and the
    /// first with judged ones (`YYYY-MM-DD`). None when no row has a state.
    /// Read from the rows already loaded (those with an origin).
    pub fn hunt_of_file(&self, file: u16) -> Option<(u64, u64, String, String)> {
        let (a, b) = self.files.get(file as usize)?.edge_range;
        let (mut n, mut sig) = (0u64, 0u64);
        let (mut last_base, mut first_judged): (Option<i64>, Option<i64>) = (None, None);
        for e in &self.edges[a as usize..b as usize] {
            if e.hunt == H_NONE {
                continue;
            }
            n += 1;
            if e.hunt == H_BASELINE {
                last_base = Some(last_base.map_or(e.t, |x: i64| x.max(e.t)));
            } else {
                if e.hunt == H_SIGNIFICANT {
                    sig += 1;
                }
                first_judged = Some(first_judged.map_or(e.t, |x: i64| x.min(e.t)));
            }
        }
        if n == 0 {
            return None;
        }
        let day = |t: Option<i64>| t.and_then(|t| chrono::DateTime::from_timestamp(t, 0)).map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default();
        Some((n, sig, day(last_base), day(first_judged)))
    }

    /// The header line of a file, as written (no line end).
    pub fn header_text(&self, file: u16) -> std::io::Result<String> {
        let f = self.files.get(file as usize).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"))?;
        let mut rd = std::io::BufReader::new(std::fs::File::open(&f.path)?);
        let mut text = String::new();
        csv_out::read_record(&mut rd, &mut text)?;
        Ok(text.trim_end_matches(['\r', '\n']).to_string())
    }

    /// These rows of a file exactly as it has them (no line end), in the
    /// order asked: the file is opened once.
    pub fn raw_texts(&self, file: u16, lines: &[u32]) -> std::io::Result<Vec<String>> {
        let f = self.files.get(file as usize).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"))?;
        let mut rd = std::io::BufReader::new(std::fs::File::open(&f.path)?);
        let mut out = Vec::with_capacity(lines.len());
        let mut text = String::new();
        for line in lines {
            let at = *f.offsets.get(*line as usize).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such row"))?;
            rd.seek(SeekFrom::Start(at))?;
            text.clear();
            csv_out::read_record(&mut rd, &mut text)?;
            out.push(text.trim_end_matches(['\r', '\n']).to_string());
        }
        Ok(out)
    }

    /// The rows of a file whose text `keep` accepts, in the file's order:
    /// the whole file is read once.
    pub fn file_rows_where(&self, file: u16, keep: &dyn Fn(&str) -> bool) -> std::io::Result<Vec<u32>> {
        let f = self.files.get(file as usize).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"))?;
        let rd = std::io::BufReader::new(std::fs::File::open(&f.path)?);
        let mut out = Vec::new();
        // line 0 of the file is the header: data row k is file line k + 1
        for (k, line) in csv_out::records(rd).enumerate().skip(1) {
            if keep(line?.trim_end_matches(['\r', '\n'])) {
                out.push((k - 1) as u32);
            }
        }
        Ok(out)
    }

    /// The rows of a file whose text holds `needle` (any case), in the
    /// file's order: the whole file is read once.
    pub fn file_rows_matching(&self, file: u16, needle: &str) -> std::io::Result<Vec<u32>> {
        let f = self.files.get(file as usize).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"))?;
        let needle = needle.to_lowercase();
        let rd = std::io::BufReader::new(std::fs::File::open(&f.path)?);
        let mut out = Vec::new();
        // line 0 of the file is the header: data row k is file line k + 1
        for (k, line) in csv_out::records(rd).enumerate().skip(1) {
            if line?.to_lowercase().contains(&needle) {
                out.push((k - 1) as u32);
            }
        }
        Ok(out)
    }

    /// The 14 event columns of a row, read from the file.
    pub fn row_fields(&self, file: u16, line: u32) -> std::io::Result<Vec<String>> {
        let f = self.files.get(file as usize).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"))?;
        let at = *f.offsets.get(line as usize).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such row"))?;
        let mut fh = std::fs::File::open(&f.path)?;
        fh.seek(SeekFrom::Start(at))?;
        let mut rd = std::io::BufReader::new(fh);
        let mut line = String::new();
        csv_out::read_record(&mut rd, &mut line)?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let mut p: Vec<Cow<str>> = Vec::with_capacity(20);
        split_csv_into(trimmed, &mut p);
        let idx = f.layout.base_indices();
        Ok(idx.iter().map(|i| i.and_then(|i| p.get(i)).map(|s| s.to_string()).unwrap_or_default()).collect())
    }

    /// Write a verdict and notes on these rows: the edges here and the
    /// files' tails. Returns how many rows were written.
    pub fn mark(&mut self, rows: &[(u16, u32)], verdict: u8, notes: &str) -> std::io::Result<usize> {
        // The files first, the store after: a file that cannot be written
        // (open in Excel, a share that went away) leaves the store as it
        // was, so the window never shows a mark the timeline does not hold.
        let mut per_file: HashMap<u16, HashSet<u32>> = HashMap::new();
        let mut marked: Vec<(usize, u16, u32)> = Vec::new();
        for &(f, l) in rows {
            if let Some(ei) = self.edge_at(f, l) {
                marked.push((ei, f, l));
                per_file.entry(f).or_default().insert(l);
            }
        }
        let mut written = 0usize;
        let verdict_name = VERDICT_NAMES[verdict as usize];
        for (fi, lines) in per_file {
            let path = self.files[fi as usize].path.clone();
            // a name of this process: a hunt writing the same timeline at
            // the same moment has its own
            let tmp = Path::new(&path).with_extension(format!("csv.masstin-tmp-{}", std::process::id()));
            let mut new_offsets: Vec<u64> = Vec::with_capacity(self.files[fi as usize].offsets.len());
            {
                let mut rd = std::io::BufReader::with_capacity(1 << 20, std::fs::File::open(&path)?);
                let mut w = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&tmp)?);
                let mut header = String::new();
                rd.read_line(&mut header)?;
                let layout = Layout::of(&header).unwrap_or(Layout::V14);
                let header_has_q = csv_out::header_has_q(&header);
                w.write_all(csv_out::HEADER.as_bytes())?;
                w.write_all(b"\n")?;
                let mut pos: u64 = csv_out::HEADER.len() as u64 + 1;
                let mut buf = String::new();
                let mut line_no: u32 = 0;
                loop {
                    if csv_out::read_record(&mut rd, &mut buf)? == 0 {
                        break;
                    }
                    let line = buf.trim_end_matches(['\r', '\n']);
                    if line.is_empty() {
                        continue;
                    }
                    new_offsets.push(pos);
                    let out: String = if layout == Layout::V19 {
                        match base_prefix_len(line) {
                            Some(k) => {
                                let mut p: Vec<Cow<str>> = Vec::with_capacity(20);
                                split_csv_into(line, &mut p);
                                let g = |i: usize| p.get(i).map(|s| s.to_string()).unwrap_or_default();
                                let (v, n) = if lines.contains(&line_no) {
                                    (verdict_name.to_string(), notes.to_string())
                                } else {
                                    (g(17), g(18))
                                };
                                let score = if header_has_q { csv_out::score_of_text(&g(15), true).map(|s| s.to_string()).unwrap_or_default() } else { g(15) };
                                format!("{}{}", &line[..k], csv_out::tail(&g(14), &score, &g(16), &v, &n))
                            }
                            None => line.to_string(),
                        }
                    } else {
                        let mut p: Vec<Cow<str>> = Vec::with_capacity(20);
                        split_csv_into(line, &mut p);
                        let base: Vec<String> = layout.to_v19(&p.iter().map(|s| s.as_ref()).collect::<Vec<&str>>())[..14].iter().map(|s| csv_out::q(s)).collect();
                        let (v, n) = if lines.contains(&line_no) { (verdict_name, notes) } else { ("", "") };
                        format!("{}{}", base.join(","), csv_out::tail("", "", "", v, n))
                    };
                    w.write_all(out.as_bytes())?;
                    w.write_all(b"\n")?;
                    pos += out.len() as u64 + 1;
                    line_no += 1;
                }
                w.flush()?;
            }
            replace_file(&tmp, Path::new(&path))?;
            let meta = std::fs::metadata(&path)?;
            let f = &mut self.files[fi as usize];
            f.len = meta.len();
            f.mtime = meta.modified().ok();
            f.layout = Layout::V19;
            f.offsets = new_offsets;
            written += lines.len();
        }
        for (ei, f, l) in marked {
            self.edges[ei].verdict = verdict;
            if notes.is_empty() {
                self.notes.remove(&(f, l));
            } else {
                self.notes.insert((f, l), notes.to_string());
            }
        }
        Ok(written)
    }
}

/// A host / user pattern: `*` wildcards, case-insensitive, `!` negates.
/// Several patterns: any positive one matches and no negative one does.
pub struct Pattern {
    negate: bool,
    parts: Vec<String>,
    anchored_start: bool,
    anchored_end: bool,
}

impl Pattern {
    pub fn parse_list(s: &str) -> Vec<Pattern> {
        s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).map(Pattern::parse).collect()
    }

    pub fn parse(s: &str) -> Pattern {
        let (negate, s) = match s.strip_prefix('!') {
            Some(r) => (true, r),
            None => (false, s),
        };
        // `=name` is the name exactly (what a host's own rule uses)
        if let Some(exact) = s.strip_prefix('=') {
            return Pattern { negate, anchored_start: true, anchored_end: true, parts: vec![exact.to_uppercase()] };
        }
        // a bare word means "contains"
        let glob = if s.contains('*') { s.to_string() } else { format!("*{}*", s) };
        Pattern {
            negate,
            anchored_start: !glob.starts_with('*'),
            anchored_end: !glob.ends_with('*'),
            parts: glob.split('*').filter(|p| !p.is_empty()).map(|p| p.to_uppercase()).collect(),
        }
    }

    fn matches(&self, s: &str) -> bool {
        // The literal that must start the name and the one that must end
        // it are taken from the two ends first; the ones between are then
        // looked for, in order, in what is left. (Looked for from the left
        // all the way, the last literal was found at its FIRST place:
        // `*1` did not match `WS11`, nor `10.*.5` the address `10.5.5.5`,
        // and written with `!` those hosts were not left out.)
        let u = s.to_uppercase();
        let (mut lo, mut hi) = (0usize, u.len());
        let (mut first, mut last) = (0usize, self.parts.len());
        if self.anchored_start && first < last {
            let p = self.parts[first].as_str();
            if !u.starts_with(p) {
                return false;
            }
            lo = p.len();
            first += 1;
        }
        if self.anchored_end {
            if first == last {
                // one literal, anchored at both ends: the whole name
                return lo == hi;
            }
            let p = self.parts[last - 1].as_str();
            if hi - lo < p.len() || !u[lo..].ends_with(p) {
                return false;
            }
            hi -= p.len();
            last -= 1;
        }
        for p in &self.parts[first..last] {
            match u[lo..hi].find(p.as_str()) {
                Some(k) => lo += k + p.len(),
                None => return false,
            }
        }
        true
    }

    /// `any` for an account (`name@DOMAIN`): a pattern that names no
    /// domain is about the name alone, so `adm*`, `!*$` and `=alice` mean
    /// what they always did; one with an `@` is about the whole.
    pub fn any_account(pats: &[Pattern], account: &str) -> bool {
        if pats.is_empty() {
            return true;
        }
        let name = account.split('@').next().unwrap_or(account);
        let positives = pats.iter().filter(|p| !p.negate).count();
        let mut hit = positives == 0;
        for p in pats {
            let m = p.matches(if p.parts.iter().any(|x| x.contains('@')) { account } else { name });
            if p.negate && m {
                return false;
            }
            if !p.negate && m {
                hit = true;
            }
        }
        hit
    }

    pub fn any(pats: &[Pattern], s: &str) -> bool {
        if pats.is_empty() {
            return true;
        }
        let positives = pats.iter().filter(|p| !p.negate).count();
        let mut hit = positives == 0;
        for p in pats {
            let m = p.matches(s);
            if p.negate && m {
                return false;
            }
            if !p.negate && m {
                hit = true;
            }
        }
        hit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_fold_hosts_and_follow_chains() {
        let dir = std::env::temp_dir().join(format!("masstin-merge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.csv");
        let s = [
            csv_out::HEADER.to_string(),
            row(1, 10, "10.0.0.7", "SRV01", "bob", "SUCCESSFUL_LOGON", ",,,,"),
            row(1, 11, "10.0.0.5", "SRV01", "eve", "SUCCESSFUL_LOGON", ",,,,"),
            row(1, 12, "10.0.0.7", "DC01", "bob", "SUCCESSFUL_LOGON", ",,,,"),
        ]
        .join("\n");
        std::fs::write(&p, s).unwrap();
        let path = p.to_string_lossy().to_string();
        let plain = Store::load(&[path.clone()], 0.05).unwrap();
        let names: Vec<&str> = (0..plain.hosts.len() as u32).map(|h| plain.hosts.name(h)).collect();
        assert_eq!(plain.hosts.len(), 4, "hosts {:?}, {} rows without origin", names, plain.rows_without_origin);
        let merged = Store::load_with(&[path.clone()], 0.05, &[("10.0.0.5".into(), "10.0.0.7".into())]).unwrap();
        assert_eq!(merged.hosts.len(), 3, "the two addresses are one host");
        let ws = merged.hosts.get("10.0.0.7").unwrap();
        assert!(merged.aliases[ws as usize].iter().any(|a| a == "10.0.0.5"));
        assert_eq!(merged.out_adj.of(ws).len(), 3);
        let chained = Store::load_with(&[path], 0.05, &[("10.0.0.5".into(), "10.0.0.7".into()), ("10.0.0.7".into(), "DC01".into())]).unwrap();
        assert_eq!(chained.hosts.len(), 2, "both addresses end in DC01");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_row_reads_back_in_its_nineteen_columns() {
        let dir = std::env::temp_dir().join(format!("masstin-raw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.csv");
        let s = [
            csv_out::HEADER.to_string(),
            row(1, 10, "10.0.0.7", "SRV01", "bob", "SUCCESSFUL_LOGON", ",significant,40,new origin,,"),
            // a row without an origin: no edge, still a row of the file
            row(1, 11, "", "SRV01", "SYSTEM", "SUCCESSFUL_LOGON", ",,,,,"),
            row(1, 12, "lnx-web01", "DC01", "eve", "FAILED_LOGON", ",,,,,"),
        ]
        .join("\n");
        std::fs::write(&p, s).unwrap();
        let st = Store::load(&[p.to_string_lossy().to_string()], 0.05).unwrap();
        assert_eq!(st.file_rows(0), 3, "every row of the file, the one without an origin too");
        let r = st.raw_row(0, 0).unwrap();
        assert_eq!(r.len(), csv_out::COLUMNS);
        assert_eq!(r[1], "SRV01");
        assert_eq!(r[2], "SUCCESSFUL_LOGON");
        assert_eq!(r[8], "10.0.0.7");
        assert_eq!(r[14], "significant");
        assert_eq!(r[16], "new origin");
        assert_eq!(st.raw_row(0, 1).unwrap()[5], "SYSTEM");
        assert_eq!(st.file_rows_matching(0, "LNX-WEB").unwrap(), vec![2]);
        assert_eq!(st.file_rows_matching(0, "srv01").unwrap(), vec![0, 1]);
        assert!(st.raw_row(0, 3).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_equals_pattern_is_exact() {
        let p = Pattern::parse_list("=PTR-DC01");
        assert!(Pattern::any(&p, "ptr-dc01"));
        assert!(!Pattern::any(&p, "PTR-DC01$"));
        assert!(!Pattern::any(&p, "RF-PTR-DC01"));
        let n = Pattern::parse_list("!=PTR-DC01");
        assert!(!Pattern::any(&n, "PTR-DC01"));
        assert!(Pattern::any(&n, "PTR-DC01$"));
    }

    #[test]
    fn patterns_are_globs_or_contains() {
        let p = Pattern::parse_list("svc_*,*$");
        assert!(Pattern::any(&p, "svc_backup"));
        assert!(Pattern::any(&p, "WS01$"));
        assert!(!Pattern::any(&p, "alice"));
        let q = Pattern::parse_list("adm");
        assert!(Pattern::any(&q, "ADMIN"));
        assert!(Pattern::any(&q, "sysadm"));
        let n = Pattern::parse_list("!*$");
        assert!(Pattern::any(&n, "alice"));
        assert!(!Pattern::any(&n, "WS01$"));
        let both = Pattern::parse_list("ws*,!ws09");
        assert!(Pattern::any(&both, "WS01"));
        assert!(!Pattern::any(&both, "WS09"));
        assert!(!Pattern::any(&both, "SRV01"));
    }

    fn row(day: u32, hour: u32, src: &str, dst: &str, user: &str, et: &str, tail: &str) -> String {
        format!("2026-01-{:02}T{:02}:00:00Z,{},{},4624,3,{},CORP,,{},,,0x{},,Security.evtx{}", day, hour, dst, et, user, src, hour, tail)
    }

    #[test]
    fn store_converts_the_raw_q_of_the_first_tail() {
        // a timeline annotated on 2026-11-02/03 carries `hunt_q` with the raw
        // q-value: it is read as a score and rewritten as one on the first mark
        let path = std::env::temp_dir().join(format!("masstin-store-q-{}.csv", std::process::id()));
        let body = [
            csv_out::HEADER_19_Q.to_string(),
            row(5, 9, "10.0.0.5", "SRV01", "alice", "SUCCESSFUL_LOGON", ",habitual,1,nothing new,,"),
            row(5, 10, "10.0.0.9", "SRV01", "mallory", "SUCCESSFUL_LOGON", ",significant,1.000e-3,origin never seen before,,"),
        ]
        .join("
");
        std::fs::write(&path, format!("{}
", body)).unwrap();
        let p = path.to_string_lossy().to_string();
        let mut s = Store::load(&[p.clone()], 0.05).unwrap();
        assert_eq!(s.edges.len(), 2);
        assert!((s.edges[0].score - 0.0).abs() < 1e-6);
        assert!((s.edges[1].score - 30.0).abs() < 1e-6);
        s.mark(&[(0, 1)], verdict_code("suspicious"), "").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], csv_out::HEADER);
        assert!(lines[1].ends_with(",habitual,0,nothing new,,"), "{}", lines[1]);
        assert!(lines[2].ends_with(",significant,30,origin never seen before,suspicious,"), "{}", lines[2]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_wildcard_is_matched_from_both_ends() {
        let m = |pat: &str, s: &str| Pattern::any(&Pattern::parse_list(pat), s);
        assert!(m("*1", "WS11") && m("*1", "WS1") && !m("*1", "WS12"));
        assert!(m("10.*.5", "10.5.5.5") && m("10.*.5", "10.0.0.5") && !m("10.*.5", "10.0.0.50") && !m("10.*.5", "110.0.0.5"));
        assert!(m("ws*", "WS07") && !m("ws*", "DEVWS07"));
        assert!(m("*srv*", "DEV-SRV01") && m("srv", "DEV-SRV01"));
        assert!(m("=SRV01", "srv01") && !m("=SRV01", "SRV011") && !m("=SRV01", "XSRV01"));
        assert!(m("a*b*c", "aXbXc") && m("a*b*c", "abc") && !m("a*b*c", "acb") && !m("ab*b", "ab"));
        assert!(m("*a*a", "aa") && !m("*a*a", "a"));
        // left out with `!`: the hosts that end in 1, whatever else they hold
        assert!(!m("!*1", "WS11") && m("!*1", "WS12"));
        assert!(!m("!10.*.5", "10.5.5.5") && m("!10.*.5", "10.5.5.6"));
        // letters outside ASCII are compared, not cut
        assert!(m("*ñ", "CAÑAÑ") && m("ñ*ñ", "ñandúñ") && !m("ñ*ñ", "ñ"));
    }

    /// A note of several lines is one row: the file keeps its row count,
    /// the note reads back whole, and a mark made after it lands on the
    /// row chosen (it used to land one row early for every line break).
    #[test]
    fn a_note_of_several_lines_is_still_one_row() {
        let path = std::env::temp_dir().join(format!("masstin-store-ml-{}.csv", std::process::id()));
        let body = [
            csv_out::HEADER.to_string(),
            row(5, 9, "10.0.0.5", "SRV01", "alice", "SUCCESSFUL_LOGON", ",,,,,"),
            row(5, 10, "10.0.0.9", "SRV01", "mallory", "SUCCESSFUL_LOGON", ",,,,,"),
            row(5, 11, "10.0.0.7", "SRV01", "carol", "SUCCESSFUL_LOGON", ",,,,,"),
        ]
        .join("\n");
        std::fs::write(&path, format!("{}\n", body)).unwrap();
        let p = path.to_string_lossy().to_string();
        let mut s = Store::load(&[p.clone()], 0.05).unwrap();
        let note = "first line\nsecond, with a comma\r\nthird \"quoted\"";
        assert_eq!(s.mark(&[(0, 0)], verdict_code("suspicious"), note).unwrap(), 1);
        // a mark on a later row, after the multi-line one
        assert_eq!(s.mark(&[(0, 2)], verdict_code("benign"), "carol is fine").unwrap(), 1);
        assert_eq!(s.row_fields(0, 2).unwrap()[5], "carol");
        assert_eq!(s.raw_row(0, 0).unwrap()[18], note);

        let again = Store::load(&[p.clone()], 0.05).unwrap();
        assert_eq!(again.rows_total, 3);
        assert_eq!(again.edges.len(), 3);
        assert_eq!(again.notes.get(&(0, 0)).map(|x| x.as_str()), Some(note));
        assert_eq!(again.notes.get(&(0, 2)).map(|x| x.as_str()), Some("carol is fine"));
        assert_eq!(again.notes.get(&(0, 1)), None);
        assert_eq!(again.edges[2].verdict, verdict_code("benign"));
        assert_eq!(again.row_fields(0, 1).unwrap()[5], "mallory");
        // what the csv crate reads is the same three rows
        let n = csv::ReaderBuilder::new().flexible(true).from_path(&path).unwrap().records().filter(|r| r.as_ref().map(|r| r.len() == 19).unwrap_or(false)).count();
        assert_eq!(n, 3);
        let _ = std::fs::remove_file(&path);
    }

    /// A timeline that cannot be replaced leaves the store unmarked.
    #[test]
    fn a_mark_that_cannot_be_written_is_not_shown() {
        let path = std::env::temp_dir().join(format!("masstin-store-ro-{}.csv", std::process::id()));
        let body = [csv_out::HEADER.to_string(), row(5, 9, "10.0.0.5", "SRV01", "alice", "SUCCESSFUL_LOGON", ",,,,,")].join("\n");
        std::fs::write(&path, format!("{}\n", body)).unwrap();
        let p = path.to_string_lossy().to_string();
        let mut s = Store::load(&[p.clone()], 0.05).unwrap();
        // the file is gone when the mark is written
        std::fs::remove_file(&path).unwrap();
        assert!(s.mark(&[(0, 0)], verdict_code("suspicious"), "x").is_err());
        assert_eq!(s.edges[0].verdict, V_NONE);
        assert!(s.notes.is_empty());
    }

    /// A Kerberos ticket or an NTLM validation that succeeded is an
    /// authentication at the domain controller, not a logon on it: a
    /// connection for the graph. A failed one stays a failure, and a real
    /// logon a logon.
    #[test]
    fn a_ticket_is_not_a_logon_on_the_domain_controller() {
        let path = std::env::temp_dir().join(format!("masstin-tickets-{}.csv", std::process::id()));
        let line = |min: u32, eid: &str, et: &str| format!("2026-01-05T10:{:02}:00Z,DC01,{},{},3,ana,CORP,,10.0.0.5,,,,,Security.evtx,,,,,", min, et, eid);
        let body = [
            csv_out::HEADER.to_string(),
            line(1, "4768", "SUCCESSFUL_LOGON"),
            line(2, "4769", "SUCCESSFUL_LOGON"),
            line(3, "4770", "SUCCESSFUL_LOGON"),
            line(4, "4776", "SUCCESSFUL_LOGON"),
            line(5, "4771", "FAILED_LOGON"),
            line(6, "4768", "FAILED_LOGON"),
            line(7, "4624", "SUCCESSFUL_LOGON"),
            line(8, "4648", "CONNECT"),
        ]
        .join("
");
        std::fs::write(&path, format!("{}
", body)).unwrap();
        let s = Store::load(&[path.to_string_lossy().to_string()], 0.05).unwrap();
        let got: Vec<u8> = s.by_time.iter().map(|&i| s.edges[i as usize].result).collect();
        assert_eq!(got, [R_CONNECT, R_CONNECT, R_CONNECT, R_CONNECT, R_FAIL, R_FAIL, R_OK, R_CONNECT]);
        assert_eq!(s.logons, 1);
        let _ = std::fs::remove_file(path);
    }

    /// A Linux timeline pairs a logon with its end too: the logon ID is
    /// the process id of the sshd of the connection, on both rows. The
    /// same id used again later is another session.
    #[test]
    fn an_ssh_session_is_paired_by_the_pid_of_its_sshd() {
        let path = std::env::temp_dir().join(format!("masstin-sshsess-{}.csv", std::process::id()));
        let line = |hm: &str, et: &str, eid: &str, user: &str, src: &str, pid: &str| format!("2026-11-17T{}:00+00:00,web01,{},{},SSH,{},,,{},,,{},,auth.log,,,,,", hm, et, eid, user, src, pid);
        let body = [
            csv_out::HEADER.to_string(),
            line("10:00", "SUCCESSFUL_LOGON", "SSH_SUCCESS", "alice", "10.0.0.5", "4242"),
            line("10:05", "SUCCESSFUL_LOGON", "SSH_SUCCESS", "bob", "10.0.0.9", "5000"),
            line("10:20", "LOGOFF", "LOGOUT", "alice", "10.0.0.5", "4242"),
            line("11:00", "LOGOFF", "LOGOUT", "bob", "10.0.0.9", "5000"),
            // the pid handed out again, and never closed in the log
            line("12:00", "SUCCESSFUL_LOGON", "SSH_SUCCESS", "carol", "10.0.0.7", "4242"),
        ]
        .join("
");
        std::fs::write(&path, format!("{}
", body)).unwrap();
        let s = Store::load(&[path.to_string_lossy().to_string()], 0.05).unwrap();
        let of = |user: &str| -> Option<i64> { s.edges.iter().position(|e| e.result == R_OK && s.users.name(e.user).starts_with(user)).and_then(|i| s.session_of(i as u32)) };
        assert_eq!((of("alice"), of("bob"), of("carol")), (Some(20 * 60), Some(55 * 60), None));
        assert_eq!((s.logons, s.sessions_known), (3, 2));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn store_reads_edges_and_writes_marks_back() {
        let path = std::env::temp_dir().join(format!("masstin-store-{}.csv", std::process::id()));
        let body = [
            csv_out::HEADER.to_string(),
            row(5, 9, "10.0.0.5", "SRV01", "alice", "SUCCESSFUL_LOGON", ",habitual,0,nothing new,,"),
            row(5, 10, "10.0.0.9", "SRV01", "mallory", "SUCCESSFUL_LOGON", ",significant,30,origin never seen before,,"),
            row(5, 11, "127.0.0.1", "SRV01", "system", "SUCCESSFUL_LOGON", ",,,,,"),
            row(5, 12, "SRV01", "WS02", "mallory", "FAILED_LOGON", ",candidate,7,new,benign,seen it"),
        ]
        .join("\n");
        std::fs::write(&path, format!("{}\n", body)).unwrap();
        let p = path.to_string_lossy().to_string();
        let mut s = Store::load(&[p.clone()], 0.05).unwrap();
        assert_eq!(s.rows_total, 4);
        assert_eq!(s.rows_without_origin, 1);
        assert_eq!(s.edges.len(), 3);
        assert_eq!(s.hosts.len(), 4);
        let srv = s.hosts.get("SRV01").unwrap();
        assert_eq!(s.in_adj.of(srv).len(), 2);
        assert_eq!(s.out_adj.of(srv).len(), 1);
        let e = &s.edges[1];
        assert_eq!(e.hunt, H_SIGNIFICANT);
        assert!((e.score - 30.0).abs() < 1e-6);
        assert_eq!(s.whys.name(e.why), "origin never seen before");
        assert_eq!(s.edges[2].verdict, verdict_code("benign"));
        assert_eq!(s.notes.get(&(0, 3)).map(|x| x.as_str()), Some("seen it"));
        let nb = s.neighbourhood(&[srv], 1, None, None);
        assert_eq!(nb.len(), 4);
        assert_eq!(s.row_fields(0, 1).unwrap()[5], "mallory");

        // mark the significant row; the file changes, the store does not reload
        let n = s.mark(&[(0, 1)], verdict_code("suspicious"), "pivot, check SRV01").unwrap();
        assert_eq!(n, 1);
        assert!(!s.changed());
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], csv_out::HEADER);
        assert!(lines[2].ends_with(",significant,30,origin never seen before,suspicious,\"pivot, check SRV01\""), "{}", lines[2]);
        assert!(lines[4].ends_with(",benign,seen it"), "{}", lines[4]);
        assert!(lines[3].ends_with(",,,,,"), "{}", lines[3]);
        // the rows are still found at their new offsets
        assert_eq!(s.row_fields(0, 3).unwrap()[1], "WS02");
        let again = Store::load(&[p], 0.05).unwrap();
        assert_eq!(again.edges[1].verdict, verdict_code("suspicious"));
        let _ = std::fs::remove_file(&path);
    }
}
