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
use crate::graph_hunt_common::engine::{ambiguous_short_names, base_prefix_len, ip_names_for_csv, replace_file, row_key, split_csv_into};
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

fn result_code(event_type: &str) -> u8 {
    match event_type {
        "SUCCESSFUL_LOGON" => R_OK,
        "FAILED_LOGON" => R_FAIL,
        "LOGOFF" => R_LOGOFF,
        _ => R_CONNECT,
    }
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
}

impl Store {
    /// Read the timelines. `alpha` is the false discovery rate of the
    /// IP -> name test (the one graph-hunt and the loaders use).
    pub fn load(paths: &[String], alpha: f64) -> std::io::Result<Store> {
        let ambiguous = ambiguous_short_names(paths)?;
        let resolved: HashMap<String, (String, u32, f64)> = ip_names_for_csv(paths, alpha).unwrap_or_default();
        let mut hosts = Interner::default();
        let mut aliases: Vec<Vec<String>> = Vec::new();
        let mut host_of = |raw: &str, hosts: &mut Interner| -> u32 {
            let label = resolved.get(raw).map(|r| r.0.as_str()).unwrap_or(raw);
            let id = hosts.id(label);
            if aliases.len() <= id as usize {
                aliases.push(vec![label.to_string()]);
            }
            if !aliases[id as usize].iter().any(|a| a == raw) {
                aliases[id as usize].push(raw.to_string());
            }
            id
        };
        let mut users = Interner::default();
        let mut logon_types = Interner::default();
        let mut event_ids = Interner::default();
        let mut whys = Interner::default();
        whys.id("");
        let mut edges: Vec<Edge> = Vec::new();
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
                line.clear();
                let n = rd.read_line(&mut line)?;
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
                let (origin, dest, _acct, _cls) = match row_key(&b, &ambiguous) {
                    Some(k) => k,
                    None => {
                        rows_without_origin += 1;
                        continue;
                    }
                };
                let sc = b[7].trim();
                let src_is_ip = sc.is_empty() || sc == "-" || crate::load_neo4j::looks_like_ip(sc);
                let src = host_of(&origin, &mut hosts);
                let dst = host_of(&dest, &mut hosts);
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
                edges.push(Edge {
                    t,
                    src,
                    dst,
                    user: users.id(b[5].trim()),
                    logon_type: logon_types.id(b[4].trim()),
                    event_id: event_ids.id(b[3].trim()),
                    why,
                    line: line_no,
                    score,
                    file: fi as u16,
                    result: result_code(b[2].trim()),
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
        Ok(Store { files, hosts, aliases, users, logon_types, event_ids, whys, edges, by_time, out_adj, in_adj, notes, rows_total, rows_without_origin, rows_bad_time, t_min, t_max })
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

    /// The 14 event columns of a row, read from the file.
    pub fn row_fields(&self, file: u16, line: u32) -> std::io::Result<Vec<String>> {
        let f = self.files.get(file as usize).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"))?;
        let at = *f.offsets.get(line as usize).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no such row"))?;
        let mut fh = std::fs::File::open(&f.path)?;
        fh.seek(SeekFrom::Start(at))?;
        let mut rd = std::io::BufReader::new(fh);
        let mut line = String::new();
        rd.read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let mut p: Vec<Cow<str>> = Vec::with_capacity(20);
        split_csv_into(trimmed, &mut p);
        let idx = f.layout.base_indices();
        Ok(idx.iter().map(|i| i.and_then(|i| p.get(i)).map(|s| s.to_string()).unwrap_or_default()).collect())
    }

    /// Write a verdict and notes on these rows: the edges here and the
    /// files' tails. Returns how many rows were written.
    pub fn mark(&mut self, rows: &[(u16, u32)], verdict: u8, notes: &str) -> std::io::Result<usize> {
        let mut per_file: HashMap<u16, HashSet<u32>> = HashMap::new();
        for &(f, l) in rows {
            if let Some(ei) = self.edge_at(f, l) {
                self.edges[ei].verdict = verdict;
                if notes.is_empty() {
                    self.notes.remove(&(f, l));
                } else {
                    self.notes.insert((f, l), notes.to_string());
                }
                per_file.entry(f).or_default().insert(l);
            }
        }
        let mut written = 0usize;
        let verdict_name = VERDICT_NAMES[verdict as usize];
        for (fi, lines) in per_file {
            let path = self.files[fi as usize].path.clone();
            let tmp = Path::new(&path).with_extension("csv.masstin-tmp");
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
                    buf.clear();
                    if rd.read_line(&mut buf)? == 0 {
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
        let u = s.to_uppercase();
        let mut at = 0usize;
        for (i, part) in self.parts.iter().enumerate() {
            match u[at..].find(part.as_str()) {
                Some(k) => {
                    if i == 0 && self.anchored_start && k != 0 {
                        return false;
                    }
                    at += k + part.len();
                }
                None => return false,
            }
        }
        if self.anchored_end {
            if let Some(last) = self.parts.last() {
                return u.ends_with(last.as_str()) && at == u.len();
            }
        }
        true
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
