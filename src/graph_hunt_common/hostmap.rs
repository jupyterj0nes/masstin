//! Whose address is it: the table of addresses and host names of a
//! timeline, and which of them can be made one machine without asking.
//!
//! A timeline names the origin of a connection by its name when the event
//! gives one and by its address when it does not, so one machine is often
//! two nodes: `DEV-DC01` and `10.10.0.37`. Each half has part of the
//! connections, and the hunt profiles two origins where there is one. The
//! same-login test (`resolve`) folds an address into a name when the same
//! login was recorded twice. This module adds the evidence that says it
//! outright, and keeps apart what can be trusted from what cannot:
//!
//! - `own`: the machine's own network configuration (the addresses of its
//!   interfaces in its SYSTEM hive, see `parse_hostcfg`), read when the
//!   evidence was parsed and kept in the timeline's masstin file (key
//!   `hosts`). It settles which of two addresses is a host's.
//! - `locator`: the domain controller a machine found and bound to, by
//!   name and address (Group Policy 5308), kept in the same place.
//! - `machine-account`: the computer account `NAME$` authenticated from
//!   the address (4624 network logon, 4768). The account is the machine's
//!   own secret: only that machine (or whoever stole or relayed it) logs
//!   on with it.
//! - `declared`: the name the client itself gave in the event that also
//!   has its address (NTLM workstation name, RDP client name). The client
//!   chooses it; an attack tool sends what it likes.
//! - `same-login`: the statistical test of `resolve`.
//!
//! Three levels say how much of it is applied without asking:
//!
//! - `strict`: `own` and `locator`: what a machine says of itself or of
//!   its domain controller.
//! - `standard`: also `machine-account`, when the name is a machine the
//!   timeline knows (a destination, a declared origin, a host of `own` /
//!   `locator`); a `NAME$` that is nothing else may be a service account.
//! - `broad`: everything.
//!
//! And at every level an address is left alone, and said, when the
//! evidence disagrees: several names at one address (NAT, a proxy, an
//! address that changed hands, a forged name), or a host seen at two
//! addresses in the same period with nothing of its own to tell which is
//! its (a second interface, or its account used from somewhere else: a
//! relayed machine account looks exactly like that). The nodes of a
//! timeline are not time-aware, so an address that was one machine in
//! October and another in November cannot be merged into either.
//!
//! Nothing here changes the timeline: the 19 columns keep both names. The
//! result is a list of `(address, host)` the hunt and the viewer read the
//! timeline with.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

use super::engine::{ambiguous_short_names, clean_host, ip_names_for_csv, names_no_machine, row_key, short_name, split_csv_into};
use super::parse_ts;
use crate::load_neo4j::looks_like_ip;

/// What says that an address is a host. Ordered from the weakest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    SameLogin,
    Declared,
    MachineAccount,
    Locator,
    Own,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::SameLogin => "same-login",
            Kind::Declared => "declared",
            Kind::MachineAccount => "machine-account",
            Kind::Locator => "locator",
            Kind::Own => "own",
        }
    }
    /// What it is, in a line.
    pub fn explain(self) -> &'static str {
        match self {
            Kind::SameLogin => "the same login recorded once with the address and once with the name (statistical test)",
            Kind::Declared => "the name the client gave in the event that has its address",
            Kind::MachineAccount => "the machine's own account (NAME$) authenticated from the address",
            Kind::Locator => "the domain controller a machine found and bound to, by name and address",
            Kind::Own => "the machine's own network configuration",
        }
    }
    fn is_strict(self) -> bool {
        matches!(self, Kind::Own | Kind::Locator)
    }
}

/// How much is merged without asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Strict,
    Standard,
    Broad,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        match s.trim().to_ascii_lowercase().as_str() {
            "strict" => Some(Level::Strict),
            "standard" => Some(Level::Standard),
            "broad" => Some(Level::Broad),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Level::Strict => "strict",
            Level::Standard => "standard",
            Level::Broad => "broad",
        }
    }
    pub fn explain(self) -> &'static str {
        match self {
            Level::Strict => "what a machine says of itself (its SYSTEM hive) or of its domain controller (Group Policy 5308)",
            Level::Standard => "also a machine account (NAME$) authenticated from the address",
            Level::Broad => "also a name the client gave, and the same-login test",
        }
    }
}

/// A fact kept in a timeline's masstin file (key `hosts`), written by the
/// parsers from evidence that is not an event of the timeline.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fact {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub address: String,
    /// `own` or `locator`
    #[serde(default)]
    pub kind: String,
    /// the period it holds for, UTC `YYYY-MM-DD HH:MM:SS`; empty when the
    /// evidence gives none
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub to: String,
    /// where it was read
    #[serde(default)]
    pub source: String,
}

/// The key of the timeline's file the facts are kept under.
pub const KEY: &str = "hosts";

pub fn read_facts(timeline: &str) -> Vec<Fact> {
    crate::timeline_file::get(timeline, KEY).and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default()
}

/// Add facts to those of a timeline (each once).
pub fn write_facts(timeline: &str, facts: &[Fact]) -> std::io::Result<Option<std::path::PathBuf>> {
    let mut all = read_facts(timeline);
    let before = all.len();
    for f in facts {
        if !all.contains(f) {
            all.push(f.clone());
        }
    }
    if all.len() == before {
        return Ok(None);
    }
    crate::timeline_file::set(timeline, KEY, serde_json::to_value(&all).map_err(std::io::Error::other)?).map(Some)
}

/// Facts the parsers of this run came upon in evidence that gives no row
/// (a Group Policy log): kept until the timeline is written, then stored
/// in its masstin file. The same fact seen again widens its period.
static NOTED: std::sync::Mutex<Vec<Fact>> = std::sync::Mutex::new(Vec::new());

pub fn note_fact(f: Fact) {
    let Ok(mut all) = NOTED.lock() else { return };
    match all.iter_mut().find(|x| x.host.eq_ignore_ascii_case(&f.host) && x.address == f.address && x.kind == f.kind && x.source == f.source) {
        Some(x) => {
            if !f.from.is_empty() && (x.from.is_empty() || f.from < x.from) {
                x.from = f.from;
            }
            if f.to > x.to {
                x.to = f.to;
            }
        }
        None => all.push(f),
    }
}

/// The facts noted so far, taken (the list is left empty).
pub fn take_noted() -> Vec<Fact> {
    NOTED.lock().map(|mut a| std::mem::take(&mut *a)).unwrap_or_default()
}

/// One kind of evidence for one (address, name).
#[derive(Clone, Debug, PartialEq)]
pub struct Seen {
    pub kind: Kind,
    pub count: u64,
    /// unix seconds; 0 when the evidence has no time
    pub first: i64,
    pub last: i64,
    /// one case of it, in words
    pub example: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Entry {
    pub address: String,
    /// every name the address was given, strongest evidence first
    pub names: Vec<(String, Vec<Seen>)>,
    /// the host it is, when the evidence names one; empty otherwise
    pub host: String,
    /// the lowest level that merges it without asking; None: left to the
    /// analyst (see `note`)
    pub level: Option<Level>,
    /// why it is not merged, or what to know about the merge
    pub note: String,
    /// rows of the timelines whose origin is this address alone, and
    /// their span (unix seconds)
    pub rows: u64,
    pub first: i64,
    pub last: i64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Table {
    pub entries: Vec<Entry>,
}

fn fmt_t(t: i64) -> String {
    if t == 0 {
        return String::new();
    }
    chrono::DateTime::from_timestamp(t, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_default()
}

fn parse_t(s: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(s.trim(), "%Y-%m-%d %H:%M:%S").map(|n| n.and_utc().timestamp()).unwrap_or(0)
}

/// `DEV\WS01$`, `WS01$@DEV.CORP` -> `WS01`; None when it is no computer
/// account.
pub(crate) fn machine_of_account(user: &str) -> Option<String> {
    let u = user.trim();
    let u = u.rsplit('\\').next().unwrap_or(u);
    let u = u.split('@').next().unwrap_or(u);
    let name = u.strip_suffix('$')?;
    if name.is_empty() || name.contains([' ', '$', '/']) || looks_like_ip(name) {
        return None;
    }
    Some(name.to_string())
}

/// Evidence gathered before any decision.
#[derive(Default)]
struct Gathered {
    /// address -> name -> kind -> seen
    ev: BTreeMap<String, BTreeMap<String, BTreeMap<Kind, Seen>>>,
    /// names the timelines know as machines
    known: HashSet<String>,
    /// address -> (rows as an origin on its own, first, last)
    alone: HashMap<String, (u64, i64, i64)>,
}

impl Gathered {
    fn add(&mut self, address: &str, name: &str, kind: Kind, t: i64, example: impl FnOnce() -> String) {
        self.add_span(address, name, kind, t, t, 1, example)
    }
    fn add_span(&mut self, address: &str, name: &str, kind: Kind, first: i64, last: i64, count: u64, example: impl FnOnce() -> String) {
        let by_kind = self.ev.entry(address.to_string()).or_default().entry(name.to_string()).or_default();
        match by_kind.get_mut(&kind) {
            Some(s) => {
                s.count += count;
                if first != 0 && (s.first == 0 || first < s.first) {
                    s.first = first;
                }
                if last > s.last {
                    s.last = last;
                }
            }
            None => {
                by_kind.insert(kind, Seen { kind, count, first, last, example: example() });
            }
        }
    }
}

/// The span the evidence of (address, name) covers; None when some of it
/// has no time (it holds whenever).
fn span_of(seen: &[Seen]) -> Option<(i64, i64)> {
    if seen.iter().any(|s| s.first == 0 && s.last == 0) {
        return None;
    }
    Some((seen.iter().map(|s| s.first).min().unwrap_or(0), seen.iter().map(|s| s.last).max().unwrap_or(0)))
}

fn overlap(a: Option<(i64, i64)>, b: Option<(i64, i64)>) -> bool {
    match (a, b) {
        (Some((a0, a1)), Some((b0, b1))) => a0 <= b1 && b0 <= a1,
        _ => true,
    }
}

/// The table of the timelines: every address that is an origin on its own
/// or has evidence of whose it is.
pub fn build(files: &[String], alpha: f64) -> std::io::Result<Table> {
    let ambiguous = ambiguous_short_names(files)?;
    let short = |v: &str| short_name(v, &ambiguous);
    let mut g = Gathered::default();
    for f in files {
        let rd = std::io::BufReader::new(std::fs::File::open(f)?);
        let mut lines = crate::csv_out::records(rd);
        let header = lines.next().transpose()?.unwrap_or_default();
        let Some(layout) = crate::csv_out::Layout::of(&header) else { continue };
        let idx = layout.base_indices();
        for line in lines {
            let line = line?;
            let mut p: Vec<std::borrow::Cow<str>> = Vec::with_capacity(20);
            split_csv_into(line.trim_end_matches(['\r', '\n']), &mut p);
            let b: Vec<std::borrow::Cow<str>> = idx.iter().map(|i| i.and_then(|i| p.get(i)).cloned().unwrap_or(std::borrow::Cow::Borrowed(""))).collect();
            let Some(t) = parse_ts(&b[0]).map(|x| x.and_utc().timestamp()) else { continue };
            let dest = short(&clean_host(&b[1]));
            if dest.is_empty() {
                continue;
            }
            g.known.insert(dest.clone());
            let sc = clean_host(&b[7]);
            let si = clean_host(&b[8]);
            let named = !names_no_machine(&sc) && !looks_like_ip(&sc);
            if named {
                g.known.insert(short(&sc));
            }
            // the row's origin, as the hunt and the viewer key it
            if let Some((origin, _, _, _)) = row_key(&b, &ambiguous) {
                if looks_like_ip(&origin) {
                    let e = g.alone.entry(origin).or_insert((0, t, t));
                    e.0 += 1;
                    e.1 = e.1.min(t);
                    e.2 = e.2.max(t);
                }
            }
            if names_no_machine(&si) || !looks_like_ip(&si) {
                continue;
            }
            let address = short(&si);
            let (event_type, event_id) = (b[2].trim(), b[3].trim());
            // the name the client gave, next to its address (a name that is
            // the destination's own says nothing: a logoff, an RDP logon
            // written with the server's name)
            if named {
                let name = short(&sc);
                if name != dest {
                    g.add(&address, &name, Kind::Declared, t, || format!("{} {} on {}", event_id, event_type, dest));
                }
            }
            // the computer account authenticated from the address: a logon
            // that succeeded, in the events that carry the address itself
            if event_type == "SUCCESSFUL_LOGON" && (event_id == "4624" || event_id == "4768") {
                if let Some(m) = machine_of_account(&b[5]) {
                    let name = short(&m);
                    g.add(&address, &name, Kind::MachineAccount, t, || if name == dest { format!("{} of {}$ on {} itself", event_id, name, dest) } else { format!("{} of {}$ on {}", event_id, name, dest) });
                }
            }
        }
        // what the parsers kept of evidence that is no event
        for fact in read_facts(f) {
            let kind = match fact.kind.as_str() {
                "own" => Kind::Own,
                "locator" => Kind::Locator,
                _ => continue,
            };
            let (host, address) = (short(&clean_host(&fact.host)), short(&clean_host(&fact.address)));
            if host.is_empty() || !looks_like_ip(&address) || names_no_machine(&address) {
                continue;
            }
            g.known.insert(host.clone());
            let src = fact.source.clone();
            g.add_span(&address, &host, kind, parse_t(&fact.from), parse_t(&fact.to), 1, || src);
        }
    }
    // the same-login test, as one more piece of evidence
    for (ip, (name, votes, _)) in ip_names_for_csv(files, alpha).unwrap_or_default() {
        let name = short(&name);
        let (first, last) = g.alone.get(&ip).map(|a| (a.1, a.2)).unwrap_or((0, 0));
        g.add_span(&ip, &name, Kind::SameLogin, first, last, votes as u64, || format!("{} login(s) recorded with both", votes));
    }
    Ok(decide(g))
}

fn decide(g: Gathered) -> Table {
    let Gathered { ev, known, alone } = g;
    let mut entries: Vec<Entry> = Vec::new();
    for (address, by_name) in &ev {
        let mut names: Vec<(String, Vec<Seen>)> = by_name.iter().map(|(n, k)| (n.clone(), k.values().rev().cloned().collect())).collect();
        // strongest first, then the most seen
        names.sort_by(|a, b| (b.1[0].kind, b.1.iter().map(|s| s.count).sum::<u64>()).cmp(&(a.1[0].kind, a.1.iter().map(|s| s.count).sum::<u64>())).then(a.0.cmp(&b.0)));
        let (rows, first, last) = alone.get(address).copied().unwrap_or((0, 0, 0));
        let mut e = Entry { address: address.clone(), names, rows, first, last, ..Entry::default() };
        // a `NAME$` that is no machine the timelines know, at an address
        // that has a machine: a service account used from it
        let service = |(n, seen): &(String, Vec<Seen>)| seen.iter().all(|s| s.kind == Kind::MachineAccount) && !known.contains(n);
        let machines: Vec<usize> = (0..e.names.len()).filter(|&i| !service(&e.names[i])).collect();
        let pick = if e.names.len() == 1 {
            Some(0)
        } else if machines.len() == 1 {
            let others: Vec<String> = e.names.iter().filter(|n| service(*n)).map(|(n, _)| format!("{}$", n)).collect();
            e.note = format!("{} also authenticated from it: no other trace of a machine of that name, taken as a service account", others.join(", "));
            Some(machines[0])
        } else {
            None
        };
        match pick {
            Some(i) => {
                let (name, seen) = &e.names[i];
                e.host = name.clone();
                let best = seen[0].kind;
                e.level = Some(if best.is_strict() {
                    Level::Strict
                } else if best == Kind::MachineAccount && known.contains(name) {
                    Level::Standard
                } else {
                    Level::Broad
                });
                if best == Kind::MachineAccount && !known.contains(name) {
                    e.note = format!("{}$ authenticated from it, and the timelines have no other trace of a machine of that name: it may be a service account", name);
                }
            }
            None => {
                let spans: Vec<Option<(i64, i64)>> = e.names.iter().map(|(_, s)| span_of(s)).collect();
                // "the same period" to within a day: two names a few minutes
                // apart share the address, they did not take turns at it
                let wide = |s: Option<(i64, i64)>| s.map(|(a, b)| (a - 43_200, b + 43_200));
                let together = (0..spans.len()).any(|i| (i + 1..spans.len()).any(|j| overlap(wide(spans[i]), wide(spans[j]))));
                let list: Vec<String> = e.names.iter().map(|(n, s)| match span_of(s) {
                    Some((a, b)) => format!("{} ({} to {})", n, fmt_t(a), fmt_t(b)),
                    None => n.clone(),
                }).collect();
                e.note = if together {
                    format!("several names at this address in the same period: {}. NAT, a proxy, a jump host, or a name that is not the machine's", list.join(", "))
                } else {
                    format!("the address changed hands: {}. A node of the graph is one machine for the whole timeline, so it is merged into neither", list.join(", "))
                };
            }
        }
        entries.push(e);
    }
    // a host seen at two addresses in the same period: only an address
    // the host itself (or its domain) vouches for is its without asking
    let mut by_host: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, e) in entries.iter().enumerate() {
        if e.level.is_some() {
            by_host.entry(e.host.clone()).or_default().push(i);
        }
    }
    let seen_of = |e: &Entry| -> Vec<Seen> { e.names.iter().find(|(n, _)| *n == e.host).map(|(_, s)| s.clone()).unwrap_or_default() };
    let mut contested: Vec<(usize, String)> = Vec::new();
    for (host, ids) in &by_host {
        for &i in ids {
            let mine = seen_of(&entries[i]);
            if mine.iter().any(|s| s.kind.is_strict()) {
                continue;
            }
            let others: Vec<&str> = ids.iter().filter(|&&j| j != i && overlap(span_of(&mine), span_of(&seen_of(&entries[j])))).map(|&j| entries[j].address.as_str()).collect();
            if !others.is_empty() {
                contested.push((i, format!("{} is also seen at {} in the same period, and nothing of its own says which address is its: a second interface, or its name or account used from somewhere else", host, others.join(", "))));
            }
        }
    }
    for (i, note) in contested {
        entries[i].level = None;
        entries[i].note = note;
    }
    // addresses that are origins on their own and nothing says whose
    for (address, (rows, first, last)) in &alone {
        if !ev.contains_key(address) {
            entries.push(Entry { address: address.clone(), rows: *rows, first: *first, last: *last, note: "nothing in the timelines says whose it is".to_string(), ..Entry::default() });
        }
    }
    // what merges first, then by the rows that would follow
    entries.sort_by(|a, b| (a.level.is_none(), a.host.is_empty(), a.level, std::cmp::Reverse(a.rows)).cmp(&(b.level.is_none(), b.host.is_empty(), b.level, std::cmp::Reverse(b.rows))).then(a.address.cmp(&b.address)));
    Table { entries }
}

impl Entry {
    /// The evidence for the host it is (or for every name, when there are
    /// several), in a line.
    pub fn evidence(&self) -> String {
        let one = |seen: &[Seen]| seen.iter().map(|s| format!("{} x{} ({})", s.kind.name(), s.count, s.example)).collect::<Vec<_>>().join("; ");
        if self.host.is_empty() {
            self.names.iter().map(|(n, s)| format!("{}: {}", n, one(s))).collect::<Vec<_>>().join(" | ")
        } else {
            self.names.iter().find(|(n, _)| *n == self.host).map(|(_, s)| one(s)).unwrap_or_default()
        }
    }
    pub fn level_name(&self) -> &'static str {
        match self.level {
            Some(l) => l.name(),
            None if self.names.is_empty() => "unknown",
            None => "ask",
        }
    }
}

impl Table {
    /// The `(address, host)` merged without asking at this level, less the
    /// addresses the analyst left out.
    pub fn merges(&self, level: Level, skip: &HashSet<String>) -> Vec<(String, String)> {
        self.entries.iter().filter(|e| e.level.is_some_and(|l| l <= level) && !skip.contains(&e.address.to_uppercase())).map(|e| (e.address.clone(), e.host.clone())).collect()
    }

    /// How many addresses each level adds, and how many are left to ask.
    pub fn counts(&self) -> [usize; 5] {
        let n = |l: Level| self.entries.iter().filter(|e| e.level == Some(l)).count();
        [n(Level::Strict), n(Level::Standard), n(Level::Broad), self.entries.iter().filter(|e| e.level.is_none() && !e.names.is_empty()).count(), self.entries.iter().filter(|e| e.names.is_empty()).count()]
    }

    /// The table as CSV: one address per line.
    pub fn to_csv(&self) -> String {
        let q = |s: &str| if s.contains([',', '"', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() };
        let mut out = String::from("address,host,merge,rows_as_origin,first_seen,last_seen,evidence,note\n");
        for e in &self.entries {
            out.push_str(&format!("{},{},{},{},{},{},{},{}\n", q(&e.address), q(&e.host), e.level_name(), e.rows, fmt_t(e.first), fmt_t(e.last), q(&e.evidence()), q(&e.note)));
        }
        out
    }

    /// The summary, as lines to print.
    pub fn summary(&self) -> Vec<String> {
        let c = self.counts();
        vec![
            format!("{} address(es): {} with evidence of whose they are, {} without", self.entries.len(), self.entries.len() - c[4], c[4]),
            format!("strict    {:>5}  {}", c[0], Level::Strict.explain()),
            format!("standard  {:>5}  {}", c[1], Level::Standard.explain()),
            format!("broad     {:>5}  {}", c[2], Level::Broad.explain()),
            format!("ask       {:>5}  the evidence disagrees: left to you at every level", c[3]),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tl(dir: &std::path::Path, name: &str, rows: &[String]) -> String {
        let p = dir.join(name);
        std::fs::write(&p, format!("{}\n{}\n", crate::csv_out::HEADER, rows.join("\n"))).unwrap();
        p.to_string_lossy().to_string()
    }
    /// time, destination, event type, id, logon type, user, source name, source address
    fn row(t: &str, dst: &str, et: &str, id: &str, lt: &str, user: &str, sc: &str, si: &str) -> String {
        format!("{t},{dst},{et},{id},{lt},{user},CORP,{sc},{si},,,0x1,,Security.evtx,,,,,")
    }
    fn entry<'a>(t: &'a Table, a: &str) -> &'a Entry {
        t.entries.iter().find(|e| e.address == a).unwrap_or_else(|| panic!("no entry for {a}"))
    }

    #[test]
    fn machine_accounts() {
        assert_eq!(machine_of_account("WS01$").as_deref(), Some("WS01"));
        assert_eq!(machine_of_account("DEV\\ws01$").as_deref(), Some("ws01"));
        assert_eq!(machine_of_account("WS01$@DEV.CORP").as_deref(), Some("WS01"));
        assert_eq!(machine_of_account("alice"), None);
        assert_eq!(machine_of_account("$"), None);
        assert_eq!(machine_of_account("ANONYMOUS LOGON$"), None);
        assert_eq!(machine_of_account("10.0.0.5$"), None);
    }

    #[test]
    fn what_merges_at_each_level_and_what_is_left_to_ask() {
        let dir = std::env::temp_dir().join(format!("masstin_hostmap_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ok = "SUCCESSFUL_LOGON";
        let f = tl(&dir, "a.csv", &[
            // SRV01: its account from 10.0.0.5, a known machine (it is a destination below)
            row("2026-11-03T08:00:00+00:00", "DC01", ok, "4624", "3", "SRV01$", "", "10.0.0.5"),
            row("2026-11-03T09:00:00+00:00", "DC01", ok, "4768", "", "SRV01$@CORP.TEST", "", "10.0.0.5"),
            row("2026-11-03T09:30:00+00:00", "SRV01", ok, "4624", "3", "alice", "", "10.0.0.9"),
            // a logon by address alone from 10.0.0.5: the rows that follow the merge
            row("2026-11-03T10:00:00+00:00", "DC01", ok, "4624", "3", "alice", "", "10.0.0.5"),
            // a failed logon as a machine account proves nothing
            row("2026-11-03T10:05:00+00:00", "DC01", "FAILED_LOGON", "4625", "3", "DC02$", "", "10.0.0.66"),
            // a name the client gave: broad only
            row("2026-11-03T10:10:00+00:00", "DC01", ok, "4624", "3", "bob", "JUMPBOX", "10.0.0.50"),
            // an RDP logon written with the server's own name says nothing of 10.0.0.9
            row("2026-11-03T10:20:00+00:00", "SRV01", ok, "4624", "10", "alice", "SRV01", "10.0.0.9"),
            // two machines behind one address
            row("2026-11-03T11:00:00+00:00", "DC01", ok, "4624", "3", "WS01$", "WS01", "10.0.0.77"),
            row("2026-11-03T11:01:00+00:00", "DC01", ok, "4624", "3", "WS02$", "WS02", "10.0.0.77"),
            // a service account next to the machine's own: the machine wins
            row("2026-11-03T11:10:00+00:00", "DC01", ok, "4624", "3", "SQL01$", "SQL01", "10.0.0.80"),
            row("2026-11-03T11:11:00+00:00", "DC01", ok, "4624", "3", "gmsa_sql$", "", "10.0.0.80"),
            // a `NAME$` alone that is no machine anywhere: broad, with the caveat
            row("2026-11-03T11:20:00+00:00", "DC01", ok, "4624", "3", "svc_backup$", "", "10.0.0.81"),
            // DC02 at two addresses in the same hours: neither without asking
            row("2026-11-03T12:00:00+00:00", "DC01", ok, "4624", "3", "DC02$", "", "10.0.0.2"),
            row("2026-11-03T12:30:00+00:00", "DC01", ok, "4624", "3", "DC02$", "", "10.0.0.99"),
            row("2026-11-03T13:00:00+00:00", "DC01", ok, "4624", "3", "DC02$", "", "10.0.0.2"),
            row("2026-11-03T13:10:00+00:00", "DC02", ok, "4624", "3", "alice", "", "10.0.0.9"),
            // DC01 moved: .1 in October, .36 in November, never both: both are DC01
            row("2026-10-28T08:00:00+00:00", "DC01", ok, "4624", "3", "DC01$", "", "10.0.0.1"),
            row("2026-11-03T08:00:00+00:00", "DC01", ok, "4624", "3", "DC01$", "", "10.0.0.36"),
            // an address that was one machine and then another
            row("2026-10-28T08:00:00+00:00", "DC01", ok, "4624", "3", "SRV01$", "", "10.0.0.40"),
            row("2026-11-03T08:00:00+00:00", "DC01", ok, "4624", "3", "DC02$", "", "10.0.0.40"),
        ]);
        let t = build(&[f.clone()], 0.05).unwrap();
        let e = entry(&t, "10.0.0.5");
        assert_eq!((e.host.as_str(), e.level, e.rows), ("SRV01", Some(Level::Standard), 3));
        assert!(e.evidence().starts_with("machine-account x2 (4624 of SRV01$ on DC01)"), "{}", e.evidence());
        // a failed logon as a machine account is no evidence
        assert_eq!((entry(&t, "10.0.0.66").host.as_str(), entry(&t, "10.0.0.66").names.len(), entry(&t, "10.0.0.66").rows), ("", 0, 1));
        assert_eq!((entry(&t, "10.0.0.50").host.as_str(), entry(&t, "10.0.0.50").level), ("JUMPBOX", Some(Level::Broad)));
        let e = entry(&t, "10.0.0.9");
        assert_eq!((e.host.as_str(), e.level, e.rows), ("", None, 3));
        assert_eq!(e.level_name(), "unknown");
        let e = entry(&t, "10.0.0.77");
        assert_eq!((e.host.as_str(), e.level, e.level_name()), ("", None, "ask"));
        assert!(e.note.starts_with("several names at this address in the same period"), "{}", e.note);
        let e = entry(&t, "10.0.0.80");
        assert_eq!((e.host.as_str(), e.level), ("SQL01", Some(Level::Standard)));
        assert!(e.note.contains("GMSA_SQL$") && e.note.contains("service account"), "{}", e.note);
        let e = entry(&t, "10.0.0.81");
        assert_eq!((e.host.as_str(), e.level), ("SVC_BACKUP", Some(Level::Broad)));
        assert!(e.note.contains("may be a service account"), "{}", e.note);
        for a in ["10.0.0.2", "10.0.0.99"] {
            let e = entry(&t, a);
            assert_eq!((e.host.as_str(), e.level), ("DC02", None), "{a}");
            assert!(e.note.contains("also seen at"), "{}", e.note);
        }
        for a in ["10.0.0.1", "10.0.0.36"] {
            assert_eq!((entry(&t, a).host.as_str(), entry(&t, a).level), ("DC01", Some(Level::Standard)), "{a}");
        }
        let e = entry(&t, "10.0.0.40");
        assert_eq!(e.level, None);
        assert!(e.note.starts_with("the address changed hands"), "{}", e.note);

        // the levels
        let none = HashSet::new();
        assert!(t.merges(Level::Strict, &none).is_empty());
        let std_: Vec<String> = t.merges(Level::Standard, &none).into_iter().map(|(a, h)| format!("{a}>{h}")).collect();
        assert_eq!(std_.len(), 4, "{std_:?}");
        for m in ["10.0.0.5>SRV01", "10.0.0.80>SQL01", "10.0.0.1>DC01", "10.0.0.36>DC01"] {
            assert!(std_.iter().any(|x| x == m), "{m} in {std_:?}");
        }
        assert_eq!(t.merges(Level::Broad, &none).len(), 6);
        let skip: HashSet<String> = ["10.0.0.5".to_string()].into_iter().collect();
        assert_eq!(t.merges(Level::Standard, &skip).len(), 3);
        assert_eq!(t.counts(), [0, 4, 2, 4, 2]);
        assert!(t.to_csv().lines().count() == t.entries.len() + 1 && t.to_csv().starts_with("address,host,merge,"));

        // what a machine says of itself settles which of two addresses is its
        write_facts(&f, &[Fact { host: "DC02.corp.test".into(), address: "10.0.0.2".into(), kind: "own".into(), from: String::new(), to: String::new(), source: "SYSTEM hive of DC02".into() }]).unwrap();
        // and the domain controller a member found
        write_facts(&f, &[Fact { host: "DC09.corp.test".into(), address: "10.0.0.9".into(), kind: "locator".into(), from: "2026-11-03 09:00:00".into(), to: "2026-11-03 09:00:00".into(), source: "Group Policy 5308 on SRV01".into() }]).unwrap();
        assert_eq!(write_facts(&f, &[]).unwrap(), None);
        assert_eq!(read_facts(&f).len(), 2);
        let t = build(&[f.clone()], 0.05).unwrap();
        assert_eq!((entry(&t, "10.0.0.2").host.as_str(), entry(&t, "10.0.0.2").level), ("DC02", Some(Level::Strict)));
        assert_eq!(entry(&t, "10.0.0.99").level, None, "the other address of DC02 stays out");
        assert_eq!((entry(&t, "10.0.0.9").host.as_str(), entry(&t, "10.0.0.9").level), ("DC09", Some(Level::Strict)));
        assert_eq!(t.merges(Level::Strict, &none).len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
