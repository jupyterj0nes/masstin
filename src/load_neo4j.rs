// load-neo4j: stream a masstin CSV into a Neo4j graph.
//
// MEMORY MODEL (post-streaming refactor):
//   Pass 1 walks the CSV line-by-line collecting only:
//     - `counts`: weighted (src_ip → src_computer) evidence for IP↔host
//       unification. Bounded by distinct (ip, host) pairs (~thousands).
//     - `literal_hosts`: non-IP non-local hostnames seen as src or dst.
//       Bounded by total distinct hosts (~hundreds to a few thousand).
//   No raw lines or processed rows are accumulated. Memory ~few MB
//   regardless of file size.
//
//   Pass 2 walks the CSV again, resolves each row through the IP↔host
//   map, and feeds a fixed-size buffer (EDGE_BATCH rows = 5 000) that
//   flushes to the database when full. In ungrouped mode this is fully
//   streaming — peak memory is one batch (~1 MB). In grouped mode a
//   `grouped_map` is built; that map is bounded by distinct
//   (dst, user, logon_type) tuples, typically <10 k for any corpus, so
//   memory remains bounded by the GRAPH shape rather than the file size.
//
// The previous in-memory pre-pass approach allocated three large
// Vec<String> accumulators (`processed_lines`, `edges_to_emit`,
// `resolved_edges`) plus the full file as a String at the top — peak
// memory was 4-6x the file size and the loader OOMd around 1.7M edges
// on hosts with a contended page file. The streaming refactor removes
// that ceiling.

use neo4rs::*;
use futures::stream::*;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use chrono::{DateTime, Utc, NaiveDateTime, TimeZone};

/// Parse a user-supplied start/end time string (from the CLI flags) into a
/// DateTime<Utc>. Accepts the Cortex flag format `YYYY-MM-DD HH:MM:SS [-0000]`
/// already validated upstream, plus a bare `YYYY-MM-DD HH:MM:SS`.
fn parse_time_window(raw: &str) -> Option<DateTime<Utc>> {
    let trimmed = raw.trim();
    let base = if trimmed.len() >= 19 {
        &trimmed[..19]
    } else {
        trimmed
    };
    NaiveDateTime::parse_from_str(base, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|naive| Utc.from_utc_datetime(&naive))
}

/// Parse a CSV `time_created` cell into a DateTime<Utc>. masstin produces
/// several formats depending on the original source.
fn parse_csv_time(raw: &str) -> Option<DateTime<Utc>> {
    let s = raw.trim();
    if s.is_empty() { return None; }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(s.trim_end_matches(" UTC"), "%Y-%m-%d %H:%M:%S%.f") {
        return Some(Utc.from_utc_datetime(&dt));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(s.trim_end_matches('Z'), "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(Utc.from_utc_datetime(&dt));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(Utc.from_utc_datetime(&dt));
    }
    None
}

pub mod load {
    // Load module code
}

#[derive(Debug)]
struct GroupedData {
    earliest_date: String,
    count: usize,
    event_type: String,
    event_id: String,
    log_source: String,
    subject_user: String,
    subject_domain: String,
    target_domain: String,
    src_computer: String,
    src_ip: String,
}

/// A fully-resolved edge ready for batched insertion.
struct ResolvedEdge {
    origin: String,
    destination: String,
    rel_type: String,
    time: String,
    event_type: String,
    event_id: String,
    log_source: String,
    logon_type: String,
    src_computer: String,
    src_ip: String,
    target_user_name: String,
    target_domain_name: String,
    subject_user_name: String,
    subject_domain_name: String,
    /// session identifier (Windows LogonId, Linux sshd pid): the same on a
    /// login and on the LOGOFF that closes it
    logon_id: String,
    count: i64,
}

const EDGE_BATCH: usize = 5_000;

const OLD_HEADER: &str = "time_created,dst_computer,event_id,subject_user_name,subject_domain_name,target_user_name,target_domain_name,logon_type,src_computer,src_ip,process,log_filename";
const NEW_HEADER: &str = "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename";

/// Log family of a `log_filename` value (`archive.tar.gz:[root]/var/log/
/// secure-20260830.gz` -> `secure`; any EVTX -> `evtx`).
pub(crate) fn log_source_family(raw: &str) -> &'static str {
    let base = raw.trim_matches('"')
        .rsplit(|c: char| c == '/' || c == '\\' || c == ':')
        .next().unwrap_or("").to_lowercase();
    if base.starts_with("secure") || base.starts_with("auth.log") { "secure" }
    else if base.starts_with("messages") { "messages" }
    else if base.starts_with("wtmp") { "wtmp" }
    else if base.starts_with("btmp") { "btmp" }
    else if base.starts_with("utmp") { "utmp" }
    else if base == "lastlog" { "lastlog" }
    else if base.starts_with("audit.log") { "audit" }
    else if base.ends_with(".journal") || base.ends_with(".journal~") { "journal" }
    else if base.ends_with(".evtx") { "evtx" }
    else if base.is_empty() { "" }
    else { "other" }
}

/// Column position used when a layout lacks a column (`event_type` in
/// the legacy 12-column CSV).
const NONE_COL: usize = usize::MAX;

/// Column-index map for both supported masstin CSV layouts. Resolved once
/// from the header line.
#[derive(Clone, Copy)]
struct Indices {
    dst: usize,
    event_type: usize,
    log_source: usize,
    event_id: usize,
    subject_user: usize,
    subject_domain: usize,
    target_user: usize,
    target_domain: usize,
    logon_type: usize,
    src_computer: usize,
    src_ip: usize,
    logon_id: usize,
}

fn parse_indices(header: &str) -> Option<Indices> {
    if header == NEW_HEADER {
        Some(Indices {
            dst: 1, event_type: 2, log_source: 13, event_id: 3, subject_user: 9, subject_domain: 10,
            target_user: 5, target_domain: 6, logon_type: 4,
            src_computer: 7, src_ip: 8, logon_id: 11,
        })
    } else if header == OLD_HEADER {
        Some(Indices {
            dst: 1, event_type: NONE_COL, log_source: 11, event_id: 2, subject_user: 3, subject_domain: 4,
            target_user: 5, target_domain: 6, logon_type: 7,
            src_computer: 8, src_ip: 9, logon_id: NONE_COL,
        })
    } else {
        None
    }
}

/// An IPv4 address (with or without a `:port`) or an IPv6 address. The
/// former test took any string of hex digits (`CAFE`, `BADC0DE`) for an
/// IPv6 address and any string of digits for an IPv4 one.
pub(crate) fn looks_like_ip(s: &str) -> bool {
    let ipv4 = s.contains('.') && s.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':');
    ipv4 || s.split('%').next().unwrap_or(s).parse::<std::net::Ipv6Addr>().is_ok()
}

/// The address a cell starts with: `10.0.0.1 (x)`, `10.0.0.1:3389`,
/// `fe80::1%eth0`, `[2001:db8::1]`. The former version stopped at the
/// first letter and cut every IPv6 address short.
pub(crate) fn extract_leading_ip<'a>(s: &'a str) -> Option<&'a str> {
    let cand = s.trim_start_matches('[').split(|c: char| c == ' ' || c == '[' || c == ']' || c == '(').next().unwrap_or("");
    if cand.is_empty() {
        return None;
    }
    if cand.contains('.') && cand.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':') {
        return Some(cand);
    }
    if cand.split('%').next().unwrap_or(cand).parse::<std::net::Ipv6Addr>().is_ok() {
        return Some(cand);
    }
    None
}


/// Short host name of an FQDN (`LVRMVP03.SIR.RENFE.ES` -> `LVRMVP03`) —
/// unless two different FQDNs in the corpus share that short name
/// (`RUNDECK.DESA.SIR.RENFE.ES` vs `RUNDECK.SIR.RENFE.ES`), in which case
/// the full name is kept so two machines do not become one node.
fn short_name(v: &str, ambiguous: &HashSet<String>) -> String {
    if v.contains('.') && !looks_like_ip(v) {
        let short = v.split('.').next().unwrap_or(v);
        if !short.is_empty() && !ambiguous.contains(short) {
            return short.to_string();
        }
    }
    v.to_string()
}

fn shorten_parts(parts: &mut [String], idx: &Indices, ambiguous: &HashSet<String>) {
    for col in [idx.dst, idx.src_computer, idx.src_ip] {
        if col < parts.len() {
            parts[col] = short_name(&parts[col], ambiguous);
        }
    }
}

/// Outcome of cleaning one raw CSV line. `Filtered` covers time-window
/// rejection and the self-loop / local-value drops; the caller bumps the
/// time-filter counter on `FilteredTime`.
enum RowOutcome {
    FilteredTime,
    Filtered,
    Cleaned(Vec<String>),
}

/// Apply masstin's row cleaning to a single CSV line: time-window filter,
/// uppercase + bracket strip, IP/hostname normalization on the three
/// host-bearing columns, then self-loop / local-value rejection. Returns
/// the parts vector (without the trailing `log_filename` column the
/// existing pipeline always discards).
fn clean_row(
    raw_line: &str,
    idx: &Indices,
    local_values: &HashSet<&str>,
    start_dt: Option<DateTime<Utc>>,
    end_dt: Option<DateTime<Utc>>,
) -> RowOutcome {
    // Time filter is applied against the RAW first column (before uppercase
    // mutation) — timestamps are ASCII-only so case is irrelevant but it's
    // safer to keep the order of operations identical to the legacy path.
    if start_dt.is_some() || end_dt.is_some() {
        if let Some(time_cell) = raw_line.split(',').next() {
            if let Some(row_dt) = parse_csv_time(time_cell) {
                if let Some(start) = start_dt {
                    if row_dt < start { return RowOutcome::FilteredTime; }
                }
                if let Some(end) = end_dt {
                    if row_dt > end { return RowOutcome::FilteredTime; }
                }
            }
        }
    }

    // Host / IP / type columns are upper-cased for matching; the two user
    // columns keep their original case (Linux accounts are case-sensitive;
    // the relationship TYPE is still upper-cased by sanitize_rel_type, so
    // directory accounts typed in different case stay one type, but the
    // `target_user_name` property shows what was actually logged).
    // fields read with quotes honoured (a comma inside a quoted field can
    // no longer shift the columns); then the same cleaning as before
    let fields: Vec<String> = crate::graph_hunt_common::engine::csv_fields(raw_line)
        .into_iter()
        .enumerate()
        .map(|(i, f)| {
            let f = f.replace("\\", "").replace("[", "").replace("]", "");
            if i == idx.target_user || i == idx.subject_user { f } else { f.to_uppercase() }
        })
        .collect();
    let mut row: Vec<&str> = fields.iter().map(|x| x.as_str()).collect();
    if row.len() <= idx.src_ip { return RowOutcome::Filtered; }
    // log_filename is reduced to its log family (secure, wtmp, audit,
    // Security.evtx ...) and kept as the edge's `log_source`, so
    // graph-hunt can tell which sources cover which period.
    let fam_owned = log_source_family(row.last().copied().unwrap_or(""));
    if let Some(last) = row.last_mut() { *last = fam_owned; }

    // dst_computer
    if let Some(ip) = extract_leading_ip(row[idx.dst]) {
        row[idx.dst] = ip;
    }
    // src_computer
    if let Some(ip) = extract_leading_ip(row[idx.src_computer]) {
        row[idx.src_computer] = ip;
    }
    // src_ip
    if let Some(ip) = extract_leading_ip(row[idx.src_ip]) {
        row[idx.src_ip] = ip;
    }
    // strip `host:port` / `host:instance` suffixes (preserve IPv6 literals)
    if row[idx.dst].contains(':') && !looks_like_ip(row[idx.dst]) {
        row[idx.dst] = row[idx.dst].split(':').next().unwrap_or(row[idx.dst]);
    }
    if row[idx.src_computer].contains(':') && !looks_like_ip(row[idx.src_computer]) {
        row[idx.src_computer] = row[idx.src_computer].split(':').next().unwrap_or(row[idx.src_computer]);
    }
    if row[idx.src_ip].contains(':') && !looks_like_ip(row[idx.src_ip]) {
        row[idx.src_ip] = row[idx.src_ip].split(':').next().unwrap_or(row[idx.src_ip]);
    }

    if local_values.contains(&row[idx.src_computer]) && local_values.contains(&row[idx.src_ip]) {
        return RowOutcome::Filtered;
    }
    if row[idx.dst] == row[idx.src_computer] || row[idx.dst] == row[idx.src_ip] {
        return RowOutcome::Filtered;
    }

    RowOutcome::Cleaned(row.into_iter().map(|s| s.to_string()).collect())
}

/// Pass-1 streaming aggregation. Returns (counts, literal_hosts,
/// filtered_by_time, kept_rows). The counts map drives IP→hostname
/// resolution; literal_hosts seeds the pre-create-nodes phase so the
/// edge batches downstream can MATCH instead of MERGE.
fn streaming_pass1(
    path: &str,
    idx: &Indices,
    local_values: &HashSet<&str>,
    start_dt: Option<DateTime<Utc>>,
    end_dt: Option<DateTime<Utc>>,
    alpha: f64,
) -> std::io::Result<(HashMap<(String, String), u32>, HashSet<String>, usize, usize, HashMap<String, (String, u32, f64)>, HashSet<String>)> {
    let mut counts: HashMap<(String, String), u32> = HashMap::new();
    let mut literal_hosts: HashSet<String> = HashSet::new();
    let mut filtered_by_time: usize = 0;
    let mut kept_rows: usize = 0;
    // Same-login co-occurrence (Linux): sshd with `UseDNS yes` records the
    // peer by name in secure/journald, while auditd, btmp and many wtmp
    // records keep its IP. The same login therefore appears as two CSV rows,
    // one carrying only a name and one only an IP, with the same
    // destination, account, outcome and second. Pairing them gives IP ->
    // host evidence that no single row carries; without it one source
    // machine becomes two graph nodes and its history is split in half.
    // Key: (dst, user, second, event_type) -> (ips, names), single-sided
    // rows only.
    let mut cooc = crate::graph_hunt_common::resolve::CoocCollector::new();
    let mut fqdn_by_short: HashMap<String, HashSet<String>> = HashMap::new();

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    for (i, line_result) in reader.lines().enumerate() {
        let line = line_result?;
        if i == 0 { continue; }  // header already validated upstream
        match clean_row(&line, idx, local_values, start_dt, end_dt) {
            RowOutcome::FilteredTime => { filtered_by_time += 1; }
            RowOutcome::Filtered => {}
            RowOutcome::Cleaned(parts) => {
                kept_rows += 1;
                for col in [idx.dst, idx.src_computer, idx.src_ip] {
                    let v = &parts[col];
                    if v.contains('.') && !looks_like_ip(v) {
                        if let Some(short) = v.split('.').next() {
                            fqdn_by_short.entry(short.to_string()).or_default().insert(v.clone());
                        }
                    }
                }
                {
                    let sc = parts[idx.src_computer].as_str();
                    let si = parts[idx.src_ip].as_str();
                    let sc_local = local_values.contains(sc);
                    let si_local = local_values.contains(si);
                    let side = if sc_local && !si_local && looks_like_ip(si) {
                        Some((si.to_string(), true))
                    } else if !sc_local && si_local && !looks_like_ip(sc) {
                        Some((sc.to_string(), false))
                    } else { None };
                    if let Some((v, is_ip)) = side {
                        // only authentication outcomes with a named
                        // account can vote; pre-auth touches and session
                        // ends are skipped (they were 80 % of the rows and
                        // exhausted memory on a 12 M-row timeline)
                        let et = if idx.event_type == NONE_COL { "" } else { parts[idx.event_type].as_str() };
                        let user = parts[idx.target_user].as_str();
                        if (et == "SUCCESSFUL_LOGON" || et == "FAILED_LOGON") && !user.is_empty() && user != "\"\"" && user != "NO_USER" {
                            cooc.add(&parts[idx.dst], user, &parts[0], et, &v, is_ip);
                        }
                    }
                }
                // (src_ip, src_computer) direct evidence
                if !local_values.contains(parts[idx.src_computer].as_str())
                    && !local_values.contains(parts[idx.src_ip].as_str())
                    && parts[idx.src_computer] != parts[idx.src_ip]
                {
                    let weight: u32 =
                        if parts[idx.event_id] == "4778" || parts[idx.event_id] == "4779" {
                            1000
                        } else { 1 };
                    *counts
                        .entry((parts[idx.src_ip].clone(), parts[idx.src_computer].clone()))
                        .or_insert(0) += weight;
                }
                // Machine-account hint (target_user = MACHINE$ → IP)
                if local_values.contains(parts[idx.src_computer].as_str())
                    && !local_values.contains(parts[idx.src_ip].as_str())
                {
                    let target_user = parts[idx.target_user].as_str();
                    if target_user.ends_with('$') && target_user.len() > 1 {
                        let machine = &target_user[..target_user.len() - 1];
                        if !looks_like_ip(machine) && !machine.contains('.') && !machine.is_empty() {
                            *counts
                                .entry((parts[idx.src_ip].clone(), machine.to_uppercase()))
                                .or_insert(0) += 100;
                        }
                    }
                }
                // literal hosts: non-IP non-local src/dst names that will appear
                // as graph nodes after resolution (anything matching an IP will
                // be resolved through ip_to_host downstream).
                for col in &[idx.dst, idx.src_computer] {
                    let v = &parts[*col];
                    if !local_values.contains(v.as_str()) && !looks_like_ip(v) {
                        literal_hosts.insert(v.clone());
                    }
                }
            }
        }
    }
    // One vote per unambiguous same-login pair (exactly one IP and one
    // name recorded for that login). The mapping is NOT used to merge
    // nodes: the name is only what the destination's sshd resolved by
    // reverse DNS at that moment (stale PTR, DHCP reuse, NAT and aliases
    // all break it). It is kept only when every vote agrees and there are
    // unlikely to be chance coincidences (Poisson model of an unrelated
    // login in the same second, Benjamini-Hochberg across IPs at alpha;
    // graph_hunt_common::resolve), and it is written to the IP node as
    // `resolved_name` / `resolved_votes` / `resolved_p` for the analyst.
    let resolved_names: HashMap<String, (String, u32, f64)> = cooc.resolve(alpha);
    drop(cooc);
    // Short names shared by two or more different FQDNs stay fully
    // qualified; everything collected above is mapped to its final name.
    let ambiguous: HashSet<String> = fqdn_by_short
        .into_iter()
        .filter(|(_, set)| set.len() > 1)
        .map(|(short, _)| short)
        .collect();
    if !ambiguous.is_empty() {
        let mut list: Vec<&String> = ambiguous.iter().collect();
        list.sort();
        crate::banner::print_phase_detail(
            "Host names:",
            &format!("{} short name(s) shared by different FQDNs kept fully qualified: {}",
                     ambiguous.len(), list.iter().take(8).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")),
        );
    }
    let counts: HashMap<(String, String), u32> = counts
        .into_iter()
        .fold(HashMap::new(), |mut m, ((ip, host), w)| {
            *m.entry((short_name(&ip, &ambiguous), short_name(&host, &ambiguous))).or_insert(0) += w;
            m
        });
    let literal_hosts: HashSet<String> = literal_hosts.into_iter().map(|h| short_name(&h, &ambiguous)).collect();
    let resolved_names: HashMap<String, (String, u32, f64)> = resolved_names
        .into_iter()
        .map(|(ip, (name, v, p))| (ip, (short_name(&name, &ambiguous), v, p)))
        .collect();
    Ok((counts, literal_hosts, filtered_by_time, kept_rows, resolved_names, ambiguous))
}

fn derive_ip_to_host(counts: &HashMap<(String, String), u32>) -> HashMap<String, String> {
    let mut best: HashMap<String, (String, u32)> = HashMap::new();
    for ((ip, host), weight) in counts {
        let entry = best.entry(ip.clone()).or_insert((host.clone(), 0));
        if *weight > entry.1 {
            *entry = (host.clone(), *weight);
        }
    }
    let mut out: HashMap<String, String> = HashMap::new();
    for (ip, (host, _)) in best {
        out.insert(ip, host);
    }
    out
}

/// Sanitize a username into a valid Cypher relationship-type identifier:
/// [A-Za-z_][A-Za-z0-9_]*, anything else becomes `_`, digit-leading gets
/// a `u` prefix, empty becomes `NO_USER`, then uppercased.
fn sanitize_rel_type(user: &str) -> String {
    let stripped = user.split('@').next().unwrap_or(user);
    let mut s: String = stripped
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        s = format!("u{}", s);
    }
    if s.is_empty() { s = "NO_USER".to_string(); }
    s.to_uppercase()
}

/// Resolve one cleaned row into a `ResolvedEdge` (or None if both source
/// columns are noise and there's nothing to anchor the edge to). Bumps
/// `resolved_count` when the IP→host map was the source of the choice.
fn resolve_to_edge(
    parts: &[String],
    idx: &Indices,
    ip_to_host: &HashMap<String, String>,
    local_values: &HashSet<&str>,
    resolved_count: &mut usize,
) -> Option<ResolvedEdge> {
    let src_ip_raw = parts[idx.src_ip].as_str();
    let src_computer_raw = parts[idx.src_computer].as_str();
    let src_computer_is_ip = looks_like_ip(src_computer_raw) && src_computer_raw == src_ip_raw;
    let needs_resolution = local_values.contains(src_computer_raw) || src_computer_is_ip;

    let origin_name: String = if needs_resolution {
        if let Some(resolved) = ip_to_host.get(src_ip_raw) {
            *resolved_count += 1;
            resolved.clone()
        } else if !local_values.contains(src_ip_raw) {
            src_ip_raw.to_string()
        } else {
            return None;
        }
    } else {
        src_computer_raw.to_string()
    };

    let dst_raw = parts[idx.dst].as_str();
    let destination_name: String = if looks_like_ip(dst_raw) {
        ip_to_host.get(dst_raw).cloned().unwrap_or_else(|| dst_raw.to_string())
    } else {
        dst_raw.to_string()
    };

    if origin_name.eq_ignore_ascii_case(&destination_name) {
        return None;
    }

    let target_user_raw = &parts[idx.target_user];
    let relation_type = if target_user_raw.trim().is_empty() || target_user_raw == "\"\"" {
        "NO_USER"
    } else {
        target_user_raw.as_str()
    };
    let rel_type_normalized = sanitize_rel_type(relation_type);

    let clean_user = |s: &str| s.split('@').next().unwrap_or(s).to_string();

    Some(ResolvedEdge {
        origin: origin_name,
        destination: destination_name,
        rel_type: rel_type_normalized,
        time: parts[0].replace(" utc", "").replace(" ", "T"),
        event_type: if idx.event_type == NONE_COL { String::new() } else { parts[idx.event_type].clone() },
        event_id: if idx.event_id == NONE_COL { String::new() } else { parts[idx.event_id].clone() },
        log_source: if idx.log_source == NONE_COL || idx.log_source >= parts.len() { String::new() } else { parts[idx.log_source].clone() },
        logon_type: parts[idx.logon_type].clone(),
        src_computer: src_computer_raw.to_string(),
        src_ip: src_ip_raw.to_string(),
        target_user_name: clean_user(relation_type),
        target_domain_name: parts[idx.target_domain].clone(),
        subject_user_name: clean_user(&parts[idx.subject_user]),
        subject_domain_name: parts[idx.subject_domain].clone(),
        logon_id: if idx.logon_id == NONE_COL || idx.logon_id >= parts.len() { String::new() } else { parts[idx.logon_id].trim_matches('"').to_string() },
        count: 1,
    })
}

/// Flush a single batch of edges of the same `rel_type`. Returns (loaded,
/// errors) for this batch.
async fn flush_batch(
    graph: &Graph,
    rel_type: &str,
    chunk: &[ResolvedEdge],
    edge_op: &str,
) -> (usize, usize) {
    if chunk.is_empty() { return (0, 0); }
    let q_str = format!(
        "UNWIND range(0, size($origin) - 1) AS i \
         MATCH (o:host {{name: $origin[i]}}) \
         MATCH (d:host {{name: $destination[i]}}) \
         {} (o)-[r:{} {{time: datetime($time[i]), logon_type: $logon_type[i], \
         event_type: $event_type[i], event_id: $event_id[i], log_source: $log_source[i], \
         src_computer: $src_computer[i], src_ip: $src_ip[i], \
         target_user_name: $target_user_name[i], target_domain_name: $target_domain_name[i], \
         subject_user_name: $subject_user_name[i], subject_domain_name: $subject_domain_name[i], \
         logon_id: $logon_id[i], count: $count[i]}}]->(d) \
         RETURN count(r) AS created",
        edge_op, rel_type,
    );
    let q = query(&q_str)
        .param("origin", chunk.iter().map(|e| e.origin.clone()).collect::<Vec<String>>())
        .param("destination", chunk.iter().map(|e| e.destination.clone()).collect::<Vec<String>>())
        .param("time", chunk.iter().map(|e| e.time.clone()).collect::<Vec<String>>())
        .param("logon_type", chunk.iter().map(|e| e.logon_type.clone()).collect::<Vec<String>>())
        .param("event_type", chunk.iter().map(|e| e.event_type.clone()).collect::<Vec<String>>())
        .param("event_id", chunk.iter().map(|e| e.event_id.clone()).collect::<Vec<String>>())
        .param("log_source", chunk.iter().map(|e| e.log_source.clone()).collect::<Vec<String>>())
        .param("src_computer", chunk.iter().map(|e| e.src_computer.clone()).collect::<Vec<String>>())
        .param("src_ip", chunk.iter().map(|e| e.src_ip.clone()).collect::<Vec<String>>())
        .param("target_user_name", chunk.iter().map(|e| e.target_user_name.clone()).collect::<Vec<String>>())
        .param("target_domain_name", chunk.iter().map(|e| e.target_domain_name.clone()).collect::<Vec<String>>())
        .param("subject_user_name", chunk.iter().map(|e| e.subject_user_name.clone()).collect::<Vec<String>>())
        .param("subject_domain_name", chunk.iter().map(|e| e.subject_domain_name.clone()).collect::<Vec<String>>())
        .param("logon_id", chunk.iter().map(|e| e.logon_id.clone()).collect::<Vec<String>>())
        .param("count", chunk.iter().map(|e| e.count).collect::<Vec<i64>>());
    match graph.execute(q).await {
        Ok(mut result) => {
            // Report what the server actually created, not what we sent:
            // an edge whose endpoint MATCH finds no node is dropped
            // silently by Cypher and must show up as an error here.
            let created: usize = match result.next().await {
                Ok(Some(row)) => row.get::<i64>("created").unwrap_or(0).max(0) as usize,
                _ => chunk.len(),
            };
            let missing = chunk.len().saturating_sub(created);
            if missing > 0 && crate::parse::is_debug_mode() {
                eprintln!("[ERROR] edge batch (r:{}): {} of {} edges not created (endpoint node missing)",
                          rel_type, missing, chunk.len());
            }
            (created, missing)
        }
        Err(e) => {
            if crate::parse::is_debug_mode() {
                eprintln!("[ERROR] edge batch ({} edges, r:{}) failed: {:?}", chunk.len(), rel_type, e);
            }
            (0, chunk.len())
        }
    }
}

/// MERGE every host name queued in `new_nodes` and empty the queue. Must
/// run before ANY edge batch is flushed: the edge query MATCHes both
/// endpoints, so an origin/destination whose node has not been written
/// yet makes Cypher drop that edge without an error. Previously nodes
/// were only merged every 256 new names, while edge batches went out
/// every 5000 rows — on a corpus with a few dozen IP sources the IP nodes
/// were created only at the very end and every earlier batch from those
/// sources vanished (a 76k-row UAC timeline came out as 21k edges).
async fn merge_pending_nodes(graph: &Graph, new_nodes: &mut Vec<String>) {
    if new_nodes.is_empty() { return; }
    let batch: Vec<String> = new_nodes.drain(..).collect();
    match graph
        .execute(query("UNWIND $names AS n MERGE (:host {name: n})").param("names", batch))
        .await
    {
        Ok(mut r) => { let _ = r.next().await; }
        Err(e) => {
            if crate::parse::is_debug_mode() {
                eprintln!("[ERROR] host node pre-create failed: {:?}", e);
            }
        }
    }
}

pub async fn load_neo4j(
    files: &Vec<String>,
    database: &String,
    user: &String,
    db: &str,
    ungrouped: bool,
    start_time: Option<&String>,
    end_time: Option<&String>,
    alpha: f64,
) {
    let start_clock = std::time::Instant::now();

    // Phase 1: Connect
    crate::banner::print_phase("1", "2", "Connecting to Neo4j...");
    crate::banner::print_phase_detail("Database:", database);
    if ungrouped {
        crate::banner::print_phase_detail("Mode:", "UNGROUPED (one edge per CSV row)");
    }
    if let Some(s) = start_time {
        crate::banner::print_phase_detail("Start time:", s);
    }
    if let Some(e) = end_time {
        crate::banner::print_phase_detail("End time:", e);
    }
    let pass = match std::env::var("NEO4J_PASSWORD") {
        Ok(p) if !p.is_empty() => {
            crate::banner::print_phase_detail("Auth:", "password from $NEO4J_PASSWORD");
            p
        }
        _ => rpassword::prompt_password("MASSTIN - Enter Neo4j database password: ").unwrap(),
    };
    // Use ConfigBuilder so we can target a non-default database. Neo4j 5.x
    // / 2026.x deployments commonly have multiple DBs (one per case, one
    // per environment); `--db` lets the user pick. Defaults to `neo4j`.
    let config = match ConfigBuilder::default()
        .uri(database)
        .user(user)
        .password(&pass)
        .db(db)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("MASSTIN - Error: failed to build Neo4j config: {}", e);
            return;
        }
    };
    let graph = Graph::connect(config).await.unwrap();
    crate::banner::print_phase_detail("Database (Neo4j):", db);
    crate::banner::print_phase_result("Connected");

    match graph.execute(query("CREATE INDEX host_name IF NOT EXISTS FOR (h:host) ON (h.name)")).await {
        Ok(mut r) => { let _ = r.next().await; }
        Err(_) => {}
    }
    crate::banner::print_phase_result("Index :host(name) ready");

    let start_dt = start_time.and_then(|s| parse_time_window(s));
    let end_dt = end_time.and_then(|s| parse_time_window(s));

    for file in files {
        // ── Header detection (read only the first line) ──
        let header_line = {
            let f = match File::open(file) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("MASSTIN - cannot open {}: {}", file, e);
                    continue;
                }
            };
            let mut reader = BufReader::new(f);
            let mut buf = String::new();
            if reader.read_line(&mut buf).is_err() {
                eprintln!("MASSTIN - cannot read header from {}", file);
                continue;
            }
            buf.trim_end_matches(['\n', '\r']).to_string()
        };

        let idx = match parse_indices(&header_line) {
            Some(i) => i,
            None => {
                println!("MASSTIN - File {} has not been generated by Masstin", file);
                continue;
            }
        };

        let local_values: HashSet<&str> = ["LOCAL", "LOCALHOST", "127.0.0.1", "::1", "::", "0.0.0.0",
            "DEFAULT_VALUE", "\"\"", "-", "", " "].iter().cloned().collect();

        // ── Pass 1: stream-collect counts + literal hosts ──
        let (counts, mut literal_hosts, filtered_by_time, kept_rows, resolved_names, ambiguous) =
            match streaming_pass1(file, &idx, &local_values, start_dt, end_dt, alpha) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("MASSTIN - pass-1 read failed on {}: {}", file, e);
                    continue;
                }
            };
        if filtered_by_time > 0 {
            crate::banner::print_phase_detail(
                "Time window:",
                &format!("{} rows dropped (outside [start, end] window)", filtered_by_time),
            );
        }
        crate::banner::print_phase_detail(
            "Pass 1:",
            &format!("{} kept rows; {} (ip,host) evidence pairs; {} literal hosts",
                     kept_rows, counts.len(), literal_hosts.len()),
        );

        let ip_to_host = derive_ip_to_host(&counts);
        drop(counts);  // free the (ip,host)→weight map; ip_to_host is what we keep

        // All graph host names = literal hosts ∪ resolved targets ∪ unresolved
        // IPs that will appear as nodes. Capture the latter from ip_to_host
        // keys (= IPs we have resolved to a hostname; not added). Unresolved
        // IPs and `EXTERNAL`-style attacker sources go in as their raw form
        // when they survive Pass 2 — we handle those by collecting them
        // during the second pass too.
        for h in ip_to_host.values() { literal_hosts.insert(h.clone()); }

        // ── Phase 2: stream-load edges ──
        let phase_label = if ungrouped {
            format!("Streaming-loading up to {} edges to Neo4j...", kept_rows)
        } else {
            format!("Streaming-loading (grouped) up to {} rows to Neo4j...", kept_rows)
        };
        crate::banner::print_phase("2", "2", &phase_label);

        let edge_op = if ungrouped { "CREATE" } else { "MERGE" };

        // Buffers per rel_type. Each rel_type has its own pending list; we
        // flush a list when it reaches EDGE_BATCH. At the end (or when total
        // pending across all types exceeds 2*EDGE_BATCH to bound memory) we
        // flush everything. Keeping per-rel-type buffers respects the
        // schema's choice of using the username as the relationship label
        // (Cypher can't parametrize a rel type, so each UNWIND query needs
        // a single literal label).
        let mut pending: HashMap<String, Vec<ResolvedEdge>> = HashMap::new();
        let mut total_pending: usize = 0;
        let mut loaded: usize = 0;
        let mut errors: usize = 0;
        let mut resolved_count: usize = 0;
        // We pre-create nodes lazily — on first appearance of a new host
        // name we MERGE it. To keep this cheap we batch host names too.
        let mut nodes_known: HashSet<String> = HashSet::new();
        // Seed with the literal hosts we already gathered in Pass 1 so we
        // don't re-merge them per edge.
        let host_seed: Vec<String> = literal_hosts.iter().cloned().collect();
        match graph
            .execute(query("UNWIND $names AS n MERGE (:host {name: n})").param("names", host_seed))
            .await
        {
            Ok(mut r) => { let _ = r.next().await; }
            Err(e) => {
                if crate::parse::is_debug_mode() {
                    eprintln!("[ERROR] host node pre-create failed: {:?}", e);
                }
            }
        }
        for h in literal_hosts.drain() { nodes_known.insert(h); }

        // Helper to lazily MERGE any unknown node names that show up in
        // batches resolved during Pass 2 (e.g. an unresolved IP, or an
        // "EXTERNAL" attacker source).
        let mut new_nodes: Vec<String> = Vec::new();
        // (destination, log file) -> (first, last) record time: the period
        // each collected log file covers on each host. Written to the host
        // node as `cov_ok` / `cov_fail` spans for graph-hunt.
        let mut file_spans: HashMap<(String, String), (i64, i64)> = HashMap::new();
        let mut ensure_node = |name: &str, new_nodes: &mut Vec<String>, known: &mut HashSet<String>| {
            if !known.contains(name) {
                new_nodes.push(name.to_string());
                known.insert(name.to_string());
            }
        };

        let pb = crate::banner::create_progress_bar(kept_rows as u64);

        // GROUPED mode accumulator (bounded by distinct (dst,user,type)
        // tuples — small even for huge corpora).
        let mut grouped_map: HashMap<(String, String, String, String, String, String), GroupedData> = HashMap::new();

        // ── Pass 2: stream the file again ──
        let f = match File::open(file) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("MASSTIN - pass-2 cannot open {}: {}", file, e);
                continue;
            }
        };
        let reader = BufReader::new(f);
        for (line_i, line_result) in reader.lines().enumerate() {
            if line_i == 0 { continue; }  // header
            let line = match line_result {
                Ok(l) => l,
                Err(_) => continue,
            };
            let parts = match clean_row(&line, &idx, &local_values, start_dt, end_dt) {
                RowOutcome::Cleaned(p) => p,
                _ => continue,
            };
            let mut parts = parts;
            shorten_parts(&mut parts, &idx, &ambiguous);
            pb.inc(1);

            if ungrouped {
                let edge = match resolve_to_edge(&parts, &idx, &ip_to_host, &local_values, &mut resolved_count) {
                    Some(e) => e,
                    None => continue,
                };
                if let Some(t) = crate::graph_hunt_common::parse_ts(&edge.time) {
                    let t = t.and_utc().timestamp();
                    let raw_file = crate::graph_hunt_common::engine::csv_fields(&line).pop().unwrap_or_default();
                    let e = file_spans.entry((edge.destination.clone(), raw_file)).or_insert((t, t));
                    if t < e.0 { e.0 = t; }
                    if t > e.1 { e.1 = t; }
                }
                // Lazy-merge any new nodes
                ensure_node(&edge.origin, &mut new_nodes, &mut nodes_known);
                ensure_node(&edge.destination, &mut new_nodes, &mut nodes_known);
                if new_nodes.len() >= 256 {
                    merge_pending_nodes(&graph, &mut new_nodes).await;
                }

                let rt = edge.rel_type.clone();
                let buf = pending.entry(rt.clone()).or_insert_with(Vec::new);
                buf.push(edge);
                total_pending += 1;
                if buf.len() >= EDGE_BATCH {
                    let chunk: Vec<ResolvedEdge> = buf.drain(..).collect();
                    total_pending -= chunk.len();
                    merge_pending_nodes(&graph, &mut new_nodes).await;
                    let (l, e) = flush_batch(&graph, &rt, &chunk, edge_op).await;
                    loaded += l;
                    errors += e;
                }
                // Soft cap on total in-flight buffers; flush every rel_type
                // with at least 256 pending edges to bound memory.
                if total_pending >= 4 * EDGE_BATCH {
                    let keys_to_flush: Vec<String> = pending.iter()
                        .filter(|(_, v)| v.len() >= 256)
                        .map(|(k, _)| k.clone())
                        .collect();
                    merge_pending_nodes(&graph, &mut new_nodes).await;
                    for k in keys_to_flush {
                        if let Some(buf) = pending.get_mut(&k) {
                            let chunk: Vec<ResolvedEdge> = buf.drain(..).collect();
                            total_pending -= chunk.len();
                            let (l, e) = flush_batch(&graph, &k, &chunk, edge_op).await;
                            loaded += l;
                            errors += e;
                        }
                    }
                }
            } else {
                // GROUPED: one edge per (dst, user, logon_type, source,
                // outcome). The source and the outcome are part of the key:
                // without them two origins using the same account on the
                // same host collapsed into one edge (only the first origin
                // survived), and refused attempts merged with successes.
                let user_clean = parts[idx.target_user].split('@').next()
                    .unwrap_or(&parts[idx.target_user]).to_uppercase();
                let et = if idx.event_type == NONE_COL { String::new() } else { parts[idx.event_type].clone() };
                let key = (
                    parts[idx.dst].clone(),
                    user_clean,
                    parts[idx.logon_type].clone(),
                    parts[idx.src_computer].clone(),
                    parts[idx.src_ip].clone(),
                    et.clone(),
                );
                let date = parts[0].clone();
                let entry = grouped_map.entry(key).or_insert(GroupedData {
                    earliest_date: date.clone(),
                    count: 0,
                    event_type: et.clone(),
                    event_id: if idx.event_id == NONE_COL { String::new() } else { parts[idx.event_id].clone() },
                    log_source: if idx.log_source == NONE_COL || idx.log_source >= parts.len() { String::new() } else { parts[idx.log_source].clone() },
                    subject_user: parts[idx.subject_user].clone(),
                    subject_domain: parts[idx.subject_domain].clone(),
                    target_domain: parts[idx.target_domain].clone(),
                    src_computer: parts[idx.src_computer].clone(),
                    src_ip: parts[idx.src_ip].clone(),
                });
                if date < entry.earliest_date {
                    entry.earliest_date = date;
                }
                entry.count += 1;
            }
        }

        // ── Drain grouped accumulator at end of stream ──
        if !ungrouped {
            for ((dst_computer, target_user_name, logon_type, _sc, _si, _et), data) in grouped_map.drain() {
                let parts: Vec<String> = vec![
                    data.earliest_date.clone(),
                    dst_computer.clone(),
                    data.count.to_string(),
                    data.subject_user.clone(),
                    data.subject_domain.clone(),
                    target_user_name.clone(),
                    data.target_domain.clone(),
                    logon_type.clone(),
                    data.src_computer.clone(),
                    data.src_ip.clone(),
                    data.event_type.clone(),
                    data.event_id.clone(),
                    data.log_source.clone(),
                ];
                // Local index map for the synthesized 10-col row (legacy
                // shape from the previous in-memory pipeline).
                let local_idx = Indices {
                    dst: 1, event_type: 10, log_source: 12, event_id: 11, subject_user: 3, subject_domain: 4,
                    target_user: 5, target_domain: 6, logon_type: 7,
                    src_computer: 8, src_ip: 9, logon_id: NONE_COL,
                };
                let edge = match resolve_to_edge(&parts, &local_idx, &ip_to_host, &local_values, &mut resolved_count) {
                    Some(mut e) => {
                        e.count = data.count as i64;
                        e
                    }
                    None => continue,
                };
                ensure_node(&edge.origin, &mut new_nodes, &mut nodes_known);
                ensure_node(&edge.destination, &mut new_nodes, &mut nodes_known);
                let rt = edge.rel_type.clone();
                let buf = pending.entry(rt.clone()).or_insert_with(Vec::new);
                buf.push(edge);
                total_pending += 1;
                if buf.len() >= EDGE_BATCH {
                    let chunk: Vec<ResolvedEdge> = buf.drain(..).collect();
                    total_pending -= chunk.len();
                    merge_pending_nodes(&graph, &mut new_nodes).await;
                    let (l, e) = flush_batch(&graph, &rt, &chunk, edge_op).await;
                    loaded += l;
                    errors += e;
                }
            }
        }

        // ── Final flush of any remaining new nodes + pending edge buffers ──
        merge_pending_nodes(&graph, &mut new_nodes).await;
        for (rt, mut buf) in pending.drain() {
            if buf.is_empty() { continue; }
            let chunk: Vec<ResolvedEdge> = buf.drain(..).collect();
            let (l, e) = flush_batch(&graph, &rt, &chunk, edge_op).await;
            loaded += l;
            errors += e;
        }

        pb.finish_and_clear();

        // Destination nodes: log coverage spans (ungrouped loads only).
        if !file_spans.is_empty() {
            let mut per_dst: HashMap<String, (Vec<(i64, i64)>, Vec<(i64, i64)>)> = HashMap::new();
            for ((dst, file), span) in file_spans.drain() {
                let (ok, fail) = crate::graph_hunt_common::coverage_kinds(log_source_family(&file));
                let x = per_dst.entry(dst).or_default();
                if ok { x.0.push(span); }
                if fail { x.1.push(span); }
            }
            let names: Vec<String> = per_dst.keys().cloned().collect();
            let oks: Vec<Vec<i64>> = names.iter().map(|n| crate::graph_hunt_common::merge_spans(per_dst[n].0.clone())).collect();
            let fails: Vec<Vec<i64>> = names.iter().map(|n| crate::graph_hunt_common::merge_spans(per_dst[n].1.clone())).collect();
            let q_cov = "UNWIND range(0, size($names) - 1) AS i                          MATCH (h:host {name: $names[i]})                          SET h.cov_ok = $oks[i], h.cov_fail = $fails[i]                          RETURN count(h) AS n";
            match graph.execute(query(q_cov).param("names", names).param("oks", oks).param("fails", fails)).await {
                Ok(mut r) => {
                    let n: i64 = match r.next().await { Ok(Some(row)) => row.get("n").unwrap_or(0), _ => 0 };
                    crate::banner::print_phase_detail("Coverage:", &format!("{} destination node(s) annotated with log-file time spans (cov_ok / cov_fail)", n));
                }
                Err(e) => eprintln!("[ERROR] coverage annotation failed: {:?}", e),
            }
        }

        // IP nodes: annotate (never merge) with the unanimous sshd name.
        if !resolved_names.is_empty() {
            let ips: Vec<String> = resolved_names.keys().cloned().collect();
            let names: Vec<String> = ips.iter().map(|i| resolved_names[i].0.clone()).collect();
            let vts: Vec<i64> = ips.iter().map(|i| resolved_names[i].1 as i64).collect();
            let pch: Vec<f64> = ips.iter().map(|i| resolved_names[i].2).collect();
            let q_annot = "UNWIND range(0, size($ips) - 1) AS i \
                           MATCH (h:host {name: $ips[i]}) \
                           SET h.resolved_name = $names[i], h.resolved_votes = $votes[i], h.resolved_p = $pch[i] \
                           RETURN count(h) AS n";
            match graph
                .execute(query(q_annot).param("ips", ips).param("names", names).param("votes", vts).param("pch", pch))
                .await
            {
                Ok(mut r) => {
                    let n: i64 = match r.next().await { Ok(Some(row)) => row.get("n").unwrap_or(0), _ => 0 };
                    crate::banner::print_phase_detail(
                        "IP nodes:",
                        &format!("{} annotated with resolved_name (unanimous same-login evidence, chance coincidence significant at FDR {}; nodes not merged)", n, alpha),
                    );
                }
                Err(e) => {
                    if crate::parse::is_debug_mode() {
                        eprintln!("[ERROR] resolved_name annotation failed: {:?}", e);
                    }
                }
            }
        }
        crate::banner::print_load_summary("Neo4j", loaded, resolved_count, errors, start_clock);
    }
}

#[cfg(test)]
mod ip_tests {
    use super::{extract_leading_ip, looks_like_ip};

    #[test]
    fn ipv6_and_hex_names() {
        assert!(looks_like_ip("10.0.0.1"));
        assert!(looks_like_ip("10.0.0.1:3389"));
        assert!(looks_like_ip("fe80::1"));
        assert!(looks_like_ip("2001:db8::10"));
        assert!(!looks_like_ip("CAFE"));
        assert!(!looks_like_ip("BADC0DE"));
        assert!(!looks_like_ip("12345"));
        assert_eq!(extract_leading_ip("10.0.0.1 (x)"), Some("10.0.0.1"));
        assert_eq!(extract_leading_ip("fe80::1%eth0"), Some("fe80::1%eth0"));
        assert_eq!(extract_leading_ip("[2001:db8::1]"), Some("2001:db8::1"));
        assert_eq!(extract_leading_ip("SRV01"), None);
        assert_eq!(extract_leading_ip("DEADBEEF"), None);
    }
}
