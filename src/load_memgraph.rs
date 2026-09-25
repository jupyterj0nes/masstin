use neo4rs::*;
use futures::stream::*;
use indicatif::ProgressBar;
use std::collections::HashSet;
use std::collections::HashMap;
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
/// several formats depending on the original source (EVTX → ISO 8601 with
/// fractional seconds, Cortex → `YYYY-MM-DD HH:MM:SS.fff UTC`, Linux →
/// `YYYY-MM-DD HH:MM:SS`). We try the common shapes in order.
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
    // Non-key fields: stored from the first row seen for this group
    subject_user: String,
    subject_domain: String,
    target_domain: String,
    src_computer: String,
    src_ip: String,
}

/// A fully-resolved edge ready for batched insertion. All IP→hostname
/// resolution, self-loop filtering and rel-type sanitization has already
/// happened in the pre-pass, so the database phase is a pure batched write:
/// edges are bucketed by `rel_type` and streamed through UNWIND queries.
struct ResolvedEdge {
    origin: String,
    destination: String,
    rel_type: String,
    time: String,
    logon_type: String,
    src_computer: String,
    src_ip: String,
    target_user_name: String,
    target_domain_name: String,
    subject_user_name: String,
    subject_domain_name: String,
    event_type: String,
    event_id: String,
    log_source: String,
    count: i64,
}

/// Edges per UNWIND batch. Each batch is a single Bolt round-trip carrying
/// this many edges, replacing what used to be one round-trip per edge — the
/// dominant residual cost once the :host(name) index removed the O(V*E)
/// MERGE-scan term.
const EDGE_BATCH: usize = 5_000;

/// Strip timezone suffix for Memgraph localDateTime().
/// Handles: "Z", "+00:00", "-05:00", etc.
fn strip_timezone(ts: &str) -> String {
    let ts = ts.trim_end_matches('Z');
    if ts.len() > 6 {
        let tail = &ts[ts.len()-6..];
        if (tail.starts_with('+') || tail.starts_with('-')) && tail.contains(':') {
            return ts[..ts.len()-6].to_string();
        }
    }
    ts.to_string()
}

fn looks_like_ip(s: &str) -> bool {
    let ipv4 = s.chars().all(|c| c.is_ascii_digit() || c == '.');
    let ipv6 = s.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
    ipv4 || ipv6
}

fn extract_leading_ip<'a>(s: &'a str) -> Option<&'a str> {
    let candidate = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ':')
        .collect::<String>();

    if candidate.contains('.') || candidate.contains(':') {
        Some(&s[..candidate.len()])
    } else {
        None
    }
}

pub async fn load_memgraph(
    files: &Vec<String>,
    database: &String,
    user: &String,
    ungrouped: bool,
    start_time: Option<&String>,
    end_time: Option<&String>,
) {
    let start_clock = std::time::Instant::now();

    // Phase 1: Connect
    crate::banner::print_phase("1", "2", "Connecting to Memgraph...");
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
    let config = ConfigBuilder::default()
        .uri(database)
        .user(user)
        .password("")
        .db("memgraph")
        .build()
        .unwrap();
    let graph = Graph::connect(config).await.unwrap();
    crate::banner::print_phase_result("Connected");

    // Ensure a label-property index on :host(name). Every edge insert runs
    // MERGE (origin:host {name:...}) / MERGE (destination:host {name:...});
    // without this index each MERGE is a full label scan, making the whole
    // load O(V*E) — super-linear and effectively unusable past a few hundred
    // thousand edges. Creating it up front turns each lookup into O(log V).
    // Idempotent: Memgraph errors if the index already exists, which is
    // harmless here, so the error is intentionally swallowed.
    match graph.execute(query("CREATE INDEX ON :host(name)")).await {
        Ok(mut r) => { let _ = r.next().await; }
        Err(_) => {}
    }
    crate::banner::print_phase_detail("Index:", ":host(name) ready");

    let start_dt = start_time.and_then(|s| parse_time_window(s));
    let end_dt = end_time.and_then(|s| parse_time_window(s));

    for file in files {
        let file_contents: String = std::fs::read_to_string(file).unwrap();
        let mut lines: Vec<&str> = file_contents.lines().collect();

        // Verify the file header (support both old and new format)
        let old_header = "time_created,dst_computer,event_id,subject_user_name,subject_domain_name,target_user_name,target_domain_name,logon_type,src_computer,src_ip,process,log_filename";
        let new_header = "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename";
        let is_new_format = lines.get(0).map(|h| *h == new_header).unwrap_or(false);
        let is_old_format = lines.get(0).map(|h| *h == old_header).unwrap_or(false);
        if lines.is_empty() || (!is_new_format && !is_old_format) {
            println!("MASSTIN - File {} has not been generated by Masstin", file);
            continue;
        }

        // Column index mapping
        let (idx_dst, idx_event_id, idx_subject_user, idx_subject_domain, idx_target_user, idx_target_domain, idx_logon_type, idx_src_computer, idx_src_ip) = if is_new_format {
            (1usize, 3usize, 9usize, 10usize, 5usize, 6usize, 4usize, 7usize, 8usize)
        } else {
            (1usize, 2usize, 3usize, 4usize, 5usize, 6usize, 7usize, 8usize, 9usize)
        };
        // event_type exists only in the 14-column layout; log_filename is the
        // last column in both and is reduced to its log family below.
        let idx_event_type: Option<usize> = if is_new_format { Some(2) } else { None };
        let idx_log_source: usize = if is_new_format { 13 } else { 11 };

        let local_values: HashSet<&str> =
                ["LOCAL", "127.0.0.1", "::1", "::", "0.0.0.0", "DEFAULT_VALUE", "\"\"", "-", ""," ",]
                .iter().cloned().collect();

        let mut filtered_by_time: usize = 0;

        let processed_lines: Vec<String> = lines
        .into_iter()
        .skip(1)
        .map(|line| line.replace("\\", "").replace("[", "").replace("]", "").to_uppercase())
        .filter_map(|line| {
            if start_dt.is_some() || end_dt.is_some() {
                if let Some(time_cell) = line.split(',').next() {
                    if let Some(row_dt) = parse_csv_time(time_cell) {
                        if let Some(start) = start_dt {
                            if row_dt < start { filtered_by_time += 1; return None; }
                        }
                        if let Some(end) = end_dt {
                            if row_dt > end { filtered_by_time += 1; return None; }
                        }
                    }
                }
            }

            let mut row: Vec<&str> = line.split(',').collect();
            let fam = crate::load_neo4j::log_source_family(row.last().copied().unwrap_or(""));
            if let Some(last) = row.last_mut() { *last = fam; }

            if let Some(ip) = extract_leading_ip(row[idx_dst]) {
                row[idx_dst] = ip;
            } else if row[idx_dst].contains('.') && !looks_like_ip(row[idx_dst]) {
                row[idx_dst] = row[idx_dst].split('.').next().unwrap_or(row[idx_dst]);
            }

            if let Some(ip) = extract_leading_ip(row[idx_src_computer]) {
                row[idx_src_computer] = ip;
            } else if row[idx_src_computer].contains('.') && !looks_like_ip(row[idx_src_computer]) {
                row[idx_src_computer] = row[idx_src_computer].split('.').next().unwrap_or(row[idx_src_computer]);
            }

            if let Some(ip) = extract_leading_ip(row[idx_src_ip]) {
                row[idx_src_ip] = ip;
            } else if row[idx_src_ip].contains('.') && !looks_like_ip(row[idx_src_ip]) {
                row[idx_src_ip] = row[idx_src_ip].split('.').next().unwrap_or(row[idx_src_ip]);
            }

            // Strip `hostname:port` / `hostname:instance` suffixes, but preserve
            // IPv6 literals (they are all hex + colons and must never be split).
            if row[idx_dst].contains(':') && !looks_like_ip(row[idx_dst]) {
                row[idx_dst] = row[idx_dst].split(':').next().unwrap_or(row[idx_dst]);
            }

            if row[idx_src_computer].contains(':') && !looks_like_ip(row[idx_src_computer]) {
                row[idx_src_computer] = row[idx_src_computer].split(':').next().unwrap_or(row[idx_src_computer]);
            }

            if row[idx_src_ip].contains(':') && !looks_like_ip(row[idx_src_ip]) {
                row[idx_src_ip] = row[idx_src_ip].split(':').next().unwrap_or(row[idx_src_ip]);
            }

            if local_values.contains(&row[idx_src_computer]) && local_values.contains(&row[idx_src_ip]) {
                None
            } else if row[idx_dst] == row[idx_src_computer] {
                None
            } else if row[idx_dst] == row[idx_src_ip] {
                None
            } else {
                Some(row.join(","))
            }
        })
        .collect();

        if filtered_by_time > 0 {
            crate::banner::print_phase_detail(
                "Time window:",
                &format!("{} rows dropped (outside [start, end] window)", filtered_by_time),
            );
        }

        // ── Frequency map with 4778/4779 priority (x1000 weight) ──
        let mut counts: HashMap<(String, String), u32> = HashMap::new();

        for line in &processed_lines {
            let parts: Vec<String> = line.split(',').map(|s| s.to_string()).collect();

            // ── Direct evidence: (src_ip, src_computer) pair ──
            if !local_values.contains(parts[idx_src_computer].as_str())
                && !local_values.contains(parts[idx_src_ip].as_str())
                && parts[idx_src_computer] != parts[idx_src_ip]
            {
                let weight: u32 = if parts[idx_event_id] == "4778" || parts[idx_event_id] == "4779" {
                    1000
                } else {
                    1
                };
                *counts
                    .entry((parts[idx_src_ip].clone(), parts[idx_src_computer].clone()))
                    .or_insert(0) += weight;
            }

            // ── Machine-account hint: target_user ends in $ → computer name ──
            // On Kerberos AD networks every machine has a computer account
            // MACHINE$. When a 4624 arrives from an IP with src_computer
            // empty and target_user=MACHINE$, that's strong evidence the IP
            // belongs to MACHINE. Weight x100 sits between normal events
            // (x1) and the authoritative 4778/4779 pair (x1000).
            if local_values.contains(parts[idx_src_computer].as_str())
                && !local_values.contains(parts[idx_src_ip].as_str())
            {
                let target_user = parts[idx_target_user].as_str();
                if target_user.ends_with('$') && target_user.len() > 1 {
                    let machine = &target_user[..target_user.len() - 1];
                    // Reject if it still looks like an IP or has invalid chars
                    if !looks_like_ip(machine) && !machine.contains('.') && !machine.is_empty() {
                        *counts
                            .entry((parts[idx_src_ip].clone(), machine.to_string()))
                            .or_insert(0) += 100;
                    }
                }
            }
        }

        // ── Same-login IP/name co-occurrence (Linux) → resolved_name ──
        // sshd (UseDNS) records the peer by name, auditd / btmp / wtmp keep
        // its IP: the same login appears as two single-sided rows. A pair
        // is only used to ANNOTATE the IP node (resolved_name), never to
        // merge nodes, and only when every vote agrees (>= 2 logins).
        let mut cooc: HashMap<(String, String, String, String), (Vec<String>, Vec<String>)> = HashMap::new();
        for line in &processed_lines {
            let parts: Vec<&str> = line.split(',').collect();
            let sc = parts[idx_src_computer];
            let si = parts[idx_src_ip];
            let side = if local_values.contains(sc) && !local_values.contains(si) && looks_like_ip(si) {
                Some((si.to_string(), true))
            } else if !local_values.contains(sc) && local_values.contains(si) && !looks_like_ip(sc) {
                Some((sc.to_string(), false))
            } else { None };
            if let Some((v, is_ip)) = side {
                let et = idx_event_type.map(|i| parts[i]).unwrap_or("");
                let key = (parts[idx_dst].to_string(), parts[idx_target_user].to_string(),
                           parts[0].get(..19).unwrap_or(parts[0]).to_string(), et.to_string());
                let e = cooc.entry(key).or_default();
                let list = if is_ip { &mut e.0 } else { &mut e.1 };
                if !list.contains(&v) { list.push(v); }
            }
        }
        let mut votes: HashMap<String, HashMap<String, u32>> = HashMap::new();
        for (ips, names) in cooc.values() {
            if ips.len() == 1 && names.len() == 1 {
                *votes.entry(ips[0].clone()).or_default().entry(names[0].clone()).or_insert(0) += 1;
            }
        }
        drop(cooc);
        let resolved_names: HashMap<String, (String, u32)> = votes
            .into_iter()
            .filter_map(|(ip, m)| {
                if m.len() != 1 { return None; }
                let (name, v) = m.into_iter().next()?;
                if v >= 2 { Some((ip, (name, v))) } else { None }
            })
            .collect();

        // ── Global IP→hostname map ──
        let mut ip_to_host: HashMap<String, String> = HashMap::new();
        {
            let mut best: HashMap<String, (String, u32)> = HashMap::new();
            for ((ip, host), weight) in &counts {
                let entry = best.entry(ip.clone()).or_insert((host.clone(), 0));
                if *weight > entry.1 {
                    *entry = (host.clone(), *weight);
                }
            }
            for (ip, (host, _)) in best {
                ip_to_host.insert(ip, host);
            }
        }

        // ── Edge emission: either grouped or ungrouped ──
        let mut edges_to_emit: Vec<String> = Vec::new();

        if ungrouped {
            for line in &processed_lines {
                let parts: Vec<String> = line.split(',').map(|s| s.to_string()).collect();
                edges_to_emit.push(format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{}",
                    parts[0],
                    parts[idx_dst],
                    "1",
                    parts[idx_subject_user],
                    parts[idx_subject_domain],
                    parts[idx_target_user],
                    parts[idx_target_domain],
                    parts[idx_logon_type],
                    parts[idx_src_computer],
                    parts[idx_src_ip],
                    idx_event_type.map(|i| parts[i].as_str()).unwrap_or(""),
                    parts[idx_event_id],
                    parts.get(idx_log_source).map(|s| s.as_str()).unwrap_or(""),
                ));
            }
        } else {
            // Grouping key: (dst, target_user, logon_type)
            // The resolved origin node is determined downstream by ip_to_host;
            // src_ip is a detail for the CSV, not the graph. Keeping only
            // these 3 fields produces one edge per (origin, user, type, dest).
            // Key includes source and outcome: without them two origins using
            // the same account on the same host collapsed into one edge and
            // refused attempts merged with successes.
            let mut grouped_map: HashMap<
                (String, String, String, String, String, String),
                GroupedData,
            > = HashMap::new();

            for line in &processed_lines {
                let parts: Vec<String> = line.split(',').map(|s| s.to_string()).collect();
                // Strip @DOMAIN from target_user before grouping — Kerberos
                // TGS events (4769) append @REALM to the username while 4624
                // events don't, causing duplicate edges for the same user.
                let user_clean = parts[idx_target_user].split('@').next()
                    .unwrap_or(&parts[idx_target_user]).to_string();
                let et = idx_event_type.map(|i| parts[i].clone()).unwrap_or_default();
                let key = (
                    parts[idx_dst].clone(),
                    user_clean,
                    parts[idx_logon_type].clone(),
                    parts[idx_src_computer].clone(),
                    parts[idx_src_ip].clone(),
                    et.clone(),
                );
                let date = parts[0].clone();
                let entry = grouped_map.entry(key).or_insert(GroupedData {
                    earliest_date: date.clone(),
                    count: 0,
                    event_type: et.clone(),
                    event_id: parts[idx_event_id].clone(),
                    log_source: parts.get(idx_log_source).cloned().unwrap_or_default(),
                    subject_user: parts[idx_subject_user].clone(),
                    subject_domain: parts[idx_subject_domain].clone(),
                    target_domain: parts[idx_target_domain].clone(),
                    src_computer: parts[idx_src_computer].clone(),
                    src_ip: parts[idx_src_ip].clone(),
                });
                if date < entry.earliest_date {
                    entry.earliest_date = date;
                }
                entry.count += 1;
            }

            for ((dst_computer, target_user_name, logon_type, _sc, _si, _et), data) in grouped_map {
                edges_to_emit.push(format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{}",
                    data.earliest_date,
                    dst_computer,
                    data.count,
                    data.subject_user,
                    data.subject_domain,
                    target_user_name,
                    data.target_domain,
                    logon_type,
                    data.src_computer,
                    data.src_ip,
                    data.event_type,
                    data.event_id,
                    data.log_source,
                ));
            }
        }

        // ── Pre-pass: resolve every edge in Rust (no DB round-trips) ──
        // Source/destination IP→hostname resolution, self-loop filtering and
        // rel-type sanitization all happen here, so the database phase below
        // is a pure batched write.
        let mut resolved: usize = 0;
        let mut resolved_edges: Vec<ResolvedEdge> = Vec::new();
        let clean_user = |s: &str| -> String {
            s.split('@').next().unwrap_or(s).to_string()
        };
        for line in &edges_to_emit {
            let row: Vec<&str> = line.split(',').collect();
            let relation_type = if row[5].trim().is_empty() || row[5] == "\"\"" { "NO_USER" } else { row[5] };

            // ── Source-side resolution ──
            // When the parser leaves `src_computer` empty, equal to a local
            // value, OR filled in with the literal IP (which happens on 4624
            // events where WorkstationName was blank and masstin fell back
            // to the address), we resolve the real hostname from the global
            // ip_to_host map so the same physical host does not end up as
            // two nodes (one by hostname, one by IP).
            let src_ip_raw = row[9];
            let src_computer_raw = row[8];
            let src_computer_is_ip = looks_like_ip(src_computer_raw)
                && src_computer_raw == src_ip_raw;
            let needs_resolution = local_values.contains(src_computer_raw) || src_computer_is_ip;
            let origin_name: String = if needs_resolution {
                if let Some(resolved_host) = ip_to_host.get(src_ip_raw) {
                    resolved += 1;
                    resolved_host.clone()
                } else if !local_values.contains(src_ip_raw) {
                    src_ip_raw.to_string()
                } else {
                    continue;
                }
            } else {
                src_computer_raw.to_string()
            };

            // ── Destination-side resolution ──
            let dst_raw = row[1];
            let destination_name: String = if looks_like_ip(dst_raw) {
                ip_to_host.get(dst_raw).cloned().unwrap_or_else(|| dst_raw.to_string())
            } else {
                dst_raw.to_string()
            };

            // Self-loop filter: drop edges whose origin and destination point
            // at the same host post-resolution. Self-loops are pure noise in
            // a lateral-movement graph. Checked here because resolution itself
            // creates new matches (e.g. 192.168.10.11 → WINTERFELL).
            if origin_name.eq_ignore_ascii_case(&destination_name) {
                continue;
            }

            // Relationship type must be a valid Cypher identifier:
            // [A-Za-z_][A-Za-z0-9_]*. Anything else (`$`, `!`, dots, hyphens,
            // spaces, accents...) becomes `_`. The `$` case is the important
            // one — machine accounts like `SPACHE$` would otherwise generate
            // `r:SPACHE$` which Cypher parses as a parameter ref.
            let rel_type_normalized = {
                let stripped = relation_type.split('@').next().unwrap_or(relation_type);
                let mut s: String = stripped.chars().map(|c| {
                    if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }
                }).collect();
                if s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    s = format!("u{}", s);
                }
                if s.is_empty() { s = "NO_USER".to_string(); }
                s.to_uppercase()
            };

            resolved_edges.push(ResolvedEdge {
                origin: origin_name,
                destination: destination_name,
                rel_type: rel_type_normalized,
                time: strip_timezone(&row[0].replace(" utc", "").replace(" ", "T")),
                logon_type: row[7].to_string(),
                src_computer: src_computer_raw.to_string(),
                src_ip: src_ip_raw.to_string(),
                target_user_name: clean_user(relation_type),
                target_domain_name: row[6].to_string(),
                subject_user_name: clean_user(row[3]),
                subject_domain_name: row[4].to_string(),
                event_type: row.get(10).map(|s| s.to_string()).unwrap_or_default(),
                event_id: row.get(11).map(|s| s.to_string()).unwrap_or_default(),
                log_source: row.get(12).map(|s| s.to_string()).unwrap_or_default(),
                count: row[2].parse::<i64>().unwrap_or(1),
            });
        }

        // Phase 2: Load to database (serial batched)
        let edge_total = resolved_edges.len();
        let phase_label = if ungrouped {
            format!("Loading {} individual edges to Memgraph (ungrouped, batched)...", edge_total)
        } else {
            format!("Loading {} grouped connections to Memgraph (batched)...", edge_total)
        };
        crate::banner::print_phase("2", "2", &phase_label);

        // Pre-create every host node in one UNWIND pass. The edge batches
        // below then only ever MATCH their endpoints (cheaper than MERGE on
        // every batch now that the index already exists from connect-time)
        // and any host that ends up unreferenced — unusual but legal — is
        // still created so the graph keeps a stable node inventory.
        let mut host_names: Vec<String> = Vec::new();
        {
            let mut seen: HashSet<&str> = HashSet::new();
            for e in &resolved_edges {
                if seen.insert(e.origin.as_str()) { host_names.push(e.origin.clone()); }
                if seen.insert(e.destination.as_str()) { host_names.push(e.destination.clone()); }
            }
        }
        crate::banner::print_phase_detail(
            "Nodes:",
            &format!("pre-creating {} host nodes", host_names.len()),
        );
        match graph
            .execute(query("UNWIND $names AS n MERGE (:host {name: n})").param("names", host_names.clone()))
            .await
        {
            Ok(mut r) => { let _ = r.next().await; }
            Err(e) => {
                if crate::parse::is_debug_mode() {
                    eprintln!("[ERROR] host node pre-create failed: {:?}", e);
                }
            }
        }

        let pb = crate::banner::create_progress_bar(edge_total as u64);

        // Cypher cannot parametrize a relationship type, and masstin's schema
        // uses the (sanitized) username as the type. So edges are bucketed by
        // rel_type and each bucket gets its own UNWIND query with the type
        // baked in as a literal; the per-edge payload travels as parallel
        // list parameters indexed by `i`. Batches are executed one at a time:
        // a previous opt-in concurrent path was removed because it tripped a
        // Memgraph 3.9.x SIGSEGV race and didn't pay off on Neo4j 4.2 either
        // (the deadlock-retry overhead ate the parallelism gain), while
        // guaranteeing zero edge loss required additional fallback logic. A
        // strictly serial loader has no contention, so no edge can ever be
        // silently dropped.
        let edge_op = if ungrouped { "CREATE" } else { "MERGE" };
        let mut by_type: HashMap<&str, Vec<&ResolvedEdge>> = HashMap::new();
        for e in &resolved_edges {
            by_type.entry(e.rel_type.as_str()).or_default().push(e);
        }

        let mut errors: usize = 0;
        for (rel_type, edges) in &by_type {
            for chunk in edges.chunks(EDGE_BATCH) {
                let q_str = format!(
                    "UNWIND range(0, size($origin) - 1) AS i \
                     MATCH (o:host {{name: $origin[i]}}) \
                     MATCH (d:host {{name: $destination[i]}}) \
                     {} (o)-[r:{} {{time: localDateTime($time[i]), logon_type: $logon_type[i], \
                     src_computer: $src_computer[i], src_ip: $src_ip[i], \
                     target_user_name: $target_user_name[i], target_domain_name: $target_domain_name[i], \
                     subject_user_name: $subject_user_name[i], subject_domain_name: $subject_domain_name[i], \
                     event_type: $event_type[i], event_id: $event_id[i], log_source: $log_source[i], \
                     count: $count[i]}}]->(d)",
                    edge_op, rel_type,
                );
                let q = query(&q_str)
                    .param("origin", chunk.iter().map(|e| e.origin.clone()).collect::<Vec<String>>())
                    .param("destination", chunk.iter().map(|e| e.destination.clone()).collect::<Vec<String>>())
                    .param("time", chunk.iter().map(|e| e.time.clone()).collect::<Vec<String>>())
                    .param("logon_type", chunk.iter().map(|e| e.logon_type.clone()).collect::<Vec<String>>())
                    .param("src_computer", chunk.iter().map(|e| e.src_computer.clone()).collect::<Vec<String>>())
                    .param("src_ip", chunk.iter().map(|e| e.src_ip.clone()).collect::<Vec<String>>())
                    .param("target_user_name", chunk.iter().map(|e| e.target_user_name.clone()).collect::<Vec<String>>())
                    .param("target_domain_name", chunk.iter().map(|e| e.target_domain_name.clone()).collect::<Vec<String>>())
                    .param("subject_user_name", chunk.iter().map(|e| e.subject_user_name.clone()).collect::<Vec<String>>())
                    .param("subject_domain_name", chunk.iter().map(|e| e.subject_domain_name.clone()).collect::<Vec<String>>())
                    .param("event_type", chunk.iter().map(|e| e.event_type.clone()).collect::<Vec<String>>())
                    .param("event_id", chunk.iter().map(|e| e.event_id.clone()).collect::<Vec<String>>())
                    .param("log_source", chunk.iter().map(|e| e.log_source.clone()).collect::<Vec<String>>())
                    .param("count", chunk.iter().map(|e| e.count).collect::<Vec<i64>>());
                match graph.execute(q).await {
                    Ok(mut result) => { let _ = result.next().await; }
                    Err(e) => {
                        errors += chunk.len();
                        if crate::parse::is_debug_mode() {
                            eprintln!("[ERROR] edge batch ({} edges, r:{}) failed: {:?}", chunk.len(), rel_type, e);
                        }
                    }
                }
                pb.inc(chunk.len() as u64);
            }
        }

        pb.finish_and_clear();

        if !resolved_names.is_empty() {
            let ips: Vec<String> = resolved_names.keys().cloned().collect();
            let names: Vec<String> = ips.iter().map(|i| resolved_names[i].0.clone()).collect();
            let vts: Vec<i64> = ips.iter().map(|i| resolved_names[i].1 as i64).collect();
            let q_annot = "UNWIND range(0, size($ips) - 1) AS i \
                           MATCH (h:host {name: $ips[i]}) \
                           SET h.resolved_name = $names[i], h.resolved_votes = $votes[i]";
            match graph
                .execute(query(q_annot).param("ips", ips).param("names", names).param("votes", vts))
                .await
            {
                Ok(mut r) => {
                    let _ = r.next().await;
                    crate::banner::print_phase_detail(
                        "IP nodes:",
                        &format!("{} IPs annotated with resolved_name (unanimous sshd reverse-DNS, >= 2 logins; nodes not merged)", resolved_names.len()),
                    );
                }
                Err(e) => {
                    if crate::parse::is_debug_mode() {
                        eprintln!("[ERROR] resolved_name annotation failed: {:?}", e);
                    }
                }
            }
        }
        let loaded = edge_total - errors;
        crate::banner::print_load_summary("Memgraph", loaded, resolved, errors, start_clock);
    }
}
