use neo4rs::*;
use futures::stream::*;
use rpassword::read_password;
use std::io::{self, prelude::*};
use indicatif::ProgressBar;
use std::collections::HashSet;
use std::collections::HashMap;
use chrono::{DateTime, Utc, NaiveDateTime, TimeZone};

/// Parse a user-supplied start/end time string (from the CLI flags) into a
/// DateTime<Utc>. Accepts the Cortex flag format `YYYY-MM-DD HH:MM:SS [-0000]`
/// already validated upstream, plus a bare `YYYY-MM-DD HH:MM:SS`.
fn parse_time_window(raw: &str) -> Option<DateTime<Utc>> {
    let trimmed = raw.trim();
    // Strip optional trailing `-0000` / `-0100` / `+0000` etc.
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
    // 1. ISO 8601 with `T` and `Z` (EVTX)
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // 2. `YYYY-MM-DD HH:MM:SS.fff UTC` (Cortex)
    if let Ok(dt) = NaiveDateTime::parse_from_str(s.trim_end_matches(" UTC"), "%Y-%m-%d %H:%M:%S%.f") {
        return Some(Utc.from_utc_datetime(&dt));
    }
    // 3. `YYYY-MM-DDTHH:MM:SS.fff` without trailing Z
    if let Ok(dt) = NaiveDateTime::parse_from_str(s.trim_end_matches('Z'), "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(Utc.from_utc_datetime(&dt));
    }
    // 4. `YYYY-MM-DD HH:MM:SS` (Linux)
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
    count: String,
}

/// Edges per UNWIND batch. Each batch is a single Bolt round-trip carrying
/// this many edges, replacing what used to be one round-trip per edge — the
/// dominant residual cost once the :host(name) index removed the O(V*E)
/// MERGE-scan term.
const EDGE_BATCH: usize = 5_000;

// ───────── helper (inline or place it above) ─────────────────────────
fn looks_like_ip(s: &str) -> bool {
    // IPv4 → only digits + dots; IPv6 → hex digits + colons
    let ipv4 = s.chars().all(|c| c.is_ascii_digit() || c == '.');
    let ipv6 = s.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
    ipv4 || ipv6
}

// ── helper: returns the (sub-)slice that contains the leading IPv4/IPv6, if any
fn extract_leading_ip<'a>(s: &'a str) -> Option<&'a str> {
    // take chars while they are digits, dots, or colons
    let candidate = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ':')
        .collect::<String>();

    // quick tests: at least one dot for IPv4 or one colon for IPv6
    if candidate.contains('.') || candidate.contains(':') {
        Some(&s[..candidate.len()])
    } else {
        None
    }
}

pub async fn load_neo4j(
    files: &Vec<String>,
    database: &String,
    user: &String,
    ungrouped: bool,
    start_time: Option<&String>,
    end_time: Option<&String>,
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
    // Read the password from $NEO4J_PASSWORD first so scripts (the scaling
    // spike, CI) can drive load-neo4j without a tty. Fall back to the
    // interactive prompt when the env var is missing or empty. Note this
    // means the password lives in the process env; do not export it from a
    // shared shell or a logged dotfile.
    let pass = match std::env::var("NEO4J_PASSWORD") {
        Ok(p) if !p.is_empty() => {
            crate::banner::print_phase_detail("Auth:", "password from $NEO4J_PASSWORD");
            p
        }
        _ => rpassword::prompt_password("MASSTIN - Enter Neo4j database password: ").unwrap(),
    };
    let graph = Graph::new(database, user, &pass).await.unwrap();
    crate::banner::print_phase_result("Connected");

    // Ensure an index on :host(name). Every edge insert runs
    // MERGE (origin:host {name:...}) / MERGE (destination:host {name:...});
    // without this index each MERGE is a full label scan, making the whole
    // load O(V*E) — super-linear and effectively unusable past a few hundred
    // thousand edges. `IF NOT EXISTS` makes it idempotent on Neo4j 4.x/5.x;
    // any error is swallowed so an older server or a pre-existing index does
    // not abort the load.
    match graph.execute(query("CREATE INDEX host_name IF NOT EXISTS FOR (h:host) ON (h.name)")).await {
        Ok(mut r) => { let _ = r.next().await; }
        Err(_) => {}
    }
    crate::banner::print_phase_result("Index :host(name) ready");

    // Parse the optional time window once — reused for every CSV row.
    // Returns (start_utc, end_utc) as Option<DateTime<Utc>>.
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
        // New: 0=time, 1=dst, 2=event_type, 3=event_id, 4=logon_type, 5=target_user, 6=target_domain, 7=src_computer, 8=src_ip, 9=subject_user, 10=subject_domain, 11=logon_id, 12=detail, 13=log_filename
        // Old: 0=time, 1=dst, 2=event_id, 3=subject_user, 4=subject_domain, 5=target_user, 6=target_domain, 7=logon_type, 8=src_computer, 9=src_ip, 10=process, 11=log_filename
        let (idx_dst, idx_event_id, idx_subject_user, idx_subject_domain, idx_target_user, idx_target_domain, idx_logon_type, idx_src_computer, idx_src_ip) = if is_new_format {
            (1usize, 3usize, 9usize, 10usize, 5usize, 6usize, 4usize, 7usize, 8usize)
        } else {
            (1usize, 2usize, 3usize, 4usize, 5usize, 6usize, 7usize, 8usize, 9usize)
        };

        let local_values: HashSet<&str> = 
                ["LOCAL", "127.0.0.1", "::1", "::", "0.0.0.0", "DEFAULT_VALUE", "\"\"", "-", ""," ",]
                .iter().cloned().collect();

        // Counters for the summary
        let mut filtered_by_time: usize = 0;

        let processed_lines: Vec<String> = lines
        .into_iter()
        .skip(1)
        .map(|line| line.replace("\\", "").replace("[", "").replace("]", "").to_uppercase())
        .filter_map(|line| {
            // Time window filter — parsed against the first column before
            // the row uppercase mutation above touches the time format
            // (the format is ASCII-only so upper/lower doesn't matter here).
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
            row.pop();

            // dst_computer
            if let Some(ip) = extract_leading_ip(row[idx_dst]) {
                row[idx_dst] = ip;
            } else if row[idx_dst].contains('.') && !looks_like_ip(row[idx_dst]) {
                row[idx_dst] = row[idx_dst].split('.').next().unwrap_or(row[idx_dst]);
            }

            // src_computer
            if let Some(ip) = extract_leading_ip(row[idx_src_computer]) {
                row[idx_src_computer] = ip;
            } else if row[idx_src_computer].contains('.') && !looks_like_ip(row[idx_src_computer]) {
                row[idx_src_computer] = row[idx_src_computer].split('.').next().unwrap_or(row[idx_src_computer]);
            }

            // src_ip
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

        // ── Frequency map (ip, hostname) → weighted co-occurrence count ──
        // Events 4778 (RemoteInteractive Session Reconnected) and 4779
        // (RemoteInteractive Session Disconnected) always populate BOTH the
        // workstation name AND the IP reliably, so their evidence is
        // authoritative and gets a x1000 weight. A single 4778/4779 match
        // therefore beats up to 999 other events that might disagree on the
        // hostname for a given IP. See also docs/load-cli.md for rationale.
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
                    if !looks_like_ip(machine) && !machine.contains('.') && !machine.is_empty() {
                        *counts
                            .entry((parts[idx_src_ip].clone(), machine.to_string()))
                            .or_insert(0) += 100;
                    }
                }
            }
        }

        // ── Global IP→hostname map ──
        // For each IP, pick the hostname with the highest weighted score.
        // Used to resolve BOTH src_computer and dst_computer when they look
        // like an IP, so the same physical host doesn't appear as two nodes
        // (one by IP, one by hostname).
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
        // `edges_to_emit` carries one line per edge to create in the graph.
        // Line format (post-resolution): earliest_date, dst_computer, count,
        //   subject_user, subject_domain, target_user, target_domain,
        //   logon_type, src_computer, src_ip
        let mut edges_to_emit: Vec<String> = Vec::new();

        if ungrouped {
            // One edge per CSV row, preserving individual timestamps.
            // No aggregation, count is always 1.
            for line in &processed_lines {
                let parts: Vec<String> = line.split(',').map(|s| s.to_string()).collect();
                edges_to_emit.push(format!(
                    "{},{},{},{},{},{},{},{},{},{}",
                    parts[0],                        // time
                    parts[idx_dst],                  // dst_computer
                    "1",                             // count
                    parts[idx_subject_user],
                    parts[idx_subject_domain],
                    parts[idx_target_user],
                    parts[idx_target_domain],
                    parts[idx_logon_type],
                    parts[idx_src_computer],
                    parts[idx_src_ip],
                ));
            }
        } else {
            // Grouping key: (dst, target_user, logon_type)
            // The resolved origin node is determined downstream by ip_to_host;
            // src_ip is a detail for the CSV, not the graph. Keeping only
            // these 3 fields produces one edge per (origin, user, type, dest).
            let mut grouped_map: HashMap<
                (String, String, String),
                GroupedData,
            > = HashMap::new();

            for line in &processed_lines {
                let parts: Vec<String> = line.split(',').map(|s| s.to_string()).collect();
                // Strip @DOMAIN from target_user before grouping — Kerberos
                // TGS events (4769) append @REALM to the username while 4624
                // events don't, causing duplicate edges for the same user.
                let user_clean = parts[idx_target_user].split('@').next()
                    .unwrap_or(&parts[idx_target_user]).to_string();
                let key = (
                    parts[idx_dst].clone(),
                    user_clean,
                    parts[idx_logon_type].clone(),
                );
                let date = parts[0].clone();
                let entry = grouped_map.entry(key).or_insert(GroupedData {
                    earliest_date: date.clone(),
                    count: 0,
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

            for ((dst_computer, target_user_name, logon_type), data) in grouped_map {
                edges_to_emit.push(format!(
                    "{},{},{},{},{},{},{},{},{},{}",
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
            // Pick the best hostname for this row's source IP from the global
            // ip_to_host map. Also trigger resolution when src_computer was
            // filled in with the literal IP (happens on 4624 events where
            // WorkstationName was blank and masstin fell back to the address),
            // so the same physical host does not end up as two nodes (one by
            // hostname, one by IP).
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
                    // Both src_computer and src_ip are noise; skip.
                    continue;
                }
            } else {
                src_computer_raw.to_string()
            };

            // ── Destination-side resolution ──
            // If dst_computer looks like an IP and the global map has a
            // hostname for it, swap it in. This fixes the "same physical
            // host appears as two nodes" bug.
            let dst_raw = row[1];
            let destination_name: String = if looks_like_ip(dst_raw) {
                ip_to_host.get(dst_raw).cloned().unwrap_or_else(|| dst_raw.to_string())
            } else {
                dst_raw.to_string()
            };

            // Self-loop filter: after resolution, drop edges where origin
            // and destination point at the same host. Checked post-resolution
            // because resolution itself creates new matches.
            if origin_name.eq_ignore_ascii_case(&destination_name) {
                continue;
            }

            // Relationship type must be a valid Cypher identifier:
            // [A-Za-z_][A-Za-z0-9_]*. Anything else (`$`, `!`, `(`, `)`, dots,
            // hyphens, spaces, accents...) becomes `_`. The `$` case is the
            // important one — machine accounts like `SPACHE$` would otherwise
            // generate `r:SPACHE$` which Cypher parses as a parameter ref.
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
                time: row[0].replace(" utc", "").replace(" ", "T"),
                logon_type: row[7].to_string(),
                src_computer: src_computer_raw.to_string(),
                src_ip: src_ip_raw.to_string(),
                target_user_name: clean_user(relation_type),
                target_domain_name: row[6].to_string(),
                subject_user_name: clean_user(row[3]),
                subject_domain_name: row[4].to_string(),
                count: row[2].to_string(),
            });
        }

        // Phase 2: Load to database (batched + concurrent)
        let edge_total = resolved_edges.len();
        let phase_label = if ungrouped {
            format!("Loading {} individual edges to Neo4j (ungrouped, batched)...", edge_total)
        } else {
            format!("Loading {} grouped connections to Neo4j (batched)...", edge_total)
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
                     {} (o)-[r:{} {{time: datetime($time[i]), logon_type: $logon_type[i], \
                     src_computer: $src_computer[i], src_ip: $src_ip[i], \
                     target_user_name: $target_user_name[i], target_domain_name: $target_domain_name[i], \
                     subject_user_name: $subject_user_name[i], subject_domain_name: $subject_domain_name[i], \
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
                    .param("count", chunk.iter().map(|e| e.count.clone()).collect::<Vec<String>>());
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
        let loaded = edge_total - errors;
        crate::banner::print_load_summary("Neo4j", loaded, resolved, errors, start_clock);
    }
}
