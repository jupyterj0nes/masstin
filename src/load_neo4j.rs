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
    earliest_date: String, // Assuming the date is in String format
    count: usize,
}

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
    let pass = rpassword::prompt_password("MASSTIN - Enter Neo4j database password: ").unwrap();
    let graph = Graph::new(database, user, &pass).await.unwrap();
    crate::banner::print_phase_result("Connected");

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
                ["LOCAL", "127.0.0.1", "::1", "DEFAULT_VALUE", "\"\"", "-", ""," ",]
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

            if row[idx_dst].contains(':') {
                row[idx_dst] = row[idx_dst].split(':').next().unwrap_or(row[idx_dst]);
            }

            if row[idx_src_computer].contains(':') {
                row[idx_src_computer] = row[idx_src_computer].split(':').next().unwrap_or(row[idx_dst]);
            }

            if row[idx_src_ip].contains(':') {
                row[idx_src_ip] = row[idx_src_ip].split(':').next().unwrap_or(row[idx_dst]);
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
            // Classic grouped path: collapse identical (src, user, dst, ...)
            // tuples into a single edge with a `count` property.
            let mut grouped_map: HashMap<
                (String, String, String, String, String, String, String, String),
                GroupedData,
            > = HashMap::new();

            for line in &processed_lines {
                let parts: Vec<String> = line.split(',').map(|s| s.to_string()).collect();
                let key = (
                    parts[idx_dst].clone(),
                    parts[idx_subject_user].clone(),
                    parts[idx_subject_domain].clone(),
                    parts[idx_target_user].clone(),
                    parts[idx_target_domain].clone(),
                    parts[idx_logon_type].clone(),
                    parts[idx_src_computer].clone(),
                    parts[idx_src_ip].clone(),
                );
                let date = parts[0].clone();
                let entry = grouped_map.entry(key).or_insert(GroupedData {
                    earliest_date: date.clone(),
                    count: 0,
                });
                if date < entry.earliest_date {
                    entry.earliest_date = date;
                }
                entry.count += 1;
            }

            for ((dst_computer, subject_user_name, subject_domain_name, target_user_name, target_domain_name, logon_type, src_computer, src_ip), data) in grouped_map {
                edges_to_emit.push(format!(
                    "{},{},{},{},{},{},{},{},{},{}",
                    data.earliest_date,
                    dst_computer,
                    data.count,
                    subject_user_name,
                    subject_domain_name,
                    target_user_name,
                    target_domain_name,
                    logon_type,
                    src_computer,
                    src_ip,
                ));
            }
        }

        // Phase 2: Load to database
        let grouped_lines_count = edges_to_emit.len();
        let phase_label = if ungrouped {
            format!("Loading {} individual edges to Neo4j (ungrouped mode)...", grouped_lines_count)
        } else {
            format!("Loading {} grouped connections to Neo4j...", grouped_lines_count)
        };
        crate::banner::print_phase("2", "2", &phase_label);
        let pb = crate::banner::create_progress_bar(grouped_lines_count as u64);
        let grouped_lines = edges_to_emit;
        let mut errors: usize = 0;
        let mut resolved: usize = 0;

        for line in grouped_lines {
            let row: Vec<&str> = line.split(',').collect();
            let relation_type = if row[5].trim().is_empty() || row[5] == "\"\"" { "NO_USER" } else { row[5] };

            // ── Source-side resolution ──
            // Pick the best hostname for this row's source IP from the global
            // ip_to_host map. Falls back to the row's src_computer if no
            // mapping exists, and to the IP itself as last resort.
            let src_ip_raw = row[9];
            let src_computer_raw = row[8];
            let origin_name: String = if local_values.contains(src_computer_raw) {
                if let Some(resolved_host) = ip_to_host.get(src_ip_raw) {
                    resolved += 1;
                    resolved_host.clone()
                } else if !local_values.contains(src_ip_raw) {
                    src_ip_raw.to_string()
                } else {
                    // Both src_computer and src_ip are noise; skip.
                    pb.inc(1);
                    continue;
                }
            } else {
                src_computer_raw.to_string()
            };

            // ── Destination-side resolution ──
            // If dst_computer looks like an IP and the global map has a
            // hostname for it, swap it in. This fixes the "same physical
            // host appears as two nodes" bug where one node was created by
            // IP (from some rows) and another by hostname (from other rows).
            let dst_raw = row[1];
            let destination_name: String = if looks_like_ip(dst_raw) {
                if let Some(resolved_host) = ip_to_host.get(dst_raw) {
                    resolved_host.clone()
                } else {
                    dst_raw.to_string()
                }
            } else {
                dst_raw.to_string()
            };

            // Relationship type must be a valid Cypher identifier:
            // replace dots, hyphens, spaces with underscores; uppercase; strip @domain
            let rel_type_normalized = {
                let r = if relation_type.chars().next().unwrap_or(' ').is_ascii_digit() {
                    format!("u{}", relation_type)
                } else {
                    relation_type.to_string()
                };
                r.replace(".", "_").replace("-", "_").replace(" ", "_")
                    .split("@").next().unwrap_or(&r).to_uppercase()
            };

            // Node names and properties: keep original values (no normalization)
            // Only strip @domain from usernames
            let clean_user = |s: &str| -> String {
                s.split("@").next().unwrap_or(s).to_string()
            };

            // In ungrouped mode we CREATE (not MERGE) the edge so every CSV
            // row becomes a distinct edge even when (src, user, dst, logon_type)
            // repeats — otherwise MERGE would collapse events that differ
            // only in secondary properties. Nodes still MERGE.
            let edge_op = if ungrouped { "CREATE" } else { "MERGE" };

            let formatted_query = format!(
                "MERGE (origin:host{{name:'{}'}})
                MERGE (destination:host{{name:'{}'}})
                {} (origin)-[r:{}{{time:datetime('{}'), logon_type:'{}', src_computer:'{}', src_ip:'{}', target_user_name:'{}', target_domain_name:'{}', subject_user_name:'{}', subject_domain_name:'{}', count:'{}'}}]->(destination)",
                origin_name,
                destination_name,
                edge_op,
                rel_type_normalized,
                row[0].replace(" utc", "").replace(" ", "T"),
                row[7],                                                      // property: original
                src_computer_raw,                                            // property: original
                src_ip_raw,                                                  // property: original
                clean_user(relation_type),                                   // property: strip @domain only
                row[6],                                                      // property: original
                clean_user(row[3]),                                          // property: strip @domain only
                row[4],                                                      // property: original
                row[2],                                                      // property: original
            );
            
            // Execute the query and handle possible errors
            match graph.execute(query(&formatted_query)).await {
                Ok(mut result) => {
                    let row = result.next().await.unwrap();  // Process the result
                    // You can add more logic here if you need to process the result
                },
                Err(e) => {
                    errors += 1;
                    if crate::parse::is_debug_mode() {
                        eprintln!("[ERROR] Cypher query failed: {:?}", e);
                    }
                    continue;
                }
            }

            // Increment the progress bar
            pb.inc(1);
        }

        pb.finish_and_clear();
        let loaded = grouped_lines_count - errors;
        crate::banner::print_load_summary("Neo4j", loaded, resolved, errors, start_clock);
    }
}
