use std::collections::HashSet;
use std::error::Error;
use chrono::{DateTime, NaiveDateTime, SubsecRound, Utc};

/// Parse a user-supplied start/end time from the CLI flags.
/// Accepts `YYYY-MM-DD HH:MM:SS` optionally followed by an offset
/// (`-0000`, `+0200`), which is honoured.
fn parse_window(raw: &str) -> Option<NaiveDateTime> {
    let t = raw.trim();
    if let Ok(dt) = DateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S %z") {
        return Some(dt.with_timezone(&Utc).naive_utc());
    }
    let base = if t.len() >= 19 { &t[..19] } else { t };
    NaiveDateTime::parse_from_str(base, "%Y-%m-%d %H:%M:%S").ok()
}

/// time_created of any masstin source, normalised to UTC:
///   2026-09-01T10:00:00.123Z / ...+00:00 / ...+02:00  (RFC 3339)
///   2026-09-01 10:00:00                                (UAL, no zone = UTC)
///   2026-09-01T10:00:00                                (no zone = UTC)
fn parse_time(raw: &str) -> Option<NaiveDateTime> {
    let t = raw.trim().trim_matches('"');
    if let Ok(dt) = DateTime::parse_from_rfc3339(t) {
        return Some(dt.with_timezone(&Utc).naive_utc());
    }
    let t2 = t.replacen(' ', "T", 1);
    if let Ok(dt) = DateTime::parse_from_rfc3339(&t2) {
        return Some(dt.with_timezone(&Utc).naive_utc());
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(n) = NaiveDateTime::parse_from_str(&t2, f) {
            return Some(n);
        }
    }
    crate::timefmt::parse_fallback(t)
}

const MASSTIN_HEADER: &str = "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename";
const MASSTIN_HEADER_OLD: &str = "time_created,dst_computer,event_id,subject_user_name,subject_domain_name,target_user_name,target_domain_name,logon_type,src_computer,src_ip,process,log_filename";

/// Map a record to the 14-column layout. Legacy 12-column files are
/// rearranged (event_type and logon_id did not exist and stay empty) —
/// they used to be written verbatim under the 14-column header, shifting
/// every column after dst_computer.
fn to_new_layout(rec: &csv::StringRecord, old: bool) -> Vec<String> {
    let g = |i: usize| rec.get(i).unwrap_or("").to_string();
    if !old {
        return (0..14).map(g).collect();
    }
    //  old: 0 time 1 dst 2 event_id 3 subj_user 4 subj_dom 5 tgt_user
    //       6 tgt_dom 7 logon_type 8 src_computer 9 src_ip 10 process 11 file
    vec![g(0), g(1), String::new(), g(2), g(7), g(5), g(6), g(8), g(9), g(3), g(4), String::new(), g(10), g(11)]
}

pub fn merge_files(
    files: &Vec<String>,
    output: Option<&String>,
    start_time: Option<&String>,
    end_time: Option<&String>,
) -> Result<(), Box<dyn Error>> {
    let mut merged: Vec<(NaiveDateTime, Vec<String>)> = Vec::new();
    let mut seen: HashSet<Vec<String>> = HashSet::new();
    let start_dt = start_time.and_then(|s| parse_window(s));
    let end_dt = end_time.and_then(|s| parse_window(s));
    let (mut bad_cols, mut bad_time, mut out_window, mut filtered, mut dups) = (0usize, 0usize, 0usize, 0usize, 0usize);

    for file_path in files {
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .flexible(true)
            .from_path(file_path)?;
        let mut records = rdr.records();
        let header = match records.next() {
            Some(Ok(h)) => h.iter().collect::<Vec<_>>().join(","),
            _ => return Err(Box::from(format!("Could not read header from file: {}", file_path))),
        };
        let old = if header == MASSTIN_HEADER {
            false
        } else if header == MASSTIN_HEADER_OLD {
            true
        } else {
            return Err(Box::from(format!("File {} does not have the correct Masstin header", file_path)));
        };
        let want = if old { 12 } else { 14 };

        for rec in records {
            let rec = match rec { Ok(r) => r, Err(_) => { bad_cols += 1; continue; } };
            if rec.len() != want {
                bad_cols += 1;
                continue;
            }
            let fields = to_new_layout(&rec, old);
            let t = match parse_time(&fields[0]) { Some(t) => t, None => { bad_time += 1; continue; } };
            if let Some(start) = start_dt {
                if t < start { out_window += 1; continue; }
            }
            if let Some(end) = end_dt {
                // the bound has second precision: 10:00:00.5 is still "10:00:00"
                if t.trunc_subsecs(0) > end { out_window += 1; continue; }
            }
            let ld = crate::parse::LogData {
                time_created: fields[0].clone(),
                computer: fields[1].clone(),
                event_type: fields[2].clone(),
                event_id: fields[3].clone(),
                logon_type: fields[4].clone(),
                target_user_name: fields[5].clone(),
                target_domain_name: fields[6].clone(),
                workstation_name: fields[7].clone(),
                ip_address: fields[8].clone(),
                subject_user_name: fields[9].clone(),
                subject_domain_name: fields[10].clone(),
                logon_id: fields[11].clone(),
                detail: fields[12].clone(),
                filename: fields[13].clone(),
            };
            if !crate::filter::should_keep_record(&ld) {
                filtered += 1;
                continue;
            }
            if seen.insert(fields.clone()) {
                merged.push((t, fields));
            } else {
                dups += 1;
            }
        }
    }

    // Sort on the parsed UTC instant, never on the text: sources write
    // different formats (`T` vs space, `Z` vs `+00:00`, fractions).
    merged.sort_by(|a, b| a.0.cmp(&b.0));

    let mut wtr = csv::WriterBuilder::new().has_headers(false).from_writer(Vec::new());
    wtr.write_record(MASSTIN_HEADER.split(','))?;
    for (_, f) in &merged {
        wtr.write_record(f)?;
    }
    let bytes = wtr.into_inner().map_err(|e| e.to_string())?;
    match output {
        Some(p) => std::fs::write(p, &bytes)?,
        None => print!("{}", String::from_utf8_lossy(&bytes)),
    }

    let dropped = bad_cols + bad_time;
    if dropped > 0 || out_window > 0 || filtered > 0 || dups > 0 {
        crate::banner::print_info(&format!(
            "Merge: {} rows written; skipped {} malformed (wrong column count), {} unparseable time, {} outside window, {} filtered, {} duplicate",
            merged.len(), bad_cols, bad_time, out_window, filtered, dups
        ));
    }
    if dropped > 0 {
        crate::banner::print_warning(&format!("Merge: {} row(s) could not be read and were dropped", dropped));
    }
    Ok(())
}
