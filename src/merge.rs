use std::collections::HashMap;
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

use crate::csv_out::{Layout, Marks, HEADER};

/// Merge timelines into one, sorted on the instant, without duplicates.
/// Every layout is read (12, 14 or 19 columns, see `csv_out::Layout`) and
/// the output always has the 19: a row's analysis tail (`hunt*`,
/// `verdict`, `notes`) is kept, and when the same event comes twice, once
/// with a tail and once without, the tail wins. `carry_marks` names an
/// earlier timeline whose `verdict` / `notes` are copied onto the rows
/// with the same 14 event columns.
pub fn merge_files(
    files: &Vec<String>,
    output: Option<&String>,
    start_time: Option<&String>,
    end_time: Option<&String>,
    carry_marks: Option<&String>,
) -> Result<(), Box<dyn Error>> {
    let mut merged: Vec<(NaiveDateTime, Vec<String>)> = Vec::new();
    // the 14 event columns of every row kept -> its position in `merged`
    let mut seen: HashMap<Vec<String>, usize> = HashMap::new();
    let start_dt = start_time.and_then(|s| parse_window(s));
    let end_dt = end_time.and_then(|s| parse_window(s));
    let marks = match carry_marks {
        Some(p) => Some(Marks::load(p)?),
        None => None,
    };
    let (mut bad_cols, mut bad_time, mut out_window, mut filtered, mut dups, mut carried) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);

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
        let layout = match Layout::of(&header) {
            Some(l) => l,
            None => return Err(Box::from(format!("File {} does not have the correct Masstin header", file_path))),
        };
        let want = layout.columns();

        for rec in records {
            let rec = match rec { Ok(r) => r, Err(_) => { bad_cols += 1; continue; } };
            if rec.len() != want {
                bad_cols += 1;
                continue;
            }
            let raw: Vec<&str> = rec.iter().collect();
            let mut fields = layout.to_v19(&raw);
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
            if let Some(m) = &marks {
                if fields[17].is_empty() && fields[18].is_empty() {
                    if let Some((v, n)) = m.get(&fields[..14]) {
                        fields[17] = v.clone();
                        fields[18] = n.clone();
                        carried += 1;
                    }
                }
            }
            let base: Vec<String> = fields[..14].to_vec();
            match seen.get(&base) {
                None => {
                    seen.insert(base, merged.len());
                    merged.push((t, fields));
                }
                Some(&i) => {
                    // the same event again: keep the tail the kept row lacks
                    let kept = &mut merged[i].1;
                    for k in 14..fields.len() {
                        if kept[k].is_empty() && !fields[k].is_empty() {
                            kept[k] = fields[k].clone();
                        }
                    }
                    dups += 1;
                }
            }
        }
    }

    // Sort on the parsed UTC instant, never on the text: sources write
    // different formats (`T` vs space, `Z` vs `+00:00`, fractions).
    merged.sort_by(|a, b| a.0.cmp(&b.0));

    let mut wtr = csv::WriterBuilder::new().has_headers(false).from_writer(Vec::new());
    wtr.write_record(HEADER.split(','))?;
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
    if let Some(m) = &marks {
        crate::banner::print_info(&format!("Merge: {} row(s) took their verdict / notes from the earlier timeline ({} marked rows there)", carried, m.len()));
    }
    if dropped > 0 {
        crate::banner::print_warning(&format!("Merge: {} row(s) could not be read and were dropped", dropped));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csv_out::{HEADER_12, HEADER_14};

    fn tmp(name: &str, body: &str) -> String {
        let p = std::env::temp_dir().join(format!("masstin-merge-{}-{}", std::process::id(), name));
        std::fs::write(&p, body).unwrap();
        p.to_string_lossy().to_string()
    }

    fn read(path: &str) -> Vec<Vec<String>> {
        let mut rdr = csv::ReaderBuilder::new().has_headers(false).from_path(path).unwrap();
        rdr.records().map(|r| r.unwrap().iter().map(|s| s.to_string()).collect()).collect()
    }

    const ROW_A: &str = "2026-01-05T10:00:00Z,SRV01,SUCCESSFUL_LOGON,4624,10,alice,CORP,WS01,10.0.0.5,,,0x1,,Security.evtx";
    const ROW_B: &str = "2026-01-05T11:00:00Z,SRV01,SUCCESSFUL_LOGON,4624,3,bob,CORP,WS02,10.0.0.6,,,0x2,,Security.evtx";

    #[test]
    fn every_layout_is_read_and_the_output_has_19_columns() {
        let f14 = tmp("a14.csv", &format!("{}\n{}\n", HEADER_14, ROW_A));
        // 0 time 1 dst 2 event_id 3 subj_user 4 subj_dom 5 tgt_user
        // 6 tgt_dom 7 logon_type 8 src_computer 9 src_ip 10 process 11 file
        let f12 = tmp("a12.csv", &format!("{}\n2026-01-05T12:00:00Z,SRV01,4624,,,carol,CORP,3,WS03,10.0.0.7,proc,Security.evtx\n", HEADER_12));
        let f19 = tmp("a19.csv", &format!("{}\n{},significant,1.000e-3,why,benign,ok seen\n", HEADER, ROW_B));
        let out = tmp("out.csv", "");
        merge_files(&vec![f14, f12, f19], Some(&out), None, None, None).unwrap();
        let rows = read(&out);
        assert_eq!(rows[0].join(","), HEADER);
        assert_eq!(rows.len(), 4);
        assert!(rows.iter().all(|r| r.len() == 19));
        // sorted on time; the 12-column row rearranged; tails kept or empty
        assert_eq!(rows[1][5], "alice");
        assert!(rows[1][14..].iter().all(|s| s.is_empty()));
        assert_eq!(rows[2][5], "bob");
        assert_eq!(&rows[2][14..], &["significant", "1.000e-3", "why", "benign", "ok seen"]);
        assert_eq!(rows[3][5], "carol");
        assert_eq!(rows[3][12], "proc");
        assert_eq!(rows[3][4], "3");
    }

    #[test]
    fn a_duplicate_event_keeps_the_tail_one_copy_has() {
        let plain = tmp("d14.csv", &format!("{}\n{}\n", HEADER_14, ROW_A));
        let marked = tmp("d19.csv", &format!("{}\n{},,,,suspicious,note\n", HEADER, ROW_A));
        let out = tmp("dout.csv", "");
        merge_files(&vec![plain, marked], Some(&out), None, None, None).unwrap();
        let rows = read(&out);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1][17], "suspicious");
        assert_eq!(rows[1][18], "note");
    }

    #[test]
    fn carry_marks_copies_verdict_and_notes_by_event_columns() {
        let old = tmp("old.csv", &format!("{}\n{},habitual,1,nothing new,benign,checked\n{},,,,,\n", HEADER, ROW_A, ROW_B));
        let fresh = tmp("fresh.csv", &format!("{}\n{}\n{}\n", HEADER_14, ROW_A, ROW_B));
        let out = tmp("cout.csv", "");
        merge_files(&vec![fresh], Some(&out), None, None, Some(&old)).unwrap();
        let rows = read(&out);
        // the hunt columns are not carried, the analyst's are
        assert_eq!(rows[1][14], "");
        assert_eq!(rows[1][17], "benign");
        assert_eq!(rows[1][18], "checked");
        assert!(rows[2][14..].iter().all(|s| s.is_empty()));
    }
}
