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
use std::io::{Read, Write};
use std::path::PathBuf;

/// The bytes of rows held to be sorted before they go to disk as a sorted
/// run: the run's memory over what a row costs there (crate::threads). A
/// merge that fits is sorted in memory, as it always was.
fn merge_budget() -> u64 {
    crate::threads::row_budget()
}

/// A row waiting to be sorted: its instant, its place in what was read, its 19 columns.
type Held = (NaiveDateTime, u64, Vec<String>);

/// The rows of a merge, sorted on (instant, place read) without holding
/// them all: past the budget they go to disk as sorted runs, read back
/// together at the end.
struct Sorter {
    budget: u64,
    held: Vec<Held>,
    held_bytes: u64,
    runs: Vec<PathBuf>,
    dir: PathBuf,
    seq: u64,
}

fn put_row(w: &mut impl Write, row: &Held) -> std::io::Result<()> {
    w.write_all(&row.0.and_utc().timestamp().to_le_bytes())?;
    w.write_all(&row.0.and_utc().timestamp_subsec_nanos().to_le_bytes())?;
    w.write_all(&row.1.to_le_bytes())?;
    w.write_all(&(row.2.len() as u32).to_le_bytes())?;
    for f in &row.2 {
        w.write_all(&(f.len() as u32).to_le_bytes())?;
        w.write_all(f.as_bytes())?;
    }
    Ok(())
}

fn get_row(r: &mut impl Read) -> std::io::Result<Option<Held>> {
    let mut b8 = [0u8; 8];
    let mut b4 = [0u8; 4];
    match r.read_exact(&mut b8) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let secs = i64::from_le_bytes(b8);
    r.read_exact(&mut b4)?;
    let nanos = u32::from_le_bytes(b4);
    r.read_exact(&mut b8)?;
    let seq = u64::from_le_bytes(b8);
    r.read_exact(&mut b4)?;
    let n = u32::from_le_bytes(b4) as usize;
    let mut fields = Vec::with_capacity(n);
    for _ in 0..n {
        r.read_exact(&mut b4)?;
        let mut s = vec![0u8; u32::from_le_bytes(b4) as usize];
        r.read_exact(&mut s)?;
        fields.push(String::from_utf8(s).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?);
    }
    let t = DateTime::<Utc>::from_timestamp(secs, nanos).map(|d| d.naive_utc()).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "a time out of range in a sorted run"))?;
    Ok(Some((t, seq, fields)))
}

impl Sorter {
    fn new(budget: u64) -> Sorter {
        let dir = crate::space::temp_root().join(format!("masstin_run_{}", std::process::id())).join(format!("merge_runs_{:?}", std::thread::current().id()).replace(['(', ')'], "_"));
        Sorter { budget, held: Vec::new(), held_bytes: 0, runs: Vec::new(), dir, seq: 0 }
    }

    fn push(&mut self, t: NaiveDateTime, fields: Vec<String>) -> std::io::Result<()> {
        self.held_bytes += fields.iter().map(|f| f.len() as u64).sum::<u64>() + 64;
        self.held.push((t, self.seq, fields));
        self.seq += 1;
        if self.held_bytes > self.budget {
            self.spill()?;
        }
        Ok(())
    }

    fn spill(&mut self) -> std::io::Result<()> {
        if self.held.is_empty() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.dir)?;
        self.held.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        let path = self.dir.join(format!("run-{}.rows", self.runs.len()));
        let mut w = std::io::BufWriter::with_capacity(1 << 20, crate::space::create(&path)?);
        for row in &self.held {
            put_row(&mut w, row)?;
        }
        w.flush()?;
        self.runs.push(path);
        self.held = Vec::new();
        self.held_bytes = 0;
        Ok(())
    }

    /// The rows in order, each handed to `each`.
    fn drain(&mut self, each: &mut dyn FnMut(Held) -> Result<(), Box<dyn Error>>) -> Result<(), Box<dyn Error>> {
        if self.runs.is_empty() {
            self.held.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
            for row in std::mem::take(&mut self.held) {
                each(row)?;
            }
            return Ok(());
        }
        self.spill()?;
        let mut readers = Vec::with_capacity(self.runs.len());
        for p in &self.runs {
            readers.push(std::io::BufReader::with_capacity(1 << 18, std::fs::File::open(p)?));
        }
        // the next row of each run; the smallest (instant, place) goes first
        let mut heads: Vec<Option<Held>> = Vec::with_capacity(readers.len());
        let mut heap = std::collections::BinaryHeap::new();
        for (i, r) in readers.iter_mut().enumerate() {
            let h = get_row(r)?;
            if let Some(row) = &h {
                heap.push(std::cmp::Reverse((row.0, row.1, i)));
            }
            heads.push(h);
        }
        while let Some(std::cmp::Reverse((_, _, i))) = heap.pop() {
            let row = heads[i].take().expect("a run's head");
            let next = get_row(&mut readers[i])?;
            if let Some(n) = &next {
                heap.push(std::cmp::Reverse((n.0, n.1, i)));
            }
            heads[i] = next;
            each(row)?;
        }
        Ok(())
    }
}

impl Drop for Sorter {
    fn drop(&mut self) {
        if !self.runs.is_empty() {
            let _ = std::fs::remove_dir_all(&self.dir);
            // the run's folder, when this made it and nothing else is in it
            if let Some(parent) = self.dir.parent() {
                let _ = std::fs::remove_dir(parent);
            }
        }
    }
}

/// The rows of one instant, one copy of each event: the first read is
/// kept, with the analysis tail a later copy has and it lacks. (Two copies
/// of an event have the same time text, so the same instant: nothing
/// further apart is ever a duplicate.)
fn one_copy_each(group: &mut Vec<Vec<String>>, dups: &mut usize) {
    if group.len() < 2 {
        return;
    }
    let mut seen: HashMap<Vec<String>, usize> = HashMap::new();
    let mut kept: Vec<Vec<String>> = Vec::with_capacity(group.len());
    for fields in group.drain(..) {
        let base: Vec<String> = fields[..14].to_vec();
        match seen.get(&base) {
            None => {
                seen.insert(base, kept.len());
                kept.push(fields);
            }
            Some(&i) => {
                // the same event again: keep the tail the kept row lacks
                let k0 = &mut kept[i];
                for k in 14..fields.len() {
                    if k0[k].is_empty() && !fields[k].is_empty() {
                        k0[k] = fields[k].clone();
                    }
                }
                *dups += 1;
            }
        }
    }
    *group = kept;
}

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
    merge_files_within(files, output, start_time, end_time, carry_marks, merge_budget())
}

/// [`merge_files`] holding at most `budget` bytes of rows at a time: a
/// merge of any size gives the same timeline, the big ones sorted on disk.
pub(crate) fn merge_files_within(
    files: &Vec<String>,
    output: Option<&String>,
    start_time: Option<&String>,
    end_time: Option<&String>,
    carry_marks: Option<&String>,
    budget: u64,
) -> Result<(), Box<dyn Error>> {
    let mut sorter = Sorter::new(budget);
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
            sorter.push(t, fields)?;
        }
    }

    // Sorted on the parsed UTC instant, never on the text (sources write
    // different formats: `T` vs space, `Z` vs `+00:00`, fractions), the
    // rows of one instant in the order they were read. The timeline is
    // written beside its place and put there at the end: the output may be
    // one of the files merged.
    let part = output.map(|p| format!("{}.part", p));
    let sink: Box<dyn Write> = match &part {
        Some(p) => Box::new(std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(p)?)),
        None => Box::new(std::io::stdout().lock()),
    };
    let mut wtr = csv::WriterBuilder::new().has_headers(false).from_writer(sink);
    wtr.write_record(HEADER.split(','))?;
    let mut written = 0usize;
    let mut group: Vec<Vec<String>> = Vec::new();
    let mut group_t: Option<NaiveDateTime> = None;
    let wrote = (|| -> Result<(), Box<dyn Error>> {
        sorter.drain(&mut |(t, _, fields)| {
            if group_t != Some(t) {
                one_copy_each(&mut group, &mut dups);
                for f in group.drain(..) {
                    wtr.write_record(&f)?;
                    written += 1;
                }
                group_t = Some(t);
            }
            group.push(fields);
            Ok(())
        })?;
        one_copy_each(&mut group, &mut dups);
        for f in group.drain(..) {
            wtr.write_record(&f)?;
            written += 1;
        }
        wtr.flush()?;
        Ok(())
    })();
    drop(wtr);
    drop(sorter);
    if let Err(e) = wrote {
        if let Some(p) = &part {
            let _ = std::fs::remove_file(p);
        }
        return Err(e);
    }
    if let (Some(p), Some(out)) = (&part, output) {
        if std::fs::rename(p, out).is_err() {
            // (another disk's rules, a file held open: copied then)
            std::fs::copy(p, out)?;
            let _ = std::fs::remove_file(p);
        }
    }

    let dropped = bad_cols + bad_time;
    if dropped > 0 || out_window > 0 || filtered > 0 || dups > 0 {
        crate::banner::print_info(&format!(
            "Merge: {} rows written; skipped {} malformed (wrong column count), {} unparseable time, {} outside window, {} filtered, {} duplicate",
            written, bad_cols, bad_time, out_window, filtered, dups
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

    /// A merge too big for its budget (sorted on disk, in many runs) is,
    /// byte for byte, the merge done in memory: same order within an
    /// instant, same copy kept of a duplicate, same tail.
    #[test]
    fn sorted_on_disk_is_what_sorted_in_memory_gives() {
        let mut a = format!("{}\n", HEADER_14);
        let mut b = format!("{}\n", HEADER);
        for i in 0..4000u32 {
            let sec = (i * 7919) % 600; // many rows share an instant, in no order
            let row = format!("2026-01-05T10:{:02}:{:02}Z,SRV{:02},SUCCESSFUL_LOGON,4624,3,user{},CORP,WS{},10.0.{}.{},,,0x{:x},\"a, b\",Security.evtx", sec / 60, sec % 60, i % 7, i % 90, i % 40, i % 5, i % 200, i % 300);
            a.push_str(&row);
            a.push('\n');
            if i % 3 == 0 {
                // the same event again in the other file, with a tail
                b.push_str(&format!("{},,,,suspicious,note {}\n", row, i));
            }
            if i % 11 == 0 {
                b.push_str(&format!("2026-01-05 10:{:02}:{:02},SRV99,SUCCESSFUL_LOGON,4624,10,other{},CORP,WS,10.9.9.9,,,0x1,,Security.evtx,,,,,\n", sec / 60, sec % 60, i));
            }
        }
        let (fa, fb) = (tmp("big-a.csv", &a), tmp("big-b.csv", &b));
        let (whole, pieces) = (tmp("big-whole.csv", ""), tmp("big-pieces.csv", ""));
        merge_files_within(&vec![fa.clone(), fb.clone()], Some(&whole), None, None, None, u64::MAX).unwrap();
        merge_files_within(&vec![fa, fb], Some(&pieces), None, None, None, 20_000).unwrap();
        let (w, p) = (std::fs::read(&whole).unwrap(), std::fs::read(&pieces).unwrap());
        assert!(w == p, "the two merges differ");
        let rows = read(&whole);
        assert!(rows.len() > 1000 && rows.len() < 4000 + 400 + 1);
        assert!(rows.iter().any(|r| r[17] == "suspicious"));
        // the output may be one of the files merged
        merge_files_within(&vec![whole.clone()], Some(&whole), None, None, None, 20_000).unwrap();
        assert!(std::fs::read(&whole).unwrap() == p);
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
