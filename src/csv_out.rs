//! The timeline CSV: its layouts and the direct writer.
//!
//! Every parse action writes the same 19 columns: the 14 that describe
//! the event, then the analysis tail (`hunt`, `hunt_score`, `hunt_why`,
//! written by graph-hunt; `verdict`, `notes`, written by the analyst),
//! empty until something fills it. The tail is the same in caarea,
//! faramir and allymacb, so a case tool maps it once for every CSV.
//!
//! Three layouts are read: the 12-column one of 2023 (no `event_type`,
//! no `logon_id`, `process` where `detail` is now), the 14-column one
//! written until v1.3.4, and the 19-column one. Every reader goes through
//! [`Layout::of`] and the column positions it gives; no module keeps a
//! copy of the header.
//!
//! The Windows and Winlogbeat parsers used to build a polars DataFrame
//! only to write it out again. Writing the rows directly keeps the exact
//! layout polars produced (empty fields as `""`, quotes only when a value
//! contains a comma, a quote or a line break) without materialising the
//! columns a second time, and drops the heaviest dependency of the build.
//! The tail is written bare when empty (`,,,,,`): five `""` on every row
//! of a 27-million-row timeline are 400 MB of quotes.

use std::fs::File;
use std::io::{self, BufWriter, Write};

use crate::parse::LogData;

/// The 14 event columns, in order.
pub(crate) const BASE_COLUMNS: [&str; 14] = [
    "time_created",
    "dst_computer",
    "event_type",
    "event_id",
    "logon_type",
    "target_user_name",
    "target_domain_name",
    "src_computer",
    "src_ip",
    "subject_user_name",
    "subject_domain_name",
    "logon_id",
    "detail",
    "log_filename",
];

/// The analysis tail: the hunt's verdict on the row and the analyst's.
pub(crate) const TAIL_COLUMNS: [&str; 5] = ["hunt", "hunt_score", "hunt_why", "verdict", "notes"];

/// Number of columns every writer produces.
pub(crate) const COLUMNS: usize = 19;

/// The header every writer produces: the 14 event columns and the tail.
pub(crate) const HEADER: &str = "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename,hunt,hunt_score,hunt_why,verdict,notes";

/// The 19-column header of the first days of the tail (2026-11-02/03),
/// when the second column of the tail was the raw q-value. Same
/// positions; readers convert the value with [`score_of_text`].
pub(crate) const HEADER_19_Q: &str = "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename,hunt,hunt_q,hunt_why,verdict,notes";

/// The 14-column header written until v1.3.4.
pub(crate) const HEADER_14: &str = "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename";

/// The 12-column header of 2023.
pub(crate) const HEADER_12: &str = "time_created,dst_computer,event_id,subject_user_name,subject_domain_name,target_user_name,target_domain_name,logon_type,src_computer,src_ip,process,log_filename";

/// Empty tail, as the writers append it to a row.
pub(crate) const EMPTY_TAIL: &str = ",,,,,";

/// Values of the `hunt` column.
pub(crate) const HUNT_SIGNIFICANT: &str = "significant";
pub(crate) const HUNT_CANDIDATE: &str = "candidate";
pub(crate) const HUNT_HABITUAL: &str = "habitual";
pub(crate) const HUNT_NOT_EVALUATED: &str = "not_evaluated";
pub(crate) const HUNT_BASELINE: &str = "baseline";

/// Values of the `verdict` column.
pub(crate) const VERDICTS: [&str; 3] = ["suspicious", "confirmed", "benign"];

/// Which of the three layouts a header announces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Layout {
    /// 2023: 12 columns, `process` where `detail` is now, no `event_type`,
    /// no `logon_id`
    V12,
    /// until v1.3.4: the 14 event columns
    V14,
    /// the 14 event columns and the analysis tail
    V19,
}

impl Layout {
    /// The layout a header line announces, or None when it is not a
    /// masstin timeline. A UTF-8 BOM, quotes around the names and a line
    /// end are tolerated.
    pub(crate) fn of(header: &str) -> Option<Layout> {
        let h = header.trim_start_matches('\u{feff}').trim_end_matches(['\r', '\n']);
        let h: String = h.split(',').map(|c| c.trim().trim_matches('"')).collect::<Vec<_>>().join(",");
        match h.as_str() {
            HEADER | HEADER_19_Q => Some(Layout::V19),
            HEADER_14 => Some(Layout::V14),
            HEADER_12 => Some(Layout::V12),
            _ => None,
        }
    }

    /// Number of fields of a row.
    pub(crate) fn columns(self) -> usize {
        match self {
            Layout::V12 => 12,
            Layout::V14 => 14,
            Layout::V19 => COLUMNS,
        }
    }

    /// Position of each of the 14 event columns in a row of this layout
    /// (None: the column does not exist in it).
    pub(crate) fn base_indices(self) -> [Option<usize>; 14] {
        match self {
            // 0 time 1 dst 2 event_id 3 subj_user 4 subj_dom 5 tgt_user
            // 6 tgt_dom 7 logon_type 8 src_computer 9 src_ip 10 process 11 file
            Layout::V12 => [Some(0), Some(1), None, Some(2), Some(7), Some(5), Some(6), Some(8), Some(9), Some(3), Some(4), None, Some(10), Some(11)],
            Layout::V14 | Layout::V19 => {
                let mut v = [None; 14];
                for (i, slot) in v.iter_mut().enumerate() {
                    *slot = Some(i);
                }
                v
            }
        }
    }

    /// The row in the 19-column layout: the 14 event columns in their
    /// place and the tail (kept when the row has one, empty otherwise).
    pub(crate) fn to_v19(self, fields: &[&str]) -> Vec<String> {
        let g = |i: Option<usize>| i.and_then(|i| fields.get(i)).map(|s| s.to_string()).unwrap_or_default();
        let mut out: Vec<String> = self.base_indices().iter().map(|i| g(*i)).collect();
        for k in 0..TAIL_COLUMNS.len() {
            out.push(if self == Layout::V19 { g(Some(14 + k)) } else { String::new() });
        }
        out
    }
}

/// Quote one field the way polars' CSV writer did: an empty value is
/// written as `""`, a value with a comma, a quote or a line break is
/// quoted with inner quotes doubled, anything else is written bare.
pub(crate) fn q(s: &str) -> String {
    if s.is_empty() {
        "\"\"".to_string()
    } else if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Quote one tail field: like [`q`], but an empty value is written bare.
pub(crate) fn qt(s: &str) -> String {
    if s.is_empty() {
        String::new()
    } else {
        q(s)
    }
}

/// The tail of a row, from its five values.
pub(crate) fn tail(hunt: &str, hunt_score: &str, hunt_why: &str, verdict: &str, notes: &str) -> String {
    if hunt.is_empty() && hunt_score.is_empty() && hunt_why.is_empty() && verdict.is_empty() && notes.is_empty() {
        return EMPTY_TAIL.to_string();
    }
    format!(",{},{},{},{},{}", qt(hunt), qt(hunt_score), qt(hunt_why), qt(verdict), qt(notes))
}

/// Top of the `hunt_score` scale.
pub(crate) const SCORE_MAX: u8 = 100;

/// The `hunt_score` of a q-value: how rare the connection is, 0 to 100,
/// on the Phred scale (`-10 log10 q`, rounded): 0 is a connection no
/// rarer than chance (q = 1), 13 is one in twenty, 20 one in a hundred,
/// 30 one in a thousand, 60 one in a million, 100 one in ten thousand
/// million or rarer. None for NaN (no test).
pub(crate) fn score_of(q: f64) -> Option<u8> {
    if q.is_nan() {
        return None;
    }
    if q <= 0.0 {
        return Some(SCORE_MAX);
    }
    let s = (-10.0 * q.log10()).round();
    Some(s.clamp(0.0, SCORE_MAX as f64) as u8)
}

/// The `hunt_score` written in a column: a score as written by this
/// version, or a raw q-value from a timeline annotated with the
/// `hunt_q` header, converted. None when empty or not a number.
pub(crate) fn score_of_text(s: &str, header_has_q: bool) -> Option<u8> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if header_has_q {
        return s.parse::<f64>().ok().and_then(score_of);
    }
    s.parse::<f64>().ok().map(|v| v.round().clamp(0.0, SCORE_MAX as f64) as u8)
}

/// Whether a header line is the one with the raw q-value in the tail.
pub(crate) fn header_has_q(header: &str) -> bool {
    header.contains("hunt_q")
}

/// How rare a score is, in words, for a pane or a tooltip.
pub(crate) fn score_words(score: u8) -> String {
    if score == 0 {
        return "no rarer than chance".to_string();
    }
    if score >= SCORE_MAX {
        return "one in ten thousand million or rarer".to_string();
    }
    let n = 10f64.powf(score as f64 / 10.0);
    // two significant figures, with separators
    let mag = 10f64.powi(n.log10().floor() as i32 - 1).max(1.0);
    let r = (n / mag).round() * mag;
    let r = r.round() as u64;
    let mut digits = r.to_string();
    let mut out = String::new();
    while digits.len() > 3 {
        let rest = digits.split_off(digits.len() - 3);
        out = format!(",{}{}", rest, out);
    }
    format!("one in {}{}", digits, out)
}

/// Identity of a row across runs: FNV-1a over its 14 event columns. The
/// same event parsed again from the same evidence has the same hash; the
/// analysis tail is not part of it, so marking a row does not change it.
pub(crate) fn row_hash<S: AsRef<str>>(base: &[S]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for f in base.iter().take(14) {
        for &b in f.as_ref().as_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// The analyst's marks of a timeline (`verdict`, `notes`), by row hash,
/// to carry them onto another timeline of the same evidence.
pub(crate) struct Marks {
    map: std::collections::HashMap<u64, (String, String)>,
}

impl Marks {
    /// Read the marked rows of `path` (a timeline of any layout; one
    /// without a tail holds no marks).
    pub(crate) fn load(path: &str) -> io::Result<Marks> {
        let mut rdr = csv::ReaderBuilder::new().has_headers(false).flexible(true).from_path(path)?;
        let mut records = rdr.records();
        let header = match records.next() {
            Some(Ok(h)) => h.iter().collect::<Vec<_>>().join(","),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}: cannot read the header", path))),
        };
        let layout = Layout::of(&header).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{}: not a masstin timeline", path)))?;
        let mut map = std::collections::HashMap::new();
        if layout == Layout::V19 {
            for rec in records.flatten() {
                if rec.len() != COLUMNS {
                    continue;
                }
                let v = rec.get(17).unwrap_or("");
                let n = rec.get(18).unwrap_or("");
                if v.is_empty() && n.is_empty() {
                    continue;
                }
                let base: Vec<&str> = rec.iter().take(14).collect();
                map.insert(row_hash(&base), (v.to_string(), n.to_string()));
            }
        }
        Ok(Marks { map })
    }

    /// The marks of the row with these 14 event columns.
    pub(crate) fn get<S: AsRef<str>>(&self, base: &[S]) -> Option<&(String, String)> {
        self.map.get(&row_hash(base))
    }

    /// Number of marked rows read.
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }
}

/// Write `rows`, already in the order wanted, to `output` (a path) or to
/// stdout when `output` is `None`.
pub(crate) fn write_timeline(rows: &[LogData], output: Option<&String>) -> io::Result<()> {
    let mut sink: Box<dyn Write> = match output {
        Some(p) => Box::new(BufWriter::with_capacity(1 << 20, File::create(p)?)),
        None => Box::new(BufWriter::new(io::stdout())),
    };
    sink.write_all(HEADER.as_bytes())?;
    sink.write_all(b"\n")?;
    if crate::threads::workers() > 1 {
        // the lines of a block made on the pool, written in the block's order
        use rayon::prelude::*;
        for block in rows.chunks(16_384) {
            let lines: Vec<String> = block.par_iter().map(row_line).collect();
            for line in &lines {
                sink.write_all(line.as_bytes())?;
            }
        }
    } else {
        for r in rows {
            sink.write_all(row_line(r).as_bytes())?;
        }
    }
    sink.flush()
}

/// One row as its line of the timeline, newline included.
fn row_line(r: &LogData) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{}{}\n",
        q(&r.time_created),
        q(&r.computer),
        q(&r.event_type),
        q(&r.event_id),
        q(&r.logon_type),
        q(&r.target_user_name),
        q(&r.target_domain_name),
        q(&r.workstation_name),
        q(&r.ip_address),
        q(&r.subject_user_name),
        q(&r.subject_domain_name),
        q(&r.logon_id),
        q(&r.detail),
        q(&r.filename),
        EMPTY_TAIL,
    )
}

/// Write a timeline that holds only the header, so a later merge step
/// finds a valid (empty) file instead of a missing one.
pub(crate) fn write_empty_timeline(output: &str) -> io::Result<()> {
    std::fs::write(output, format!("{}\n", HEADER))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_matches_the_old_writer() {
        assert_eq!(q(""), "\"\"");
        assert_eq!(q("plain"), "plain");
        assert_eq!(q("a,b"), "\"a,b\"");
        assert_eq!(q("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(q("two\nlines"), "\"two\nlines\"");
        assert_eq!(q("with space"), "with space");
        assert_eq!(qt(""), "");
        assert_eq!(qt("a,b"), "\"a,b\"");
    }

    #[test]
    fn header_is_the_base_columns_and_the_tail() {
        let cols: Vec<&str> = BASE_COLUMNS.iter().chain(TAIL_COLUMNS.iter()).copied().collect();
        assert_eq!(HEADER, cols.join(","));
        assert_eq!(HEADER.split(',').count(), COLUMNS);
        assert_eq!(HEADER_14, BASE_COLUMNS.join(","));
        assert_eq!(EMPTY_TAIL.len(), TAIL_COLUMNS.len());
    }

    #[test]
    fn layout_is_read_from_the_header() {
        assert_eq!(Layout::of(HEADER), Some(Layout::V19));
        assert_eq!(Layout::of(HEADER_19_Q), Some(Layout::V19));
        assert!(header_has_q(HEADER_19_Q) && !header_has_q(HEADER));
    }

    #[test]
    fn score_scale() {
        assert_eq!(score_of(f64::NAN), None);
        assert_eq!(score_of(1.0), Some(0));
        assert_eq!(score_of(0.05), Some(13));
        assert_eq!(score_of(0.01), Some(20));
        assert_eq!(score_of(1e-3), Some(30));
        assert_eq!(score_of(1e-6), Some(60));
        assert_eq!(score_of(1e-12), Some(100));
        assert_eq!(score_of(0.0), Some(100));
        assert_eq!(score_of_text("", false), None);
        assert_eq!(score_of_text("30", false), Some(30));
        assert_eq!(score_of_text("1.000e-3", true), Some(30));
        assert_eq!(score_of_text("1", true), Some(0));
        assert_eq!(score_words(0), "no rarer than chance");
        assert_eq!(score_words(13), "one in 20");
        assert_eq!(score_words(30), "one in 1,000");
        assert_eq!(score_words(60), "one in 1,000,000");
        assert_eq!(score_words(100), "one in ten thousand million or rarer");
        assert_eq!(Layout::of(HEADER_14), Some(Layout::V14));
        assert_eq!(Layout::of(HEADER_12), Some(Layout::V12));
        assert_eq!(Layout::of(&format!("\u{feff}{}\r\n", HEADER)), Some(Layout::V19));
        let quoted: String = HEADER_14.split(',').map(|c| format!("\"{}\"", c)).collect::<Vec<_>>().join(",");
        assert_eq!(Layout::of(&quoted), Some(Layout::V14));
        assert_eq!(Layout::of("rank,significant,p_value"), None);
        assert_eq!(Layout::of(""), None);
    }

    #[test]
    fn rows_are_mapped_to_the_19_column_layout() {
        let v14: Vec<&str> = (0..14).map(|_| "x").collect();
        let out = Layout::V14.to_v19(&v14);
        assert_eq!(out.len(), 19);
        assert!(out[..14].iter().all(|s| s == "x"));
        assert!(out[14..].iter().all(|s| s.is_empty()));

        let v19 = ["t", "d", "SUCCESSFUL_LOGON", "4624", "10", "u", "D", "w", "ip", "s", "S", "0x1", "det", "f", "significant", "0.001", "why", "benign", "note"];
        let out = Layout::V19.to_v19(&v19);
        assert_eq!(out[14], "significant");
        assert_eq!(out[17], "benign");
        assert_eq!(out[18], "note");

        // 0 time 1 dst 2 event_id 3 subj_user 4 subj_dom 5 tgt_user
        // 6 tgt_dom 7 logon_type 8 src_computer 9 src_ip 10 process 11 file
        let v12 = ["t", "d", "4624", "su", "sd", "tu", "td", "10", "w", "ip", "proc", "f"];
        let out = Layout::V12.to_v19(&v12);
        assert_eq!(out[0], "t");
        assert_eq!(out[1], "d");
        assert_eq!(out[2], "");
        assert_eq!(out[3], "4624");
        assert_eq!(out[4], "10");
        assert_eq!(out[5], "tu");
        assert_eq!(out[6], "td");
        assert_eq!(out[7], "w");
        assert_eq!(out[8], "ip");
        assert_eq!(out[9], "su");
        assert_eq!(out[10], "sd");
        assert_eq!(out[11], "");
        assert_eq!(out[12], "proc");
        assert_eq!(out[13], "f");
        assert!(out[14..].iter().all(|s| s.is_empty()));
    }

    #[test]
    fn tail_is_bare_when_empty() {
        assert_eq!(tail("", "", "", "", ""), EMPTY_TAIL);
        assert_eq!(tail("significant", "0.001", "a; b", "", "x, y"), ",significant,0.001,a; b,,\"x, y\"");
    }
}
