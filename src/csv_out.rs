//! Direct writer for the 14-column timeline CSV.
//!
//! The Windows and Winlogbeat parsers used to build a polars DataFrame
//! only to write it out again. Writing the rows directly keeps the exact
//! layout polars produced (empty fields as `""`, quotes only when a value
//! contains a comma, a quote or a line break) without materialising
//! fourteen columns a second time, and drops the heaviest dependency of
//! the build. `parse_linux` has written its rows this way since the
//! large-corpus work; the quoting rule is the same.

use std::fs::File;
use std::io::{self, BufWriter, Write};

use crate::parse::LogData;

pub(crate) const HEADER: &str = "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename";

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

/// Write `rows`, already in the order wanted, to `output` (a path) or to
/// stdout when `output` is `None`.
pub(crate) fn write_timeline(rows: &[LogData], output: Option<&String>) -> io::Result<()> {
    let mut sink: Box<dyn Write> = match output {
        Some(p) => Box::new(BufWriter::with_capacity(1 << 20, File::create(p)?)),
        None => Box::new(BufWriter::new(io::stdout())),
    };
    sink.write_all(HEADER.as_bytes())?;
    sink.write_all(b"\n")?;
    for r in rows {
        let line = format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
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
        );
        sink.write_all(line.as_bytes())?;
    }
    sink.flush()
}

#[cfg(test)]
mod tests {
    use super::q;

    #[test]
    fn quoting_matches_the_old_writer() {
        assert_eq!(q(""), "\"\"");
        assert_eq!(q("plain"), "plain");
        assert_eq!(q("a,b"), "\"a,b\"");
        assert_eq!(q("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(q("two\nlines"), "\"two\nlines\"");
        assert_eq!(q("with space"), "with space");
    }
}
