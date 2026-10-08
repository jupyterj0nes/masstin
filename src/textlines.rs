// Line reading for evidence text logs.
//
// `BufRead::lines()` is the wrong tool for a forensic parser: a line with a
// byte that is not UTF-8 comes back as an error (and `.flatten()` drops the
// whole line, which an attacker who chooses an SSH user name can trigger),
// and an I/O error that repeats — a truncated or corrupt `.gz` does that
// inside flate2 — makes `.lines().flatten()` spin forever. `EvidenceLines`
// keeps every line (the bad bytes become U+FFFD), stops at the first read
// error and keeps what it saw, so the caller can say how the file ended.

use flate2::read::GzDecoder;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

/// Iterator over the lines of a reader, line terminator removed (`\n` or
/// `\r\n`). Ends at end of file or at the first read error.
pub struct EvidenceLines<R: BufRead> {
    rdr: R,
    buf: Vec<u8>,
    /// Lines that were not valid UTF-8 and were kept with U+FFFD in place
    /// of the bad bytes.
    pub lossy: usize,
    /// Lines returned so far.
    pub lines: usize,
    /// The read error that ended the iteration, if any.
    pub error: Option<io::Error>,
}

impl<R: BufRead> EvidenceLines<R> {
    pub fn new(rdr: R) -> Self {
        EvidenceLines { rdr, buf: Vec::with_capacity(512), lossy: 0, lines: 0, error: None }
    }

    /// One sentence for the analyst when the file was not read cleanly:
    /// `None` when every line was read and was UTF-8.
    pub fn problem(&self, path: &Path) -> Option<String> {
        match (&self.error, self.lossy) {
            (None, 0) => None,
            (Some(e), lossy) => Some(format!(
                "{}: read stopped after {} line(s): {}{}",
                path.display(),
                self.lines,
                e,
                if lossy > 0 { format!(" ({} line(s) with bytes that are not UTF-8, kept)", lossy) } else { String::new() }
            )),
            (None, lossy) => Some(format!(
                "{}: {} line(s) with bytes that are not UTF-8 (kept, bad bytes shown as U+FFFD)",
                path.display(),
                lossy
            )),
        }
    }
}

impl<R: BufRead> Iterator for EvidenceLines<R> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.error.is_some() {
            return None;
        }
        self.buf.clear();
        match self.rdr.read_until(b'\n', &mut self.buf) {
            Ok(0) => None,
            Ok(_) => Some(self.take_line()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => self.next(),
            Err(e) => {
                self.error = Some(e);
                // a partial last line read before the error is still evidence
                if self.buf.is_empty() { None } else { Some(self.take_line()) }
            }
        }
    }
}

impl<R: BufRead> EvidenceLines<R> {
    fn take_line(&mut self) -> String {
        if self.buf.last() == Some(&b'\n') {
            self.buf.pop();
            if self.buf.last() == Some(&b'\r') {
                self.buf.pop();
            }
        }
        self.lines += 1;
        match std::str::from_utf8(&self.buf) {
            Ok(s) => s.to_string(),
            Err(_) => {
                self.lossy += 1;
                String::from_utf8_lossy(&self.buf).into_owned()
            }
        }
    }
}

/// Open a plain or gzip-compressed (`.gz`) text log.
pub fn open_plain_or_gzip(path: &Path) -> io::Result<EvidenceLines<Box<dyn BufRead>>> {
    let f = File::open(path)?;
    let rdr: Box<dyn BufRead> = if path.extension().map(|e| e.eq_ignore_ascii_case("gz")).unwrap_or(false) {
        Box::new(BufReader::new(GzDecoder::new(f)))
    } else {
        Box::new(BufReader::new(f))
    };
    Ok(EvidenceLines::new(rdr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::{Cursor, Write};

    #[test]
    fn keeps_non_utf8_lines_and_strips_terminators() {
        let data = b"one\r\ntw\xffo\nthree".to_vec();
        let mut it = EvidenceLines::new(Cursor::new(data));
        let got: Vec<String> = it.by_ref().collect();
        assert_eq!(got, vec!["one", "tw\u{FFFD}o", "three"]);
        assert_eq!(it.lossy, 1);
        assert!(it.error.is_none());
    }

    #[test]
    fn truncated_gzip_ends_instead_of_spinning() {
        let text: String = (0..5000).map(|i| format!("line {} with some text to compress\n", i)).collect();
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(text.as_bytes()).unwrap();
        let gz = enc.finish().unwrap();
        let cut = gz[..gz.len() / 2].to_vec();
        let mut it = EvidenceLines::new(BufReader::new(GzDecoder::new(Cursor::new(cut))));
        let n = it.by_ref().count();
        assert!(n > 0 && n < 5000, "read {} lines", n);
        assert!(it.error.is_some());
        assert!(it.problem(Path::new("auth.log.1.gz")).unwrap().contains("read stopped"));
    }
}
