//! What the evidence is, and which parser reads it.
//!
//! `masstin parse` and the window's ingest wizard both start here: a bounded
//! walk over what was given counts what it holds (EVTX, UAL databases,
//! triage packages by kind, disk images, Linux logs by family, macOS
//! logarchives and `log show` exports, Winlogbeat JSON, masstin timelines,
//! archives of no known layout), and [`judge`] says which parser takes it,
//! how sure it is, and why, in words.

use std::collections::BTreeMap;
use std::path::Path;

/// The parsers the detector can choose, by their action name.
pub const PARSE_WINDOWS: &str = "parse-windows";
pub const PARSE_LINUX: &str = "parse-linux";
pub const PARSE_MAC: &str = "parse-mac";
pub const PARSE_IMAGE: &str = "parse-image";
pub const PARSE_MASSIVE: &str = "parse-massive";
pub const PARSER_ELASTIC: &str = "parser-elastic";

/// How far a look goes. The window looks quickly (the wizard waits on it);
/// the command line has all the time it needs.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub depth: usize,
    pub entries: usize,
    pub secs: f32,
}

impl Limits {
    /// The wizard's look: twelve levels, sixty thousand entries, eight seconds.
    pub const QUICK: Limits = Limits { depth: 12, entries: 60_000, secs: 8.0 };
    /// `masstin parse`: deep enough for any evidence folder.
    pub const FULL: Limits = Limits { depth: 64, entries: 5_000_000, secs: 600.0 };
}

/// What a look at the evidence found.
#[derive(Default, Clone, Debug)]
pub struct Scan {
    pub evtx: usize,
    pub mdb: usize,
    /// archive name and the kind of triage it is
    pub triages: Vec<(String, &'static str)>,
    /// archives of no known layout
    pub archives: usize,
    /// first segments of disk images
    pub images: Vec<String>,
    /// Linux log family -> files
    pub linux: BTreeMap<&'static str, usize>,
    pub uac: usize,
    /// tarballs of a Linux file system (etc/, var/log/...) that are not UAC
    pub linux_tars: usize,
    pub logarchives: usize,
    pub mac_json: usize,
    pub elastic_json: usize,
    pub timelines: Vec<String>,
    pub files: usize,
    pub dirs: usize,
    /// the walk stopped early (too much, or too slow)
    pub truncated: bool,
    pub secs: f32,
}

impl Scan {
    pub fn windows(&self) -> usize {
        self.evtx + self.mdb + self.triages.iter().filter(|(_, k)| *k != "UAC").count()
    }
    pub fn linux_total(&self) -> usize {
        self.linux.values().sum::<usize>() + self.uac + self.linux_tars + self.triages.iter().filter(|(_, k)| *k == "UAC").count()
    }
    pub fn mac(&self) -> usize {
        self.logarchives + self.mac_json
    }

    /// Whether anything masstin reads by itself was found (a text log of no
    /// known family is not: that is for the custom-parser rules).
    pub fn recognised(&self) -> bool {
        self.windows() + self.linux_total() + self.mac() + self.images.len() + self.elastic_json + self.timelines.len() + self.archives > 0
    }

    /// One line of what was found, for the console: "1 disk image, 4 triage
    /// packages (KAPE), 19 EVTX files, 2 Linux triages".
    pub fn summary(&self) -> String {
        let n = |k: usize, one: &str, many: &str| if k == 1 { format!("1 {}", one) } else { format!("{} {}", k, many) };
        let mut parts = Vec::new();
        if !self.images.is_empty() {
            parts.push(n(self.images.len(), "disk image", "disk images"));
        }
        let win_triages: Vec<&str> = self.triages.iter().filter(|(_, k)| *k != "UAC").map(|(_, k)| *k).collect();
        if !win_triages.is_empty() {
            let mut kinds: Vec<&str> = win_triages.clone();
            kinds.sort();
            kinds.dedup();
            parts.push(format!("{} ({})", n(win_triages.len(), "triage package", "triage packages"), kinds.join(", ")));
        }
        if self.evtx > 0 {
            parts.push(n(self.evtx, "EVTX file", "EVTX files"));
        }
        if self.mdb > 0 {
            parts.push(n(self.mdb, "UAL database", "UAL databases"));
        }
        let uac = self.uac + self.triages.iter().filter(|(_, k)| *k == "UAC").count();
        if uac > 0 {
            parts.push(n(uac, "UAC triage", "UAC triages"));
        }
        if self.linux_tars > 0 {
            parts.push(n(self.linux_tars, "Linux triage", "Linux triages"));
        }
        let lin: usize = self.linux.values().sum();
        if lin > 0 {
            parts.push(n(lin, "Linux log", "Linux logs"));
        }
        if self.logarchives > 0 {
            parts.push(n(self.logarchives, "logarchive bundle", "logarchive bundles"));
        }
        if self.mac_json > 0 {
            parts.push(n(self.mac_json, "log show export", "log show exports"));
        }
        if self.elastic_json > 0 {
            parts.push(n(self.elastic_json, "Winlogbeat JSON file", "Winlogbeat JSON files"));
        }
        if !self.timelines.is_empty() {
            parts.push(n(self.timelines.len(), "masstin timeline", "masstin timelines"));
        }
        if self.archives > 0 {
            parts.push(n(self.archives, "archive of no known layout", "archives of no known layout"));
        }
        if parts.is_empty() {
            "nothing masstin knows how to read".into()
        } else {
            parts.join(", ")
        }
    }
}

/// What the look concluded: which parser, how sure, and why.
#[derive(Clone, Debug)]
pub struct Verdict {
    /// the parser's action name; None when the sources are timelines to open
    /// as they are, or nothing masstin can read
    pub parser: Option<&'static str>,
    pub sure: bool,
    pub title: String,
    pub why: String,
}

pub fn judge(s: &Scan) -> Verdict {
    let (win, lin, mac, img, ela, tl) = (s.windows(), s.linux_total(), s.mac(), s.images.len(), s.elastic_json, s.timelines.len());
    let n = |k: usize, one: &str, many: &str| if k == 1 { format!("1 {}", one) } else { format!("{} {}", k, many) };
    if win == 0 && lin == 0 && mac == 0 && img == 0 && ela == 0 && tl > 0 {
        return Verdict { parser: None, sure: true, title: "Timelines of masstin".into(), why: format!("{}: already parsed, they open as they are.", n(tl, "timeline CSV", "timeline CSVs")) };
    }
    if img > 0 && win == 0 && lin == 0 && mac == 0 && ela == 0 {
        return Verdict { parser: Some(PARSE_IMAGE), sure: true, title: if img == 1 { "A disk image".into() } else { format!("{} disk images", img) }, why: "The file system inside is read directly: Windows event logs, UAL and shadow copies, or Linux logs, whichever it holds.".into() };
    }
    if img > 0 {
        let linux = if lin > 0 { ", the Linux logs and triages" } else { "" };
        return Verdict { parser: Some(PARSE_MASSIVE), sure: true, title: "An evidence folder".into(), why: format!("{} with other evidence beside: the massive pass takes the images, the triage packages{} and the loose EVTX together, into one timeline.", n(img, "disk image", "disk images"), linux) };
    }
    if win > 0 && lin == 0 && mac == 0 && ela == 0 {
        let mut parts = Vec::new();
        if s.evtx > 0 {
            parts.push(n(s.evtx, "EVTX file", "EVTX files"));
        }
        if s.mdb > 0 {
            parts.push(n(s.mdb, "UAL database", "UAL databases"));
        }
        let t = s.triages.len();
        if t > 0 {
            parts.push(n(t, "triage package", "triage packages"));
        }
        return Verdict { parser: Some(PARSE_WINDOWS), sure: true, title: "Windows evidence".into(), why: format!("{}.", parts.join(", ")) };
    }
    if lin > 0 && win == 0 && mac == 0 && ela == 0 {
        let fams: Vec<String> = s.linux.iter().map(|(k, v)| format!("{} {}", v, k)).collect();
        let mut why = fams.join(", ");
        if s.uac > 0 {
            if !why.is_empty() {
                why.push_str(", ");
            }
            why.push_str(&n(s.uac, "UAC archive", "UAC archives"));
        }
        if s.linux_tars > 0 {
            if !why.is_empty() {
                why.push_str(", ");
            }
            why.push_str(&n(s.linux_tars, "Linux triage", "Linux triages"));
        }
        return Verdict { parser: Some(PARSE_LINUX), sure: true, title: "Linux logs".into(), why: format!("{}.", why) };
    }
    if mac > 0 && win == 0 && lin == 0 && ela == 0 {
        return Verdict { parser: Some(PARSE_MAC), sure: true, title: "macOS logs".into(), why: format!("{}{}.", n(s.logarchives, "logarchive bundle", "logarchive bundles"), if s.mac_json > 0 { format!(", {}", n(s.mac_json, "log show export", "log show exports")) } else { String::new() }) };
    }
    if ela > 0 && win == 0 && lin == 0 && mac == 0 {
        return Verdict { parser: Some(PARSER_ELASTIC), sure: true, title: "Winlogbeat JSON".into(), why: format!("{} exported from Elasticsearch.", n(ela, "JSON file", "JSON files")) };
    }
    if win > 0 && lin > 0 && mac == 0 && ela == 0 {
        return Verdict { parser: Some(PARSE_MASSIVE), sure: true, title: "Windows and Linux together".into(), why: "The massive pass takes the Windows triage packages and EVTX and the Linux logs and triages side by side, into one timeline.".into() };
    }
    if win + lin + mac + ela > 0 {
        return Verdict { parser: Some(PARSE_MASSIVE), sure: false, title: "A mix of platforms".into(), why: "Several kinds of evidence side by side. The massive pass is the safe default; one run per platform is cleaner.".into() };
    }
    if s.archives > 0 {
        return Verdict { parser: Some(PARSE_MASSIVE), sure: false, title: "Archives of no known layout".into(), why: format!("{} that is not a triage package masstin recognises. The massive pass looks inside for images; a triage package is better unpacked first.", n(s.archives, "archive", "archives")) };
    }
    Verdict { parser: None, sure: false, title: "Nothing masstin knows how to read".into(), why: "No event logs, triage packages, images or timelines were found here. Pick a parser anyway if the evidence is deeper than the look went, or choose another folder.".into() }
}

/// Walk the sources (bounded: depth, count, time) and count what is there.
pub fn scan(sources: &[String], lim: Limits) -> Scan {
    let start = std::time::Instant::now();
    let mut s = Scan::default();
    let mut budget = lim.entries;
    for src in sources {
        let p = Path::new(src);
        if p.is_dir() {
            walk(p, 0, &mut s, &mut budget, &start, &lim);
        } else {
            look_at(p, &mut s);
        }
    }
    s.secs = start.elapsed().as_secs_f32();
    s
}

fn walk(dir: &Path, depth: usize, s: &mut Scan, budget: &mut usize, start: &std::time::Instant, lim: &Limits) {
    if depth > lim.depth || *budget == 0 || start.elapsed().as_secs_f32() > lim.secs {
        s.truncated = true;
        return;
    }
    let name = dir.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    if name.ends_with(".logarchive") {
        s.logarchives += 1;
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    s.dirs += 1;
    for e in rd.flatten() {
        if *budget == 0 {
            s.truncated = true;
            return;
        }
        *budget -= 1;
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            walk(&p, depth + 1, s, budget, start, lim);
        } else if ft.is_file() {
            look_at(&p, s);
        }
    }
}

fn look_at(p: &Path, s: &mut Scan) {
    s.files += 1;
    let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".evtx") {
        s.evtx += 1;
    } else if lower.ends_with(".mdb") {
        s.mdb += 1;
    } else if lower.ends_with(".zip") {
        let kind = crate::parse::read_zip_top_entries(p).and_then(|entries| crate::parse::detect_triage_type(&p.to_string_lossy(), &entries));
        match kind {
            Some(k) => s.triages.push((name.clone(), k.short_label())),
            None => s.archives += 1,
        }
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") || lower.ends_with(".tar") {
        if lower.starts_with("uac-") {
            s.uac += 1;
        } else if tar_holds_linux_files(p) {
            s.linux_tars += 1;
        } else {
            s.archives += 1;
        }
    } else if crate::parse_image_windows::is_first_image_segment(p) {
        s.images.push(p.to_string_lossy().to_string());
    } else if lower.ends_with(".json") || lower.ends_with(".ndjson") {
        let head = head_of(p, 4096);
        if head.contains("\"winlog\"") || head.contains("\"event_id\"") && head.contains("\"@timestamp\"") {
            s.elastic_json += 1;
        } else if head.contains("\"eventMessage\"") || head.contains("\"processImagePath\"") || head.contains("\"subsystem\"") {
            s.mac_json += 1;
        }
    } else if lower.ends_with(".csv") {
        let head = head_of(p, 2048);
        let first = head.lines().next().unwrap_or("");
        if crate::csv_out::Layout::of(first).is_some() {
            s.timelines.push(p.to_string_lossy().to_string());
        }
    } else {
        let fam = crate::parse_linux::log_family(&name);
        if fam != "other" && fam != "evtx" && is_rotated_log_name(&name, fam) {
            *s.linux.entry(fam).or_insert(0) += 1;
        }
    }
}

/// Whether a tarball carries a Linux file system: among its first entries, an
/// `etc/` or `var/log/` path. Only the head of the archive is read (a few
/// hundred entries), so a multi-gigabyte collection costs nothing to look at.
fn tar_holds_linux_files(p: &Path) -> bool {
    let Ok(f) = std::fs::File::open(p) else { return false };
    let lower = p.to_string_lossy().to_ascii_lowercase();
    let reader: Box<dyn std::io::Read> = if lower.ends_with(".tar") {
        Box::new(f)
    } else {
        Box::new(flate2::read::GzDecoder::new(f))
    };
    let mut ar = tar::Archive::new(reader);
    let Ok(entries) = ar.entries() else { return false };
    for e in entries.take(400) {
        let Ok(e) = e else { return false };
        let Ok(path) = e.path() else { continue };
        let name = path.to_string_lossy().replace('\\', "/");
        let name = name.trim_start_matches("./").trim_start_matches('/');
        if name.starts_with("etc/") || name.starts_with("var/log/") || name.contains("/var/log/") || name.contains("[root]/") {
            return true;
        }
    }
    false
}

fn head_of(p: &Path, n: usize) -> String {
    use std::io::Read;
    let mut buf = vec![0u8; n];
    let Ok(mut f) = std::fs::File::open(p) else { return String::new() };
    let got = f.read(&mut buf).unwrap_or(0);
    String::from_utf8_lossy(&buf[..got]).to_string()
}

/// Whether a file is a masstin timeline (by its header).
pub fn is_timeline(p: &Path) -> bool {
    let head = head_of(p, 2048);
    crate::csv_out::Layout::of(head.lines().next().unwrap_or("")).is_some()
}

/// `secure`, `secure-20261101`, `auth.log.2.gz`, `wtmp.1`, `messages`:
/// the family's name alone or rotated. Not `Secure-Boot-Update` (a task
/// of Windows) or `messages_old.txt`.
pub fn is_rotated_log_name(name: &str, fam: &str) -> bool {
    let base = name.rsplit(|c| c == '/' || c == '\\').next().unwrap_or(name).to_ascii_lowercase();
    let rest = match fam {
        "secure" => base.strip_prefix("auth.log").or_else(|| base.strip_prefix("secure")),
        "audit" => base.strip_prefix("audit.log"),
        "journal" | "lastlog" => return true,
        f => base.strip_prefix(f),
    };
    let mut rest = rest.unwrap_or("");
    for z in [".gz", ".xz", ".bz2", ".zst"] {
        rest = rest.strip_suffix(z).unwrap_or(rest);
    }
    rest.is_empty() || rest == ".log" || (rest.starts_with(['.', '-', '_']) && rest[1..].starts_with(|c: char| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotated_log_names_only() {
        for (n, f) in [("secure", "secure"), ("secure-20261101", "secure"), ("auth.log.2.gz", "secure"), ("auth.log", "secure"), ("wtmp.1", "wtmp"), ("btmp-20261001.gz", "btmp"), ("messages", "messages"), ("audit.log.3", "audit"), ("system.journal", "journal")] {
            assert!(is_rotated_log_name(n, f), "{}", n);
        }
        for (n, f) in [("Secure-Boot-Update", "secure"), ("SecureBootEncodeUEFI", "secure"), ("messages_old.txt", "messages"), ("wtmpx-notes", "wtmp"), ("securefile", "secure")] {
            assert!(!is_rotated_log_name(n, f), "{}", n);
        }
    }

    #[test]
    fn a_folder_of_evtx_is_windows() {
        let mut s = Scan::default();
        s.evtx = 12;
        let v = judge(&s);
        assert_eq!(v.parser, Some(PARSE_WINDOWS));
        assert!(v.sure);
    }

    #[test]
    fn images_beside_evtx_are_massive_and_alone_an_image() {
        let mut s = Scan::default();
        s.images.push("a.E01".into());
        assert_eq!(judge(&s).parser, Some(PARSE_IMAGE));
        s.evtx = 1;
        assert_eq!(judge(&s).parser, Some(PARSE_MASSIVE));
    }

    #[test]
    fn linux_and_windows_together_go_to_the_massive_pass() {
        // parse-massive reads the loose Linux evidence beside the Windows one
        let mut s = Scan::default();
        s.evtx = 1;
        s.linux.insert("secure", 2);
        let v = judge(&s);
        assert_eq!(v.parser, Some(PARSE_MASSIVE));
        assert!(v.sure);
    }

    #[test]
    fn a_tarball_of_a_linux_file_system_is_a_linux_triage() {
        let dir = std::env::temp_dir().join(format!("masstin_wizard_tar_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tgz = dir.join("web01-triage.tgz");
        {
            let f = std::fs::File::create(&tgz).unwrap();
            let gz = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
            let mut b = tar::Builder::new(gz);
            for (name, body) in [("etc/hostname", "web01\n"), ("var/log/auth.log", "x\n")] {
                let mut h = tar::Header::new_gnu();
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, body.as_bytes()).unwrap();
            }
            b.into_inner().unwrap().finish().unwrap();
        }
        let other = dir.join("photos.tgz");
        {
            let f = std::fs::File::create(&other).unwrap();
            let gz = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
            let mut b = tar::Builder::new(gz);
            let mut h = tar::Header::new_gnu();
            h.set_size(1);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "holiday/beach.jpg", &b"x"[..]).unwrap();
            b.into_inner().unwrap().finish().unwrap();
        }
        let s = scan(&[dir.to_string_lossy().to_string()], Limits::QUICK);
        assert_eq!((s.linux_tars, s.archives), (1, 1));
        let mut s2 = s.clone();
        s2.images.push("a.vmdk".into());
        let v = judge(&s2);
        assert_eq!(v.parser, Some(PARSE_MASSIVE));
        assert!(v.why.contains("Linux"), "{}", v.why);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn timelines_alone_open_and_nothing_asks() {
        let mut s = Scan::default();
        s.timelines.push("t.csv".into());
        let v = judge(&s);
        assert_eq!(v.parser, None);
        assert!(v.sure);
        let v = judge(&Scan::default());
        assert_eq!(v.parser, None);
        assert!(!v.sure);
    }

    #[test]
    fn a_uac_archive_is_linux_and_a_logarchive_mac() {
        let mut s = Scan::default();
        s.uac = 1;
        assert_eq!(judge(&s).parser, Some(PARSE_LINUX));
        let mut s = Scan::default();
        s.logarchives = 1;
        assert_eq!(judge(&s).parser, Some(PARSE_MAC));
    }

    #[test]
    fn the_summary_names_what_was_found_in_the_singular_and_plural() {
        let mut s = Scan::default();
        s.images.push("a.vmdk".into());
        s.evtx = 19;
        s.triages.push(("k1.zip".into(), "KAPE"));
        s.triages.push(("k2.zip".into(), "KAPE"));
        s.linux_tars = 2;
        assert_eq!(s.summary(), "1 disk image, 2 triage packages (KAPE), 19 EVTX files, 2 Linux triages");
        assert_eq!(Scan::default().summary(), "nothing masstin knows how to read");
    }

    #[test]
    fn linux_triages_alone_say_so() {
        let mut s = Scan::default();
        s.linux_tars = 1;
        let v = judge(&s);
        assert_eq!(v.parser, Some(PARSE_LINUX));
        assert_eq!(v.why, "1 Linux triage.");
    }
}
