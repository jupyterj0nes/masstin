//! Room on the temporary disk. What masstin unpacks (the logs out of a disk
//! image, the logs of a package, the rows it sorts on disk) goes to a
//! temporary folder, the system's by default: a big case can fill the
//! system drive, and a full system drive leaves Windows no room to grow its
//! page file, which is how a machine ends up barely answering.
//!
//! Before a file is written there, masstin checks that the disk keeps a
//! reserve free after it (5 GB, or a quarter of a small disk;
//! `MASSTIN_TEMP_RESERVE_MB` sets it). When it would not, the run waits and
//! says so, looking again every 15 seconds (another program, or the analyst,
//! may free some); after `MASSTIN_SPACE_WAIT_MIN` minutes (30) the file is
//! left out, loudly, and listed at the end of the run; until room comes
//! back, the next files that find none are left out at once instead of each
//! waiting its own minutes. The disk is never
//! filled. The check is a system call made again only when what was free
//! the last time is used up or five seconds old, so a run with room to
//! spare does not wait for anything.
//!
//! The temporary folder is the system's, or `--temp` / `MASSTIN_TEMP`; when
//! the system's disk is short of room and the disk of the timeline written
//! has more, masstin puts its temporary files beside the timeline and says so.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

static ROOT: OnceLock<PathBuf> = OnceLock::new();

/// Under this much free, the system's temporary disk is short of room and a
/// disk with more is preferred.
const SHORT_OF_ROOM: u64 = 20 << 30;

/// The folder this run's temporary files go under.
pub fn temp_root() -> PathBuf {
    if let Some(r) = ROOT.get() {
        return r.clone();
    }
    if let Some(v) = std::env::var_os("MASSTIN_TEMP").filter(|v| !v.is_empty()) {
        return PathBuf::from(v);
    }
    std::env::temp_dir()
}

/// Chooses the run's temporary folder (once) and says where, for the banner:
/// the one asked (`--temp`, `MASSTIN_TEMP`), else the system's, else, when
/// the system's disk has less than 20 GB free and the timeline's disk has
/// twice as much, a `masstin-temp` folder beside the timeline.
pub fn choose(asked: Option<&str>, output: Option<&str>) -> String {
    let asked = asked.map(str::to_string).or_else(|| std::env::var("MASSTIN_TEMP").ok()).filter(|s| !s.trim().is_empty());
    let (root, why) = match asked {
        Some(a) => (PathBuf::from(a.trim()), "asked".to_string()),
        None => {
            let sys = std::env::temp_dir();
            let sys_free = free_and_total(&sys).map(|(f, _)| f);
            let beside = output.and_then(|o| {
                let p = Path::new(o);
                let dir = p.parent().filter(|d| !d.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
                std::fs::canonicalize(&dir).ok().map(|d| d.join("masstin-temp"))
            });
            match (sys_free, beside) {
                (Some(sf), Some(b)) if sf < SHORT_OF_ROOM && !same_volume(&sys, &b) => {
                    let bf = b.parent().and_then(free_and_total).map(|(f, _)| f).unwrap_or(0);
                    if bf >= sf.saturating_mul(2) {
                        (b, format!("the system's disk has only {} free; this one has {} (--temp chooses)", human(sf), human(bf)))
                    } else {
                        (sys, "the system's; --temp chooses another".to_string())
                    }
                }
                _ => (sys, "the system's; --temp chooses another".to_string()),
            }
        }
    };
    let _ = std::fs::create_dir_all(&root);
    let _ = ROOT.set(root.clone());
    // the children this run starts (the parts of a parse) use the same
    std::env::set_var("MASSTIN_TEMP", &root);
    let room = free_and_total(&root).map(|(f, t)| format!(", {} free, {} kept free", human(f), human(reserve(t)))).unwrap_or_default();
    format!("Temporary files: {} ({}{})", root.display(), why, room)
}

/// What is kept free on a disk of `total` bytes: 5 GB, or a quarter of a
/// small disk; `MASSTIN_TEMP_RESERVE_MB` sets it.
pub fn reserve(total: u64) -> u64 {
    if let Some(mb) = std::env::var("MASSTIN_TEMP_RESERVE_MB").ok().and_then(|s| s.trim().parse::<u64>().ok()) {
        return mb << 20;
    }
    reserve_of(total)
}

pub fn reserve_of(total: u64) -> u64 {
    (5u64 << 30).min(total / 4)
}

/// What a parse of Linux evidence may write to the temporary folder, said
/// before it starts from what it found: `likely` for logs as they usually
/// are (a few lines in a hundred are logons), `at_most` for the worst
/// there is (every line a logon: a server under a brute force for weeks).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Need {
    pub likely: u64,
    pub at_most: u64,
}

/// `biggest_package`: the biggest package once unpacked (they are unpacked
/// one at a time); `log_text`: the bytes of text logs outside packages
/// (inflated, for the gzipped ones). A row on disk is a little more than
/// its line, and it is there up to three times at the end (its host's
/// file, the pieces or the sorted runs, the timeline before the merge):
/// measured, 5.6 times the log for a log of logons only.
pub fn need_of(biggest_package: u64, log_text: u64) -> Need {
    Need {
        likely: biggest_package + biggest_package / 10 + log_text / 2,
        at_most: biggest_package.saturating_mul(3).saturating_add(log_text.saturating_mul(8)),
    }
}

/// What to say of `need` against the room of `dir`: the line, and whether
/// it is a warning (the run may not fit).
pub fn forecast(need: Need, dir: &Path) -> Option<(String, bool)> {
    let (free, total) = free_and_total(dir)?;
    Some(forecast_of(need, free, reserve(total), &dir.display().to_string()))
}

fn forecast_of(need: Need, free: u64, kept: u64, dir: &str) -> (String, bool) {
    let usable = free.saturating_sub(kept);
    let room = format!("{} has {} free, {} of them usable ({} always stay free)", dir, human(free), human(usable), human(kept));
    if need.likely > usable {
        (format!(
            "The temporary folder will most likely run short: this run needs about {} there (up to {} if every line of the logs is a logon) and {}. Free room there or name another folder with --temp; started as it is, the files that find no room wait and are then left out of the timeline, named at the end.",
            human(need.likely), human(need.at_most), room
        ), true)
    } else if need.at_most > usable {
        (format!(
            "The temporary folder may run short: this run needs about {} there, and up to {} if every line of the logs is a logon (a server under a brute force); {}. --temp names a folder with more room; files that find none wait and are then left out, named at the end.",
            human(need.likely), human(need.at_most), room
        ), true)
    } else {
        (format!("Temporary room: about {} needed, {} at the very most; {}", human(need.likely), human(need.at_most), room), false)
    }
}

fn wait_limit() -> Duration {
    let min = std::env::var("MASSTIN_SPACE_WAIT_MIN").ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(30);
    Duration::from_secs(min * 60)
}

/// What was free the last time each disk was asked, less what was written
/// since, and when it was asked.
static HEADROOM: Mutex<Vec<(String, i64, Instant)>> = Mutex::new(Vec::new());
/// The files left out for lack of room, for the end of the run.
static LEFT_OUT: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// When the run last said it waits for room: once a minute at most, however
/// many files wait.
static LAST_SAID: Mutex<Option<Instant>> = Mutex::new(None);
/// A wait ran out: until room comes back, the files that find none are left
/// out at once instead of each waiting its own minutes.
static GAVE_UP: Mutex<bool> = Mutex::new(false);

/// Room for `bytes` more in `dir`, the reserve kept: at once when there is,
/// after waiting when there is not yet, an error when there never was.
pub fn make_room(dir: &Path, bytes: u64) -> std::io::Result<()> {
    if std::env::var_os("MASSTIN_NO_SPACE_GUARD").is_some() {
        return Ok(());
    }
    let key = volume_key(dir);
    {
        let mut h = HEADROOM.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = h.iter_mut().find(|e| e.0 == key) {
            if e.1 >= bytes as i64 && e.2.elapsed() < Duration::from_secs(5) {
                e.1 -= bytes as i64;
                return Ok(());
            }
        }
    }
    let started = Instant::now();
    let mut said = false;
    loop {
        let Some((free, total)) = free_and_total(dir) else { return Ok(()) };
        let room = free as i64 - reserve(total) as i64;
        if room >= bytes as i64 {
            let mut h = HEADROOM.lock().unwrap_or_else(|e| e.into_inner());
            match h.iter_mut().find(|e| e.0 == key) {
                Some(e) => *e = (key.clone(), room - bytes as i64, Instant::now()),
                None => h.push((key.clone(), room - bytes as i64, Instant::now())),
            }
            let mut gave_up = GAVE_UP.lock().unwrap_or_else(|e| e.into_inner());
            if said || *gave_up {
                crate::banner::print_info(&format!("Room on disk {} again ({} free): going on", key, human(free)));
            }
            *gave_up = false;
            return Ok(());
        }
        if !said {
            said = true;
            let mut last = LAST_SAID.lock().unwrap_or_else(|e| e.into_inner());
            if last.map_or(true, |t| t.elapsed() >= Duration::from_secs(60)) {
                *last = Some(Instant::now());
                crate::banner::print_warning(&format!(
                    "Waiting for room on disk {} ({} to write, {} free, {} kept free for the system). Free some space there, or run masstin with --temp on another disk; a file that finds no room within {} min is left out and named at the end.",
                    key,
                    human(bytes),
                    human(free),
                    human(reserve(total)),
                    wait_limit().as_secs() / 60
                ));
            }
        }
        let gave_up = *GAVE_UP.lock().unwrap_or_else(|e| e.into_inner());
        if gave_up || started.elapsed() >= wait_limit() {
            *GAVE_UP.lock().unwrap_or_else(|e| e.into_inner()) = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("no room on disk {} ({} to write, {} free, {} kept free)", key, human(bytes), human(free), human(reserve(total))),
            ));
        }
        std::thread::sleep(Duration::from_secs(15).min(wait_limit()));
    }
}

/// A file left out for lack of room, for the end of the run.
pub fn left_out(what: &str, why: &str) {
    // the temporary folder's own path says nothing: what is under it does
    let root = temp_root().to_string_lossy().to_string();
    let what = what.strip_prefix(root.as_str()).map(|r| r.trim_start_matches(['\\', '/'])).unwrap_or(what);
    LEFT_OUT.lock().unwrap_or_else(|e| e.into_inner()).push(format!("{} ({})", what, why));
}

/// At the end of a run: what was left out for lack of room, if anything.
pub fn report() {
    let v = LEFT_OUT.lock().unwrap_or_else(|e| e.into_inner());
    if v.is_empty() {
        return;
    }
    crate::banner::print_warning(&format!(
        "{} file(s) left out for lack of room on the temporary disk; their events are missing from the timeline. Run again with --temp on a disk with more room:",
        v.len()
    ));
    for f in v.iter().take(20) {
        crate::banner::print_warning(&format!("  {}", f));
    }
    if v.len() > 20 {
        crate::banner::print_warning(&format!("  ... and {} more", v.len() - 20));
    }
}

/// A file on the temporary disk whose writes wait for room (see
/// [`make_room`]); a write there is no room for fails, as on a full disk.
pub struct Guarded {
    f: std::fs::File,
    dir: PathBuf,
    path: PathBuf,
    failed: bool,
}

pub fn create(path: &Path) -> std::io::Result<Guarded> {
    let f = std::fs::File::create(path)?;
    Ok(Guarded::new(f, path))
}

/// Opened to append (created when missing).
pub fn append(path: &Path) -> std::io::Result<Guarded> {
    let f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    Ok(Guarded::new(f, path))
}

impl Guarded {
    fn new(f: std::fs::File, path: &Path) -> Guarded {
        let dir = path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
        Guarded { f, dir, path: path.to_path_buf(), failed: false }
    }
}

impl Write for Guarded {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Err(e) = make_room(&self.dir, buf.len() as u64) {
            if !self.failed {
                self.failed = true;
                left_out(&self.path.to_string_lossy(), &e.to_string());
            }
            return Err(e);
        }
        self.f.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.f.flush()
    }
}

/// The temporary folders of run `pid` (any kind masstin makes) under the
/// temporary folders it may have used, deleted; the bytes freed. For a run
/// that was stopped: killed, it could not clean up after itself.
pub fn clean_run(pid: u32) -> u64 {
    let mut freed = 0u64;
    for root in roots() {
        let Ok(rd) = std::fs::read_dir(&root) else { continue };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if run_pid(&name) == Some(pid) {
                freed += size_of(&e.path());
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    freed
}

/// The temporary folders left by runs that are no longer running (a run
/// killed, a machine switched off mid-run), deleted; the bytes freed. Only
/// folders masstin names after its runs, an hour old at least, of a process
/// that does not exist.
pub fn clean_stale() -> u64 {
    let mut freed = 0u64;
    let me = std::process::id();
    for root in roots() {
        let Ok(rd) = std::fs::read_dir(&root) else { continue };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(pid) = run_pid(&name) else { continue };
            if pid == me || sys::alive(pid) {
                continue;
            }
            let old = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).map_or(false, |a| a >= Duration::from_secs(3600));
            if !old || !e.file_type().map_or(false, |t| t.is_dir()) {
                continue;
            }
            freed += size_of(&e.path());
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
    freed
}

/// The folders masstin's temporary files go under: this run's, the
/// system's, `MASSTIN_TEMP`.
fn roots() -> Vec<PathBuf> {
    let mut v = vec![temp_root(), std::env::temp_dir()];
    if let Some(t) = std::env::var_os("MASSTIN_TEMP").filter(|t| !t.is_empty()) {
        v.push(PathBuf::from(t));
    }
    v.sort();
    v.dedup();
    v
}

/// The run a temporary folder belongs to: `masstin_run_<pid>`,
/// `masstin_linux_extract_<pid>`, `masstin_rows_<pid>_<n>`,
/// `masstin_parse_<pid>`, `masstin_cortex_<pid>`.
pub fn run_pid(name: &str) -> Option<u32> {
    for prefix in ["masstin_run_", "masstin_linux_extract_", "masstin_rows_", "masstin_parse_", "masstin_cortex_"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            let tail = &rest[digits.len()..];
            if !digits.is_empty() && (tail.is_empty() || (prefix == "masstin_rows_" && tail.starts_with('_'))) {
                return digits.parse().ok();
            }
        }
    }
    None
}

fn size_of(p: &Path) -> u64 {
    walkdir::WalkDir::new(p).into_iter().filter_map(Result::ok).filter_map(|e| e.metadata().ok()).filter(|m| m.is_file()).map(|m| m.len()).sum()
}

/// `C:`, `\\server\share`, or the path itself where there are no drives.
fn volume_key(p: &Path) -> String {
    let s = p.to_string_lossy().replace('/', "\\");
    if s.len() >= 2 && s.as_bytes()[1] == b':' {
        return s[..2].to_ascii_uppercase();
    }
    if let Some(rest) = s.strip_prefix("\\\\?\\") {
        if rest.len() >= 2 && rest.as_bytes()[1] == b':' {
            return rest[..2].to_ascii_uppercase();
        }
    }
    if s.starts_with("\\\\") {
        let parts: Vec<&str> = s.trim_start_matches('\\').splitn(3, '\\').collect();
        if parts.len() >= 2 {
            return format!("\\\\{}\\{}", parts[0], parts[1]);
        }
    }
    if cfg!(windows) {
        return s;
    }
    // no drives: the disk is found by the system from the path itself; one key
    // per folder asked (masstin writes its temporary files under one root)
    p.to_string_lossy().to_string()
}

fn same_volume(a: &Path, b: &Path) -> bool {
    cfg!(windows) && volume_key(a) == volume_key(b)
}

/// `MASSTIN_TIMING=1`: how long each stage of a parse took, on stderr
/// (`[timing] what: 12.3 s`), for measuring a run on a slow machine.
pub fn timing(what: &str, since: Instant) {
    static ON: OnceLock<bool> = OnceLock::new();
    if *ON.get_or_init(|| std::env::var_os("MASSTIN_TIMING").is_some()) {
        eprintln!("[timing] {}: {:.2} s", what, since.elapsed().as_secs_f64());
    }
}

/// `18.2 GB`, `640 MB`, `12 KB`.
pub fn human(b: u64) -> String {
    if b < 1 << 20 {
        format!("{} KB", (b + 1023) / 1024)
    } else {
        crate::threads::human_bytes(b)
    }
}

/// Free and total bytes of the disk holding `p` (or its nearest existing
/// parent), when the system says.
pub fn free_and_total(p: &Path) -> Option<(u64, u64)> {
    let mut q = p.to_path_buf();
    while !q.exists() {
        q = q.parent()?.to_path_buf();
    }
    sys::free_and_total(&q)
}

#[cfg(windows)]
mod sys {
    use std::path::Path;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetDiskFreeSpaceExW(dir: *const u16, avail: *mut u64, total: *mut u64, free: *mut u64) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
        fn GetExitCodeProcess(process: isize, code: *mut u32) -> i32;
        fn CloseHandle(handle: isize) -> i32;
    }
    /// Whether process `pid` runs (when the system cannot say, it does).
    pub fn alive(pid: u32) -> bool {
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        const STILL_ACTIVE: u32 = 259;
        // SAFETY: plain Win32 calls; the handle is closed.
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h == 0 {
                // no such process (or no right to ask: then it is not ours to clean)
                return std::io::Error::last_os_error().raw_os_error() != Some(87);
            }
            let mut code = 0u32;
            let ok = GetExitCodeProcess(h, &mut code);
            CloseHandle(h);
            ok == 0 || code == STILL_ACTIVE
        }
    }
    pub fn free_and_total(p: &Path) -> Option<(u64, u64)> {
        let w: Vec<u16> = p.as_os_str().to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
        // SAFETY: a NUL-terminated wide string and three out-parameters of the documented size.
        let ok = unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) };
        (ok != 0 && total > 0).then_some((avail, total))
    }
}

#[cfg(unix)]
mod sys {
    use std::path::Path;
    /// Whether process `pid` runs.
    pub fn alive(pid: u32) -> bool {
        // SAFETY: kill(2) with signal 0 only asks whether the process exists.
        let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    pub fn free_and_total(p: &Path) -> Option<(u64, u64)> {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
        // SAFETY: an all-zero statvfs is a valid value to be filled in.
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: a NUL-terminated path and the platform's own statvfs.
        let rc = unsafe { libc::statvfs(c.as_ptr(), &mut s) };
        if rc != 0 {
            return None;
        }
        let unit = if s.f_frsize > 0 { s.f_frsize as u64 } else { s.f_bsize as u64 };
        let total = (s.f_blocks as u64).saturating_mul(unit);
        (total > 0).then_some(((s.f_bavail as u64).saturating_mul(unit), total))
    }
}

#[cfg(not(any(windows, unix)))]
mod sys {
    pub fn free_and_total(_p: &std::path::Path) -> Option<(u64, u64)> {
        None
    }
    pub fn alive(_pid: u32) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reserve_is_five_gigabytes_or_a_quarter_of_a_small_disk() {
        assert_eq!(reserve_of(1 << 40), 5 << 30);
        assert_eq!(reserve_of(64 << 20), 16 << 20);
        assert_eq!(reserve_of(0), 0);
        assert_eq!(human(1500), "2 KB");
        assert_eq!(human(3 << 20), "3 MB");
        assert_eq!(human(5 << 30), "5.0 GB");
    }

    #[test]
    fn a_run_is_known_by_its_folders() {
        assert_eq!(run_pid("masstin_run_4242"), Some(4242));
        assert_eq!(run_pid("masstin_linux_extract_77"), Some(77));
        assert_eq!(run_pid("masstin_rows_12_3"), Some(12));
        assert_eq!(run_pid("masstin_parse_9"), Some(9));
        assert_eq!(run_pid("masstin_run_"), None);
        assert_eq!(run_pid("masstin_run_12x"), None);
        assert_eq!(run_pid("masstin_wizard_tar_5"), None, "a test's folder");
        assert_eq!(run_pid("masstin-temp"), None);
        assert!(sys::alive(std::process::id()));
        // a stopped run's folders go, another's stay
        let me = std::process::id();
        let a = std::env::temp_dir().join(format!("masstin_rows_{}_999", me));
        std::fs::create_dir_all(a.join("x")).unwrap();
        std::fs::write(a.join("x").join("f"), b"12345").unwrap();
        let b = std::env::temp_dir().join(format!("masstin_rows_{}_999", me + 1));
        std::fs::create_dir_all(&b).unwrap();
        assert!(clean_run(me) >= 5);
        assert!(!a.exists() && b.exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn the_volume_of_a_path() {
        assert_eq!(volume_key(Path::new(r"c:\Users\x\AppData\Local\Temp")), "C:");
        assert_eq!(volume_key(Path::new("D:/demo")), "D:");
        assert_eq!(volume_key(Path::new(r"\\?\D:\demo")), "D:");
        assert_eq!(volume_key(Path::new(r"\\server\share\case\x")), r"\\server\share");
    }

    #[test]
    fn the_disk_is_asked_and_a_small_write_has_room() {
        let t = std::env::temp_dir();
        let (free, total) = free_and_total(&t).expect("the system says");
        assert!(total >= free && total > 0);
        // a folder not made yet is asked through its parent
        assert!(free_and_total(&t.join("masstin-not-there").join("deeper")).is_some());
        assert!(make_room(&t, 1).is_ok());
        let p = t.join(format!("masstin_space_{}", std::process::id()));
        let mut g = create(&p).unwrap();
        g.write_all(b"room").unwrap();
        drop(g);
        let mut g = append(&p).unwrap();
        g.write_all(b" more").unwrap();
        drop(g);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "room more");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn the_room_is_said_before_the_run() {
        let g = 1u64 << 30;
        // a 2 GB package and 10 GB of text logs
        let need = need_of(2 * g, 10 * g);
        assert_eq!(need.likely, 2 * g + 2 * g / 10 + 5 * g);
        assert_eq!(need.at_most, 86 * g);
        // room for the worst: said, no warning
        let (line, warn) = forecast_of(need, 200 * g, 5 * g, "D:/t");
        assert!(!warn && line.starts_with("Temporary room"), "{}", line);
        // room for the usual, not for the worst
        let (line, warn) = forecast_of(need, 50 * g, 5 * g, "D:/t");
        assert!(warn && line.contains("may run short"), "{}", line);
        // not even for the usual
        let (line, warn) = forecast_of(need, 10 * g, 5 * g, "D:/t");
        assert!(warn && line.contains("most likely run short") && line.contains("--temp"), "{}", line);
        // nothing to write: nothing needed
        assert_eq!(need_of(0, 0), Need { likely: 0, at_most: 0 });
    }
}
