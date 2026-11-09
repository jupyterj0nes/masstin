//! What the machine can give masstin, measured rather than assumed. The
//! pool of threads is the machine's cores but one (one thread on a machine
//! of one to three); what is put to work at any moment is what the machine
//! has idle right then, less one core for the system, measured over a short
//! moment and again at most once a second as the run goes: a wave of files,
//! an image, a file's chunk decoder each ask before they start. The images
//! taken out of disks at once also follow the disks: one at a time on a
//! spinning disk, a few over the network, as many as the idle cores allow
//! on solid-state storage. The process runs below normal priority, so the
//! desktop and the analyst's other tools come first however much masstin
//! takes.
//!
//! `--threads` and `--parallel-images` fix the figures instead. One thread
//! runs the serial code paths exactly as they always ran; more threads give
//! the same rows in the same order, only sooner.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

static WORKERS: OnceLock<usize> = OnceLock::new();
static ASKED_THREADS: OnceLock<bool> = OnceLock::new();
static ASKED_IMAGES: OnceLock<Option<usize>> = OnceLock::new();

/// What was decided at the start, for the banner.
pub struct Decision {
    /// the pool: the ceiling of what a run puts to work
    pub workers: usize,
    pub cores: usize,
    /// the pool's size came from `--threads` or `MASSTIN_THREADS`
    pub asked: bool,
    /// the machine at the start
    pub snapshot: Snapshot,
    /// where the evidence sits, when images are to be read
    pub medium: Medium,
    /// `--parallel-images` or `MASSTIN_PARALLEL_IMAGES`, when given
    pub asked_images: Option<usize>,
}

/// What the machine has to give right now: its cores, how many of them
/// were idle over a short moment, the memory free.
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub cores: usize,
    pub idle_cores: f32,
    pub free_memory: Option<u64>,
}

/// The storage the evidence sits on, as far as the system tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Medium {
    /// a share over the network: bandwidth-bound, a few readers hide the latency
    Network,
    /// a spinning disk: readers at once only make it seek
    Rotational,
    /// solid state: as many readers as there are cores to feed them
    Solid,
    Unknown,
}

impl Medium {
    pub fn label(self) -> &'static str {
        match self {
            Medium::Network => "a network share",
            Medium::Rotational => "a spinning disk",
            Medium::Solid => "solid-state storage",
            Medium::Unknown => "storage of an unknown kind",
        }
    }
}

/// The pool for this run (`asked` when it says one or more, the machine's
/// ceiling otherwise), the machine as it is now, and the medium of the
/// evidence paths given (for the images read at once).
pub fn decide(asked: Option<usize>, asked_images: Option<usize>, evidence: &[String]) -> Decision {
    let snapshot = snapshot();
    let (workers, was_asked) = match asked {
        Some(n) if n >= 1 => (n, true),
        _ => (policy(snapshot.cores), false),
    };
    let medium = medium_of_paths(evidence);
    Decision { workers, cores: snapshot.cores, asked: was_asked, snapshot, medium, asked_images: asked_images.filter(|&n| n >= 1) }
}

/// The ceiling: all the cores but one when there are four or more; one otherwise.
pub fn policy(cores: usize) -> usize {
    if cores >= 4 {
        cores - 1
    } else {
        1
    }
}

/// Build the global pool and lower the process priority. Once per process;
/// a second call changes nothing.
pub fn install(d: &Decision) {
    if WORKERS.set(d.workers).is_err() {
        return;
    }
    let _ = ASKED_THREADS.set(d.asked);
    let _ = ASKED_IMAGES.set(d.asked_images);
    // built with the figure even when it is one: rayon would otherwise make
    // its default pool, one thread a core, the first time a stage touches it
    let _ = rayon::ThreadPoolBuilder::new().num_threads(d.workers).thread_name(|i| format!("masstin-{}", i)).build_global();
    if !keeps_normal_priority() {
        lower_priority();
    }
}

/// The pool's size: one before `install`, and when one was chosen.
pub fn workers() -> usize {
    WORKERS.get().copied().unwrap_or(1)
}

/// The machine now: cores, the idle ones measured over 150 ms, the memory free.
pub fn snapshot() -> Snapshot {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let idle = idle_fraction(Duration::from_millis(150)).unwrap_or(1.0);
    Snapshot { cores, idle_cores: idle * cores as f32, free_memory: available_memory() }
}

/// The threads worth putting to work right now: the cores idle at this
/// moment less one for the system, never more than the pool, never less
/// than one; the pool itself when `--threads` fixed it. Measured at most
/// once a second, so a wave of files or an image asks before it starts
/// and the run follows the machine as other work comes and goes.
pub fn available_now() -> usize {
    static LAST: Mutex<Option<(Instant, usize)>> = Mutex::new(None);
    let workers = workers();
    if workers <= 1 || ASKED_THREADS.get().copied().unwrap_or(false) {
        return workers;
    }
    let mut last = LAST.lock().unwrap();
    if let Some((at, n)) = *last {
        if at.elapsed() < Duration::from_secs(1) {
            return n;
        }
    }
    let s = snapshot();
    let n = idle_workers(s.idle_cores, workers);
    *last = Some((Instant::now(), n));
    n
}

/// The idle cores less one for the system, within the pool, one at least.
pub fn idle_workers(idle_cores: f32, workers: usize) -> usize {
    ((idle_cores - 1.0).floor().max(1.0) as usize).min(workers.max(1))
}

/// The images to read at once right now: `--parallel-images` when given;
/// else what the medium and the moment allow: one on a spinning disk, up
/// to four over the network, the idle cores on solid-state (or unknown)
/// storage; and never more than the free memory gives a reader half a
/// gigabyte for. Asked before each image starts.
pub fn images_now(medium: Medium) -> usize {
    if let Some(Some(n)) = ASKED_IMAGES.get() {
        return *n;
    }
    let avail = available_now();
    let by_medium = match medium {
        Medium::Rotational => 1,
        Medium::Network => avail.min(4),
        Medium::Solid | Medium::Unknown => avail,
    };
    let by_memory = available_memory().map(|m| (m / (512 << 20)) as usize).unwrap_or(usize::MAX);
    by_medium.min(by_memory).max(1)
}

/// The threads worth giving a file of `bytes`: an EVTX is decoded a 64 KiB
/// chunk at a time, and a pool woken for a file of a handful of chunks
/// costs more than it saves (293 small files took a fifth longer on
/// eleven threads than on one). A thread for every four chunks, what is
/// idle now at most, one at least.
pub fn for_bytes(bytes: u64) -> usize {
    let chunks = bytes / 65_536;
    (chunks / 4).clamp(1, available_now() as u64) as usize
}

/// Whether the process keeps its normal priority: `MASSTIN_PRIORITY=normal`,
/// for a server where masstin is the job and nothing else should come
/// first. Below normal otherwise: a busy machine (another build, a scan)
/// makes masstin wait, by design, so a run can take longer on a loaded box.
pub fn keeps_normal_priority() -> bool {
    std::env::var("MASSTIN_PRIORITY").map(|v| v.trim().eq_ignore_ascii_case("normal")).unwrap_or(false)
}

/// The bytes of EVTX a run holds in memory at once while several files are
/// read: a quarter of the memory the machine has free, 512 MiB at least;
/// 2 GiB when the machine does not say. A file bigger than the budget is
/// read alone.
pub fn file_budget() -> u64 {
    available_memory().map(|m| (m / 4).max(512 << 20)).unwrap_or(2 << 30)
}

/// `18.2 GB`, `640 MB`.
pub fn human_bytes(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.1} GB", b as f64 / (1u64 << 30) as f64)
    } else {
        format!("{:.0} MB", b as f64 / (1u64 << 20) as f64)
    }
}

/// The most cautious medium among the paths: a spinning disk anywhere
/// means one image at a time, a share anywhere means a few.
pub fn medium_of_paths(paths: &[String]) -> Medium {
    let mut network = false;
    let mut solid = false;
    for p in paths {
        match medium_of(p) {
            Medium::Rotational => return Medium::Rotational,
            Medium::Network => network = true,
            Medium::Solid => solid = true,
            Medium::Unknown => {}
        }
    }
    if network {
        Medium::Network
    } else if solid {
        Medium::Solid
    } else {
        Medium::Unknown
    }
}

// ───────────────────────── the system, by platform ─────────────────────────

#[cfg(windows)]
mod sys {
    use super::Medium;
    use std::time::Duration;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    impl FileTime {
        fn as_u64(self) -> u64 {
            (self.high as u64) << 32 | self.low as u64
        }
    }

    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page_file: u64,
        avail_page_file: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }

    #[repr(C)]
    struct StoragePropertyQuery {
        property_id: u32,
        query_type: u32,
        additional: [u8; 1],
    }

    #[repr(C)]
    struct DeviceSeekPenaltyDescriptor {
        version: u32,
        size: u32,
        incurs_seek_penalty: u8,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemTimes(idle: *mut FileTime, kernel: *mut FileTime, user: *mut FileTime) -> i32;
        fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
        fn GetDriveTypeW(root: *const u16) -> u32;
        fn CreateFileW(name: *const u16, access: u32, share: u32, security: *const std::ffi::c_void, disposition: u32, flags: u32, template: isize) -> isize;
        fn DeviceIoControl(device: isize, code: u32, input: *const std::ffi::c_void, input_len: u32, output: *mut std::ffi::c_void, output_len: u32, returned: *mut u32, overlapped: *mut std::ffi::c_void) -> i32;
        fn CloseHandle(handle: isize) -> i32;
        fn GetCurrentProcess() -> isize;
        fn SetPriorityClass(process: isize, class: u32) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn times() -> Option<(u64, u64)> {
        let (mut i, mut k, mut u) = (FileTime::default(), FileTime::default(), FileTime::default());
        // SAFETY: three out-parameters of the documented size.
        let ok = unsafe { GetSystemTimes(&mut i, &mut k, &mut u) };
        // the kernel time counts the idle time too
        (ok != 0).then(|| (i.as_u64(), k.as_u64() + u.as_u64()))
    }

    /// The share of the machine's cores that sat idle over `window`.
    pub fn idle_fraction(window: Duration) -> Option<f32> {
        let (i0, t0) = times()?;
        std::thread::sleep(window);
        let (i1, t1) = times()?;
        let total = t1.saturating_sub(t0);
        (total > 0).then(|| (i1.saturating_sub(i0) as f32 / total as f32).clamp(0.0, 1.0))
    }

    pub fn available_memory() -> Option<u64> {
        let mut m = MemoryStatusEx { length: std::mem::size_of::<MemoryStatusEx>() as u32, memory_load: 0, total_phys: 0, avail_phys: 0, total_page_file: 0, avail_page_file: 0, total_virtual: 0, avail_virtual: 0, avail_extended_virtual: 0 };
        // SAFETY: a documented Win32 call that fills the struct whose size it is told.
        let ok = unsafe { GlobalMemoryStatusEx(&mut m) };
        (ok != 0 && m.avail_phys > 0).then_some(m.avail_phys)
    }

    /// The medium a path sits on: a UNC path or a remote drive is the
    /// network; a fixed drive is asked whether its device incurs a seek
    /// penalty (a spinning disk does); anything else is unknown.
    pub fn medium_of(path: &str) -> Medium {
        let p = path.replace('/', "\\");
        if p.starts_with("\\\\") {
            return Medium::Network;
        }
        let bytes = p.as_bytes();
        if bytes.len() < 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
            return Medium::Unknown;
        }
        let letter = (bytes[0] as char).to_ascii_uppercase();
        let root = wide(&format!("{}:\\", letter));
        // SAFETY: a NUL-terminated wide string.
        let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
        match kind {
            4 => return Medium::Network, // DRIVE_REMOTE
            3 => {}                      // DRIVE_FIXED: asked below
            _ => return Medium::Unknown,
        }
        const FILE_SHARE_READ_WRITE: u32 = 3;
        const OPEN_EXISTING: u32 = 3;
        const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
        const STORAGE_DEVICE_SEEK_PENALTY_PROPERTY: u32 = 7;
        let device = wide(&format!("\\\\.\\{}:", letter));
        // SAFETY: a volume opened with no access rights, which needs no privilege, for a property query only.
        let h = unsafe { CreateFileW(device.as_ptr(), 0, FILE_SHARE_READ_WRITE, std::ptr::null(), OPEN_EXISTING, 0, 0) };
        if h == -1 || h == 0 {
            return Medium::Unknown;
        }
        let query = StoragePropertyQuery { property_id: STORAGE_DEVICE_SEEK_PENALTY_PROPERTY, query_type: 0, additional: [0] };
        let mut out = DeviceSeekPenaltyDescriptor { version: 0, size: 0, incurs_seek_penalty: 0 };
        let mut returned = 0u32;
        // SAFETY: the query and the descriptor are the documented structures, their sizes given.
        let ok = unsafe {
            DeviceIoControl(
                h,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &query as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<StoragePropertyQuery>() as u32,
                &mut out as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<DeviceSeekPenaltyDescriptor>() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        // SAFETY: the handle came from CreateFileW above.
        unsafe {
            CloseHandle(h);
        }
        if ok == 0 || (returned as usize) < std::mem::size_of::<DeviceSeekPenaltyDescriptor>() {
            return Medium::Unknown;
        }
        if out.incurs_seek_penalty != 0 {
            Medium::Rotational
        } else {
            Medium::Solid
        }
    }

    pub fn lower_priority() {
        const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;
        // SAFETY: both are plain Win32 calls on the current process's pseudo-handle.
        unsafe {
            SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
        }
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use super::Medium;
    use std::time::Duration;

    fn cpu_line() -> Option<(u64, u64)> {
        let text = std::fs::read_to_string("/proc/stat").ok()?;
        super::parse_proc_stat_cpu(text.lines().next()?)
    }

    pub fn idle_fraction(window: Duration) -> Option<f32> {
        let (i0, t0) = cpu_line()?;
        std::thread::sleep(window);
        let (i1, t1) = cpu_line()?;
        let total = t1.saturating_sub(t0);
        (total > 0).then(|| (i1.saturating_sub(i0) as f32 / total as f32).clamp(0.0, 1.0))
    }

    pub fn available_memory() -> Option<u64> {
        let text = std::fs::read_to_string("/proc/meminfo").ok()?;
        let line = text.lines().find(|l| l.starts_with("MemAvailable:"))?;
        let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kb * 1024)
    }

    /// The medium under a path: the mount that holds it, its file system
    /// (a network one is the network) and its block device's `rotational`.
    pub fn medium_of(path: &str) -> Medium {
        let path = std::fs::canonicalize(path).unwrap_or_else(|_| std::path::PathBuf::from(path));
        let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else { return Medium::Unknown };
        let mut best: Option<(usize, String, String)> = None;
        for line in mounts.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 3 {
                continue;
            }
            let point = f[1].replace("\\040", " ");
            if path.starts_with(&point) && best.as_ref().map_or(true, |(l, _, _)| point.len() > *l) {
                best = Some((point.len(), f[0].to_string(), f[2].to_string()));
            }
        }
        let Some((_, device, fstype)) = best else { return Medium::Unknown };
        if matches!(fstype.as_str(), "nfs" | "nfs4" | "cifs" | "smb3" | "fuse.sshfs" | "9p" | "afs") {
            return Medium::Network;
        }
        let Some(dev) = device.strip_prefix("/dev/") else { return Medium::Unknown };
        // /dev/sda1 -> sda, /dev/nvme0n1p2 -> nvme0n1; a mapper or md device is left unknown
        let base = if dev.starts_with("nvme") || dev.starts_with("mmcblk") {
            dev.split('p').next().unwrap_or(dev).to_string()
        } else if dev.starts_with("sd") || dev.starts_with("vd") || dev.starts_with("xvd") || dev.starts_with("hd") {
            dev.trim_end_matches(|c: char| c.is_ascii_digit()).to_string()
        } else {
            return Medium::Unknown;
        };
        match std::fs::read_to_string(format!("/sys/block/{}/queue/rotational", base)).map(|s| s.trim().to_string()) {
            Ok(v) if v == "1" => Medium::Rotational,
            Ok(v) if v == "0" => Medium::Solid,
            _ => Medium::Unknown,
        }
    }

    pub fn lower_priority() {
        extern "C" {
            fn nice(inc: i32) -> i32;
        }
        // SAFETY: nice(2) takes an increment and returns the new value; nothing else.
        unsafe {
            nice(5);
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod sys {
    use super::Medium;
    use std::time::Duration;

    pub fn idle_fraction(_window: Duration) -> Option<f32> {
        None
    }

    #[cfg(target_os = "macos")]
    pub fn available_memory() -> Option<u64> {
        extern "C" {
            fn sysctlbyname(name: *const std::os::raw::c_char, oldp: *mut std::os::raw::c_void, oldlenp: *mut usize, newp: *const std::os::raw::c_void, newlen: usize) -> i32;
        }
        let mut total: u64 = 0;
        let mut len = std::mem::size_of::<u64>();
        // SAFETY: hw.memsize is a u64; the buffer and its length are given.
        let rc = unsafe { sysctlbyname(c"hw.memsize".as_ptr(), &mut total as *mut u64 as *mut _, &mut len, std::ptr::null(), 0) };
        // the system does not say what is free: half of what there is
        (rc == 0 && total > 0).then_some(total / 2)
    }

    #[cfg(not(target_os = "macos"))]
    pub fn available_memory() -> Option<u64> {
        None
    }

    pub fn medium_of(_path: &str) -> Medium {
        Medium::Unknown
    }

    pub fn lower_priority() {
        extern "C" {
            fn nice(inc: i32) -> i32;
        }
        // SAFETY: nice(2) takes an increment and returns the new value; nothing else.
        unsafe {
            nice(5);
        }
    }
}

#[cfg(not(any(windows, unix)))]
mod sys {
    use super::Medium;
    use std::time::Duration;
    pub fn idle_fraction(_window: Duration) -> Option<f32> {
        None
    }
    pub fn available_memory() -> Option<u64> {
        None
    }
    pub fn medium_of(_path: &str) -> Medium {
        Medium::Unknown
    }
    pub fn lower_priority() {}
}

/// Physical memory free right now, bytes, when the system tells.
pub fn available_memory() -> Option<u64> {
    sys::available_memory()
}

/// The share of the cores idle over `window`, when the system tells.
fn idle_fraction(window: Duration) -> Option<f32> {
    sys::idle_fraction(window)
}

/// The storage a path sits on, as far as the system tells.
pub fn medium_of(path: &str) -> Medium {
    sys::medium_of(path)
}

fn lower_priority() {
    sys::lower_priority()
}

/// `cpu  user nice system idle iowait irq softirq steal …` of /proc/stat:
/// (idle + iowait, total).
#[allow(dead_code)]
fn parse_proc_stat_cpu(line: &str) -> Option<(u64, u64)> {
    let mut it = line.split_whitespace();
    if it.next()? != "cpu" {
        return None;
    }
    let v: Vec<u64> = it.filter_map(|x| x.parse().ok()).collect();
    if v.len() < 4 {
        return None;
    }
    let idle = v[3] + v.get(4).copied().unwrap_or(0);
    Some((idle, v.iter().sum()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ceiling_leaves_the_system_a_core() {
        assert_eq!(policy(1), 1);
        assert_eq!(policy(2), 1);
        assert_eq!(policy(3), 1);
        assert_eq!(policy(4), 3);
        assert_eq!(policy(12), 11);
        assert_eq!(policy(64), 63);
        let d = decide(Some(3), None, &[]);
        assert_eq!(d.workers, 3);
        assert!(d.asked);
        // zero asked is no answer: the ceiling decides
        let d = decide(Some(0), None, &[]);
        assert!(!d.asked);
        assert_eq!(d.workers, policy(d.cores));
        assert!(d.snapshot.idle_cores >= 0.0 && d.snapshot.idle_cores <= d.cores as f32);
    }

    #[test]
    fn what_is_idle_is_what_goes_to_work() {
        // eight idle of a pool of eleven: seven go (one stays for the system)
        assert_eq!(idle_workers(8.4, 11), 7);
        // the machine is busy: one thread still works
        assert_eq!(idle_workers(0.3, 11), 1);
        assert_eq!(idle_workers(1.9, 11), 1);
        // a quiet 64-core server with a pool of 63
        assert_eq!(idle_workers(63.5, 63), 62);
        assert_eq!(idle_workers(100.0, 63), 63);
    }

    #[test]
    fn the_medium_sets_the_readers() {
        assert_eq!(medium_of_paths(&[]), Medium::Unknown);
        assert_eq!(Medium::Rotational.label(), "a spinning disk");
        #[cfg(windows)]
        {
            // a UNC path is the network without asking the disk
            assert_eq!(medium_of(r"\\server\share\case\disk.E01"), Medium::Network);
            // the system drive is a fixed disk: the system says which kind, or does not
            let m = medium_of(r"C:\Windows");
            assert!(matches!(m, Medium::Solid | Medium::Rotational | Medium::Unknown));
        }
    }

    #[test]
    fn proc_stat_is_read_and_the_budget_is_sane() {
        assert_eq!(parse_proc_stat_cpu("cpu  100 0 50 800 50 0 0 0 0 0"), Some((850, 1000)));
        assert_eq!(parse_proc_stat_cpu("cpu0 1 2 3 4"), None);
        assert_eq!(parse_proc_stat_cpu("cpu 1 2"), None);
        let b = file_budget();
        assert!(b >= 512 << 20, "{}", b);
        if cfg!(any(windows, target_os = "linux")) {
            assert!(available_memory().unwrap() > 0);
            let f = idle_fraction(Duration::from_millis(50)).unwrap();
            assert!((0.0..=1.0).contains(&f), "{}", f);
        }
        assert_eq!(human_bytes(18 << 30), "18.0 GB");
        assert_eq!(human_bytes(640 << 20), "640 MB");
    }

    #[test]
    fn small_files_take_one_thread() {
        // before `install`, the pool is one: every size gives one
        assert_eq!(for_bytes(0), 1);
        assert_eq!(for_bytes(8 << 20), 1);
        // the rule itself, with what is idle as the ceiling
        let rule = |bytes: u64, avail: u64| (bytes / 65_536 / 4).clamp(1, avail);
        assert_eq!(rule(100 << 10, 11), 1);
        assert_eq!(rule(1 << 20, 11), 4);
        assert_eq!(rule(8 << 20, 11), 11);
        assert_eq!(rule(1 << 30, 11), 11);
    }
}
