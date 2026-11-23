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

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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

/// The ceiling: all the cores but the ones left to the system ([`reserved`],
/// one unless asked) when there are four or more; one otherwise.
pub fn policy(cores: usize) -> usize {
    policy_leaving(cores, reserved())
}

/// [`policy`] with `reserve` cores left to the system.
pub fn policy_leaving(cores: usize, reserve: usize) -> usize {
    if cores >= 4 {
        cores.saturating_sub(reserve.max(1)).max(1)
    } else {
        1
    }
}

/// The cores a run leaves to the rest of the machine: one, or what
/// `MASSTIN_RESERVE_CORES` says. The viewer asks two for the parses it
/// starts: the window and, over remote desktop, the session that carries
/// it need a core of their own while the evidence is read.
pub fn reserved() -> usize {
    reserved_from(std::env::var("MASSTIN_RESERVE_CORES").ok().as_deref())
}

/// [`reserved`] from the variable's text: a whole number, one at least; one
/// when it is not one.
pub fn reserved_from(v: Option<&str>) -> usize {
    v.and_then(|s| s.trim().parse::<usize>().ok()).filter(|&n| n >= 1).unwrap_or(1)
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
        if background_io() {
            sys::background_io();
        }
    }
}

/// Whether the run reads and writes the disk in the background
/// (`MASSTIN_IO_PRIORITY=low`): its disk work, and on Windows its memory and
/// CPU too, yield to everything else. With the disk to itself the run goes
/// as fast as ever; it waits only when something else wants the disk. Off
/// unless asked: measured while a 25 GB image was extracted, it made no
/// difference to the desktop's own disk work (spinning disk and SSD alike).
pub fn background_io() -> bool {
    std::env::var("MASSTIN_IO_PRIORITY").map(|v| v.trim().eq_ignore_ascii_case("low")).unwrap_or(false)
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
    idle_workers_leaving(idle_cores, workers, reserved())
}

/// [`idle_workers`] with `reserve` idle cores left to the system.
pub fn idle_workers_leaving(idle_cores: f32, workers: usize, reserve: usize) -> usize {
    ((idle_cores - reserve.max(1) as f32).floor().max(1.0) as usize).min(workers.max(1))
}

/// `--parallel-images`, when given.
pub fn asked_images() -> Option<usize> {
    ASKED_IMAGES.get().copied().flatten()
}

/// The most images worth reading at once right now whatever the storage
/// says: the idle cores, and the free memory at half a gigabyte a reader.
pub fn images_cap() -> usize {
    let by_memory = available_memory().map(|m| (m / (512 << 20)) as usize).unwrap_or(usize::MAX);
    available_now().min(by_memory).max(1)
}

static BYTES_READ: AtomicU64 = AtomicU64::new(0);

/// Bytes read from the images so far: the readers count what they read
/// (`parse_image_windows::Counting`), the controller below measures the
/// rate.
pub fn note_read(bytes: u64) {
    BYTES_READ.fetch_add(bytes, Ordering::Relaxed);
}

pub fn bytes_read() -> u64 {
    BYTES_READ.load(Ordering::Relaxed)
}

/// A window of measurement: this long with the readers steady before the
/// rate is judged.
pub const PROBE_WINDOW: Duration = Duration::from_secs(3);
/// After a step back, no new growth for this long.
const PROBE_REST: Duration = Duration::from_secs(60);

/// How many images to read at once, found by measuring rather than set:
/// readers are doubled while the bytes a second coming off the images keep
/// growing, the last size is kept back when a doubling brings nothing, and
/// they are halved when the rate falls; the storage's kind only says where
/// to start (one reader on a spinning disk, two elsewhere), the idle cores
/// and the free memory are the ceiling. `--parallel-images` fixes the
/// figure instead. The output never depends on the count.
pub struct Readers {
    floor: usize,
    target: AtomicUsize,
    probe: Mutex<Probe>,
}

/// What the controller remembers between windows. Pure, so it is tested
/// with made-up rates.
#[derive(Debug, Clone)]
pub struct Probe {
    /// bytes a second at the best size seen
    best: f64,
    /// the size that gave `best`
    best_at: usize,
    /// no growth tried until this moment passes
    rest_until: Option<Instant>,
    window_start: Instant,
    bytes_at_start: u64,
}

impl Probe {
    fn new() -> Probe {
        Probe { best: 0.0, best_at: 0, rest_until: None, window_start: Instant::now(), bytes_at_start: 0 }
    }

    /// The size to read at next, given the rate a window saw with `under_way`
    /// readers at the current `target`: doubled (within `cap`) while the rate
    /// grows a sixth or more over the best; back to the best size when a
    /// bigger one brought nothing; halved (down to `floor`) when the rate fell
    /// by a third or more. A window with fewer readers than the target, or
    /// with nothing read, judges nothing.
    pub fn step(&mut self, target: usize, under_way: usize, rate: f64, now: Instant, floor: usize, cap: usize) -> usize {
        if under_way < target || rate <= 0.0 {
            return target.clamp(floor.min(cap), cap.max(floor));
        }
        let resting = self.rest_until.map_or(false, |t| now < t);
        let next = if self.best == 0.0 || rate >= self.best * 1.16 {
            // better than anything seen: keep it, and try more
            self.best = rate;
            self.best_at = target;
            if resting { target } else { (target * 2).min(cap) }
        } else if rate <= self.best * 0.66 {
            // the storage fell behind: fewer readers, and a rest from growing
            self.rest_until = Some(now + PROBE_REST);
            (target / 2).max(floor)
        } else if target > self.best_at {
            // more readers than the best size, nothing gained: back to it, and a rest
            self.rest_until = Some(now + PROBE_REST);
            self.best_at
        } else {
            target
        };
        next.clamp(floor.min(cap), cap.max(floor))
    }
}

impl Readers {
    /// The controller for images on `medium`.
    pub fn new(medium: Medium) -> Readers {
        let floor = match medium {
            Medium::Rotational => 1,
            _ => 2,
        };
        let start = asked_images().unwrap_or(floor);
        Readers { floor, target: AtomicUsize::new(start), probe: Mutex::new(Probe::new()) }
    }

    /// The readers allowed right now, with `under_way` reading. Once a window
    /// has passed, the rate over it is judged and the target moves.
    pub fn allowed(&self, under_way: usize) -> usize {
        if let Some(n) = asked_images() {
            return n;
        }
        let cap = images_cap();
        let target = self.target.load(Ordering::SeqCst);
        let mut p = self.probe.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(p.window_start);
        if elapsed < PROBE_WINDOW {
            return target.min(cap).max(1);
        }
        let bytes = bytes_read().saturating_sub(p.bytes_at_start);
        let rate = bytes as f64 / elapsed.as_secs_f64();
        let next = p.step(target, under_way, rate, now, self.floor, cap);
        p.window_start = now;
        p.bytes_at_start = bytes_read();
        if next != target {
            self.target.store(next, Ordering::SeqCst);
            if crate::parse::is_debug_mode() {
                eprintln!("[images] {} reader(s) gave {:.0} MB/s: {} from here", target, rate / 1e6, next);
            }
        }
        next.min(cap).max(1)
    }

    /// Where it starts, for the banner.
    pub fn floor(&self) -> usize {
        self.floor
    }
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
    // (a quarter of what is free, as it always was, and never more than a
    // third of the run's memory when that was set lower)
    available_memory().map(|m| (m / 4).min(memory_limit() / 3).max(512 << 20)).unwrap_or(2 << 30)
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

    pub fn total_memory() -> Option<u64> {
        let mut m = MemoryStatusEx { length: std::mem::size_of::<MemoryStatusEx>() as u32, memory_load: 0, total_phys: 0, avail_phys: 0, total_page_file: 0, avail_page_file: 0, total_virtual: 0, avail_virtual: 0, avail_extended_virtual: 0 };
        // SAFETY: a documented Win32 call that fills the struct whose size it is told.
        let ok = unsafe { GlobalMemoryStatusEx(&mut m) };
        (ok != 0 && m.total_phys > 0).then_some(m.total_phys)
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

    /// Windows' background mode: very low disk priority, low memory
    /// priority (its pages are the first trimmed), low CPU priority.
    pub fn background_io() {
        const PROCESS_MODE_BACKGROUND_BEGIN: u32 = 0x0010_0000;
        // SAFETY: a plain Win32 call on the current process's pseudo-handle.
        unsafe {
            SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN);
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

    pub fn total_memory() -> Option<u64> {
        let text = std::fs::read_to_string("/proc/meminfo").ok()?;
        let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
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

    /// The lowest best-effort disk priority (ioprio class 2, level 7) for
    /// the whole process.
    pub fn background_io() {
        const IOPRIO_WHO_PROCESS: libc::c_long = 1;
        const IOPRIO_CLASS_BE: libc::c_long = 2;
        // SAFETY: ioprio_set(2) on the calling process (who 0), with a priority value.
        unsafe {
            libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0 as libc::c_long, (IOPRIO_CLASS_BE << 13) | 7);
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

    pub fn total_memory() -> Option<u64> {
        // (half of it is what `available_memory` answers here)
        available_memory().map(|half| half * 2)
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

    pub fn background_io() {}
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
    pub fn total_memory() -> Option<u64> {
        None
    }
    pub fn medium_of(_path: &str) -> Medium {
        Medium::Unknown
    }
    pub fn lower_priority() {}
    pub fn background_io() {}
}

/// Physical memory free right now, bytes, when the system tells.
pub fn available_memory() -> Option<u64> {
    sys::available_memory()
}

/// The memory the machine has.
pub fn total_memory() -> Option<u64> {
    sys::total_memory()
}

// ───────────────────────── the memory of a run ─────────────────────────
//
// A parse holds rows in memory to remove the duplicates, pair the sessions
// and sort: as long as they fit, that is the fastest there is. What does
// not fit goes to disk in pieces (a host's rows by source, a merge in
// sorted runs) and costs time. So the run takes what the machine can
// give, three quarters of its memory unless told otherwise, and each
// stage asks, when it starts, how much of that is really free.

static MEMORY_ASKED: OnceLock<Option<u64>> = OnceLock::new();

/// The share of the machine's memory a run may use when nothing is asked.
pub const MEMORY_SHARE_PERCENT: u64 = 75;
/// What a run may use on a machine that does not say what it has.
const MEMORY_UNKNOWN: u64 = 2 << 30;
/// The least a run is given, whatever is asked or free.
const MEMORY_LEAST: u64 = 256 << 20;

/// `8G`, `4096M`, `1.5G`, `50%`, or a bare number of MiB, as bytes
/// (`total`: the machine's memory, for a percentage).
pub fn parse_memory(s: &str, total: Option<u64>) -> Result<u64, String> {
    let t = s.trim().to_ascii_lowercase().replace(' ', "");
    let bad = || format!("`{}` is not an amount of memory: write 8G, 4096M or 50%", s.trim());
    let (num, unit) = match t.find(|c: char| !(c.is_ascii_digit() || c == '.')) {
        Some(i) => (&t[..i], &t[i..]),
        None => (t.as_str(), "m"),
    };
    let n: f64 = num.parse().map_err(|_| bad())?;
    if !(n > 0.0) {
        return Err(bad());
    }
    let bytes = match unit {
        "%" => {
            if n > 100.0 {
                return Err(bad());
            }
            let total = total.ok_or_else(|| "this machine does not say how much memory it has: give an amount (8G), not a percentage".to_string())?;
            (total as f64 * n / 100.0) as u64
        }
        "k" | "kb" | "kib" => (n * 1024.0) as u64,
        "m" | "mb" | "mib" => (n * 1048576.0) as u64,
        "g" | "gb" | "gib" => (n * 1073741824.0) as u64,
        "t" | "tb" | "tib" => (n * 1099511627776.0) as u64,
        _ => return Err(bad()),
    };
    Ok(bytes.max(MEMORY_LEAST))
}

/// Sets the memory of the run from `--memory` (else `MASSTIN_MEMORY`, else
/// three quarters of the machine's); the line for the banner.
pub fn set_memory(asked: Option<&str>) -> Result<String, String> {
    let from_env = std::env::var("MASSTIN_MEMORY").ok().filter(|v| !v.trim().is_empty());
    let (text, source) = match (asked, &from_env) {
        (Some(a), _) => (Some(a.to_string()), "--memory"),
        (None, Some(e)) => (Some(e.clone()), "MASSTIN_MEMORY"),
        (None, None) => (None, ""),
    };
    let total = total_memory();
    let parsed = match &text {
        Some(t) => Some(parse_memory(t, total)?),
        None => None,
    };
    let _ = MEMORY_ASKED.set(parsed);
    let machine = match (total, available_memory()) {
        (Some(t), Some(a)) => format!("the machine has {}, {} free now", human_bytes(t), human_bytes(a)),
        (Some(t), None) => format!("the machine has {}", human_bytes(t)),
        _ => "the machine does not say what it has".to_string(),
    };
    Ok(match parsed {
        Some(b) => format!("Memory: up to {} (asked with {}; {}); never more than what is free when a stage starts, the rest is sorted on disk", human_bytes(b), source, machine),
        None => format!("Memory: up to {} ({}% of the machine's; {}; --memory sets it); never more than what is free when a stage starts, the rest is sorted on disk", human_bytes(memory_limit()), MEMORY_SHARE_PERCENT, machine),
    })
}

/// The memory the run may use: what was asked, else three quarters of the
/// machine's.
pub fn memory_limit() -> u64 {
    if let Some(Some(b)) = MEMORY_ASKED.get() {
        return *b;
    }
    total_memory().map(|t| t / 100 * MEMORY_SHARE_PERCENT).unwrap_or(MEMORY_UNKNOWN).max(MEMORY_LEAST)
}

/// What a stage that starts now may take: the run's memory, and never more
/// than half of what the machine has free at this moment. The other half
/// stays with everything else: measured on a 20 GB machine, a stage that
/// planned to fill all but two gigabytes of what was free left the system
/// critically short (other programs were closed by it) and was a tenth
/// faster at best than one held to a fraction of that.
pub fn memory_now() -> u64 {
    memory_of(memory_limit(), available_memory())
}

fn memory_of(limit: u64, free: Option<u64>) -> u64 {
    let usable = free.map(|f| f / 2);
    usable.map_or(limit, |u| u.min(limit)).max(MEMORY_LEAST)
}

/// Rows held in memory take several times their bytes as text (a string a
/// column, each with its own allocation): measured, three to four times.
const ROWS_IN_MEMORY: u64 = 6;

/// The bytes of rows, as text, a stage may hold at once to sort or reduce
/// them: the memory it may take now over what a row costs in memory. What
/// is past that goes to disk. `MASSTIN_ROW_BUDGET_MB` fixes it.
pub fn row_budget() -> u64 {
    if let Some(mb) = std::env::var("MASSTIN_ROW_BUDGET_MB").ok().and_then(|s| s.trim().parse::<u64>().ok()).filter(|&m| m >= 1) {
        return mb << 20;
    }
    (memory_now() / ROWS_IN_MEMORY).max(32 << 20)
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
        // cores left to the system: the window's parses leave two
        assert_eq!(policy_leaving(12, 2), 10);
        assert_eq!(policy_leaving(4, 2), 2);
        assert_eq!(policy_leaving(4, 9), 1, "never fewer than one");
        assert_eq!(policy_leaving(3, 2), 1);
        assert_eq!(policy_leaving(12, 0), 11, "one at least is left");
        assert_eq!(idle_workers_leaving(8.4, 11, 2), 6);
        assert_eq!(idle_workers_leaving(2.5, 11, 2), 1);
        assert_eq!(idle_workers_leaving(100.0, 10, 2), 10);
        assert_eq!(reserved_from(None), 1);
        assert_eq!(reserved_from(Some(" 2 ")), 2);
        assert_eq!(reserved_from(Some("0")), 1);
        assert_eq!(reserved_from(Some("two")), 1);
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
            assert!(total_memory().unwrap() >= available_memory().unwrap());
            let f = idle_fraction(Duration::from_millis(50)).unwrap();
            assert!((0.0..=1.0).contains(&f), "{}", f);
        }
        assert_eq!(human_bytes(18 << 30), "18.0 GB");
        assert_eq!(human_bytes(640 << 20), "640 MB");
    }

    #[test]
    fn readers_grow_while_the_rate_grows_and_fall_back_when_it_does_not() {
        let t0 = Instant::now();
        let mut p = Probe::new();
        // two readers give 100 MB/s: the first measurement is the best, try four
        assert_eq!(p.step(2, 2, 100e6, t0, 2, 62), 4);
        // four give 180: better, try eight
        assert_eq!(p.step(4, 4, 180e6, t0, 2, 62), 8);
        // eight give 185: nothing gained, back to four and rest
        assert_eq!(p.step(8, 8, 185e6, t0, 2, 62), 4);
        // during the rest a good rate does not grow
        assert_eq!(p.step(4, 4, 300e6, t0 + Duration::from_secs(10), 2, 62), 4);
        // the rest over, growth resumes
        assert_eq!(p.step(4, 4, 360e6, t0 + PROBE_REST + Duration::from_secs(61), 2, 62), 8);
        // the storage falls behind: halved, never under the floor
        assert_eq!(p.step(8, 8, 100e6, t0 + PROBE_REST + Duration::from_secs(62), 2, 62), 4);
        let mut q = Probe::new();
        assert_eq!(q.step(2, 2, 100e6, t0, 1, 62), 4);
        assert_eq!(q.step(4, 4, 10e6, t0, 1, 62), 2);
        assert_eq!(q.step(2, 2, 5e6, t0, 1, 62), 1);
        // a window with fewer readers than the target, or nothing read, judges nothing
        let mut r = Probe::new();
        assert_eq!(r.step(4, 2, 500e6, t0, 2, 62), 4);
        assert_eq!(r.step(4, 4, 0.0, t0, 2, 62), 4);
        // the cap holds: a 64-core server with 62 idle doubles up to 62, no further
        let mut big = Probe::new();
        let mut target = 2;
        for (i, rate) in [100e6, 200e6, 400e6, 800e6, 1600e6, 3200e6, 6400e6].iter().enumerate() {
            target = big.step(target, target, *rate, t0 + Duration::from_secs(i as u64), 2, 62);
        }
        assert_eq!(target, 62);
        // a spinning disk starts at one; a fixed figure is kept whatever the rate
        assert_eq!(Readers::new(Medium::Rotational).floor(), 1);
        assert_eq!(Readers::new(Medium::Solid).floor(), 2);
        assert_eq!(Readers::new(Medium::Network).floor(), 2);
        // before `install` the pool is one, and the cap holds whatever the floor
        assert_eq!(Readers::new(Medium::Network).allowed(0), 1);
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

    #[test]
    fn memory_is_read_as_written() {
        let g = 1u64 << 30;
        assert_eq!(parse_memory("8G", None).unwrap(), 8 * g);
        assert_eq!(parse_memory(" 8 gb ", None).unwrap(), 8 * g);
        assert_eq!(parse_memory("1.5G", None).unwrap(), g + g / 2);
        assert_eq!(parse_memory("4096M", None).unwrap(), 4 * g);
        assert_eq!(parse_memory("4096", None).unwrap(), 4 * g);
        assert_eq!(parse_memory("50%", Some(32 * g)).unwrap(), 16 * g);
        // too little to work with is brought up to the least
        assert_eq!(parse_memory("10M", None).unwrap(), MEMORY_LEAST);
        for bad in ["", "lots", "0", "-2G", "150%", "8X"] {
            assert!(parse_memory(bad, Some(32 * g)).is_err(), "{}", bad);
        }
        assert!(parse_memory("50%", None).is_err());
    }

    #[test]
    fn a_stage_takes_the_limit_or_what_is_free() {
        let g = 1u64 << 30;
        // plenty free: the limit
        assert_eq!(memory_of(12 * g, Some(30 * g)), 12 * g);
        assert_eq!(memory_of(24 * g, Some(48 * g)), 24 * g);
        // half of what is free, whatever the limit
        assert_eq!(memory_of(24 * g, Some(8 * g)), 4 * g);
        assert_eq!(memory_of(24 * g, Some(20 * g)), 10 * g);
        assert_eq!(memory_of(2 * g, Some(20 * g)), 2 * g);
        // nearly nothing free: the least, never zero
        assert_eq!(memory_of(24 * g, Some(100 << 20)), MEMORY_LEAST);
        // a machine that does not say: the limit
        assert_eq!(memory_of(2 * g, None), 2 * g);
    }
}
