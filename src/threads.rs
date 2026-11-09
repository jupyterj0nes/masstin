//! How many threads a run takes, decided from the machine when `--threads`
//! does not say: the cores the process may use, one of them left to the
//! system on a machine of four or more, a single thread on one of one or
//! two. The pool is rayon's global one, shared by every parallel stage (the
//! evtx crate's chunk decoding among them), so the total never exceeds the
//! figure. The process runs below normal priority, so the desktop and the
//! analyst's other tools come first however many cores masstin takes.
//!
//! One thread runs the serial code paths exactly as they always ran; more
//! threads give the same rows in the same order (every stage collects its
//! results in the order of its inputs), only sooner.

use std::sync::OnceLock;

static WORKERS: OnceLock<usize> = OnceLock::new();
static IMAGES: OnceLock<usize> = OnceLock::new();

/// What was decided, for the banner.
pub struct Decision {
    pub workers: usize,
    pub cores: usize,
    /// the figure came from `--threads` or `MASSTIN_THREADS`
    pub asked: bool,
    /// forensic images extracted at once (parse-image, parse-massive)
    pub images: usize,
}

/// The threads for this run: `asked` when it says one or more, the
/// machine's policy otherwise; and the images extracted at once:
/// `asked_images`, or two with four threads or more, one otherwise.
pub fn decide(asked: Option<usize>, asked_images: Option<usize>) -> Decision {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let (workers, was_asked) = match asked {
        Some(n) if n >= 1 => (n, true),
        _ => (policy(cores), false),
    };
    let images = match asked_images {
        Some(n) if n >= 1 => n.min(MAX_IMAGES),
        _ => images_policy(workers),
    };
    Decision { workers, cores, asked: was_asked, images }
}

/// Images extracted at once, at most: more readers than this on one disk
/// only fight each other.
pub const MAX_IMAGES: usize = 8;

/// Two images at a time when the run has four threads or more (an NVMe
/// keeps up; a spinning disk or a share over the network gains nothing from
/// more), one otherwise.
pub fn images_policy(workers: usize) -> usize {
    if workers >= 4 {
        2
    } else {
        1
    }
}

/// The images extracted at once in this run.
pub fn images() -> usize {
    IMAGES.get().copied().unwrap_or(1)
}

/// All the cores but one when there are four or more; one otherwise.
pub fn policy(cores: usize) -> usize {
    if cores >= 4 {
        cores - 1
    } else {
        1
    }
}

/// Whether the process keeps its normal priority: `MASSTIN_PRIORITY=normal`,
/// for a server where masstin is the job and nothing else should come
/// first. Below normal otherwise: a busy machine (another build, a scan)
/// makes masstin wait, by design, so a run can take longer on a loaded box.
pub fn keeps_normal_priority() -> bool {
    std::env::var("MASSTIN_PRIORITY").map(|v| v.trim().eq_ignore_ascii_case("normal")).unwrap_or(false)
}

/// Build the global pool and lower the process priority. Once per process;
/// a second call changes nothing.
pub fn install(d: &Decision) {
    if WORKERS.set(d.workers).is_err() {
        return;
    }
    let _ = IMAGES.set(d.images);
    // built with the figure even when it is one: rayon would otherwise make
    // its default pool, one thread a core, the first time a stage touches it
    let _ = rayon::ThreadPoolBuilder::new().num_threads(d.workers).thread_name(|i| format!("masstin-{}", i)).build_global();
    if !keeps_normal_priority() {
        lower_priority();
    }
}

/// The threads of this run: one before `install`, and when one was chosen.
pub fn workers() -> usize {
    WORKERS.get().copied().unwrap_or(1)
}

/// The threads worth giving a file of `bytes`: an EVTX is decoded a 64 KiB
/// chunk at a time, and a pool woken for a file of a handful of chunks
/// costs more than it saves (293 small files took a fifth longer on
/// eleven threads than on one). A thread for every four chunks, the
/// run's figure at most, one at least.
pub fn for_bytes(bytes: u64) -> usize {
    let chunks = bytes / 65_536;
    (chunks / 4).clamp(1, workers() as u64) as usize
}

/// The bytes of EVTX a run holds in memory at once while several files are
/// read: a quarter of the memory the machine has free, 512 MiB at least;
/// 2 GiB when the machine does not say. A file bigger than the budget is
/// read alone.
pub fn file_budget() -> u64 {
    available_memory().map(|m| (m / 4).max(512 << 20)).unwrap_or(2 << 30)
}

/// Physical memory free right now, bytes, when the system tells.
#[cfg(windows)]
pub fn available_memory() -> Option<u64> {
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
    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
    }
    let mut m = MemoryStatusEx { length: std::mem::size_of::<MemoryStatusEx>() as u32, memory_load: 0, total_phys: 0, avail_phys: 0, total_page_file: 0, avail_page_file: 0, total_virtual: 0, avail_virtual: 0, avail_extended_virtual: 0 };
    // SAFETY: a documented Win32 call that fills the struct whose size it is told.
    let ok = unsafe { GlobalMemoryStatusEx(&mut m) };
    (ok != 0 && m.avail_phys > 0).then_some(m.avail_phys)
}

#[cfg(target_os = "linux")]
pub fn available_memory() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = text.lines().find(|l| l.starts_with("MemAvailable:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
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

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn available_memory() -> Option<u64> {
    None
}

#[cfg(windows)]
fn lower_priority() {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn SetPriorityClass(process: isize, class: u32) -> i32;
    }
    const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;
    // SAFETY: both are plain Win32 calls on the current process's pseudo-handle.
    unsafe {
        SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    }
}

#[cfg(unix)]
fn lower_priority() {
    extern "C" {
        fn nice(inc: i32) -> i32;
    }
    // SAFETY: nice(2) takes an increment and returns the new value; nothing else.
    unsafe {
        nice(5);
    }
}

#[cfg(not(any(windows, unix)))]
fn lower_priority() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_leaves_the_system_a_core() {
        assert_eq!(policy(1), 1);
        assert_eq!(policy(2), 1);
        assert_eq!(policy(3), 1);
        assert_eq!(policy(4), 3);
        assert_eq!(policy(12), 11);
        assert_eq!(policy(64), 63);
        assert_eq!(decide(Some(3), None).workers, 3);
        assert!(decide(Some(3), None).asked);
        // zero asked is no answer: the policy decides
        let d = decide(Some(0), None);
        assert!(!d.asked);
        assert_eq!(d.workers, policy(d.cores));
    }

    #[test]
    fn images_two_at_a_time_on_a_machine_with_threads() {
        assert_eq!(images_policy(1), 1);
        assert_eq!(images_policy(3), 1);
        assert_eq!(images_policy(4), 2);
        assert_eq!(images_policy(31), 2);
        assert_eq!(decide(Some(8), Some(4)).images, 4);
        assert_eq!(decide(Some(8), Some(40)).images, MAX_IMAGES);
        assert_eq!(decide(Some(8), Some(0)).images, 2);
        assert_eq!(decide(Some(1), None).images, 1);
    }

    #[test]
    fn the_file_budget_is_sane() {
        let b = file_budget();
        assert!(b >= 512 << 20, "{}", b);
        if cfg!(any(windows, target_os = "linux")) {
            assert!(available_memory().unwrap() > 0);
        }
    }

    #[test]
    fn small_files_take_one_thread() {
        // before `install`, the run's figure is one: every size gives one
        assert_eq!(for_bytes(0), 1);
        assert_eq!(for_bytes(8 << 20), 1);
        // the rule itself, with the run's figure as the ceiling
        let rule = |bytes: u64, workers: u64| (bytes / 65_536 / 4).clamp(1, workers);
        assert_eq!(rule(100 << 10, 11), 1);
        assert_eq!(rule(1 << 20, 11), 4);
        assert_eq!(rule(8 << 20, 11), 11);
        assert_eq!(rule(1 << 30, 11), 11);
    }
}
