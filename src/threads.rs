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

/// What was decided, for the banner.
pub struct Decision {
    pub workers: usize,
    pub cores: usize,
    /// the figure came from `--threads` or `MASSTIN_THREADS`
    pub asked: bool,
}

/// The threads for this run: `asked` when it says one or more, the
/// machine's policy otherwise.
pub fn decide(asked: Option<usize>) -> Decision {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    match asked {
        Some(n) if n >= 1 => Decision { workers: n, cores, asked: true },
        _ => Decision { workers: policy(cores), cores, asked: false },
    }
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
        assert_eq!(decide(Some(3)).workers, 3);
        assert!(decide(Some(3)).asked);
        // zero asked is no answer: the policy decides
        let d = decide(Some(0));
        assert!(!d.asked);
        assert_eq!(d.workers, policy(d.cores));
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
