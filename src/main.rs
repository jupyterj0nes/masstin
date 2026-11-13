use masstin::Cli;
use clap::Parser;
use std::process;
use tokio;

/// A console nobody else is attached to was created for this process by
/// a double-click: free it, so only the window stays. From a terminal the
/// console is shared and kept.
#[cfg(windows)]
fn detach_own_console() {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
        fn FreeConsole() -> i32;
    }
    let mut ids = [0u32; 4];
    // SAFETY: plain Win32 calls with a valid buffer and its length
    let n = unsafe { GetConsoleProcessList(ids.as_mut_ptr(), ids.len() as u32) };
    if n <= 1 {
        unsafe {
            FreeConsole();
        }
    }
}

#[tokio::main]
async fn main() {
    // Hidden mode: when MASSTIN_VALIDATE_EVTX is set, this process is a child
    // spawned by parse-carve's phase-2 validation to parse a single synthetic
    // EVTX in full isolation. The alloc_error path in the evtx crate
    // (`Vec::with_capacity` on a corrupt BinXML template-values count) calls
    // `abort()` — `catch_unwind` does NOT intercept that, so the only way to
    // survive it is to quarantine the risk in a child process and let the
    // parent observe a non-zero exit code.
    if let Ok(path) = std::env::var("MASSTIN_VALIDATE_EVTX") {
        let ok = masstin::validate_evtx_file(&path);
        process::exit(if ok { 0 } else { 1 });
    }

    // No arguments (a double-click on masstin.exe, or `masstin` alone): the
    // window, on its welcome. With a console of its own and nothing to print
    // on it, the console goes away.
    let cli = if std::env::args_os().len() == 1 && cfg!(feature = "ui") {
        #[cfg(windows)]
        detach_own_console();
        Cli::parse_from(["masstin", "-a", "view"])
    } else {
        // `masstin parse D:\case` is `masstin -a parse D:\case`
        Cli::parse_from(masstin::args_with_action_flag(std::env::args_os()))
    };

    if let Err(e) = masstin::run(cli).await {
        eprintln!("Masstin - Error: {}", e);
        process::exit(1);
    }
}
