use masstin::Cli;
use clap::Parser;
use std::process;
use tokio;

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

    let cli = Cli::parse();

    if let Err(e) = masstin::run(cli).await {
        eprintln!("Masstin - Error: {}", e);
        process::exit(1);
    }
}
