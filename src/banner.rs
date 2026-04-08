use console::style;
use indicatif::{ProgressBar, ProgressStyle, ProgressDrawTarget};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

static SILENT_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_silent_mode(silent: bool) {
    SILENT_MODE.store(silent, Ordering::Relaxed);
}

pub fn is_silent() -> bool {
    SILENT_MODE.load(Ordering::Relaxed)
}

/// Prints to stderr only if not in silent mode
macro_rules! banner_print {
    ($($arg:tt)*) => {
        if !$crate::banner::is_silent() {
            eprint!($($arg)*);
        }
    };
}

macro_rules! banner_println {
    ($($arg:tt)*) => {
        if !$crate::banner::is_silent() {
            eprintln!($($arg)*);
        }
    };
}

pub(crate) use banner_print;
pub(crate) use banner_println;

// ─────────────────────────────────────────────────────────────────────────────
//  Banner
// ─────────────────────────────────────────────────────────────────────────────

const BANNER: &str = r#"
 ███╗   ███╗ █████╗ ███████╗███████╗████████╗██╗███╗   ██╗
 ████╗ ████║██╔══██╗██╔════╝██╔════╝╚══██╔══╝██║████╗  ██║
 ██╔████╔██║███████║███████╗███████╗   ██║   ██║██╔██╗ ██║
 ██║╚██╔╝██║██╔══██║╚════██║╚════██║   ██║   ██║██║╚██╗██║
 ██║ ╚═╝ ██║██║  ██║███████║███████║   ██║   ██║██║ ╚████║
 ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝"#;

pub fn print_banner(action: &str) {
    if is_silent() {
        return;
    }
    eprintln!("{}", style(BANNER).color256(208)); // orange
    eprintln!();
    eprintln!("  {} {}",
        style("Lateral Movement Tracker").bold(),
        style(format!("v{}", env!("CARGO_PKG_VERSION"))).dim(),
    );
    eprintln!("  {} {}",
        style("by").dim(),
        style("Tono Diaz (@jupyterj0nes)").dim(),
    );
    eprintln!("  {}", style("https://weinvestigateanything.com").dim());
    eprintln!();
    eprintln!("  {} {}",
        style("Action:").cyan().bold(),
        style(action).white().bold(),
    );
    eprintln!("{}", style("  ─────────────────────────────────────────────────────────").dim());
}

// ─────────────────────────────────────────────────────────────────────────────
//  Phase: Searching for artifacts
// ─────────────────────────────────────────────────────────────────────────────

pub fn print_search_start() {
    if is_silent() { return; }
    eprintln!();
    eprintln!("  {} {}",
        style("[1/3]").cyan().bold(),
        style("Searching for artifacts...").bold(),
    );
}

pub fn print_search_results(evtx_count: usize, zip_count: usize, dir_count: usize, file_count: usize) {
    if is_silent() { return; }
    if dir_count > 0 {
        eprintln!("        {} directories scanned", style(dir_count).yellow());
    }
    if file_count > 0 {
        eprintln!("        {} individual files added", style(file_count).yellow());
    }
    if zip_count > 0 {
        eprintln!("        {} compressed packages found", style(zip_count).yellow());
    }
    eprintln!("        {} {} EVTX artifacts found",
        style("=>").green().bold(),
        style(evtx_count).green().bold(),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  Phase: Processing artifacts
// ─────────────────────────────────────────────────────────────────────────────

pub fn print_processing_start() {
    if is_silent() { return; }
    eprintln!();
    eprintln!("  {} {}",
        style("[2/3]").cyan().bold(),
        style("Processing artifacts...").bold(),
    );
}

pub fn create_progress_bar(total: u64) -> ProgressBar {
    if is_silent() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(total);
    pb.set_draw_target(ProgressDrawTarget::stderr());
    pb.set_style(
        ProgressStyle::default_bar()
            .template("        [{bar:40.cyan/dim}] {pos}/{len} {spinner} {msg}")
            .unwrap()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
            .progress_chars("━╸─"),
    );
    pb
}

pub fn progress_set_message(pb: &ProgressBar, filename: &str) {
    // Extract just the filename from the full path
    let short = std::path::Path::new(filename)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(filename);
    // Truncate if too long
    let display = if short.len() > 40 {
        format!("{}...", &short[..37])
    } else {
        short.to_string()
    };
    pb.set_message(display);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Phase: Output
// ─────────────────────────────────────────────────────────────────────────────

pub fn print_output_start() {
    if is_silent() { return; }
    eprintln!();
    eprintln!("  {} {}",
        style("[3/3]").cyan().bold(),
        style("Generating output...").bold(),
    );
}

pub fn print_summary(total_events: usize, output_path: Option<&str>, elapsed: Instant) {
    if is_silent() { return; }
    let duration = elapsed.elapsed();
    let secs = duration.as_secs_f64();

    eprintln!();
    eprintln!("{}", style("  ─────────────────────────────────────────────────────────").dim());
    eprintln!("  {} {}", style("Events collected:").bold(), style(total_events).green().bold());
    if let Some(path) = output_path {
        eprintln!("  {} {}", style("Output written to:").bold(), style(path).green());
    } else {
        eprintln!("  {} {}", style("Output:").bold(), style("stdout").green());
    }
    eprintln!("  {} {:.2}s", style("Completed in:").bold(), style(secs).cyan());
    eprintln!();
}
