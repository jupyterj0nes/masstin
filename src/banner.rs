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
//  Banner — mastiff profile from logo, split cyan (left) / pink (right)
// ─────────────────────────────────────────────────────────────────────────────

const BANNER_ART: &[&str] = &[
    r"                              tAAAAAAAAAAAAa",
    r"                     SSRFAAAAS              aAHO2ad",
    r"                SSSSSSS                           aaaaa",
    r"              SSS   S                                aaaa",
    r"            SS                                          aaah",
    r"          SSS                              a              aaac",
    r"        SSS            S                    a               aaaa",
    r"       SS       S     SSSS   S              bg                 aaae",
    r"      SS    S  SS     S         AM           a                    aaa a",
    r"       SSSSSSY                               a                     hb",
    r"    SSSSSz                S    a             a                     da",
    r"  SSU      SSS             AA               wa                     ef",
    r" SS           S              Y              ca                   haeda",
    r" S            t                             aa                  aav ada",
    r" SS  S   S   t                              aa                aaa    eeg h",
    r"SS                                     h    aa              kaa      adc a",
    r"SS                                     a    aa             a           aaa",
    r"SS     S                               a     aa                          taaa",
    r"SS     S                               a     za                      hah   aaa",
    r"SS    SSSS                             a      eaa                     a abe  a ac",
    r"SS   SS    SS                          a        aaa   a                  hdaa hha",
    r"SS   S       SS                        m           aae                     v adhc",
    r"SSS            S                 a    a                                        acba",
    r" SS             St               a                                     a        eaaag",
    r"  SSS             S              ad                                  a  ha         av",
    r"   SSSSSS                        a                                      aa          aaa",
    r"       SSSS                 taagqa                                        a          aaaa",
    r"          SSSSS           ST    a                                         g            aa",
    r"            SW1S                                                                   a",
    r"            SSSt S",
    r"             S  S z",
    r"              h  d                                               aaa",
    r"                                                         aaa     aaa",
    r"                                                         rzk",
    r"         SSSSSSSSSSSSSSS   SSSSSSSS   SSSSSSS  ptttcaa aarylaaa  aaa  aaaaaaaaaa",
    r"         SdS   SlS   SfSS       uuta Sit      xttu       syn     aua  amd    gkb",
    r"         SeS   SmS   778S  SSSSSStt4  0XSS5tS   tttttj   iyb     ava  ana    ald",
    r"         SfS   SkS   UY6S SSc    tt3      tur       wt   aun     ata  ana    ald",
    r"         SSS   SSS   SSSS  SSSSSSSSS jSSSSdtt  7knrstk    aaaaa  aaa  aaa    aca",
];

// Gradient from cyan (left) to pink (right), matching the logo
// Based on absolute column position across ~85 char width
const GRADIENT: &[u8] = &[51, 51, 45, 45, 39, 33, 127, 163, 169, 213, 213];
const BANNER_WIDTH: usize = 85;

fn print_art_line(line: &str) {
    if is_silent() { return; }
    let trimmed = line.trim_end();
    if trimmed.is_empty() {
        eprintln!();
        return;
    }

    for (i, ch) in trimmed.chars().enumerate() {
        if ch == ' ' {
            eprint!(" ");
        } else {
            // Absolute column position mapped to gradient
            let grad_idx = (i * (GRADIENT.len() - 1)) / BANNER_WIDTH;
            let grad_idx = grad_idx.min(GRADIENT.len() - 1);
            eprint!("{}", style(ch).color256(GRADIENT[grad_idx]));
        }
    }
    eprintln!();
}

pub fn print_banner(action: &str) {
    if is_silent() {
        return;
    }

    eprintln!();
    for line in BANNER_ART {
        print_art_line(line);
    }

    eprintln!();
    eprintln!("        {}",
        style("lateral movement tracker for anything!").dim().italic(),
    );
    eprintln!();
    eprintln!("  {} {}  {}  {}",
        style(format!("v{}", env!("CARGO_PKG_VERSION"))).dim(),
        style("|").dim(),
        style("Tono Diaz (@jupyterj0nes)").dim(),
        style("| weinvestigateanything.com").dim(),
    );
    eprintln!();
    eprintln!("  {} {}",
        style("Action:").cyan().bold(),
        style(action).white().bold(),
    );
    eprintln!("{}", style("  ──────────────────────────────────────────────────").dim());
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
            .template("        [{bar:25.cyan/dim}] {pos}/{len} {spinner} {msg}")
            .unwrap()
            .tick_chars("\u{28fb}\u{28fd}\u{28fe}\u{28f7}\u{28ef}\u{28df}\u{28bf}\u{287f} ")
            .progress_chars("━╸─"),
    );
    pb
}

pub fn progress_set_message(pb: &ProgressBar, filename: &str) {
    let short = std::path::Path::new(filename)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(filename);
    let display = if short.len() > 60 {
        format!("{}...", &short[..57])
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

pub fn print_artifact_detail(artifacts: &[(String, usize)]) {
    if is_silent() { return; }
    if artifacts.is_empty() { return; }
    eprintln!();
    eprintln!("  {} {}",
        style("[+]").green().bold(),
        style("Artifacts with events:").bold(),
    );
    for (name, count) in artifacts {
        let short = std::path::Path::new(name)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(name);
        eprintln!("        {} {} {}",
            style("=>").green(),
            style(short).white(),
            style(format!("({} events)", count)).dim(),
        );
    }
}

pub fn print_summary(total_events: usize, parsed_files: usize, skipped: usize, output_path: Option<&str>, elapsed: Instant) {
    if is_silent() { return; }
    let duration = elapsed.elapsed();
    let secs = duration.as_secs_f64();

    eprintln!();
    eprintln!("{}", style("  ──────────────────────────────────────────────────").dim());
    eprintln!("  {} {}",
        style("Artifacts parsed:").bold(),
        style(parsed_files).green().bold(),
    );
    if skipped > 0 {
        eprintln!("  {} {} {}",
            style("Skipped:").bold(),
            style(skipped).yellow(),
            style("(no relevant events or access denied)").dim(),
        );
    }
    eprintln!("  {} {}",
        style("Events collected:").bold(),
        style(total_events).green().bold(),
    );
    if let Some(path) = output_path {
        eprintln!("  {} {}", style("Output:").bold(), style(path).green());
    } else {
        eprintln!("  {} {}", style("Output:").bold(), style("stdout").green());
    }
    eprintln!("  {} {:.2}s",
        style("Completed in:").bold(),
        style(secs).cyan(),
    );
    eprintln!();
}
