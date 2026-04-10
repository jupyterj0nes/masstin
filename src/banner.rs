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

pub fn print_search_results(artifact_count: usize, zip_count: usize, dir_count: usize, file_count: usize) {
    print_search_results_labeled(artifact_count, zip_count, dir_count, file_count, "artifacts");
}

pub fn print_search_results_labeled(artifact_count: usize, zip_count: usize, dir_count: usize, file_count: usize, label: &str) {
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
    eprintln!("        {} {} {} found",
        style("=>").green().bold(),
        style(artifact_count).green().bold(),
        label,
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

    // Group artifacts by image name (extracted from path)
    let mut grouped: Vec<(String, Vec<(&str, usize)>)> = Vec::new();
    for (name, count) in artifacts {
        let image = extract_image_name_from_path(name);
        let short = std::path::Path::new(name)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(name);

        if let Some(group) = grouped.iter_mut().find(|(img, _)| *img == image) {
            group.1.push((short, *count));
        } else {
            grouped.push((image, vec![(short, *count)]));
        }
    }

    if grouped.len() == 1 {
        // Single image — flat list (no grouping needed)
        for (_, items) in &grouped {
            for (short, count) in items {
                eprintln!("        {} {} {}",
                    style("=>").green(),
                    style(short).white(),
                    style(format!("({} events)", count)).dim(),
                );
            }
        }
    } else {
        // Multiple images — group by image name
        for (image, items) in &grouped {
            let total: usize = items.iter().map(|(_, c)| c).sum();
            eprintln!("        {} {} {}",
                style("=>").green().bold(),
                style(image).cyan().bold(),
                style(format!("({} events total)", total)).dim(),
            );
            for (short, count) in items {
                eprintln!("           {} {} {}",
                    style("-").dim(),
                    style(short).white(),
                    style(format!("({})", count)).dim(),
                );
            }
        }
    }
}

/// Extract image name from artifact path.
/// Path like ".../masstin_image_extract/HRServer_Disk0.e01/evtx_extracted/partition_0/Security.evtx"
/// Returns "HRServer_Disk0.e01"
fn extract_image_name_from_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let marker = "masstin_image_extract/";
    if let Some(pos) = normalized.find(marker) {
        let after = &normalized[pos + marker.len()..];
        if let Some(slash) = after.find('/') {
            return after[..slash].to_string();
        }
    }
    // Fallback: try to get parent directory name
    std::path::Path::new(path)
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
//  Generic phase printing (for modules with custom flows)
// ─────────────────────────────────────────────────────────────────────────────

pub fn print_phase(step: &str, total: &str, message: &str) {
    if is_silent() { return; }
    eprintln!();
    eprintln!("  {} {}",
        style(format!("[{}/{}]", step, total)).cyan().bold(),
        style(message).bold(),
    );
}

pub fn print_phase_detail(label: &str, value: &str) {
    if is_silent() { return; }
    eprintln!("        {} {}", style(label).yellow(), value);
}

pub fn print_phase_result(message: &str) {
    if is_silent() { return; }
    eprintln!("        {} {}", style("=>").green().bold(), style(message).green().bold());
}

/// Print a search result line with green arrow + green number + white label (same style as EVTX count)
pub fn print_search_result_line(count: usize, label: &str) {
    if is_silent() { return; }
    eprintln!("        {} {} {} found",
        style("=>").green().bold(),
        style(count).green().bold(),
        label,
    );
}

pub fn print_info(message: &str) {
    if is_silent() { return; }
    eprintln!("        {}", style(message).dim());
}

pub fn print_separator() {
    if is_silent() { return; }
    eprintln!();
}

pub fn create_spinner(message: &str) -> ProgressBar {
    if is_silent() {
        return ProgressBar::hidden();
    }
    let sp = ProgressBar::new_spinner();
    sp.set_draw_target(ProgressDrawTarget::stderr());
    sp.set_style(
        ProgressStyle::default_spinner()
            .template("        {spinner} {msg}")
            .unwrap()
            .tick_chars("\u{28fb}\u{28fd}\u{28fe}\u{28f7}\u{28ef}\u{28df}\u{28bf}\u{287f} "),
    );
    sp.set_message(message.to_string());
    sp.enable_steady_tick(std::time::Duration::from_millis(100));
    sp
}

// ─────────────────────────────────────────────────────────────────────────────
//  Load summary (Neo4j / Memgraph)
// ─────────────────────────────────────────────────────────────────────────────

pub fn print_load_summary(
    db_type: &str,
    connections_loaded: usize,
    hosts_resolved: usize,
    errors: usize,
    elapsed: Instant,
) {
    if is_silent() { return; }
    let secs = elapsed.elapsed().as_secs_f64();

    eprintln!();
    eprintln!("{}", style("  ──────────────────────────────────────────────────").dim());
    eprintln!("  {} {}", style("Database:").bold(), style(db_type).cyan());
    eprintln!("  {} {}", style("Connections loaded:").bold(), style(connections_loaded).green().bold());
    if hosts_resolved > 0 {
        eprintln!("  {} {}", style("IPs resolved to hostname:").bold(), style(hosts_resolved).green());
    }
    if errors > 0 {
        eprintln!("  {} {}", style("Query errors:").bold(), style(errors).red());
    }
    eprintln!("  {} {:.2}s", style("Completed in:").bold(), style(secs).cyan());
    eprintln!();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Cortex API summary
// ─────────────────────────────────────────────────────────────────────────────

pub fn print_cortex_network_summary(total: usize, rdp: usize, smb: usize, ssh: usize) {
    if is_silent() { return; }
    eprintln!();
    eprintln!("  {} {}",
        style("[+]").green().bold(),
        style("Network connections retrieved:").bold(),
    );
    if rdp > 0 { eprintln!("        {} RDP {}", style("=>").green(), style(format!("(port 3389) - {} connections", rdp)).dim()); }
    if smb > 0 { eprintln!("        {} SMB {}", style("=>").green(), style(format!("(port 445)  - {} connections", smb)).dim()); }
    if ssh > 0 { eprintln!("        {} SSH {}", style("=>").green(), style(format!("(port 22)   - {} connections", ssh)).dim()); }
    eprintln!("        {} {} total events",
        style("=>").green().bold(),
        style(total).green().bold(),
    );
}

pub fn print_cortex_forensics_summary(machines: usize, artifacts: usize, events: usize) {
    if is_silent() { return; }
    eprintln!();
    eprintln!("  {} {}",
        style("[+]").green().bold(),
        style("Forensic artifacts retrieved:").bold(),
    );
    eprintln!("        {} {} from {} {}",
        style("=>").green().bold(),
        style(format!("{} events", events)).green().bold(),
        style(artifacts).yellow(),
        style(format!("artifacts across {} machines", machines)).dim(),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
//  Parse summary (reused by parse-windows, parse-linux, parser-elastic)
// ─────────────────────────────────────────────────────────────────────────────

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
