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

/// Legacy wrapper kept for parse_linux callers that haven't been migrated yet.
/// Prefer print_search_results_v2 in new code — it distinguishes archive count
/// from entries-inside-archives and reports archives_with_evtx separately.
pub fn print_search_results_labeled(artifact_count: usize, zip_count: usize, dir_count: usize, file_count: usize, label: &str) {
    if is_silent() { return; }
    if zip_count > 0 {
        eprintln!("        {} {} found inside compressed archives",
            style(zip_count).yellow(),
            label,
        );
    }
    eprintln!("        {} {} {} found total",
        style("=>").green().bold(),
        style(artifact_count).green().bold(),
        label,
    );
    let _ = (dir_count, file_count); // silence unused warning
}

/// New search-results printer used by parse-windows. Always shows how many
/// archives were scanned vs how many actually contributed entries (bug #4),
/// and reports the entries-inside-archives count instead of the misleading
/// "{N} compressed packages found" wording (bug #1).
pub fn print_search_results_v2(
    total_artifacts: usize,
    entries_inside_archives: usize,
    archives_scanned: usize,
    archives_with_artifacts: usize,
    _dir_count: usize,
    _file_count: usize,
    label: &str,
) {
    if is_silent() { return; }
    if archives_scanned > 0 {
        if entries_inside_archives > 0 {
            eprintln!("        {} {} found inside {} of {} compressed archives",
                style(entries_inside_archives).yellow(),
                label,
                style(archives_with_artifacts).yellow(),
                style(archives_scanned).yellow(),
            );
        } else {
            eprintln!("        {} compressed archives scanned, none contained {}",
                style(archives_scanned).dim(),
                label,
            );
        }
    }
    eprintln!("        {} {} {} found total",
        style("=>").green().bold(),
        style(total_artifacts).green().bold(),
        label,
    );
}

/// Print a "Triage found" line during the discovery phase, with the type,
/// optional hostname, the FULL path to the source zip, and the artifact
/// count inside. Full path (not just filename) is critical because real
/// cases often have duplicate copies of the same triage zip in different
/// subfolders (e.g. SFTP/.../host.zip vs To-Unit42/.../host.zip) and the
/// analyst needs to see they're physically different files.
pub fn print_triage_found(type_label: &str, hostname: Option<&str>, zip_fullpath: &str, artifact_count: usize) {
    if is_silent() { return; }
    let host_part = match hostname {
        Some(h) => format!(" {}", style(format!("[host: {}]", h)).dim()),
        None => String::new(),
    };
    eprintln!("        {} {} {}{}",
        style("=>").green().bold(),
        style("Triage found:").yellow().bold(),
        style(type_label).white().bold(),
        host_part,
    );
    // Normalise backslashes to forward slashes for consistency with the
    // rest of the output and to work well on RDP / conhost.
    let pretty_path = zip_fullpath.replace('\\', "/");
    eprintln!("           {} {}",
        style("source:").dim(),
        style(pretty_path).white(),
    );
    if artifact_count > 0 {
        eprintln!("           {} {} {}",
            style("entries inside:").dim(),
            style(artifact_count).yellow(),
            style("(EVTX or other matched files)").dim(),
        );
    } else {
        // Always show the line — analyst needs visual confirmation that the
        // detection happened even when nothing usable was found inside (very
        // common with Velociraptor collections that ran a parsing artifact
        // without uploading raw EVTX, so the zip has only JSON results).
        eprintln!("           {} {} {}",
            style("entries inside:").dim(),
            style("0").dim(),
            style("(no raw .evtx files — likely parsed JSON artifacts only)").dim(),
        );
    }
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
            .tick_chars("|/-\\ ")
            .progress_chars("=>-"),
    );
    pb
}

pub fn progress_set_message(pb: &ProgressBar, filename: &str) {
    let image = extract_image_name_from_path(filename);
    let short = std::path::Path::new(filename)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(filename);
    let display = if image != "unknown" && !image.is_empty() {
        format!("{}: {}", image, short)
    } else {
        short.to_string()
    };
    let display = if display.len() > 80 {
        format!("{}...", &display[..77])
    } else {
        display
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
    print_artifact_detail_ex(artifacts, 0);
}

/// New per-source breakdown printer used by parse-windows + parse-linux.
/// Receives `(source_label, artifact_short_name, vss_index, count)` tuples.
///
/// `vss_index = None` means the artifact came from a live partition (or from
/// a context without VSS semantics like a triage zip); `Some(N)` means it
/// came from VSS snapshot N of the same image. Within each source group the
/// items are sorted live-first then by VSS index, and VSS entries are
/// rendered with a "[VSS]" / "[VSS-N]" suffix so the analyst can tell at a
/// glance which events were recovered from a shadow copy.
pub fn print_artifact_detail_grouped(artifacts: &[(String, String, Option<u32>, usize)]) {
    if is_silent() { return; }
    if artifacts.is_empty() { return; }
    eprintln!();

    // Group preserving first-seen order of sources. Within each source,
    // dedupe items by `(name, vss_idx)` and SUM their counts. This collapses
    // duplicate entries that happen when two physical copies of the same
    // image file (different paths but same filename) get processed under
    // the same `[IMAGE]` source label and produce identical (name, None)
    // tuples. VSS entries are preserved separately because their `vss_idx`
    // is `Some(N)` while live entries are `None`.
    //
    // The summed counts are PRE-deduplication totals (i.e. raw work done
    // by the parser), matching the per-source `events total` line at the
    // top of each group. The global dedup count printed at the end of
    // phase 3 explains the gap between the breakdown total and the final
    // CSV row count.
    let mut grouped: Vec<(String, Vec<(String, Option<u32>, usize)>)> = Vec::new();
    for (source, name, vss_idx, count) in artifacts {
        if let Some(g) = grouped.iter_mut().find(|(s, _)| s == source) {
            if let Some(existing) = g.1.iter_mut().find(|(n, v, _)| n == name && v == vss_idx) {
                existing.2 += count;
            } else {
                g.1.push((name.clone(), *vss_idx, *count));
            }
        } else {
            grouped.push((source.clone(), vec![(name.clone(), *vss_idx, *count)]));
        }
    }

    eprintln!("  {} {}",
        style("[+]").green().bold(),
        style(format!("Lateral movement events grouped by source ({} sources):", grouped.len())).bold(),
    );

    for (source, items) in &mut grouped {
        let total: usize = items.iter().map(|(_, _, c)| c).sum();
        // Pick a color hint based on the source tag prefix so the user can
        // visually scan IMAGE / TRIAGE / ARCHIVE / FOLDER groups.
        let styled_source = if source.starts_with("[IMAGE]") {
            style(source.clone()).cyan().bold().to_string()
        } else if source.starts_with("[TRIAGE:") {
            style(source.clone()).yellow().bold().to_string()
        } else if source.starts_with("[ARCHIVE]") {
            style(source.clone()).white().bold().to_string()
        } else {
            // [FOLDER] or unknown prefix
            style(source.clone()).white().to_string()
        };

        // Sort live-first (None), then by VSS index, then by name.
        items.sort_by(|a, b| {
            a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0))
        });

        // Decide whether VSS entries need an index suffix. If more than one
        // distinct VSS snapshot appears inside this source group, we must
        // show "[VSS-0]", "[VSS-1]"... to disambiguate. If only one VSS
        // snapshot is present we render a cleaner "[VSS]" with no index.
        use std::collections::HashSet;
        let distinct_vss: HashSet<u32> = items
            .iter()
            .filter_map(|(_, v, _)| *v)
            .collect();
        let needs_vss_index = distinct_vss.len() > 1;

        eprintln!();
        eprintln!("        {} {}  {}",
            style("=>").green().bold(),
            styled_source,
            style(format!("({} events total)", total)).dim(),
        );
        for (name, vss_idx, count) in items.iter() {
            let suffix = match vss_idx {
                None => String::new(),
                Some(n) => {
                    if needs_vss_index {
                        format!("  {}", style(format!("[VSS-{}]", n)).yellow())
                    } else {
                        format!("  {}", style("[VSS]").yellow())
                    }
                }
            };
            eprintln!("           {} {} {}{}",
                style("-").dim(),
                style(name).white(),
                style(format!("({})", count)).dim(),
                suffix,
            );
        }
    }
}

pub fn print_artifact_detail_ex(artifacts: &[(String, usize)], total_images: usize) {
    if is_silent() { return; }
    if artifacts.is_empty() { return; }
    eprintln!();

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

    let title = if total_images > 0 && grouped.len() < total_images {
        format!("Artifacts with lateral movement events ({} of {} images):", grouped.len(), total_images)
    } else {
        "Artifacts with lateral movement events:".to_string()
    };
    eprintln!("  {} {}",
        style("[+]").green().bold(),
        style(title).bold(),
    );

    // Always show image name + artifacts grouped
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

/// Extract image name from artifact path.
/// Path like ".../masstin_image_extract/HRServer_Disk0.e01/evtx_extracted/partition_0/Security.evtx"
/// Returns "HRServer_Disk0.e01"
fn extract_image_name_from_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let marker = "masstin_image_extract/";
    if let Some(pos) = normalized.find(marker) {
        let after = &normalized[pos + marker.len()..];
        if let Some(slash) = after.find('/') {
            let dir_name = &after[..slash];
            // Strip numeric prefix added for uniqueness (e.g., "0_HRServer.e01" -> "HRServer.e01")
            if let Some(underscore) = dir_name.find('_') {
                let prefix = &dir_name[..underscore];
                if prefix.chars().all(|c| c.is_ascii_digit()) {
                    return dir_name[underscore + 1..].to_string();
                }
            }
            return dir_name.to_string();
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

pub fn print_warning(message: &str) {
    if is_silent() { return; }
    eprintln!("        {}", style(message).yellow());
}

pub fn print_separator() {
    if is_silent() { return; }
    eprintln!();
}

pub fn print_massive_warning() {
    if is_silent() { return; }
    eprintln!();
    eprintln!("  {} {}",
        style("!!!").red().bold(),
        style("MASSIVE MODE ACTIVATED").red().bold(),
    );
    eprintln!("        {}",
        style("Processing ALL forensic images + triage packages + loose artifacts.").dim(),
    );
    eprintln!("        {}",
        style("The Masstin is off the leash. Stand back.").dim(),
    );
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
            .tick_chars("|/-\\ "),
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
            style("(no relevant events found in file)").dim(),
        );
    }
    eprintln!("  {} {}",
        style("Events collected:").bold(),
        style(total_events).green().bold(),
    );
    if let Some(path) = output_path {
        let pretty = normalize_display_path(path);
        eprintln!("  {} {}", style("Output:").bold(), style(pretty).green());
    } else {
        eprintln!("  {} {}", style("Output:").bold(), style("stdout").green());
    }
    eprintln!("  {} {:.2}s",
        style("Completed in:").bold(),
        style(secs).cyan(),
    );
    eprintln!();
}

/// Normalise a Windows path for human display: resolve 8.3 short names like
/// "C:/Users/C00PR~1.DES/..." into their long-form equivalent, and strip the
/// "\\?\" prefix that std::fs::canonicalize leaves on Windows. Falls back to
/// the input unchanged on any error or on non-Windows platforms.
pub(crate) fn normalize_display_path(p: &str) -> String {
    match std::fs::canonicalize(p) {
        Ok(buf) => {
            let s = buf.to_string_lossy().to_string();
            // Strip Windows verbatim prefix
            let trimmed = s.strip_prefix(r"\\?\").unwrap_or(&s);
            trimmed.replace('\\', "/")
        }
        Err(_) => p.replace('\\', "/"),
    }
}
