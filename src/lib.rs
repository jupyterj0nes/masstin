use clap::{Parser, ValueEnum};
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind};
use std::error::Error;
use std::fs::File;
use std::io::Read;
mod parse;
use tokio;
pub use crate::parse::*;
mod load_neo4j;
pub use crate::load_neo4j::*;
mod load_memgraph;
pub use crate::load_memgraph::*;
mod merge_neo4j_nodes;
pub use crate::merge_neo4j_nodes::*;
mod merge_memgraph_nodes;
pub use crate::merge_memgraph_nodes::*;
mod merge;
pub use crate::merge::*;
use serde_json::Value;
mod parse_elastic;
pub use crate::parse_elastic::*;
mod parse_cortex;
pub use crate::parse_cortex::*;
mod parse_cortex_evtx_forensics;
pub use crate::parse_cortex_evtx_forensics::*;
mod parse_linux;
pub use crate::parse_linux::*;
mod parse_journal;
mod parse_image_windows;
pub use crate::parse_image_windows::*;
mod parse_image_linux;
pub use crate::parse_image_linux::*;
pub mod banner;
pub use crate::banner::*;
pub mod parse_ese;
pub use crate::parse_ese::*;
mod parse_ual;
pub use crate::parse_ual::*;
mod parse_tasks;
pub use crate::parse_tasks::*;
mod parse_mountpoints;
pub use crate::parse_mountpoints::*;
pub mod parse_carve;
pub use crate::parse_carve::validate_evtx_file;
pub mod parse_custom;
pub mod filter;
pub mod vmdk;
pub use crate::vmdk::*;
mod graph_hunt;

// -----------------------------------------------------------------------------
//   Command-line interface struct
// -----------------------------------------------------------------------------
#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    /// Action to perform
    #[arg(short, long)]
    action: ActionType,

    /// Directories to process — also accepts drive letters (D:) for mounted volumes
    #[arg(short, long)]
    directory: Vec<String>,

    /// Individual files to process (EVTX, JSON, .mdb, E01, dd/raw)
    #[arg(short, long)]
    file: Vec<String>,

    /// File where parsed output will be stored
    #[arg(short, long)]
    output: Option<String>,

    /// URL of the database for the Load action or base URL for parse_cortex
    #[arg(long)]
    database: Option<String>,

    /// Database user (used in Load)
    #[arg(short, long)]
    user: Option<String>,

    /// If specified, overwrite the output file if it exists
    #[arg(long)]
    overwrite: bool,

    /// If specified, print output only to stdout
    #[arg(long)]
    stdout: bool,

    /// If specified, print debug information
    #[arg(long)]
    debug: bool,

    /// Silent mode: suppress all output except CSV data (for automation/Velociraptor integration)
    #[arg(long)]
    silent: bool,

    /// Cortex API base URL (must start with 'api-' if using parse_cortex)
    #[arg(long)]
    cortex_url: Option<String>,

    /// Optional start time in format "YYYY-MM-DD HH:MM:SS -0000"
    /// If the timezone offset is omitted, "-0000" is automatically added.
    #[arg(long, value_parser = parse_cortex_time)]
    start_time: Option<String>,

    /// Optional end time in format "YYYY-MM-DD HH:MM:SS -0000"
    /// If the timezone offset is omitted, "-0000" is automatically added.
    #[arg(long, value_parser = parse_cortex_time)]
    end_time: Option<String>,


    /// Optional IP to filter in Cortex queries (used with ParseCortex)
    #[arg(long)]
    filter_cortex_ip: Option<String>,

    /// For `parse-cortex`: restrict the XQL network query to admin/lateral-movement
    /// ports only (22, 135, 139, 445, 1433, 3306, 3389, 5900, 5985, 5986).
    /// Without this flag the query still defaults to (22, 445, 3389). Use it when
    /// you want WinRM/RPC/VNC/SQL pivoting visible as well, or when the default
    /// three-port query returns too much noise/hits the 1M API cap.
    #[arg(long)]
    admin_ports: bool,

    /// For `parse-cortex`: minimum time window (in seconds) the auto-pagination
    /// splitter is allowed to produce. When a query saturates the API 1M cap,
    /// the window is bisected until either the count drops below the cap or
    /// the window reaches this floor. Lower = more passes, higher fidelity on
    /// bursty tenants but more API calls. Higher = fewer passes, cheaper but
    /// may truncate during traffic spikes. Default: 300 (5 min).
    #[arg(long, default_value_t = 300)]
    cortex_min_window_secs: i64,

    /// For `parse-cortex`: hard cap on the total number of auto-pagination
    /// passes. Prevents a pathological tenant (e.g. sustained saturation at
    /// minute granularity) from blowing up memory or API quota. When reached,
    /// remaining windows in the queue are processed without further splitting
    /// and a warning is emitted. Default: 200.
    #[arg(long, default_value_t = 200)]
    cortex_max_passes: usize,

    /// For `parse-cortex-evtx-forensics`: comma-separated list of Windows Event IDs
    /// to include in the forensics XQL query. Overrides the default set
    /// (4624,4625,4648,21,22,24,25,1009,551,31001,30803-30808,1024,1102,1149).
    /// Example: --cortex-event-ids 4624,4625,4648
    #[arg(long)]
    cortex_event_ids: Option<String>,

    /// For load-neo4j / load-memgraph: emit one edge per CSV row instead of
    /// collapsing duplicate (src, user, dst) triples into a single edge with
    /// a `count` property. Useful when you want to see every individual
    /// lateral movement event, typically combined with --start-time /
    /// --end-time to restrict the view to a narrow time window. Also usable
    /// with `merge` to produce an ungrouped intermediate CSV.
    #[arg(long)]
    ungrouped: bool,

    /// Scan all NTFS volumes on the system for VSS (parse-image-windows only, requires admin)
    #[arg(long)]
    all_volumes: bool,

    /// Carve only unallocated space (faster). Default: carve entire disk.
    #[arg(long)]
    carve_unalloc: bool,

    /// Comma-separated list of hex offsets to skip during carving (for corrupted E01 chunks that hang).
    /// Example: --skip-offsets 0x6478b6000,0x7a0000000
    /// Each offset skips a 32 MB window starting at that offset.
    #[arg(long)]
    skip_offsets: Option<String>,

    /// Path to a YAML rule file or directory for `parse-custom`.
    /// See rules/ and docs/custom-parsers.md for the schema and contributed rules.
    #[arg(long)]
    rules: Option<String>,

    /// Dry-run mode. For `parse-custom`: parse and show first matches + rejects, do not write CSV.
    /// When combined with any `--ignore-local` / `--exclude-*` flag on any parser action:
    /// run the parser, count what would be filtered, print the stats summary, and write
    /// only the CSV header (no rows). Useful as a pre-flight check before committing to
    /// a big filter run.
    #[arg(long)]
    dry_run: bool,

    // ─── Noise filtering flags ──────────────────────────────────────────────
    //
    // Applied sequentially to every LogData record before writing. The filter
    // is a global singleton initialized at startup from these flags; see
    // src/filter.rs for the full rule table and src/filter.rs::classify_local()
    // for the --ignore-local decision logic.

    /// Drop records that carry no usable source information: loopback IPs
    /// (127.0.0.1, ::1, 0.0.0.0, link-local), literal "LOCAL" markers,
    /// service/interactive logons with empty source, and noise placeholders
    /// observed in real forensic data (MSTSC, default_value, "-"). A record
    /// is kept whenever either src_ip or src_computer carries meaningful
    /// lateral-movement signal — the IP always wins, so `MSTSC|<real-IP>`
    /// stays and `MSTSC|-` is filtered.
    #[arg(long)]
    ignore_local: bool,

    /// Comma-separated list of usernames to filter out. Matches against both
    /// subject_user_name and target_user_name (case-insensitive). Supports
    /// glob wildcards (`svc_*`, `*$` for machine accounts, `*admin*`) and
    /// the `@file.txt` prefix to load one entry per line.
    /// Example: --exclude-users svc_backup,svc_monitor,*$,@corpsvc.txt
    #[arg(long)]
    exclude_users: Option<String>,

    /// Comma-separated list of hostnames to filter out. Matches against
    /// dst_computer and src_computer. Same syntax as --exclude-users.
    /// Example: --exclude-hosts JUMP01,JUMP02,*-MON,@jumpboxes.txt
    #[arg(long)]
    exclude_hosts: Option<String>,

    /// Comma-separated list of IPs or CIDR ranges to filter out. Matches
    /// src_ip. Accepts individual IPs (`10.0.0.5`), CIDR ranges
    /// (`10.0.0.0/24`, `fe80::/10`), and the `@file.txt` prefix.
    /// Example: --exclude-ips 10.0.0.0/8,172.16.0.0/12,@bluenet.txt
    #[arg(long)]
    exclude_ips: Option<String>,

    /// For `merge-neo4j-nodes` / `merge-memgraph-nodes`: name of the node to
    /// remove (its edges are transferred to `--new-node`, then it is deleted).
    /// Typically the duplicate IP-shaped node that the loader could not unify.
    #[arg(long)]
    old_node: Option<String>,

    /// For `merge-neo4j-nodes` / `merge-memgraph-nodes`: name of the node to
    /// keep. All edges from `--old-node` are transferred here, with their
    /// properties preserved.
    #[arg(long)]
    new_node: Option<String>,

    /// For `graph-hunt`: cutoff datetime separating baseline from investigation
    /// window. Events strictly before this timestamp form the baseline; events
    /// at or after it are the window scanned for anomalies. Format:
    /// "YYYY-MM-DD HH:MM:SS" (UTC assumed).
    #[arg(long)]
    investigation_from: Option<String>,

    /// For `graph-hunt`: comma-separated list of detector names to skip.
    /// Available: novel-edge, chain-motif, pagerank-spike, betweenness-spike,
    /// community-bridge, cred-rotation, rare-logon-type.
    /// Example: --skip-detectors pagerank-spike,betweenness-spike
    #[arg(long)]
    skip_detectors: Option<String>,

    /// For `graph-hunt`: comma-separated list of detector names to run
    /// exclusively (all others disabled). Same names as --skip-detectors.
    /// Mutually exclusive with --skip-detectors.
    #[arg(long)]
    only_detectors: Option<String>,
}

// -----------------------------------------------------------------------------
//   List of possible actions
// -----------------------------------------------------------------------------
#[derive(ValueEnum, Clone, Debug, PartialEq)]
enum ActionType {
    /// Parse Windows EVTX files and UAL databases (.mdb) from directories or individual files
    #[value(alias = "parse")]
    ParseWindows,
    /// Load a CSV timeline into a Neo4j graph database
    #[value(alias = "load")]
    LoadNeo4j,
    /// Load a CSV timeline into a Memgraph graph database
    LoadMemgraph,
    /// Merge multiple CSV timelines into a single chronological file
    Merge,
    /// Parse Winlogbeat JSON logs exported from Elasticsearch
    ParserElastic,
    /// Query Cortex XDR API for network connections (RDP/SMB/SSH)
    ParseCortex,
    /// Query Cortex XDR API for forensic EVTX collections
    ParseCortexEvtxForensics,
    /// Parse Linux logs: auth.log, secure, messages, audit.log, utmp, wtmp, btmp, lastlog
    ParseLinux,
    /// Parse from forensic images (E01/dd/VMDK), mounted volumes (-d D:), or --all-volumes. Auto-detects OS: NTFS→EVTX+UAL+VSS, ext4→Linux logs
    #[value(alias = "parse-image-windows", alias = "parse-image-linux")]
    ParseImage,
    /// MASSIVE mode: process EVERYTHING — forensic images + triage packages + loose EVTX/logs. Point at evidence folder, get a timeline. No mercy.
    ParseMassive,
    /// Carve EVTX records from disk images — recovers events from unallocated space after log deletion. Use --carve-unalloc for faster unallocated-only scan.
    CarveImage,
    /// Parse arbitrary text logs (VPN/firewall/proxy) using YAML rule files from the rules/ library. See docs/custom-parsers.md.
    ParseCustom,
    /// Merge two :host nodes in a Neo4j graph: transfers all edges from `--old-node` to `--new-node` and deletes the old node. Used to unify a host that appears as both an IP and a hostname after loading. No APOC required.
    MergeNeo4jNodes,
    /// Merge two :host nodes in a Memgraph graph: transfers all edges from `--old-node` to `--new-node` and deletes the old node. Same as `merge-neo4j-nodes` but for Memgraph.
    MergeMemgraphNodes,
    /// Hunt lateral movement anomalies on a graph already loaded into Memgraph. Uses native graph algorithms (PageRank, Louvain, betweenness) plus structural detectors (novel edges, chain motifs, credential rotation) to surface pivots. Requires --database and --investigation-from. Best results with --ungrouped loads.
    #[value(alias = "graph-hunt")]
    GraphHunt,
}

// -----------------------------------------------------------------------------
//   Main library function called from main.rs
// -----------------------------------------------------------------------------
pub async fn run(mut config: Cli) -> Result<(), Box<dyn Error>> {
    // Clean and normalize paths
    config.directory = {
        let mut dirs = Vec::new();
        for d in &config.directory {
            let cleaned = clean_path(d)?;
            let trimmed = cleaned.trim_end_matches(&['\\', '/'][..]);
            if trimmed.len() == 2 && trimmed.as_bytes()[0].is_ascii_alphabetic() && trimmed.as_bytes()[1] == b':' {
                dirs.push(trimmed.to_string());
            } else {
                dirs.push(normalize_path(&cleaned));
            }
        }
        dirs
    };
    config.file = {
        let mut files = Vec::new();
        for f in &config.file {
            let cleaned = clean_path(f)?;
            files.push(normalize_path(&cleaned));
        }
        files
    };

    validate_folders(&config)?;

    // Enable or disable debug/silent mode
    crate::parse::set_debug_mode(config.debug);
    crate::parse_elastic::set_debug_mode(config.debug);
    crate::banner::set_silent_mode(config.silent);

    // Build the global noise filter from CLI flags and install it before any
    // parser action runs. If all four filter flags are off, the filter is a
    // no-op (should_keep_record always returns true) so there is zero cost.
    match crate::filter::build_config(
        config.ignore_local,
        config.exclude_users.as_deref(),
        config.exclude_hosts.as_deref(),
        config.exclude_ips.as_deref(),
    ) {
        Ok(cfg) => crate::filter::init_filter(cfg, config.dry_run),
        Err(e) => {
            eprintln!("Error: invalid filter argument: {}", e);
            return Ok(());
        }
    }

    // Print banner
    let action_name = format!("{:?}", config.action);
    crate::banner::print_banner(&action_name);

    // Match the selected action and call the corresponding function
    match config.action {
        ActionType::ParseWindows => {
            parse_events(&config.file, &config.directory, config.output.as_ref());
        }
        ActionType::LoadNeo4j => {
            load_neo4j(
                &config.file,
                &config.database.as_ref().unwrap(),
                &config.user.as_ref().unwrap(),
                config.ungrouped,
                config.start_time.as_ref(),
                config.end_time.as_ref(),
            )
            .await;
        }
        ActionType::LoadMemgraph => {
            let default_user = String::from("");
            load_memgraph(
                &config.file,
                &config.database.as_ref().unwrap(),
                config.user.as_ref().unwrap_or(&default_user),
                config.ungrouped,
                config.start_time.as_ref(),
                config.end_time.as_ref(),
            )
            .await;
        }
        ActionType::Merge => {
            merge_files(
                &config.file,
                config.output.as_ref(),
                config.start_time.as_ref(),
                config.end_time.as_ref(),
            )?;
        }
        ActionType::ParserElastic => {
            parse_events_elastic(&config.file, &config.directory, config.output.as_ref());
        }
        ActionType::ParseCortex => {
            parse_cortex_data(
        config.cortex_url.as_ref().unwrap(),
                config.output.as_ref(),
                config.debug,
                config.start_time.as_ref(),
                config.end_time.as_ref(),
                config.filter_cortex_ip.as_ref(),
                config.ignore_local,
                config.admin_ports,
                config.cortex_min_window_secs,
                config.cortex_max_passes,
            )
            .await?;
        }

        ActionType::ParseCortexEvtxForensics => {
            parse_cortex_evtx_forensics_data(
                config.cortex_url.as_ref().unwrap(),
                config.output.as_ref(),
                config.debug,
                config.start_time.as_ref(),
                config.end_time.as_ref(),
                config.ignore_local,
                config.cortex_event_ids.as_ref(),
                config.cortex_min_window_secs,
                config.cortex_max_passes,
            )
            .await?;
        }

        ActionType::ParseLinux => {
            parse_linux(&config.file, &config.directory, config.output.as_ref());
        }
        ActionType::ParseImage => {
            parse_image(&config.file, &config.directory, config.all_volumes, config.output.as_ref(), false);
        }
        ActionType::ParseMassive => {
            crate::banner::print_massive_warning();
            parse_image(&config.file, &config.directory, config.all_volumes, config.output.as_ref(), true);
        }
        ActionType::ParseCustom => {
            let rules_path = match config.rules.as_ref() {
                Some(r) => r.clone(),
                None => {
                    eprintln!("Error: parse-custom requires --rules <path> (file or directory of YAML rule files)");
                    return Ok(());
                }
            };
            if config.file.is_empty() {
                eprintln!("Error: parse-custom requires at least one -f <logfile>");
                return Ok(());
            }
            crate::parse_custom::parse_custom(
                &config.file,
                &rules_path,
                config.output.as_ref(),
                config.dry_run,
            );
        }
        ActionType::CarveImage => {
            let skip_offsets: Vec<u64> = config.skip_offsets.as_deref()
                .map(|s| s.split(',')
                    .filter_map(|tok| {
                        let t = tok.trim();
                        let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
                        u64::from_str_radix(t, 16).ok()
                    })
                    .collect())
                .unwrap_or_default();
            if !skip_offsets.is_empty() {
                eprintln!("  Skip offsets configured: {} offset(s)", skip_offsets.len());
                for o in &skip_offsets {
                    eprintln!("    → {:#x} ({:.2} GB)", o, *o as f64 / 1_073_741_824.0);
                }
            }
            crate::parse_carve::carve_image(&config.file, config.output.as_ref(), config.carve_unalloc, &skip_offsets);
        }
        ActionType::MergeNeo4jNodes => {
            merge_neo4j_nodes(
                config.database.as_ref().unwrap(),
                config.user.as_ref().unwrap(),
                config.old_node.as_ref().unwrap(),
                config.new_node.as_ref().unwrap(),
            )
            .await;
        }
        ActionType::MergeMemgraphNodes => {
            let default_user = String::from("");
            merge_memgraph_nodes(
                config.database.as_ref().unwrap(),
                config.user.as_ref().unwrap_or(&default_user),
                config.old_node.as_ref().unwrap(),
                config.new_node.as_ref().unwrap(),
            )
            .await;
        }
        ActionType::GraphHunt => {
            let default_user = String::from("");
            crate::graph_hunt::graph_hunt(
                config.database.as_ref().unwrap(),
                config.user.as_ref().unwrap_or(&default_user),
                config.investigation_from.as_ref().unwrap(),
                config.skip_detectors.as_deref(),
                config.only_detectors.as_deref(),
                config.output.as_deref(),
            )
            .await;
        }
    }

    // Print noise filter summary (no-op if no filter flags were set)
    crate::filter::print_filter_summary();

    Ok(())
}

// -----------------------------------------------------------------------------
//   Validates input configuration depending on the chosen action
// -----------------------------------------------------------------------------
fn validate_folders(config: &Cli) -> Result<(), String> {
    // Check the action
    match config.action {
        ActionType::ParseWindows | ActionType::ParserElastic | ActionType::ParseLinux => {
            // For these actions, at least one file or directory is required
            if config.directory.is_empty() && config.file.is_empty() {
                return Err(String::from(
                    "At least one directory or file is required for this action.",
                ));
            }

            // Validate each file
            for file in &config.file {
                if !std::path::Path::new(file).exists() {
                    return Err(format!("File {} does not exist.", file));
                }
                if config.action == ActionType::ParseWindows {
                    // Check if EVTX or MDB (UAL database)
                    let is_mdb = file.to_lowercase().ends_with(".mdb");
                    if !is_mdb && !is_evtx_file(file) {
                        return Err(format!(
                            "File {} does not appear to be an EVTX or MDB file.",
                            file
                        ));
                    }
                } else if config.action == ActionType::ParserElastic {
                    // Check if Winlogbeat JSON
                    if !is_winlogbeat_file(file) {
                        return Err(format!(
                            "File {} does not appear to be a valid Winlogbeat JSON file.",
                            file
                        ));
                    }
                }
            }

            // Validate directories
            for folder in &config.directory {
                let path = std::path::Path::new(folder);
                if !path.exists() {
                    return Err(format!("Directory {} does not exist.", folder));
                }
                if !path.is_dir() {
                    return Err(format!("{} is not a directory.", folder));
                }
            }

            // Validate output file if provided
            if let Some(output) = config.output.as_ref() {
                let output_path = std::path::Path::new(output);

                if let Some(parent) = output_path.parent() {
                    if parent != std::path::Path::new("") && !parent.exists() {
                        return Err(format!(
                            "Parent folder of output file {} does not exist.",
                            output_path.display()
                        ));
                    }
                }

                if output_path.exists() && !config.overwrite {
                    return Err(format!(
                        "Output file {} already exists. Use --overwrite to overwrite it.",
                        output_path.display()
                    ));
                }

                // Check write permissions
                let temp_file = output_path.join("temp_file.txt");
                match fs::File::create(&temp_file) {
                    Ok(_) => {
                        fs::remove_file(&temp_file).unwrap();
                    }
                    Err(e) => {
                        if e.kind() == ErrorKind::PermissionDenied {
                            return Err(format!(
                                "Cannot write to output folder {}.",
                                output_path.display()
                            ));
                        }
                    }
                }
            }
        }
        ActionType::ParseImage | ActionType::ParseMassive => {
            if config.file.is_empty() && config.directory.is_empty() && !config.all_volumes {
                return Err(String::from(
                    "For parse-image/parse-massive, specify image files with -f, directories with -d, a volume with -d D:, or --all-volumes.",
                ));
            }
        }
        ActionType::CarveImage => {
            if config.file.is_empty() {
                return Err(String::from(
                    "For carve-image, specify forensic image files with -f (E01/VMDK/dd).",
                ));
            }
        }
        ActionType::ParseCustom => {
            if config.file.is_empty() {
                return Err(String::from(
                    "For parse-custom, specify log files with -f and a rule file or directory with --rules.",
                ));
            }
            if config.rules.is_none() {
                return Err(String::from(
                    "For parse-custom, --rules <path> is required (YAML rule file or directory).",
                ));
            }
        }
        ActionType::LoadNeo4j => {
            if config.file.is_empty() || config.database.is_none() || config.user.is_none() {
                return Err(String::from(
                    "For the Load action, you must specify at least one file, a database, and a user.",
                ));
            }
        }
        ActionType::LoadMemgraph => {
            if config.file.is_empty() || config.database.is_none() {
                return Err(String::from(
                    "For the Load Memgraph action, you must specify at least one file and a database.",
                ));
            }
        }
        ActionType::Merge => {
            // Merge requires at least two files
            if config.file.len() < 2 {
                return Err(String::from("You must specify at least two files to merge."));
            }
        }
        ActionType::MergeNeo4jNodes => {
            if config.database.is_none() || config.user.is_none()
                || config.old_node.is_none() || config.new_node.is_none() {
                return Err(String::from(
                    "For merge-neo4j-nodes you must specify --database, --user, --old-node and --new-node.",
                ));
            }
        }
        ActionType::MergeMemgraphNodes => {
            if config.database.is_none()
                || config.old_node.is_none() || config.new_node.is_none() {
                return Err(String::from(
                    "For merge-memgraph-nodes you must specify --database, --old-node and --new-node.",
                ));
            }
        }
        ActionType::GraphHunt => {
            if config.database.is_none() {
                return Err(String::from(
                    "For graph-hunt you must specify --database (Memgraph bolt URI).",
                ));
            }
            if config.investigation_from.is_none() {
                return Err(String::from(
                    "For graph-hunt you must specify --investigation-from \"YYYY-MM-DD HH:MM:SS\".",
                ));
            }
            if config.skip_detectors.is_some() && config.only_detectors.is_some() {
                return Err(String::from(
                    "--skip-detectors and --only-detectors are mutually exclusive.",
                ));
            }
        }
        ActionType::ParseCortex => {
            // For parse_cortex, we need a base URL that starts with "api-"
            let base_url = config
                .cortex_url
                .as_ref()
                .ok_or("The --cortex_url argument is required for parse_cortex.")?;

            if !base_url.starts_with("https://api-") {
                return Err(format!(
                    "Cortex URL must start with 'https://api-'. Received: {}",
                    base_url
                ));
            }

            // Also validate the output path if provided
            if let Some(output) = config.output.as_ref() {
                let output_path = std::path::Path::new(output);
                if let Some(parent) = output_path.parent() {
                    if parent != std::path::Path::new("") && !parent.exists() {
                        return Err(format!(
                            "Parent folder of output file {} does not exist.",
                            output_path.display()
                        ));
                    }
                }
                if output_path.exists() && !config.overwrite {
                    return Err(format!(
                        "Output file {} already exists. Use --overwrite to overwrite it.",
                        output_path.display()
                    ));
                }
            }
        }
        ActionType::ParseCortexEvtxForensics  => {
            // For parse_cortex, we need a base URL that starts with "api-"
            let base_url = config
                .cortex_url
                .as_ref()
                .ok_or("The --cortex_url argument is required for parse_cortex.")?;

            if !base_url.starts_with("https://api-") {
                return Err(format!(
                    "Cortex URL must start with 'https://api-'. Received: {}",
                    base_url
                ));
            }

            // Also validate the output path if provided
            if let Some(output) = config.output.as_ref() {
                let output_path = std::path::Path::new(output);
                if let Some(parent) = output_path.parent() {
                    if parent != std::path::Path::new("") && !parent.exists() {
                        return Err(format!(
                            "Parent folder of output file {} does not exist.",
                            output_path.display()
                        ));
                    }
                }
                if output_path.exists() && !config.overwrite {
                    return Err(format!(
                        "Output file {} already exists. Use --overwrite to overwrite it.",
                        output_path.display()
                    ));
                }
            }
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
//   Checks if a file is an EVTX file
// -----------------------------------------------------------------------------
fn is_evtx_file(file_path: &str) -> bool {
    let path = std::path::Path::new(file_path);
    if path.extension().map_or(false, |ext| ext == "evtx") {
        return true;
    }

    // Additional check to avoid false positives
    if let Ok(mut f) = File::open(file_path) {
        let mut buffer = [0; 4];
        if f.read_exact(&mut buffer).is_ok() {
            // "ElfF" is the signature of an EVTX file
            return buffer == [0x45, 0x6C, 0x66, 0x46];
        }
    }

    false
}

// -----------------------------------------------------------------------------
//   Checks if a file is a valid Winlogbeat JSON file
// -----------------------------------------------------------------------------
fn is_winlogbeat_file(file_path: &str) -> bool {
    let file = File::open(file_path);
    if file.is_err() {
        return false;
    }

    let reader = BufReader::new(file.unwrap());

    for line in reader.lines().flatten() {
        // Try to parse each line as JSON
        if let Ok(json) = serde_json::from_str::<Value>(&line) {
            // Check for some typical Winlogbeat fields
            if json
                .get("agent")
                .and_then(|agent| agent.get("type"))
                .and_then(|t| t.as_str())
                == Some("winlogbeat")
                && json.get("winlog").is_some()
                && json.get("event").is_some()
                && json.get("@timestamp").is_some()
            {
                return true;
            }
        }
    }

    false
}

// -----------------------------------------------------------------------------
//   Cleans a path that may have been corrupted by shell quoting issues.
//   e.g., PowerShell trailing \ can cause: path.vmdk" -o output.csv --overwrite
// -----------------------------------------------------------------------------
fn clean_path(path: &str) -> Result<String, String> {
    let p = path.to_string();

    // Detect shell quoting corruption: path contains what looks like CLI flags
    // This happens in PowerShell when a path ends with \ inside single quotes:
    //   -d 'C:\path\' -o output.csv  →  -d receives 'C:\path" -o output.csv'
    if p.contains("\" -") || p.contains("\" --") || p.contains(" -o ") || p.contains(" --overwrite") {
        return Err(format!(
            "Path corrupted by shell quoting: '{}...'\n\
             This happens when a path ends with \\ inside single quotes in PowerShell.\n\
             Fix: remove the trailing \\ or use double quotes.\n\
             Example: -d \"C:\\evidence\\image.vmdk\"",
            &p[..p.len().min(80)]
        ));
    }

    // Remove trailing quotes and slashes
    let p = p.trim_matches('"')
        .trim_end_matches(&['\\', '/'][..])
        .to_string();

    Ok(p)
}

// -----------------------------------------------------------------------------
//   Normalizes a file or directory path:
//   - Strips trailing slashes and backslashes
//   - Canonicalizes if possible (resolves ., .., symlinks)
//   - Falls back to trimmed path if canonicalization fails
// -----------------------------------------------------------------------------
fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_end_matches(|c| c == '/' || c == '\\');
    let trimmed = if trimmed.is_empty() { path } else { trimmed };
    match std::fs::canonicalize(trimmed) {
        Ok(canonical) => {
            let s = canonical.to_string_lossy().to_string();
            // Remove \\?\ prefix from Windows extended-length paths
            let s = s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
            // Fix UNC paths: \\?\UNC\server\share → \\server\share
            if s.starts_with(r"UNC\") {
                format!(r"\\{}", &s[4..])
            } else {
                s
            }
        }
        Err(_) => trimmed.to_string(),
    }
}

// -----------------------------------------------------------------------------
//   Tries to parse the provided string as a UTC date/time
// -----------------------------------------------------------------------------
fn parse_cortex_time(raw: &str) -> Result<String, String> {
    // Si ya contiene offset, lo aceptamos tal cual (pero validamos el formato base).
    let has_offset = raw.trim().ends_with("-0000") || raw.trim().ends_with("-1000") || raw.trim().ends_with("-0100");

    let base_part = if has_offset {
        raw.trim().to_string()
    } else {
        format!("{} -0000", raw.trim())
    };

    // Validar que esté en formato "YYYY-MM-DD HH:MM:SS -0000"
    match chrono::NaiveDateTime::parse_from_str(&base_part[..19], "%Y-%m-%d %H:%M:%S") {
        Ok(_) => Ok(base_part),
        Err(_) => Err("Date must be in format 'YYYY-MM-DD HH:MM:SS [-0000]'".to_string()),
    }
}