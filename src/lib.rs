use clap::{Parser, ValueEnum};
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind};
use std::error::Error;
use std::fs::File;
use std::io::Read;
mod parse;
pub mod threads;
pub mod detect;
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
mod csv_out;
pub use crate::parse_elastic::*;
mod parse_cortex;
pub use crate::parse_cortex::*;
mod parse_cortex_evtx_forensics;
pub use crate::parse_cortex_evtx_forensics::*;
mod parse_linux;
mod parse_mac;
pub use crate::parse_linux::*;
pub use crate::parse_mac::parse_mac;
mod parse_journal;
pub(crate) mod linux_tz;
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
pub mod vhd;
pub mod timefmt;
pub mod textlines;
pub use crate::vmdk::*;
mod graph_hunt;
mod graph_hunt_common;
mod graph_hunt_neo4j;
#[cfg(feature = "ui")]
mod view;

// -----------------------------------------------------------------------------
//   Command-line interface struct
// -----------------------------------------------------------------------------
#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    /// Action to perform. `parse` is the one to start with: it looks at the
    /// evidence given with -d / -f and picks the parser itself.
    #[arg(short, long)]
    action: ActionType,

    /// Directories to process — also accepts drive letters (D:) for mounted volumes
    #[arg(short, long)]
    directory: Vec<String>,

    /// Individual files to process (EVTX, JSON, .mdb, E01, VMDK, VHD/VHDX, dd/raw)
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

    /// Target database name on the graph server. Defaults to `neo4j` for
    /// load-neo4j / graph-hunt-neo4j and to `memgraph` for load-memgraph /
    /// graph-hunt. Useful when a single Neo4j 5.x / 2026.x server holds
    /// multiple databases (e.g. one per case) and you want to keep them
    /// separate. Ignored when the server doesn't support multi-database.
    #[arg(long)]
    db: Option<String>,

    /// If specified, overwrite the output file if it exists
    #[arg(long)]
    overwrite: bool,

    /// No effect, kept so existing command lines still parse: output goes
    /// to stdout whenever `-o` is omitted.
    #[arg(long, hide = true)]
    stdout: bool,

    /// If specified, print debug information
    #[arg(long)]
    debug: bool,

    /// Silent mode: suppress all output except CSV data (for automation/Velociraptor integration)
    #[arg(long)]
    silent: bool,

    /// Cortex API base URL (must start with 'https://api-')
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
    /// Without this flag the query defaults to (22, 445, 3389, 5985, 5986). Use it when
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
    /// (4624,4625,4634,4647,4648,4768-4771,4776,4778,4779,5140,31001,30803-30808,
    /// 1009,551,1024,1102,1149,21,22,24,25,131,6,5858).
    /// Example: --cortex-event-ids 4624,4625,4648
    #[arg(long)]
    cortex_event_ids: Option<String>,

    /// For load-neo4j / load-memgraph: emit one edge per CSV row instead of
    /// collapsing duplicate (src, user, dst) triples into a single edge with
    /// a `count` property. Useful when you want to see every individual
    /// lateral movement event, typically combined with --start-time /
    /// --end-time to restrict the view to a narrow time window.
    #[arg(long)]
    ungrouped: bool,

    /// Scan all NTFS volumes on the system for VSS (parse-image-windows only, requires admin)
    #[arg(long)]
    all_volumes: bool,

    /// Planned: carve only unallocated space. Not implemented yet; the
    /// whole image is scanned either way.
    #[arg(long)]
    carve_unalloc: bool,

    /// Comma-separated list of hex offsets to skip during carving (for corrupted E01 chunks that hang).
    /// Example: --skip-offsets 0x6478b6000,0x7a0000000
    /// Each offset skips a 32 MB window starting at that offset.
    #[arg(long)]
    skip_offsets: Option<String>,

    /// Path to a YAML rule file or directory for `parse-custom`, or for
    /// `parse`: the files masstin does not recognise (a VPN, firewall or
    /// proxy log) are read with these rules and merged into the same
    /// timeline. See rules/ and docs/custom-parsers.md for the schema and
    /// contributed rules.
    #[arg(long)]
    rules: Option<String>,

    /// For `parse`: also carve EVTX records out of the disk images found,
    /// unallocated space included (the records of deleted or overwritten
    /// logs, as `carve-image` does), merged into the same timeline. Slow:
    /// every byte of every image is read.
    #[arg(long)]
    carve: bool,

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
    /// Available: novel-edge, community-bridge, origin-fanout, cred-rotation,
    /// pagerank-spike, betweenness-spike, failed-sweep, preauth-sweep,
    /// probe-then-success, rare-logon-type, causal-path, credential-switch,
    /// sigma.
    /// Example: --skip-detectors pagerank-spike,betweenness-spike
    #[arg(long)]
    skip_detectors: Option<String>,

    /// For `graph-hunt`: comma-separated list of detector names to run
    /// exclusively (all others disabled). Same names as --skip-detectors.
    /// Mutually exclusive with --skip-detectors.
    #[arg(long)]
    only_detectors: Option<String>,

    /// For `graph-hunt` (and the loaders' IP -> name annotation): false
    /// discovery rate controlled with Benjamini-Hochberg. It is the only
    /// chosen number: every score is a probability measured in the corpus.
    #[arg(long, default_value_t = 0.05)]
    alpha: f64,

    /// For `graph-hunt` / `graph-hunt-neo4j`: also write an analyst report
    /// (Markdown) to this path: one story per origin with a significant
    /// connection, most unusual first, in words, with the baseline count
    /// behind every statement. The CSV is unchanged.
    #[arg(long)]
    report: Option<String>,

    /// For `graph-hunt-csv`: do not write the hunt's verdict into the
    /// timeline. By default every timeline given with -f is rewritten in
    /// place with its `hunt`, `hunt_score` and `hunt_why` columns filled
    /// (`verdict` and `notes` are kept); with this flag the timeline is
    /// left untouched and only -o / --report are written.
    #[arg(long)]
    no_annotate: bool,

    /// For `merge` / `graph-hunt-csv`: an earlier timeline whose `verdict`
    /// and `notes` are copied onto the rows with the same 14 event columns
    /// (after the evidence was parsed again, for instance).
    #[arg(long)]
    carry_marks: Option<String>,

    /// For `view`: open on the neighbourhood of this host (name or IP,
    /// `*` wildcards) instead of the hunt's findings.
    #[arg(long)]
    focus: Option<String>,

    /// For `view`: what draws the window, `glow` (OpenGL, a GPU) or
    /// `software` (masstin's own CPU rasteriser). Left out, it is picked by
    /// itself: software over a remote desktop or without a GPU driver on
    /// Windows, OpenGL elsewhere. `MASSTIN_VIEW_RENDERER` does the same.
    #[arg(long)]
    renderer: Option<String>,

    /// Threads for parsing: decoding the EVTX chunks, turning the records
    /// into rows, sorting and writing the timeline. Left out, the machine
    /// decides: all its cores but one (a single thread on a machine of one
    /// or two cores). `1` runs exactly as masstin ran with no parallelism.
    /// The process runs below normal priority either way, so the desktop and
    /// other tools come first (`MASSTIN_PRIORITY=normal` keeps it normal, for
    /// a server where masstin is the job). `MASSTIN_THREADS` does the same.
    #[arg(long)]
    threads: Option<usize>,

    /// For `parse-image` / `parse-massive`: forensic images extracted at
    /// once. Left out, two when the run has four threads or more, one
    /// otherwise; eight at most. An NVMe keeps up with several; a spinning
    /// disk or a share over the network gains nothing from more than one.
    /// `MASSTIN_PARALLEL_IMAGES` does the same.
    #[arg(long)]
    parallel_images: Option<usize>,

    /// For `view`: the case file (`.masstin`) to open, or to start with the
    /// timelines given by `-f`. The saved views, the style, the merged hosts,
    /// the subnets, the presentation and the notes are kept in it instead of
    /// next to the timelines, so nothing is written where the evidence is.
    #[arg(long)]
    case: Option<String>,

    /// For `graph-hunt` / `graph-hunt-neo4j`: reconstruct the incident from
    /// known-bad seeds (comma-separated host names, IPs or accounts). The
    /// report gets a first section with every hop the seeds took in the
    /// window, in order, with session ends and certainty, and one Cypher
    /// query that draws the whole chain. Requires --report.
    #[arg(long)]
    seed: Option<String>,

    /// For `--seed`: only logins at or after this time start the chain
    /// ("YYYY-MM-DD HH:MM:SS", UTC). Default: the cutoff.
    #[arg(long)]
    seed_from: Option<String>,

    /// For `--seed`: only logins at or before this time start the chain
    /// ("YYYY-MM-DD HH:MM:SS", UTC). Default: the end of the window.
    #[arg(long)]
    seed_to: Option<String>,

    /// For `graph-hunt` / `graph-hunt-neo4j`: Sigma hits from Hayabusa or
    /// Chainsaw (JSON / JSONL files or directories, comma-separated). A hit
    /// on a machine while a login session is open on it corroborates that
    /// connection (coordinate `sigma`), and the report names the rule.
    #[arg(long)]
    sigma: Option<String>,
}

// -----------------------------------------------------------------------------
//   List of possible actions
// -----------------------------------------------------------------------------
#[derive(ValueEnum, Clone, Debug, PartialEq)]
enum ActionType {
    /// Read any evidence and pick the parser: masstin looks at what it is given (EVTX, UAL databases, KAPE / Velociraptor / Cortex XDR / UAC triages, disk images, Linux logs and triages, macOS logarchives and `log show` exports, Winlogbeat JSON, masstin timelines), says what it found and which parser takes it, and runs it. Images with anything else beside them, or Windows and Linux together, go through the massive pass. --rules adds custom-parser rules for the files it does not recognise, --carve the EVTX carving of the images; both are merged into the one timeline.
    #[value(alias = "auto")]
    Parse,
    /// Parse Windows EVTX files and UAL databases (.mdb) from directories or individual files
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
    /// Parse macOS logs: a .logarchive bundle (binary Unified Log) or a `log show` JSON/NDJSON export. Extracts SSH and Screen Sharing / ARD remote logons.
    #[value(alias = "parse-macos")]
    ParseMac,
    /// Parse from forensic images (E01/dd/VMDK/VHD/VHDX), mounted volumes (-d D:), or --all-volumes. Auto-detects OS: NTFS→EVTX+UAL+VSS, ext4 / XFS→Linux logs
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
    /// Statistical lateral-movement hunt on a graph loaded into Memgraph with --ungrouped. Every signal is a probability measured against the network's own baseline (conformal p-values, Benjamini-Hochberg at --alpha); no MAGE plugin needed. Requires --database and --investigation-from. Options: --report, --seed, --sigma, --only/--skip-detectors.
    #[value(alias = "graph-hunt")]
    GraphHunt,
    /// Same statistical hunt on a graph loaded into Neo4j with --ungrouped. Edges are read once over bolt and every statistic (PageRank, betweenness, Louvain included) is computed in memory; no GDS plugin needed. Requires --database, --user and --investigation-from; --db selects the database. Password from $NEO4J_PASSWORD or a prompt.
    #[value(alias = "graph-hunt-neo4j")]
    GraphHuntNeo4j,
    /// Same hunt as graph-hunt / graph-hunt-neo4j but straight from masstin timeline CSVs (-f), no graph database: every statistic is computed in memory. Requires --investigation-from.
    #[value(alias = "graph-hunt-csv")]
    GraphHuntCsv,
    /// Open the graph viewer (a window) on timeline CSVs (-f): the lateral-movement graph with its hunt states, filters, neighbourhoods, a replay in time order and the analyst's marks, written back into the CSV. Without -f it opens on a welcome, to open a timeline or ingest evidence (drop it on the window). --focus HOST opens on a host's neighbourhood; --start-time / --end-time bound the window.
    View,
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

    // Enable or disable debug/silent mode
    crate::parse::set_debug_mode(config.debug);
    crate::parse_elastic::set_debug_mode(config.debug);
    crate::banner::set_silent_mode(config.silent);

    // `parse`: look at the evidence and pick the parser. One parser: the run
    // goes on as that action. Several (custom rules, carving, timelines
    // beside the evidence): each writes a part, merged at the end.
    let mut plan: Option<Vec<ParseStep>> = None;
    let mut banner_done = false;
    if config.action == ActionType::Parse {
        crate::banner::print_banner("Parse");
        banner_done = true;
        let steps = resolve_parse(&config)?;
        if steps.len() == 1 && steps[0].action != ActionType::Merge {
            let st = steps.into_iter().next().unwrap();
            config.action = st.action;
            config.file = st.files;
            config.directory = st.dirs;
        } else {
            plan = Some(steps);
        }
    }

    validate_folders(&config)?;

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
    if !banner_done {
        crate::banner::print_banner(&action_name);
    }

    // the threads of this run: the flag, the environment, or the machine's
    // policy; the window keeps its normal priority, it is interactive
    if config.action != ActionType::View {
        let asked = config.threads.or_else(|| std::env::var("MASSTIN_THREADS").ok().and_then(|s| s.trim().parse().ok()));
        let asked_images = config.parallel_images.or_else(|| std::env::var("MASSTIN_PARALLEL_IMAGES").ok().and_then(|s| s.trim().parse().ok()));
        let reads_images = matches!(config.action, ActionType::ParseImage | ActionType::ParseMassive)
            || plan.as_ref().map_or(false, |p| p.iter().any(|s| matches!(s.action, ActionType::ParseImage | ActionType::ParseMassive)));
        let evidence: Vec<String> = if reads_images { config.file.iter().chain(config.directory.iter()).cloned().collect() } else { Vec::new() };
        let d = crate::threads::decide(asked, asked_images, &evidence);
        crate::threads::install(&d);
        let machine = format!(
            "{} core{}, {:.1} idle now{}",
            d.cores,
            if d.cores == 1 { "" } else { "s" },
            d.snapshot.idle_cores,
            d.snapshot.free_memory.map(|m| format!(", {} free", crate::threads::human_bytes(m))).unwrap_or_default()
        );
        let threads = if d.asked {
            format!("Threads: {} (asked; {})", d.workers, machine)
        } else {
            format!("Threads: up to {}, what is idle at each moment ({}; --threads fixes it, 1 runs serial)", d.workers, machine)
        };
        let images = if !reads_images {
            String::new()
        } else if let Some(n) = d.asked_images {
            format!("; images {} at a time (asked)", n)
        } else {
            format!(
                "; images at a time measured as they are read ({} to start on {}, more while the rate grows, the idle cores the ceiling; --parallel-images fixes it)",
                match d.medium {
                    crate::threads::Medium::Rotational => "one",
                    _ => "two",
                },
                d.medium.label()
            )
        };
        crate::banner::print_info(&format!(
            "{}; priority {}{}",
            threads,
            if crate::threads::keeps_normal_priority() { "normal (MASSTIN_PRIORITY)" } else { "below normal (MASSTIN_PRIORITY=normal keeps it)" },
            images
        ));
    }

    // Match the selected action and call the corresponding function
    match config.action {
        ActionType::Parse => {
            run_parse_plan(&config, plan.take().unwrap_or_default())?;
        }
        ActionType::ParseWindows => {
            parse_events(&config.file, &config.directory, config.output.as_ref());
        }
        ActionType::LoadNeo4j => {
            load_neo4j(
                &config.file,
                &config.database.as_ref().unwrap(),
                &config.user.as_ref().unwrap(),
                config.db.as_deref().unwrap_or("neo4j"),
                config.ungrouped,
                config.start_time.as_ref(),
                config.end_time.as_ref(),
                config.alpha,
            )
            .await;
        }
        ActionType::LoadMemgraph => {
            let default_user = String::from("");
            load_memgraph(
                &config.file,
                &config.database.as_ref().unwrap(),
                config.user.as_ref().unwrap_or(&default_user),
                config.db.as_deref().unwrap_or("memgraph"),
                config.ungrouped,
                config.start_time.as_ref(),
                config.end_time.as_ref(),
                config.alpha,
            )
            .await;
        }
        ActionType::Merge => {
            merge_files(
                &config.file,
                config.output.as_ref(),
                config.start_time.as_ref(),
                config.end_time.as_ref(),
                config.carry_marks.as_ref(),
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
        ActionType::ParseMac => {
            parse_mac(&config.file, &config.directory, config.output.as_ref());
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
            let skip_offsets = carve_skip_offsets(&config);
            crate::parse_carve::carve_image(&config.file, config.output.as_ref(), config.carve_unalloc, &skip_offsets);
        }
        ActionType::MergeNeo4jNodes => {
            merge_neo4j_nodes(
                config.database.as_ref().unwrap(),
                config.user.as_ref().unwrap(),
                config.db.as_deref().unwrap_or("neo4j"),
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
                config.db.as_deref().unwrap_or("memgraph"),
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
                config.db.as_deref().unwrap_or("memgraph"),
                config.investigation_from.as_ref().unwrap(),
                config.skip_detectors.as_deref(),
                config.only_detectors.as_deref(),
                config.alpha,
                config.end_time.as_deref(),
                config.output.as_deref(),
                config.report.as_deref(),
                config.seed.as_deref(),
                config.seed_from.as_deref(),
                config.seed_to.as_deref(),
                config.sigma.as_deref(),
            )
            .await;
        }
        ActionType::View => {
            #[cfg(feature = "ui")]
            {
                let opts = crate::view::Options {
                    files: config.file.clone(),
                    alpha: config.alpha,
                    focus: config.focus.clone(),
                    start: config.start_time.clone(),
                    end: config.end_time.clone(),
                    renderer: config.renderer.clone(),
                    case: config.case.clone(),
                };
                crate::view::run(opts)?;
            }
            #[cfg(not(feature = "ui"))]
            {
                return Err(Box::from("this masstin was built without the `ui` feature: `-a view` is not available"));
            }
        }
        ActionType::GraphHuntCsv => {
            crate::graph_hunt::graph_hunt_csv(
                &config.file,
                config.investigation_from.as_ref().unwrap(),
                config.skip_detectors.as_deref(),
                config.only_detectors.as_deref(),
                config.alpha,
                config.end_time.as_deref(),
                config.output.as_deref(),
                config.report.as_deref(),
                config.seed.as_deref(),
                config.seed_from.as_deref(),
                config.seed_to.as_deref(),
                config.sigma.as_deref(),
                !config.no_annotate,
                config.carry_marks.as_deref(),
            );
        }
        ActionType::GraphHuntNeo4j => {
            let default_user = String::from("neo4j");
            crate::graph_hunt_neo4j::graph_hunt_neo4j(
                config.database.as_ref().unwrap(),
                config.user.as_ref().unwrap_or(&default_user),
                config.db.as_deref().unwrap_or("neo4j"),
                config.investigation_from.as_ref().unwrap(),
                config.skip_detectors.as_deref(),
                config.only_detectors.as_deref(),
                config.alpha,
                config.end_time.as_deref(),
                config.output.as_deref(),
                config.report.as_deref(),
                config.seed.as_deref(),
                config.seed_from.as_deref(),
                config.seed_to.as_deref(),
                config.sigma.as_deref(),
            )
            .await;
        }
    }

    // Print noise filter summary (no-op if no filter flags were set)
    crate::filter::print_filter_summary();

    Ok(())
}

// -----------------------------------------------------------------------------
//   `parse`: the evidence decides the parser
// -----------------------------------------------------------------------------

/// One part of a `parse` run: a parser and what it reads.
#[derive(Debug, Clone)]
struct ParseStep {
    action: ActionType,
    files: Vec<String>,
    dirs: Vec<String>,
}

fn action_name(a: &ActionType) -> String {
    a.to_possible_value().map(|v| v.get_name().to_string()).unwrap_or_else(|| format!("{:?}", a))
}

fn action_of(name: &str) -> ActionType {
    ActionType::from_str(name, true).unwrap_or(ActionType::ParseMassive)
}

/// What `parse` will run: the detector's look at the evidence (the same one
/// the window's ingest wizard makes, without its time limit), said on the
/// console in words, and the parts it adds (custom rules, carving).
fn resolve_parse(config: &Cli) -> Result<Vec<ParseStep>, String> {
    use crate::detect::{self, Limits};
    if let Some(out) = config.output.as_ref() {
        let op = std::path::Path::new(out);
        if op.exists() && !config.overwrite {
            return Err(format!("Output file {} already exists. Use --overwrite to overwrite it.", op.display()));
        }
        if let Some(parent) = op.parent() {
            if parent != std::path::Path::new("") && !parent.exists() {
                return Err(format!("Parent folder of output file {} does not exist.", op.display()));
            }
        }
    }
    if config.all_volumes {
        crate::banner::print_phase_result("--all-volumes: every NTFS volume of this machine -> parse-image");
        return Ok(vec![ParseStep { action: ActionType::ParseImage, files: config.file.clone(), dirs: config.directory.clone() }]);
    }
    if config.file.is_empty() && config.directory.is_empty() {
        return Err("parse needs evidence to read: a folder, files, disk images or archives (masstin -a parse -d D:\\evidence -o timeline.csv).".into());
    }
    for f in &config.file {
        if !std::path::Path::new(f).exists() {
            return Err(format!("{} does not exist.", f));
        }
    }
    for d in &config.directory {
        if !std::path::Path::new(d).exists() {
            return Err(format!("Directory {} does not exist.", d));
        }
    }
    // mounted volumes are read the way parse-image reads them, never walked
    let (volumes, dirs): (Vec<String>, Vec<String>) = config.directory.iter().cloned().partition(|d| crate::parse_image_windows::is_drive_letter(d));
    let mut files = config.file.clone();
    // with --rules, the files masstin does not recognise are the rules' to read
    let mut custom = Vec::new();
    if let Some(rules) = config.rules.as_ref() {
        files.retain(|f| {
            if detect::scan(&[f.clone()], Limits::QUICK).recognised() {
                true
            } else {
                custom.push(f.clone());
                false
            }
        });
        if custom.is_empty() {
            crate::banner::print_warning(&format!(
                "--rules {}: every file given is evidence masstin reads itself; the rules read the files given one by one that it does not recognise",
                rules
            ));
        }
    }

    // masstin timelines given with -f are merged as they are, never handed to
    // a parser; the ones lying inside the folders are left out (a timeline of
    // an earlier run, of another case) unless the folders hold nothing else
    let mut given_tl = Vec::new();
    files.retain(|f| {
        if detect::is_timeline(std::path::Path::new(f)) {
            given_tl.push(f.clone());
            false
        } else {
            true
        }
    });

    let mut steps: Vec<ParseStep> = Vec::new();
    let mut images: Vec<String> = Vec::new();
    let rest: Vec<String> = files.iter().chain(dirs.iter()).cloned().collect();
    if !rest.is_empty() {
        let s = detect::scan(&rest, Limits::FULL);
        let v = detect::judge(&s);
        crate::banner::print_info(&format!(
            "Found: {} ({} file{} in {} folder{}, {:.1} s{})",
            s.summary(),
            s.files,
            if s.files == 1 { "" } else { "s" },
            s.dirs,
            if s.dirs == 1 { "" } else { "s" },
            s.secs,
            if s.truncated { "; the look stopped early, the parser goes all the way" } else { "" }
        ));
        match v.parser {
            None if v.sure => {
                crate::banner::print_phase_result(&format!("{} -> merged into one timeline (merge)", v.title));
                let mut all = s.timelines.clone();
                all.extend(given_tl.drain(..));
                steps.push(ParseStep { action: ActionType::Merge, files: all, dirs: Vec::new() });
            }
            None => {
                if custom.is_empty() && volumes.is_empty() && given_tl.is_empty() {
                    return Err(format!(
                        "Nothing masstin knows how to read in {}: no event logs, triage packages, disk images, Linux or macOS logs, Winlogbeat JSON or timelines. Name the parser with -a (parse-windows, parse-linux, parse-mac, parse-image, parse-massive) if the evidence is there in another shape, or read text logs (VPN, firewall, proxy) with --rules.",
                        rest.join(", ")
                    ));
                }
            }
            Some(a) => {
                let mut act = action_of(a);
                // parse-windows reads EVTX, UAL and ZIP files given one by one;
                // anything else given as a file goes through the massive pass
                if act == ActionType::ParseWindows && files.iter().any(|f| !f.to_ascii_lowercase().ends_with(".mdb") && !f.to_ascii_lowercase().ends_with(".zip") && !is_evtx_file(f)) {
                    act = ActionType::ParseMassive;
                }
                crate::banner::print_phase_result(&format!("{} -> {}: {}", v.title, action_name(&act), v.why));
                if !v.sure {
                    crate::banner::print_warning("Not sure of the parser: -a names one (parse-windows, parse-linux, parse-mac, parse-image, parse-massive)");
                }
                steps.push(ParseStep { action: act, files: files.clone(), dirs: dirs.clone() });
                if !s.timelines.is_empty() {
                    crate::banner::print_info(&format!(
                        "{} masstin timeline(s) inside the folders left out (an earlier run's, another case's): give one with -f to merge it in",
                        s.timelines.len()
                    ));
                }
            }
        }
        images = s.images.clone();
    }
    if !given_tl.is_empty() {
        let only = steps.is_empty() && volumes.is_empty() && custom.is_empty();
        crate::banner::print_phase_result(&if only {
            format!("{} masstin timeline(s) -> merged into one timeline (merge)", given_tl.len())
        } else {
            format!("{} masstin timeline(s) given -> merged in", given_tl.len())
        });
        steps.push(ParseStep { action: ActionType::Merge, files: given_tl, dirs: Vec::new() });
    }
    if !volumes.is_empty() {
        crate::banner::print_phase_result(&format!("Mounted volume(s) {} -> parse-image (the live files and the shadow copies)", volumes.join(", ")));
        match steps.iter_mut().find(|st| matches!(st.action, ActionType::ParseImage | ActionType::ParseMassive)) {
            Some(st) => st.dirs.extend(volumes),
            None => steps.push(ParseStep { action: ActionType::ParseImage, files: Vec::new(), dirs: volumes }),
        }
    }
    if !custom.is_empty() {
        crate::banner::print_phase_result(&format!(
            "{} file(s) masstin does not recognise -> parse-custom with the rules in {}",
            custom.len(),
            config.rules.as_deref().unwrap_or("")
        ));
        steps.push(ParseStep { action: ActionType::ParseCustom, files: custom, dirs: Vec::new() });
    }
    if config.carve {
        if images.is_empty() {
            crate::banner::print_warning("--carve: no disk image among the evidence, nothing to carve");
        } else {
            crate::banner::print_phase_result(&format!("--carve: {} disk image(s) -> carve-image, the EVTX records of deleted or overwritten logs", images.len()));
            steps.push(ParseStep { action: ActionType::CarveImage, files: images, dirs: Vec::new() });
        }
    } else if !images.is_empty() {
        crate::banner::print_info("Disk images: --carve also carves the EVTX records of deleted or overwritten logs out of them");
    }
    if steps.is_empty() {
        return Err("parse found nothing to run.".into());
    }
    Ok(steps)
}

/// The skip list of `carve-image` (`--skip-offsets`), said on the console.
fn carve_skip_offsets(config: &Cli) -> Vec<u64> {
    let skip_offsets: Vec<u64> = config
        .skip_offsets
        .as_deref()
        .map(|s| {
            s.split(',')
                .filter_map(|tok| {
                    let t = tok.trim();
                    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
                    u64::from_str_radix(t, 16).ok()
                })
                .collect()
        })
        .unwrap_or_default();
    if !skip_offsets.is_empty() {
        eprintln!("  Skip offsets configured: {} offset(s)", skip_offsets.len());
        for o in &skip_offsets {
            eprintln!("    → {:#x} ({:.2} GB)", o, *o as f64 / 1_073_741_824.0);
        }
    }
    skip_offsets
}

/// A `parse` of several parts: each part writes a timeline of its own in a
/// temporary folder, and the parts are merged (sorted, without duplicates)
/// into the output. Timelines given as evidence are merged as they are.
fn run_parse_plan(config: &Cli, steps: Vec<ParseStep>) -> Result<(), Box<dyn Error>> {
    let tmp = std::env::temp_dir().join(format!("masstin_parse_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp)?;
    let mut parts: Vec<String> = Vec::new();
    let total = steps.len();
    for (i, st) in steps.iter().enumerate() {
        crate::banner::print_info(&format!("Part {} of {}: {}", i + 1, total, action_name(&st.action)));
        if st.action == ActionType::Merge {
            parts.extend(st.files.iter().cloned());
            continue;
        }
        let out = tmp.join(format!("part-{}.csv", i + 1)).to_string_lossy().to_string();
        let o = Some(&out);
        match st.action {
            ActionType::ParseWindows => parse_events(&st.files, &st.dirs, o),
            ActionType::ParseLinux => parse_linux(&st.files, &st.dirs, o),
            ActionType::ParseMac => parse_mac(&st.files, &st.dirs, o),
            ActionType::ParserElastic => parse_events_elastic(&st.files, &st.dirs, o),
            ActionType::ParseImage => parse_image(&st.files, &st.dirs, config.all_volumes, o, false),
            ActionType::ParseMassive => {
                crate::banner::print_massive_warning();
                parse_image(&st.files, &st.dirs, config.all_volumes, o, true)
            }
            ActionType::ParseCustom => crate::parse_custom::parse_custom(&st.files, config.rules.as_deref().unwrap_or(""), o, config.dry_run),
            ActionType::CarveImage => crate::parse_carve::carve_image(&st.files, o, config.carve_unalloc, &carve_skip_offsets(config)),
            _ => {}
        }
        if std::path::Path::new(&out).exists() {
            parts.push(out);
        }
    }
    if parts.is_empty() {
        let _ = fs::remove_dir_all(&tmp);
        return Err("No events from any part: nothing to write.".into());
    }
    crate::banner::print_info(&format!("Merging the {} part(s) into one timeline", parts.len()));
    let r = merge_files(&parts, config.output.as_ref(), None, None, None);
    let _ = fs::remove_dir_all(&tmp);
    r
}

// -----------------------------------------------------------------------------
//   Validates input configuration depending on the chosen action
// -----------------------------------------------------------------------------
fn validate_folders(config: &Cli) -> Result<(), String> {
    // Check the action
    match config.action {
        // a `parse` of several parts was checked when it was resolved
        ActionType::Parse => {}
        ActionType::ParseWindows | ActionType::ParserElastic | ActionType::ParseLinux | ActionType::ParseMac => {
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
                    // EVTX, MDB (UAL database) or a ZIP of them (walked like a folder's)
                    let is_mdb = file.to_lowercase().ends_with(".mdb");
                    let is_zip = file.to_lowercase().ends_with(".zip");
                    if !is_mdb && !is_zip && !is_evtx_file(file) {
                        return Err(format!(
                            "File {} does not appear to be an EVTX, MDB or ZIP file.",
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
                    "For carve-image, specify forensic image files with -f (E01/VMDK/VHD/VHDX/dd).",
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
        ActionType::View => {
            // no -f: the window opens on its welcome, to open or ingest one
        }
        ActionType::GraphHuntCsv => {
            if config.file.is_empty() {
                return Err(String::from(
                    "For graph-hunt-csv you must specify at least one timeline CSV with -f.",
                ));
            }
            if config.investigation_from.is_none() {
                return Err(String::from(
                    "For graph-hunt-csv you must specify --investigation-from \"YYYY-MM-DD HH:MM:SS\".",
                ));
            }
            if config.skip_detectors.is_some() && config.only_detectors.is_some() {
                return Err(String::from(
                    "--skip-detectors and --only-detectors are mutually exclusive.",
                ));
            }
        }
        ActionType::GraphHuntNeo4j => {
            if config.database.is_none() {
                return Err(String::from(
                    "For graph-hunt-neo4j you must specify --database (Neo4j bolt URI).",
                ));
            }
            if config.investigation_from.is_none() {
                return Err(String::from(
                    "For graph-hunt-neo4j you must specify --investigation-from \"YYYY-MM-DD HH:MM:SS\".",
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

    // the first lines decide; a file that is not Winlogbeat is not read whole
    for line in crate::textlines::EvidenceLines::new(reader).take(1000) {
        // Try to parse each line as JSON
        if let Ok(json) = serde_json::from_str::<Value>(&line) {
            // The winlog.* shape: Winlogbeat writes it, and so does Elastic
            // Agent's Windows integration (agent.type "filebeat"), so the
            // shape decides, not the shipper's name.
            let w = json.get("winlog");
            if w.and_then(|w| w.get("event_id")).is_some()
                && (w.and_then(|w| w.get("channel")).is_some() || w.and_then(|w| w.get("provider_name")).is_some())
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
#[cfg(test)]
mod parse_auto_tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("masstin_parse_auto_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cli(args: &[&str]) -> Cli {
        Cli::parse_from(args)
    }

    #[test]
    fn a_folder_of_evtx_is_read_by_parse_windows() {
        let d = tmp("evtx");
        std::fs::write(d.join("Security.evtx"), b"ElfFile").unwrap();
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-d", d.to_str().unwrap()])).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action, ActionType::ParseWindows);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_archive_of_no_known_layout_given_as_a_file_goes_through_the_massive_pass() {
        let d = tmp("zip");
        let e = d.join("Security.evtx");
        std::fs::write(&e, b"ElfFile").unwrap();
        let z = d.join("triage.zip");
        {
            let mut w = zip::ZipWriter::new(std::fs::File::create(&z).unwrap());
            w.start_file("notes.txt", zip::write::FileOptions::default()).unwrap();
            std::io::Write::write_all(&mut w, b"x").unwrap();
            w.finish().unwrap();
        }
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-f", e.to_str().unwrap(), "-f", z.to_str().unwrap()])).unwrap();
        assert_eq!(steps[0].action, ActionType::ParseWindows, "a ZIP is read by parse-windows");
        // a tarball beside EVTX is not: the massive pass
        let t = d.join("other.tgz");
        std::fs::write(&t, b"not really").unwrap();
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-f", e.to_str().unwrap(), "-f", t.to_str().unwrap()])).unwrap();
        assert_eq!(steps[0].action, ActionType::ParseMassive);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn text_logs_masstin_does_not_know_go_to_the_rules() {
        let d = tmp("rules");
        let e = d.join("Security.evtx");
        std::fs::write(&e, b"ElfFile").unwrap();
        let vpn = d.join("fortigate-vpn.log");
        std::fs::write(&vpn, b"date=2026-11-10 time=01:39:00 action=tunnel-up\n").unwrap();
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-f", e.to_str().unwrap(), "-f", vpn.to_str().unwrap(), "--rules", "rules/vpn"])).unwrap();
        let acts: Vec<ActionType> = steps.iter().map(|s| s.action.clone()).collect();
        assert_eq!(acts, vec![ActionType::ParseWindows, ActionType::ParseCustom]);
        assert_eq!(steps[1].files, vec![vpn.to_string_lossy().to_string()]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn carving_is_asked_for_and_needs_an_image() {
        let d = tmp("carve");
        std::fs::write(d.join("Security.evtx"), b"ElfFile").unwrap();
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-d", d.to_str().unwrap(), "--carve"])).unwrap();
        assert_eq!(steps.len(), 1, "no image, no carving");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn nothing_known_is_an_error_that_says_what_to_do() {
        let d = tmp("nothing");
        std::fs::write(d.join("readme.txt"), b"hello").unwrap();
        let e = resolve_parse(&cli(&["masstin", "-a", "parse", "-d", d.to_str().unwrap()])).unwrap_err();
        assert!(e.contains("Nothing masstin knows how to read") && e.contains("-a"), "{}", e);
        let e = resolve_parse(&cli(&["masstin", "-a", "parse"])).unwrap_err();
        assert!(e.contains("needs evidence"), "{}", e);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn timelines_alone_are_merged() {
        let d = tmp("timelines");
        let t = d.join("a.csv");
        std::fs::write(&t, format!("{}\n", crate::csv_out::HEADER)).unwrap();
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-f", t.to_str().unwrap()])).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action, ActionType::Merge);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_timeline_inside_the_folder_is_left_out_and_one_given_is_merged_in() {
        let d = tmp("tl_beside");
        std::fs::write(d.join("Security.evtx"), b"ElfFile").unwrap();
        // an earlier run's output lying in the evidence folder
        std::fs::write(d.join("old-run.csv"), format!("{}\n", crate::csv_out::HEADER)).unwrap();
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-d", d.to_str().unwrap()])).unwrap();
        assert_eq!(steps.len(), 1, "{:?}", steps);
        assert_eq!(steps[0].action, ActionType::ParseWindows);
        // given with -f it joins, and is never handed to the parser
        let other = tmp("tl_given");
        let t = other.join("other.csv");
        std::fs::write(&t, format!("{}\n", crate::csv_out::HEADER)).unwrap();
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-d", d.to_str().unwrap(), "-f", t.to_str().unwrap()])).unwrap();
        let acts: Vec<ActionType> = steps.iter().map(|s| s.action.clone()).collect();
        assert_eq!(acts, vec![ActionType::ParseWindows, ActionType::Merge]);
        assert!(steps[0].files.is_empty(), "the timeline is not a parser's input");
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn a_vhd_is_a_disk_image() {
        let d = tmp("vhd");
        let v = d.join("disk.vhd");
        std::fs::write(&v, b"conectix").unwrap();
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-f", v.to_str().unwrap()])).unwrap();
        assert_eq!(steps[0].action, ActionType::ParseImage);
        assert!(crate::parse_image_windows::is_first_image_segment(std::path::Path::new("x.VHDX")));
        let _ = std::fs::remove_dir_all(&d);
    }
}
