use clap::{Parser, ValueEnum};
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind};
use std::error::Error;
use std::fs::File;
use std::io::Read;
mod parse;
pub mod threads;
pub mod space;
pub mod image_kind;
pub mod vfs;
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
pub mod ingest_record;
pub mod timeline_file;
mod parse_hostcfg;
pub use crate::merge::*;
use serde_json::Value;
mod parse_elastic;
mod csv_out;
pub use crate::parse_elastic::*;
mod cortex_auth;
mod parse_cortex;
mod parse_cortex_eventlog;
mod parse_cortex_artifacts;
pub use crate::parse_cortex::*;
mod parse_cortex_evtx_forensics;
pub use crate::parse_cortex_evtx_forensics::*;
mod parse_linux;
mod parse_mac;
pub use crate::parse_linux::*;
pub use crate::parse_mac::parse_mac;
mod parse_journal;
pub(crate) mod linux_tz;
mod partitions;
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
pub mod raw_split;
pub mod vhd;
pub mod qcow2;
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
    /// Action to perform. `parse` is the one to start with: it reads every kind
    /// of evidence given with -d / -f. The ones marked Advanced are its parts, for
    /// a caller that already knows what the evidence is.
    #[arg(short, long)]
    action: ActionType,

    /// Directories to process — also accepts drive letters (D:) for mounted volumes
    #[arg(short, long)]
    directory: Vec<String>,

    /// Individual files to process (EVTX, JSON, .mdb, E01, VMDK, VHD/VHDX, QCOW2, dd/raw)
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

    /// Overwrite the output file (-o) if it exists. Every action that
    /// writes a timeline asks for it: without it an existing -o is an error,
    /// said before anything is read. -o is never one of the files being
    /// read, unless that file is a masstin timeline being merged into.
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

    /// Cortex API base URL (must start with 'https://api-'). The API key
    /// and its numeric id are asked on the console, or read from
    /// `$CORTEX_API_KEY` and `$CORTEX_API_KEY_ID` when both are set (so a
    /// script, or masstin's window, never puts the key on a command line).
    #[arg(long)]
    cortex_url: Option<String>,

    /// Optional start time, "YYYY-MM-DD HH:MM:SS", in UTC. Also read: a
    /// date alone ("2026-01-05", its first second), "T" between date and
    /// time, no seconds, and a zone at the end ("+0200", "-05:00", "Z"),
    /// which is converted to UTC. For the Cortex actions the range is sent
    /// to Cortex in UTC.
    #[arg(long, value_parser = parse_start_time)]
    start_time: Option<String>,

    /// Optional end time, "YYYY-MM-DD HH:MM:SS", in UTC. Same shapes as
    /// --start-time; a date alone ("2026-10-20") is its last second, so
    /// the whole day is inside.
    #[arg(long, value_parser = parse_end_time)]
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

    /// For `parse-cortex`: which of the tenant's sources to read, a
    /// comma-separated list of `network` (the endpoints' network
    /// connections), `eventlog` (the Windows event logs every agent sends by
    /// itself: logons, logoffs, Kerberos and NTLM, share access) and
    /// `forensics` (the event logs collected by the forensics add-on's
    /// triages and hunts, with the RDP, SMB and WinRM channels). Left out,
    /// or `all`: the three, merged into one timeline; a source the tenant
    /// does not have is said and left out. With no --start-time / --end-time
    /// the network and the agents' event logs cover the last 7 days, the
    /// forensics event logs the last year.
    #[arg(long)]
    cortex_sources: Option<String>,

    /// For `parse-cortex`: minimum time window (in seconds) the auto-pagination
    /// splitter is allowed to produce. When a query saturates the API 1M cap,
    /// the window is bisected until either the count drops below the cap or
    /// the window reaches this floor. Lower = more passes, higher fidelity on
    /// bursty tenants but more API calls. Higher = fewer passes, cheaper but
    /// may truncate during traffic spikes. Default: 300 (5 min).
    #[arg(long, default_value_t = 300)]
    cortex_min_window_secs: i64,

    /// For `parse-cortex`: only check the connection. Asks the tenant whether
    /// --cortex-url, the API key and its ID work, with the one request that
    /// costs no compute units (the XQL quota), says what the tenant answered
    /// (the kind of key, the quota used today, or its refusal in its own
    /// words with what it usually means) and ends: nothing is read and no
    /// timeline is written. Exit code 0 when the tenant accepted, 1 when it
    /// did not. The key comes from $CORTEX_API_KEY / $CORTEX_API_KEY_ID, or
    /// is asked on the console. Example:
    /// masstin -a parse-cortex --cortex-url https://api-TENANT.xdr.eu.paloaltonetworks.com --cortex-check
    #[arg(long, default_value_t = false)]
    cortex_check: bool,

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
    /// "YYYY-MM-DD HH:MM:SS" (UTC); a date alone is read too. A hunt that
    /// cannot be computed (no connection on or after the cutoff, fewer
    /// than two days before it) writes nothing and ends with an error.
    #[arg(long)]
    investigation_from: Option<String>,

    /// For `graph-hunt`: comma-separated list of detector names to skip.
    /// Available: novel-edge, community-bridge, origin-fanout, cred-rotation,
    /// pagerank-spike, betweenness-spike, failed-sweep, preauth-sweep,
    /// probe-then-success, rare-logon-type, causal-path, credential-switch.
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

    /// For `graph-hunt-csv`: what to do with a timeline given with -f that
    /// already carries a hunt (rows with a `hunt` state, or a hunt record
    /// next to it): `overwrite` (the default) writes this hunt over the
    /// one it had, in place; `keep` leaves that timeline as it is (it
    /// still counts in the statistics; nothing is written into it); `new`
    /// writes the timeline with this hunt to a new file next to it,
    /// `<name>.hunt-<YYYY-MM-DD of --investigation-from>.csv`, and the one
    /// given keeps the hunt it had (the line `New timeline: OLD -> NEW`
    /// names it). Whatever the answer, masstin says that the timeline was
    /// hunted before and with what: the start of the investigation, alpha
    /// and the date of that hunt from its record
    /// (kept in `<name>.masstin`, written by every hunt next to the timeline),
    /// or, without a record, the days between which it started, read off
    /// the `baseline` rows. A timeline never hunted is written in place.
    #[arg(long, value_name = "overwrite|keep|new")]
    if_hunted: Option<String>,

    /// For `graph-hunt-csv`: read an address as the host it is, for the
    /// whole hunt, when the timelines themselves say whose it is. A
    /// timeline names an origin by its name when the event gives one and
    /// by its address when it does not, so one machine is often two
    /// origins (`DEV-DC01` and `10.10.0.37`), each with part of its
    /// connections; merged, the hunt profiles one machine, and a login
    /// from a host to its own address is no connection. The level says
    /// which evidence is taken without asking: `strict` (what a machine
    /// says of itself, the addresses of its interfaces in its SYSTEM
    /// hive, or of its domain controller, the one it found and bound to
    /// in Group Policy 5308; both kept in `<name>.masstin` when the
    /// evidence was parsed), `standard` (also the machine's own account, `NAME$`,
    /// authenticated from the address: 4624 network logon, 4768), `broad`
    /// (also the name the client itself gave in the event, and the
    /// same-login test). At every level an address stays as it is when
    /// the evidence disagrees: several names at it (NAT, a proxy, an
    /// address that changed hands) or its host seen at two addresses in
    /// the same period. The timeline's columns are not changed. `masstin
    /// -a host-map -f <timelines>` shows the table and the evidence of
    /// every address first. Without the option nothing is merged this
    /// way (the same-login test folds what it always did).
    #[arg(long, value_name = "strict|standard|broad")]
    merge_hosts: Option<String>,

    /// With `--merge-hosts`: addresses to leave as they are whatever the
    /// evidence says (comma separated).
    #[arg(long, value_name = "ADDRESS,ADDRESS")]
    merge_hosts_skip: Option<String>,

    /// For `merge` / `graph-hunt-csv`: an earlier timeline whose `verdict`
    /// and `notes` are copied onto the rows with the same 14 event columns
    /// (after the evidence was parsed again, for instance).
    #[arg(long)]
    carry_marks: Option<String>,

    /// For `view`: open on the neighbourhood of this host (name or IP,
    /// `*` wildcards) instead of the hunt's findings.
    #[arg(long)]
    focus: Option<String>,

    /// For `view`: open on exactly these rows of the timeline, as a graph
    /// of their own: one edge per row (ungrouped) and only the hosts they
    /// name, whatever the filters would show. Rows are given by their
    /// line in the file, as an editor and the Timeline mode number them
    /// (the header is line 1, the first row 2), comma separated: `--rows
    /// 12,57,301`. With several timelines, `N:LINE` is a line of the N-th
    /// `-f` (`--rows 1:12,2:40`). A row that names no origin other than
    /// its destination has no edge and is said. Back to the view (right
    /// click on the background) leaves the selection. It is how another
    /// program hands a selection of rows to masstin's graph.
    #[arg(long, value_name = "LINE,LINE")]
    rows: Option<String>,

    /// For `view`: open on exactly the events that answer to this, as a
    /// graph of their own: one edge per event (ungrouped) and only the
    /// hosts they name, whatever the filters would show. An event is
    /// named by what it is, not by where it sits in the file:
    /// `TIME,USER,ORIGIN,DESTINATION`, for example `--event "2026-11-03
    /// 11:12:56,alice,WS01,SRV01"`. TIME is UTC, to the second or with
    /// its fraction (`2026-11-03T11:12:56.143498Z` is read too; with a
    /// fraction only the events of that instant answer); ORIGIN and
    /// DESTINATION are a host name or an address, in any case, short or
    /// fully qualified, and an address or a name merged into a host
    /// answers for it; an empty field is not asked about (`,alice,,SRV01`
    /// is every login of alice on SRV01). Repeat the option for several:
    /// the events of any of them are drawn. An event that names no
    /// origin other than its destination has no edge. It is how a case
    /// tool hands a selection of rows to masstin's graph without knowing
    /// the timeline's lines.
    #[arg(long = "event", value_name = "TIME,USER,ORIGIN,DESTINATION")]
    event: Vec<String>,

    /// For `view`: a file with one `--event` per line (lines that are
    /// empty or start with `#` are skipped), for a selection too long for
    /// a command line.
    #[arg(long, value_name = "FILE")]
    events_file: Option<String>,

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

    /// Where the temporary files of a parse go: the logs unpacked from disk
    /// images and packages, the rows sorted on disk. Left out, the system's
    /// temporary folder, or, when its disk has less than 20 GB free and the
    /// disk of the timeline written has twice as much, a `masstin-temp`
    /// folder beside the timeline. Whatever the folder, masstin keeps 5 GB
    /// of its disk free (a quarter of a small disk; `MASSTIN_TEMP_RESERVE_MB`
    /// sets it): a file that would eat into that waits for room, up to
    /// `MASSTIN_SPACE_WAIT_MIN` minutes (30), and is then left out, named at
    /// the end of the run. `MASSTIN_TEMP` does the same as this option.
    #[arg(long, value_name = "DIR")]
    temp: Option<String>,

    /// The memory a parse may use to hold rows while it removes duplicates,
    /// pairs sessions and sorts: `8G`, `4096M`, `50%` (of the machine's), or
    /// a bare number of MiB. Left out, three quarters of the machine's
    /// memory. As long as the rows fit they are worked in memory, the
    /// fastest there is; what does not fit is worked in pieces on disk (the
    /// temporary folder), slower and with the same timeline. Each stage
    /// asks, when it starts, what the machine has free at that moment and
    /// never takes more than half of that, whatever was asked, so the
    /// machine and what else runs on it keep the other half.
    /// More memory: fewer pieces, a faster run. Less: a run that leaves
    /// room for other work. `MASSTIN_MEMORY` does the same.
    #[arg(long, value_name = "SIZE")]
    memory: Option<String>,

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
}

// -----------------------------------------------------------------------------
//   List of possible actions
// -----------------------------------------------------------------------------
#[derive(ValueEnum, Clone, Debug, PartialEq)]
enum ActionType {
    /// The one to use: reads every kind of evidence given with -d (a folder, walked whole) and -f (one file). masstin first says what it found (EVTX, UAL databases, KAPE / Velociraptor / Cortex XDR / UAC triages, disk images, Linux logs and triages, macOS logarchives and `log show` exports, Winlogbeat JSON, masstin timelines), then reads it all in one pass: Windows and Linux evidence, disk images with their shadow copies, archives nested or not; macOS logs and Winlogbeat JSON by their own parsers. Timelines given with -f are merged in. --rules reads the files it does not recognise (VPN, firewall, proxy logs) with custom-parser rules; --carve adds the EVTX records carved from the images, without the ones the live logs already hold. Every part ends in the one timeline.
    #[value(alias = "auto")]
    Parse,
    /// Advanced, a part of `parse` without its look first: Windows EVTX files and UAL databases (.mdb), loose or inside zips
    ParseWindows,
    /// Load a CSV timeline into a Neo4j graph database
    #[value(alias = "load")]
    LoadNeo4j,
    /// Load a CSV timeline into a Memgraph graph database
    LoadMemgraph,
    /// Merge multiple CSV timelines into a single chronological file
    Merge,
    /// Advanced, a part of `parse` without its look first: Windows events exported as JSON (Winlogbeat / Elastic Agent, evtx_dump, Velociraptor, and the flat JSON of NXLog, OTRF Security-Datasets and Microsoft Sentinel). Another shape is read with a rule: parse-custom
    ParserElastic,
    /// Query Cortex XDR API for network connections (RDP/SMB/SSH)
    ParseCortex,
    /// Query Cortex XDR API for forensic EVTX collections
    ParseCortexEvtxForensics,
    /// Advanced, a part of `parse` without its look first: Linux logs and triages: auth.log, secure, messages, audit.log, utmp, wtmp, btmp, lastlog
    ParseLinux,
    /// Advanced, a part of `parse` without its look first: macOS logs, a .logarchive bundle (binary Unified Log) or a `log show` JSON/NDJSON export: SSH and Screen Sharing / ARD remote logons
    #[value(alias = "parse-macos")]
    ParseMac,
    /// Advanced, a part of `parse` without its look first: forensic images (E01/dd/VMDK/VHD/VHDX/QCOW2), mounted volumes (-d D:) or --all-volumes; NTFS gives EVTX + UAL + shadow copies, ext4 / XFS the Linux logs
    #[value(alias = "parse-image-windows", alias = "parse-image-linux")]
    ParseImage,
    /// Advanced, a part of `parse` without its look first: the massive pass on its own: forensic images, triage packages, loose EVTX and Linux logs, archives nested or not (no macOS, no Winlogbeat)
    ParseMassive,
    /// Advanced, a part of `parse` without its look first: EVTX records carved from disk images, the events of deleted or overwritten logs; only the carved ones, without dropping those the live logs hold (`parse --carve` does). --carve-unalloc scans the unallocated space only, faster
    CarveImage,
    /// Advanced, a part of `parse` without its look first: text logs (VPN, firewall, proxy) read with YAML rule files from the rules/ library (`parse --rules` does the same beside the rest). See docs/custom-parsers.md
    ParseCustom,
    /// Merge two :host nodes in a Neo4j graph: transfers all edges from `--old-node` to `--new-node` and deletes the old node. Used to unify a host that appears as both an IP and a hostname after loading. No APOC required.
    MergeNeo4jNodes,
    /// Merge two :host nodes in a Memgraph graph: transfers all edges from `--old-node` to `--new-node` and deletes the old node. Same as `merge-neo4j-nodes` but for Memgraph.
    MergeMemgraphNodes,
    /// Statistical lateral-movement hunt on a graph loaded into Memgraph with --ungrouped. Every signal is a probability measured against the network's own baseline (conformal p-values, Benjamini-Hochberg at --alpha); no MAGE plugin needed. Requires --database and --investigation-from. Options: --report, --seed, --only/--skip-detectors.
    #[value(alias = "graph-hunt")]
    GraphHunt,
    /// Same statistical hunt on a graph loaded into Neo4j with --ungrouped. Edges are read once over bolt and every statistic (PageRank, betweenness, Louvain included) is computed in memory; no GDS plugin needed. Requires --database, --user and --investigation-from; --db selects the database. Password from $NEO4J_PASSWORD or a prompt.
    #[value(alias = "graph-hunt-neo4j")]
    GraphHuntNeo4j,
    /// Same hunt as graph-hunt / graph-hunt-neo4j but straight from masstin timeline CSVs (-f), no graph database: every statistic is computed in memory. Requires --investigation-from.
    #[value(alias = "graph-hunt-csv")]
    GraphHuntCsv,
    /// Whose address is it: the table of the addresses of masstin timelines (-f) and the host each is, with the evidence: `own` (the machine's own network configuration: the SYSTEM hive of a triage, loose or in a zip) and `locator` (the domain controller a machine found and bound to, by name and address: Group Policy 5308), both kept in `<name>.masstin` when the evidence was parsed; `machine-account` (the computer account NAME$ authenticated from the address); `declared` (the name the client gave in the event that has its address); `same-login` (the statistical test). Each address says at which level it is merged without asking (strict, standard, broad: see --merge-hosts), or why it is left to you (several names at it, its host at two addresses in the same period, nothing says whose it is), and how many rows have it as their origin. -o writes the table as CSV. Nothing is changed in the timelines.
    #[value(alias = "hosts")]
    HostMap,
    /// Open the graph viewer (a window) on timeline CSVs (-f): the lateral-movement graph with its hunt states, filters, neighbourhoods, a replay in time order and the analyst's marks, written back into the CSV. Without -f it opens on a welcome, to open a timeline or ingest evidence (drop it on the window). --focus HOST opens on a host's neighbourhood; --start-time / --end-time bound the window.
    View,
}

// -----------------------------------------------------------------------------
//   Main library function called from main.rs
// -----------------------------------------------------------------------------
pub async fn run(mut config: Cli) -> Result<(), Box<dyn Error>> {
    crate::banner::say_faults();
    let ingest_started = chrono::Utc::now();
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
    check_output(&config)?;

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
        Err(e) => return Err(format!("invalid filter argument: {}", e).into()),
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
            let left = crate::threads::reserved();
            let left = if left > 1 { format!("{} cores left to the rest of the machine (MASSTIN_RESERVE_CORES); ", left) } else { String::new() };
            format!("Threads: up to {}, what is idle at each moment ({}; {}--threads fixes it, 1 runs serial)", d.workers, machine, left)
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
            if crate::threads::keeps_normal_priority() {
                "normal (MASSTIN_PRIORITY)"
            } else if crate::threads::background_io() {
                "below normal, disk in the background (MASSTIN_IO_PRIORITY=low: the desktop's disk work comes first)"
            } else {
                "below normal (MASSTIN_PRIORITY=normal keeps it)"
            },
            images
        ));
        crate::banner::print_info(&crate::space::choose(config.temp.as_deref(), config.output.as_deref()));
        match crate::threads::set_memory(config.memory.as_deref()) {
            Ok(line) => crate::banner::print_info(&line),
            Err(e) => {
                // a figure that cannot be read is not guessed: the default, said
                crate::banner::print_warning(&format!("{}; the run takes its default", e));
                std::env::remove_var("MASSTIN_MEMORY");
                if let Ok(line) = crate::threads::set_memory(None) {
                    crate::banner::print_info(&line);
                }
            }
        }
        // what runs killed or cut short left behind
        let freed = crate::space::clean_stale();
        if freed > 0 {
            crate::banner::print_info(&format!("Deleted {} of temporary files left by runs that were stopped", crate::space::human(freed)));
        }
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
        ActionType::ParseCortex if config.cortex_check => {
            crate::parse_cortex::check_connection(config.cortex_url.as_ref().unwrap()).await?;
        }
        ActionType::ParseCortex => {
            let sources = crate::parse_cortex::sources_from(config.cortex_sources.as_deref())?;
            crate::parse_cortex::parse_cortex_sources(
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
                config.cortex_event_ids.as_ref(),
                &sources,
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
                None => return Err("parse-custom requires --rules <path> (file or directory of YAML rule files)".into()),
            };
            if config.file.is_empty() {
                return Err("parse-custom requires at least one -f <logfile>".into());
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
                    rows: config.rows.clone(),
                    events: {
                        let mut ev = config.event.clone();
                        if let Some(f) = &config.events_file {
                            let text = std::fs::read_to_string(f).map_err(|e| format!("--events-file {}: {}", f, e))?;
                            ev.extend(text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_string));
                        }
                        ev
                    },
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
        ActionType::HostMap => {
            crate::banner::print_phase("1", "1", "Addresses and the hosts they are");
            match crate::graph_hunt_common::hostmap::build(&config.file, config.alpha) {
                Ok(table) => {
                    for l in table.summary() {
                        crate::banner::print_phase_detail("", &l);
                    }
                    println!();
                    println!("{:<40} {:<28} {:<9} {:>8}  {}", "ADDRESS", "HOST", "MERGE", "ROWS", "EVIDENCE / WHY NOT");
                    for e in &table.entries {
                        let what = match (e.evidence().as_str(), e.note.as_str()) {
                            ("", n) => n.to_string(),
                            (ev, "") => ev.to_string(),
                            (ev, n) => format!("{} -- {}", ev, n),
                        };
                        println!("{:<40} {:<28} {:<9} {:>8}  {}", e.address, if e.host.is_empty() { "-" } else { e.host.as_str() }, e.level_name(), e.rows, what);
                    }
                    if let Some(out) = config.output.as_deref() {
                        match std::fs::write(out, table.to_csv()) {
                            Ok(()) => crate::banner::print_phase_detail("Table:", out),
                            Err(e) => {
                                eprintln!("Masstin - Error: cannot write {}: {}", out, e);
                                crate::mark_failed();
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Masstin - Error: cannot read the timelines: {}", e);
                    crate::mark_failed();
                }
            }
        }
        ActionType::GraphHuntCsv => {
            let merge_hosts = match config.merge_hosts.as_deref() {
                None => None,
                Some(v) => match crate::graph_hunt_common::hostmap::Level::parse(v) {
                    Some(l) => Some((l, config.merge_hosts_skip.as_deref().unwrap_or("").split(',').map(|s| s.trim().to_uppercase()).filter(|s| !s.is_empty()).collect::<std::collections::HashSet<String>>())),
                    None => {
                        eprintln!("Masstin - Error: --merge-hosts {}: one of strict, standard, broad", v);
                        crate::mark_failed();
                        return Ok(());
                    }
                },
            };
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
                !config.no_annotate,
                config.carry_marks.as_deref(),
                match config.if_hunted.as_deref() {
                    None => Default::default(),
                    Some(v) => match crate::graph_hunt_common::record::IfHunted::parse(v) {
                        Some(x) => x,
                        None => {
                            eprintln!("Masstin - Error: --if-hunted {}: one of overwrite, keep, new", v);
                            crate::mark_failed();
                            return Ok(());
                        }
                    },
                },
                merge_hosts,
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
            )
            .await;
        }
    }

    // Print noise filter summary (no-op if no filter flags were set)
    crate::filter::print_filter_summary();

    if failed() {
        return Err("the run did not complete: see the error above.".into());
    }
    // What the timeline was read from, in its file next to it (`<name>.masstin`):
    // the evidence given, the command, the date. See `ingest_record`.
    if let Some(out) = config.output.as_deref().filter(|o| std::path::Path::new(o).is_file()) {
        let ingests = match config.action {
            ActionType::Parse | ActionType::ParseWindows | ActionType::ParseLinux | ActionType::ParseMac | ActionType::ParseImage | ActionType::ParseMassive | ActionType::CarveImage | ActionType::ParseCustom | ActionType::ParserElastic => {
                use clap::ValueEnum;
                let action = config.action.to_possible_value().map(|v| v.get_name().to_string()).unwrap_or_default();
                let args: Vec<String> = std::env::args().collect();
                ingest_record::of_parse(&action, &config.file, &config.directory, ingest_record::command_line(&args), ingest_started).into_iter().collect()
            }
            ActionType::Merge => ingest_record::of_merge(&config.file),
            _ => Vec::new(),
        };
        // what the evidence said of whose an address is, outside the events
        // of the timeline (see graph_hunt_common::hostmap)
        let mut facts = crate::graph_hunt_common::hostmap::take_noted();
        // a merged timeline keeps the facts of the ones merged
        if config.action == ActionType::Merge {
            for f in &config.file {
                facts.extend(crate::graph_hunt_common::hostmap::read_facts(f));
            }
        }
        if !facts.is_empty() {
            match crate::graph_hunt_common::hostmap::write_facts(out, &facts) {
                Ok(_) => crate::banner::print_phase_detail("Hosts:", &format!("{} address(es) the evidence names the host of (a machine's own network configuration in its SYSTEM hive, the domain controller a member found in Group Policy 5308), kept in the timeline's masstin file for --merge-hosts and host-map", facts.len())),
                Err(e) => eprintln!("Masstin - Warning: cannot write the host facts of {}: {}", out, e),
            }
        }
        if !ingests.is_empty() {
            match ingest_record::write(out, ingests) {
                Ok(p) => crate::banner::print_phase_detail("Ingest record:", &format!("{} (what this timeline was read from, kept in its masstin file)", p.display())),
                Err(e) => eprintln!("Masstin - Warning: cannot write the ingest record next to {}: {}", out, e),
            }
        }
    }
    crate::space::report();
    Ok(())
}

static RUN_FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// An action that reports its own error on the console and returns calls
/// this, so the process still ends with a non-zero code: masstin's window
/// and every script decide by the exit code whether the run worked.
pub(crate) fn mark_failed() {
    RUN_FAILED.store(true, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn failed() -> bool {
    RUN_FAILED.load(std::sync::atomic::Ordering::Relaxed)
}

/// `-o` of an action that writes a timeline, checked before anything is
/// read: it is a file, in a folder that exists; an existing file is
/// replaced only with --overwrite; and it is never one of the files the
/// run reads (the timeline would replace the evidence), unless that file
/// is itself a masstin timeline being merged into.
fn check_output(config: &Cli) -> Result<(), String> {
    let writes = matches!(
        config.action,
        ActionType::Parse
            | ActionType::ParseWindows
            | ActionType::ParserElastic
            | ActionType::ParseLinux
            | ActionType::ParseMac
            | ActionType::ParseImage
            | ActionType::ParseMassive
            | ActionType::CarveImage
            | ActionType::ParseCustom
            | ActionType::Merge
            | ActionType::ParseCortex
            | ActionType::ParseCortexEvtxForensics
    );
    let Some(output) = config.output.as_ref().filter(|_| writes) else { return Ok(()) };
    let op = std::path::Path::new(output);
    if op.is_dir() {
        return Err(format!("-o {} is a folder: give the name of the timeline file to write (for example {}).", op.display(), op.join("timeline.csv").display()));
    }
    if let Some(parent) = op.parent() {
        if parent != std::path::Path::new("") && !parent.exists() {
            return Err(format!("Parent folder of output file {} does not exist.", op.display()));
        }
    }
    if !op.exists() {
        return Ok(());
    }
    let same = |a: &std::path::Path, b: &std::path::Path| match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    };
    for f in &config.file {
        let fp = std::path::Path::new(f);
        if same(op, fp) && !crate::detect::is_timeline(fp) {
            return Err(format!("-o {} is one of the files to read: the timeline would replace the evidence. Give the timeline another name.", op.display()));
        }
    }
    if !config.overwrite {
        return Err(format!("Output file {} already exists. Use --overwrite to overwrite it.", op.display()));
    }
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

/// What a part of `parse` reads, in words: the console of `parse` speaks of
/// the evidence, not of the specific actions underneath.
fn part_name(a: &ActionType) -> &'static str {
    match a {
        ActionType::ParseWindows => "Windows event logs and triages",
        ActionType::ParseLinux => "Linux logs and triages",
        ActionType::ParseMac => "macOS logs",
        ActionType::ParserElastic => "Windows events as JSON",
        ActionType::ParseImage => "disk images",
        ActionType::ParseMassive => "the evidence: images, triages and logs in one pass",
        ActionType::ParseCustom => "the files the rules read",
        ActionType::CarveImage => "carving the disk images",
        ActionType::Merge => "the timelines given",
        _ => "evidence",
    }
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
        crate::banner::print_phase_result("--all-volumes: every NTFS volume of this machine -> read whole, shadow copies included");
        return Ok(vec![ParseStep { action: ActionType::ParseMassive, files: config.file.clone(), dirs: config.directory.clone() }]);
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
        if !s.massive_reads() && s.mac_paths.is_empty() && s.elastic_paths.is_empty() && !s.timelines.is_empty() {
            // a folder of timelines and nothing else: merged
            crate::banner::print_phase_result(&format!("{} masstin timeline(s) -> merged into one timeline (merge)", s.timelines.len()));
            let mut all = s.timelines.clone();
            all.extend(given_tl.drain(..));
            steps.push(ParseStep { action: ActionType::Merge, files: all, dirs: Vec::new() });
        } else {
            let other: std::collections::HashSet<&String> = s.mac_paths.iter().chain(s.elastic_paths.iter()).collect();
            if s.massive_reads() {
                // everything goes through the massive pass, given with -d or with
                // -f alike: Windows and Linux evidence, disk images, archives
                let mf: Vec<String> = files.iter().filter(|f| !other.contains(f)).cloned().collect();
                crate::banner::print_phase_result("Windows and Linux evidence, disk images and archives -> read in one pass");
                steps.push(ParseStep { action: ActionType::ParseMassive, files: mf, dirs: dirs.clone() });
            }
            // what the massive pass does not read, each by its own parser
            if !s.mac_paths.is_empty() {
                let (bundles, exports): (Vec<String>, Vec<String>) = s.mac_paths.iter().cloned().partition(|m| std::path::Path::new(m).is_dir());
                crate::banner::print_phase_result(&format!("{} macOS log source(s) -> read by the macOS parser", s.mac_paths.len()));
                steps.push(ParseStep { action: ActionType::ParseMac, files: exports, dirs: bundles });
            }
            if !s.elastic_paths.is_empty() {
                crate::banner::print_phase_result(&format!("{} Windows-event JSON file(s) -> read by the JSON event parser", s.elastic_paths.len()));
                steps.push(ParseStep { action: ActionType::ParserElastic, files: s.elastic_paths.clone(), dirs: Vec::new() });
            }
            if steps.is_empty() && custom.is_empty() && volumes.is_empty() && given_tl.is_empty() {
                return Err(format!(
                    "Nothing masstin knows how to read in {}: no event logs, triage packages, disk images, Linux or macOS logs, Windows events as JSON or timelines. Text logs (VPN, firewall, proxy) are read with --rules.",
                    rest.join(", ")
                ));
            }
            if !s.timelines.is_empty() {
                crate::banner::print_info(&format!(
                    "{} masstin timeline(s) inside the folders left out (an earlier run's, another case's): give one with -f to merge it in",
                    s.timelines.len()
                ));
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
        crate::banner::print_phase_result(&format!("Mounted volume(s) {} -> read whole: the live files and the shadow copies", volumes.join(", ")));
        match steps.iter_mut().find(|st| st.action == ActionType::ParseMassive) {
            Some(st) => st.dirs.extend(volumes),
            None => steps.push(ParseStep { action: ActionType::ParseMassive, files: Vec::new(), dirs: volumes }),
        }
    }
    if !custom.is_empty() {
        crate::banner::print_phase_result(&format!(
            "{} file(s) masstin does not recognise -> read with the rules in {}",
            custom.len(),
            config.rules.as_deref().unwrap_or("")
        ));
        steps.push(ParseStep { action: ActionType::ParseCustom, files: custom, dirs: Vec::new() });
    }
    if config.carve {
        if images.is_empty() {
            crate::banner::print_warning("--carve: no disk image among the evidence, nothing to carve");
        } else {
            crate::banner::print_phase_result(&format!("--carve: {} disk image(s) -> carved for the EVTX records of deleted or overwritten logs", images.len()));
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

/// Rewrites the carved timeline without the events the live timelines hold:
/// the same 13 event columns (time, hosts, event, logon, accounts, logon id,
/// detail), whatever the `log_filename`. Returns (carved events, dropped).
fn drop_carved_duplicates(carved: &str, live: &[String]) -> Result<(usize, usize), Box<dyn Error>> {
    let key = |r: &csv::StringRecord| -> Vec<String> { r.iter().take(13).map(|s| s.to_string()).collect() };
    let mut seen: std::collections::HashSet<Vec<String>> = std::collections::HashSet::new();
    for p in live {
        let mut rdr = csv::ReaderBuilder::new().has_headers(true).flexible(true).from_path(p)?;
        for r in rdr.records() {
            seen.insert(key(&r?));
        }
    }
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).flexible(true).from_path(carved)?;
    let header = rdr.headers()?.clone();
    let mut kept = Vec::new();
    let (mut total, mut dup) = (0usize, 0usize);
    for r in rdr.records() {
        let r = r?;
        total += 1;
        if seen.contains(&key(&r)) {
            dup += 1;
        } else {
            kept.push(r);
        }
    }
    drop(rdr);
    let mut w = csv::WriterBuilder::new().from_path(carved)?;
    w.write_record(&header)?;
    for r in &kept {
        w.write_record(r)?;
    }
    w.flush()?;
    Ok((total, dup))
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
    let tmp = crate::space::temp_root().join(format!("masstin_parse_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp)?;
    let mut parts: Vec<String> = Vec::new();
    let total = steps.len();
    // the parts write to the temporary folder: their summaries name no output
    // and suggest no graph load; the merged timeline gets both at the end
    crate::banner::set_parse_part(true);
    for (i, st) in steps.iter().enumerate() {
        crate::banner::print_info(&format!("Part {} of {}: {}", i + 1, total, part_name(&st.action)));
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
    // the carved part: an event the live logs already hold comes back from the
    // carved chunks with another log_filename, so the merge would keep both
    let carved = steps
        .iter()
        .enumerate()
        .find(|(_, st)| st.action == ActionType::CarveImage)
        .map(|(i, _)| tmp.join(format!("part-{}.csv", i + 1)).to_string_lossy().to_string())
        .filter(|p| parts.contains(p));
    if let Some(c) = carved {
        let live: Vec<String> = parts.iter().filter(|p| **p != c).cloned().collect();
        match drop_carved_duplicates(&c, &live) {
            Ok((total, dup)) => crate::banner::print_phase_result(&format!(
                "Carving: {} event(s), {} already in the live logs, {} recovered",
                total,
                dup,
                total - dup
            )),
            Err(e) => crate::banner::print_warning(&format!("Carving: the carved events could not be compared with the live ones ({}); all are kept", e)),
        }
    }
    crate::banner::set_parse_part(false);
    if parts.is_empty() {
        let _ = fs::remove_dir_all(&tmp);
        return Err("No events from any part: nothing to write.".into());
    }
    crate::banner::print_info(&format!("Merging the {} part(s) into one timeline", parts.len()));
    // the parts were filtered as they were parsed
    crate::filter::pause_filter(true);
    let r = merge_files(&parts, config.output.as_ref(), None, None, None);
    crate::filter::pause_filter(false);
    let _ = fs::remove_dir_all(&tmp);
    if r.is_ok() {
        if let Some(out) = config.output.as_ref() {
            let rows = csv::Reader::from_path(out).map(|mut r| r.records().count()).unwrap_or(0);
            crate::banner::print_phase_result(&format!("Timeline: {} ({} events)", crate::banner::normalize_display_path(out), rows));
            // the count of the whole run, after every part is in
            crate::banner::print_timeline_total(out);
            crate::banner::print_load_hint(out);
        }
    }
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
                            "File {} holds no Windows events as JSON in a shape masstin reads (Winlogbeat, evtx_dump, Velociraptor, or flat as NXLog and Sentinel write it). For another shape, write a rule: parse-custom.",
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

                // the rest (a folder, an existing file, the evidence itself)
                // is check_output's, for every action that writes a timeline
                let _ = output_path;
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
                    "For carve-image, specify forensic image files with -f (E01/VMDK/VHD/VHDX/QCOW2/dd).",
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
            // Two timelines to merge; one is enough when the merge is asked
            // to change it (a noise filter, or marks carried from an earlier one)
            let changes_one = config.ignore_local || config.exclude_users.is_some() || config.exclude_hosts.is_some() || config.exclude_ips.is_some() || config.carry_marks.is_some();
            if config.file.is_empty() || (config.file.len() < 2 && !changes_one) {
                return Err(String::from("You must specify at least two files to merge (one is enough with --ignore-local, --exclude-* or --carry-marks)."));
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
        ActionType::HostMap => {
            if config.file.is_empty() {
                return Err(String::from("For host-map you must specify at least one timeline CSV with -f."));
            }
        }
        ActionType::GraphHuntCsv => {
            if config.file.is_empty() {
                return Err(String::from(
                    "For graph-hunt-csv you must specify at least one timeline CSV with -f.",
                ));
            }
            if config.merge_hosts_skip.is_some() && config.merge_hosts.is_none() {
                return Err(String::from("--merge-hosts-skip names addresses to leave out of --merge-hosts: give --merge-hosts strict|standard|broad too."));
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
    if path.extension().map_or(false, |ext| ext.eq_ignore_ascii_case("evtx")) {
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
    crate::parse_elastic::holds_windows_events(file_path)
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
    // (a path that exists is what it says, whatever it contains: a folder
    // can be called `logs -o old`)
    let swallowed_flags = p.contains("\" -") || p.contains("\" --") || ((p.contains(" -o ") || p.contains(" --overwrite")) && !std::path::Path::new(&p).exists());
    if swallowed_flags {
        return Err(format!(
            "Path corrupted by shell quoting: '{}...'\n\
             This happens when a path ends with \\ inside single quotes in PowerShell.\n\
             Fix: remove the trailing \\ or use double quotes.\n\
             Example: -d \"C:\\evidence\\image.vmdk\"",
            p.chars().take(80).collect::<String>()
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
/// `--start-time` / `--end-time` as every action receives them: UTC,
/// written "YYYY-MM-DD HH:MM:SS -0000" (see `timefmt::time_bound` for
/// what is read).
fn parse_time_option(raw: &str, end_of_day: bool) -> Result<String, String> {
    match crate::timefmt::time_bound(raw, end_of_day) {
        Some(t) => Ok(format!("{} -0000", t.format("%Y-%m-%d %H:%M:%S"))),
        None => Err("write the time as \"YYYY-MM-DD HH:MM:SS\" (UTC); a date alone, and a zone at the end (+0200, -05:00, Z), are read too".to_string()),
    }
}

fn parse_start_time(raw: &str) -> Result<String, String> {
    parse_time_option(raw, false)
}

fn parse_end_time(raw: &str) -> Result<String, String> {
    parse_time_option(raw, true)
}

#[cfg(test)]
mod time_option_tests {
    use super::*;

    #[test]
    fn short_values_and_zones_are_read_not_a_panic() {
        assert_eq!(parse_start_time("2026-01-05").unwrap(), "2026-01-05 00:00:00 -0000");
        assert_eq!(parse_end_time("2026-10-20").unwrap(), "2026-10-20 23:59:59 -0000");
        assert_eq!(parse_start_time("2026-01-05 10:00:00").unwrap(), "2026-01-05 10:00:00 -0000");
        assert_eq!(parse_start_time("2026-01-05 10:00:00 -0000").unwrap(), "2026-01-05 10:00:00 -0000");
        assert_eq!(parse_start_time("2026-01-05 10:00:00 +0200").unwrap(), "2026-01-05 08:00:00 -0000");
        assert!(parse_start_time("x").is_err());
        assert!(parse_end_time("2026").is_err());
    }

    #[test]
    fn a_path_is_cleaned_without_cutting_a_character() {
        let long = format!("{}é\" -o out.csv", "a".repeat(79));
        assert!(clean_path(&long).unwrap_err().contains("corrupted"));
        // flags inside a path that does not exist: the shell swallowed them
        assert!(clean_path("Z:\\no\\such -o out.csv").is_err());
        // the same text in a path that exists is the path
        let d = std::env::temp_dir().join(format!("masstin logs -o old {}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(clean_path(&d.to_string_lossy()).unwrap(), d.to_string_lossy());
        let _ = std::fs::remove_dir_all(&d);
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
    fn a_folder_of_evtx_goes_through_the_massive_pass() {
        let d = tmp("evtx");
        std::fs::write(d.join("Security.evtx"), b"ElfFile").unwrap();
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-d", d.to_str().unwrap()])).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action, ActionType::ParseMassive);
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
        assert_eq!(steps[0].action, ActionType::ParseMassive);
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
        assert_eq!(acts, vec![ActionType::ParseMassive, ActionType::ParseCustom]);
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
        assert!(e.contains("Nothing masstin knows how to read") && e.contains("--rules"), "{}", e);
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
        assert_eq!(steps[0].action, ActionType::ParseMassive);
        // given with -f it joins, and is never handed to the parser
        let other = tmp("tl_given");
        let t = other.join("other.csv");
        std::fs::write(&t, format!("{}\n", crate::csv_out::HEADER)).unwrap();
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-d", d.to_str().unwrap(), "-f", t.to_str().unwrap()])).unwrap();
        let acts: Vec<ActionType> = steps.iter().map(|s| s.action.clone()).collect();
        assert_eq!(acts, vec![ActionType::ParseMassive, ActionType::Merge]);
        assert!(steps[0].files.is_empty(), "the timeline is not a parser's input");
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn a_carved_event_the_live_logs_hold_is_dropped() {
        let d = tmp("carve_dups");
        let h = crate::csv_out::HEADER;
        let row = |t: &str, src: &str| format!("{},SRV01,SUCCESSFUL_LOGON,4624,3,alice,CORP,WS01,10.0.0.5,-,-,0x1,,{},,,,,", t, src);
        let live = d.join("live.csv");
        std::fs::write(&live, format!("{}\n{}\n", h, row("2026-11-10T01:00:00.000000Z", "srv.vmdk:live:Security.evtx"))).unwrap();
        let carved = d.join("carved.csv");
        std::fs::write(
            &carved,
            format!("{}\n{}\n{}\n", h, row("2026-11-10T01:00:00.000000Z", "srv.vmdk:carved:Security.evtx"), row("2026-11-09T23:00:00.000000Z", "srv.vmdk:carved:Security.evtx")),
        )
        .unwrap();
        let (total, dup) = drop_carved_duplicates(carved.to_str().unwrap(), &[live.to_string_lossy().to_string()]).unwrap();
        assert_eq!((total, dup), (2, 1));
        let left = std::fs::read_to_string(&carved).unwrap();
        assert!(left.contains("2026-11-09T23:00:00") && !left.contains("2026-11-10T01:00:00"), "{}", left);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn macos_and_winlogbeat_are_read_beside_the_massive_pass() {
        let d = tmp("mac_wl");
        std::fs::write(d.join("Security.evtx"), b"ElfFile").unwrap();
        let mac = d.join("logshow.ndjson");
        std::fs::write(&mac, "{\"timestamp\":\"2026-03-15 09:12:30.250000+0200\",\"processImagePath\":\"/usr/sbin/sshd\",\"eventMessage\":\"Accepted publickey for alice\"}
").unwrap();
        let wl = d.join("winlogbeat.json");
        std::fs::write(&wl, "{\"@timestamp\":\"2026-01-01T00:00:00Z\",\"winlog\":{\"channel\":\"Security\",\"event_id\":4624}}
").unwrap();
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-d", d.to_str().unwrap()])).unwrap();
        let acts: Vec<ActionType> = steps.iter().map(|s| s.action.clone()).collect();
        assert_eq!(acts, vec![ActionType::ParseMassive, ActionType::ParseMac, ActionType::ParserElastic]);
        assert_eq!(steps[1].files, vec![mac.to_string_lossy().to_string()]);
        assert_eq!(steps[2].files, vec![wl.to_string_lossy().to_string()]);
        // given alone with -f: only their own parsers, no massive pass
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-f", mac.to_str().unwrap(), "-f", wl.to_str().unwrap()])).unwrap();
        let acts: Vec<ActionType> = steps.iter().map(|s| s.action.clone()).collect();
        assert_eq!(acts, vec![ActionType::ParseMac, ActionType::ParserElastic]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_vhd_is_a_disk_image() {
        let d = tmp("vhd");
        let v = d.join("disk.vhd");
        std::fs::write(&v, b"conectix").unwrap();
        let steps = resolve_parse(&cli(&["masstin", "-a", "parse", "-f", v.to_str().unwrap()])).unwrap();
        assert_eq!(steps[0].action, ActionType::ParseMassive);
        assert!(crate::parse_image_windows::is_first_image_segment(std::path::Path::new("x.VHDX")));
        let _ = std::fs::remove_dir_all(&d);
    }
}
