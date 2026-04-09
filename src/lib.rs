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
mod parse_image_windows;
pub use crate::parse_image_windows::*;
pub mod banner;
pub use crate::banner::*;
pub mod parse_ese;
pub use crate::parse_ese::*;
mod parse_ual;
pub use crate::parse_ual::*;
pub mod vmdk;
pub use crate::vmdk::*;

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

    /// Scan all NTFS volumes on the system for VSS (parse-image-windows only, requires admin)
    #[arg(long)]
    all_volumes: bool,
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
    /// Parse from forensic images (E01/dd/VMDK), mounted volumes (-d D:), or --all-volumes. Extracts EVTX + UAL from live + VSS
    ParseImageWindows,
}

// -----------------------------------------------------------------------------
//   Main library function called from main.rs
// -----------------------------------------------------------------------------
pub async fn run(mut config: Cli) -> Result<(), Box<dyn Error>> {
    // Normalize paths, but preserve bare drive letters (D:, F:\) for parse-image-windows
    config.directory = config.directory.iter().map(|d| {
        let trimmed = d.trim_end_matches(&['\\', '/'][..]);
        if trimmed.len() == 2 && trimmed.as_bytes()[0].is_ascii_alphabetic() && trimmed.as_bytes()[1] == b':' {
            trimmed.to_string() // Preserve "D:" as-is for volume detection
        } else {
            normalize_path(d)
        }
    }).collect();
    config.file = config.file.iter().map(|f| normalize_path(f)).collect();

    validate_folders(&config)?;

    // Enable or disable debug/silent mode
    crate::parse::set_debug_mode(config.debug);
    crate::parse_elastic::set_debug_mode(config.debug);
    crate::banner::set_silent_mode(config.silent);

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
            )
            .await;
        }
        ActionType::LoadMemgraph => {
            let default_user = String::from("");
            load_memgraph(
                &config.file,
                &config.database.as_ref().unwrap(),
                config.user.as_ref().unwrap_or(&default_user),
            )
            .await;
        }
        ActionType::Merge => {
            merge_files(&config.file, config.output.as_ref())?;
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
                config.filter_cortex_ip.as_ref(), // 👈 nuevo parámetro
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
            )
            .await?;
        }

        ActionType::ParseLinux => {
            parse_linux(&config.file, &config.directory, config.output.as_ref());
        }
        ActionType::ParseImageWindows => {
            parse_image_windows(&config.file, &config.directory, config.all_volumes, config.output.as_ref());
        }
    }

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
        ActionType::ParseImageWindows => {
            if config.file.is_empty() && config.directory.is_empty() && !config.all_volumes {
                return Err(String::from(
                    "For parse-image-windows, specify image files with -f, a volume with -d (e.g. -d D:), or --all-volumes.",
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