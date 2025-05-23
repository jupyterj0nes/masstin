use clap::{Parser, ValueEnum};
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind};
use std::error::Error;
use std::fs::File;
use std::io::Read;
mod parse;
use tokio;
pub use crate::parse::*;
mod load;
pub use crate::load::*;
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

// -----------------------------------------------------------------------------
//   Command-line interface struct
// -----------------------------------------------------------------------------
#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    /// Action to perform (parse, load, merge, parser_elastic, parse_cortex_network, parse_cortex_evtx_forensics)
    #[arg(short, long)]
    action: ActionType,

    /// Directories to process (can be specified multiple times)
    #[arg(short, long)]
    directory: Vec<String>,

    /// Individual event log files (EVTX or JSON) to process (can be specified multiple times)
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
}

// -----------------------------------------------------------------------------
//   List of possible actions
// -----------------------------------------------------------------------------
#[derive(ValueEnum, Clone, Debug, PartialEq)]
enum ActionType {
    /// Parses EVTX files from single files or directories and outputs a CSV
    Parse,
    /// Loads a previously generated CSV file into a Neo4j database
    Load,
    /// Merges multiple CSV files (previously generated) into a single time-sorted file
    Merge,
    /// Parses Winlogbeat JSON logs
    ParserElastic,
    /// Parses Cortex Network data by calling the specified API
    ParseCortex,
    /// Parses Cortex EVTX Forensics data by calling the specified API
    ParseCortexEvtxForensics,
    /// Parses Linux logs and accounting entries  
    ParseLinux,
}

// -----------------------------------------------------------------------------
//   Main library function called from main.rs
// -----------------------------------------------------------------------------
pub async fn run(config: Cli) -> Result<(), Box<dyn Error>> {
    validate_folders(&config)?;

    // Enable or disable debug mode in other modules
    crate::parse::set_debug_mode(config.debug);
    crate::parse_elastic::set_debug_mode(config.debug);

    // Match the selected action and call the corresponding function
    match config.action {
        ActionType::Parse => {
            parse_events(&config.file, &config.directory, config.output.as_ref());
        }
        ActionType::Load => {
            load_neo(
                &config.file,
                &config.database.as_ref().unwrap(),
                &config.user.as_ref().unwrap(),
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
    }

    Ok(())
}

// -----------------------------------------------------------------------------
//   Validates input configuration depending on the chosen action
// -----------------------------------------------------------------------------
fn validate_folders(config: &Cli) -> Result<(), String> {
    // Check the action
    match config.action {
        ActionType::Parse | ActionType::ParserElastic | ActionType::ParseLinux => {
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
                if config.action == ActionType::Parse {
                    // Check if EVTX
                    if !is_evtx_file(file) {
                        return Err(format!(
                            "File {} does not appear to be an EVTX file.",
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
                    if !parent.exists() {
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
        ActionType::Load => {
            // For Load, we need at least one file, plus the database and user
            if config.file.is_empty() || config.database.is_none() || config.user.is_none() {
                return Err(String::from(
                    "For the Load action, you must specify at least one file, a database, and a user.",
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
                    if !parent.exists() {
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
                    if !parent.exists() {
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