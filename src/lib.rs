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

/// **Command-line interface struct**
#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    /// Action to perform (parse, load, merge, or parser_elastic)
    #[arg(short, long)]
    action: ActionType,

    /// Directories to use (can be specified multiple times)
    #[arg(short, long)]
    directory: Vec<String>,

    /// Single event log files (EVTX or Winlogbeat JSON) to process (can be specified multiple times)
    #[arg(short, long)]
    file: Vec<String>,

    /// File where parsed output will be stored
    #[arg(short, long)]
    output: Option<String>,

    /// URL of the Neo4j or Elasticsearch database
    #[arg(long)]
    database: Option<String>,

    /// Database user
    #[arg(short, long)]
    user: Option<String>,

    /// If specified, overwrite output file if it exists
    #[arg(long)]
    overwrite: bool,

    /// If specified, print output only to stdout
    #[arg(long)]
    stdout: bool,

    /// If specified, print debug information
    #[arg(long)]
    debug: bool,
}

/// **List of possible actions**  
#[derive(ValueEnum, Clone, Debug, PartialEq)]
enum ActionType {
    /// Parses EVTX files from single files or directories and outputs a CSV with lateral movements
    Parse,
    /// Loads a previously generated CSV file into a Neo4j database
    Load,
    /// Merges multiple CSV files (previously generated) into a single, time-sorted file
    Merge,
    /// Parses Winlogbeat JSON logs and processes them (e.g., for Elasticsearch)
    ParserElastic,
}

/// **Checks whether the files and directories match the expected format for the chosen action**
fn validate_folders(config: &Cli) -> Result<(), String> {
    match config.action {
        ActionType::Parse | ActionType::ParserElastic => {
            if config.directory.is_empty() && config.file.is_empty() {
                return Err(String::from("At least one directory or file is required for this action"));
            }

            for file in &config.file {
                if !std::path::Path::new(file).exists() {
                    return Err(format!("File {} does not exist", file));
                }

                if config.action == ActionType::Parse {
                    // Validate EVTX files
                    if !is_evtx_file(file) {
                        return Err(format!("File {} does not appear to be an EVTX file", file));
                    }
                } else if config.action == ActionType::ParserElastic {
                    // Validate Winlogbeat JSON files
                    if !is_winlogbeat_file(file) {
                        return Err(format!("File {} does not appear to be a valid Winlogbeat JSON file", file));
                    }
                }
            }

            for folder in &config.directory {
                let path = std::path::Path::new(folder);
                if !path.exists() {
                    return Err(format!("Directory {} does not exist", folder));
                }
                if !path.is_dir() {
                    return Err(format!("{} is not a directory", folder));
                }
            }

            if let Some(output) = config.output.as_ref() {
                let output_path = std::path::Path::new(output);

                if !output_path.parent().unwrap().exists() {
                    return Err(format!("Parent folder of output file {} does not exist", output_path.display()));
                }
                if output_path.exists() && !config.overwrite {
                    return Err(format!(
                        "Output file {} already exists. Use --overwrite to overwrite it",
                        output_path.display()
                    ));
                }

                let temp_file = output_path.join("temp_file.txt");
                match fs::File::create(&temp_file) {
                    Ok(_) => {
                        fs::remove_file(&temp_file).unwrap();
                    }
                    Err(e) => {
                        if e.kind() == ErrorKind::PermissionDenied {
                            return Err(format!("Cannot write to output folder {}", output_path.display()));
                        }
                    }
                }
            }
        }
        ActionType::Load => {
            if config.file.is_empty() || config.database.is_none() || config.user.is_none() {
                return Err(String::from(
                    "For the Load action, you must specify at least one file, a database, and a user",
                ));
            }
        }
        ActionType::Merge => {
            if config.file.len() < 2 {
                return Err(String::from("You must specify at least two files to merge"));
            }
        }
    }

    Ok(())
}

/// **Checks if a file is an EVTX file**
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

/// **Checks if a file is a valid Winlogbeat JSON file**
fn is_winlogbeat_file(file_path: &str) -> bool {
    let file = File::open(file_path);
    if file.is_err() {
        return false;
    }

    let reader = BufReader::new(file.unwrap());

    for line in reader.lines().flatten() {
        // Try to parse each line as JSON
        if let Ok(json) = serde_json::from_str::<Value>(&line) {
            // Check if it has the keys we expect in Winlogbeat
            if json.get("agent")
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

/// **Main function called from `main.rs`**
pub async fn run(config: Cli) -> Result<(), Box<dyn Error>> {
    validate_folders(&config)?;

    // Set debug mode in parse.rs
    crate::parse::set_debug_mode(config.debug);
    crate::parse_elastic::set_debug_mode(config.debug);

    match config.action {
        ActionType::Parse => {
            parse_events(&config.file, &config.directory, config.output.as_ref());
        }
        ActionType::Load => {
            load_neo(&config.file, &config.database.as_ref().unwrap(), &config.user.as_ref().unwrap()).await;
        }
        ActionType::Merge => {
            merge_files(&config.file, config.output.as_ref())?;
        }
        ActionType::ParserElastic => {
            parse_events_elastic(&config.file, &config.directory, config.output.as_ref());
        }
    }

    Ok(())
}