use clap::{Parser, ValueEnum};
use std::fs;
use std::io::ErrorKind;
use std::error::Error;
mod parse;
use tokio;
pub use crate::parse::*;
mod load;
pub use crate::load::*;

#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    /// Action to perform (parse or load)
    #[arg(short, long)]
    action: ActionType,

    /// The directory(ies) to use, this arg can be added multiple times
    #[arg(short, long)]
    directory: Vec<String>,

    /// Single evtx files to use, this arg can be added multiple times
    #[arg(short, long)]
    file: Vec<String>,

    /// File where parsed output will be stored
    #[arg(short, long)]
    output: Option<String>,

    /// URL of neo4j databse where CSV file will be uploaded
    #[arg(long)]
    database: Option<String>,

    /// User of neo4j database 
    #[arg(short, long)]
    user: Option<String>,

    /// When specified, if output file exists, it will be overwritten
    #[arg(long)]
    overwrite: bool,

    /// When specified, Output will be displayed in stdout only
    #[arg(long)]
    stdout: bool,
}

#[derive(ValueEnum)]
#[derive(Clone)]
#[derive(Debug)]
enum ActionType {
    /// Parses evtx files located in single files or directories, and generates a CSV file with all lateral movements
    Parse,
    /// Loads a CSV file, previously generated with Masstin, into a Neo4j database
    Load,
}

fn validate_folders(config: &Cli) -> Result<(), String> {
    match config.action {
        ActionType::Parse => {
            if config.directory.is_empty() && config.file.is_empty() {
                return Err(String::from("At least one folder or file is required when action is parse"));
            }

            for file in &config.file {
                if !std::path::Path::new(file).exists() {
                    return Err(format!("File {} does not exist", file));
                }
                if file.split(".").last().unwrap() != "evtx" {
                    return Err(format!("File {} is not an evtx file", file));
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
                    return Err(format!("Output file {} already exists. Use --overwrite to force overwrite", output_path.display()));
                }

                let temp_file = output_path.join("temp_file.txt");
                match fs::File::create(&temp_file) {
                    Ok(_) => {
                        fs::remove_file(&temp_file).unwrap();
                    },
                    Err(e) => {
                        if e.kind() == ErrorKind::PermissionDenied {
                            return Err(format!("Cannot write to output folder {}", output_path.display()));
                        }
                    }
                }
            }
        },    
        ActionType::Load => {
            if config.file.is_empty() || config.database.is_none() || config.user.is_none() {
                return Err(String::from("You need to specify at least one file, database and user argument"));
            }
        },
    }

    Ok(())
}


pub async fn run(config: Cli) -> Result<(), Box<dyn Error>> {
    validate_folders(&config)?;
    //println!("Masstin: Action to perform: {:?}",config.action);
    //println!("Masstin: Folders to process: {:?}",config.directory);
    //println!("Masstin: Single files to process {:?}",config.file);

    match config.action{
        ActionType::Parse => parse_events(&config.file, &config.directory,config.output.as_ref()),
        //ActionType::Load => println!("Masstin: Load functionality not implemented yet"),
        ActionType::Load =>  load_neo(&config.file, &config.database.unwrap(),&config.user.unwrap()).await,
    }
    Ok(())
}