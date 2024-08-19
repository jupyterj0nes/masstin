
use masstin::Cli;
use clap::Parser;
use std::process;
use tokio;

#[tokio::main]
async fn  main() {
    let cli = Cli::parse();

    if let Err(e) = masstin::run(cli).await {
        eprintln!("Masstin - Error: {}", e);
        process::exit(1);
    }
}