mod cli;
mod config;
mod controller;

use clap::Parser as _;

#[tokio::main]
async fn main() {
    if let Err(error) = cli::execute(cli::Cli::parse()).await {
        eprintln!("sandbox autoscaler: {error}");
        std::process::exit(1);
    }
}
