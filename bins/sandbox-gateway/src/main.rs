mod api;
mod auth;
mod cli;
mod config;

use clap::Parser as _;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build Tokio runtime");
    if let Err(error) = runtime.block_on(cli::execute(cli::Cli::parse())) {
        eprintln!("sandbox gateway: {error}");
        std::process::exit(1);
    }
}
