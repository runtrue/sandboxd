mod broker;
mod cli;
mod protocol;

use clap::Parser as _;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build Tokio runtime");
    if let Err(error) = runtime.block_on(cli::execute(cli::Cli::parse())) {
        eprintln!("sandbox broker: {error}");
        std::process::exit(1);
    }
}
