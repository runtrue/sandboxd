mod cache;
mod cli;
mod command;
mod launcher;
mod publication;

use clap::Parser as _;

fn main() {
    if launcher::is_launcher_invocation() {
        launcher::run_or_exit();
        return;
    }
    if let Err(error) = command::execute(cli::Cli::parse()) {
        eprintln!("runtrue-sandboxctl: {error}");
        std::process::exit(1);
    }
}
