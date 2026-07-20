mod assignment;
mod audit;
mod authorization;
mod cli;
mod client;
mod command;
mod journal;
mod launcher;
mod protocol;
mod server;
mod service;
mod state;

use clap::Parser as _;
use cli::Cli;

fn main() {
    if launcher::is_launcher_invocation() {
        launcher::execute_or_exit();
        return;
    }
    if let Err(error) = command::execute(Cli::parse()) {
        eprintln!("runtrue-sandboxd: {error}");
        std::process::exit(1);
    }
}
