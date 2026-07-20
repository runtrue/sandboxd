use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub(crate) const DEFAULT_SOCKET: &str = "/run/runtrue-sandboxd/control.sock";

#[derive(Debug, Parser)]
#[command(name = "runtrue-sandboxd", about = "Runtrue OCI sandbox worker")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Serve {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long, default_value = "/var/lib/runtrue-sandboxd/state")]
        state_root: PathBuf,
        #[arg(long, default_value = "/var/lib/runtrue-sandboxd/images")]
        image_store: PathBuf,
        #[arg(long, default_value = "/usr/local/bin/runsc")]
        runsc: PathBuf,
        #[arg(long, default_value = "/usr/sbin/ip")]
        ip: PathBuf,
    },
    Ping {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
    Stats {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
    Admit {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        lock: PathBuf,
    },
    Run {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        project: String,
        #[arg(long)]
        wait_for: String,
        #[arg(long, default_value_t = 15)]
        timeout_seconds: u64,
    },
    Create {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        sandbox: String,
        #[arg(long, default_value_t = 15)]
        timeout_seconds: u64,
    },
    Restore {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        sandbox: String,
        #[arg(long)]
        snapshot: String,
        #[arg(long, default_value_t = 15)]
        timeout_seconds: u64,
    },
    Inspect {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        sandbox: String,
    },
    Pause {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        sandbox: String,
    },
    Resume {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        sandbox: String,
    },
    Stop {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        sandbox: String,
    },
    Logs {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        sandbox: String,
        #[arg(long)]
        container: String,
    },
    Snapshot {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        sandbox: String,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        stop_after: bool,
    },
    Shutdown {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
}
