use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "runtrue-sandboxctl",
    about = "Build and execute restricted OCI sandbox topologies"
)]
pub(crate) struct Cli {
    #[arg(long, global = true, default_value = "/usr/bin/docker")]
    pub(crate) docker: PathBuf,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Compile restricted Compose and local image digests into an immutable lock.
    Lock {
        #[arg(long)]
        compose: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare one local image as a verified rootfs for runsc execution.
    PrepareImage {
        #[arg(long)]
        reference: String,
        #[arg(long, default_value = "/var/lib/runtrue-sandboxd/images")]
        image_store: PathBuf,
        #[arg(long, default_value = "/usr/bin/tar")]
        tar: PathBuf,
    },
    /// Run a locked topology through the embedded gVisor executor.
    Run {
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        project: String,
        #[arg(long)]
        wait_for: String,
        #[arg(long, default_value_t = 15)]
        timeout_seconds: u64,
        #[arg(long, default_value = "/tmp/runtrue-sandboxctl")]
        state_root: PathBuf,
        #[arg(long, default_value = "/var/lib/runtrue-sandboxd/images")]
        image_store: PathBuf,
        #[arg(long, default_value = "/usr/local/bin/runsc")]
        runsc: PathBuf,
        #[arg(long, default_value = "/usr/sbin/ip")]
        ip: PathBuf,
    },
}
