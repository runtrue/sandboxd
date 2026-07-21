use clap::{Args, Parser, Subcommand};
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
    Serve(Box<ServeArgs>),
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

#[derive(Debug, Args)]
pub(crate) struct ServeArgs {
    #[arg(long, default_value = DEFAULT_SOCKET)]
    pub(crate) socket: PathBuf,
    #[arg(long)]
    pub(crate) workload_socket: Option<PathBuf>,
    #[arg(long)]
    pub(crate) broker_uid: Option<u32>,
    #[arg(long)]
    pub(crate) work_order_key: Option<PathBuf>,
    #[arg(long, default_value_t = 64)]
    pub(crate) maximum_connections: usize,
    #[arg(long, default_value_t = 5)]
    pub(crate) io_timeout_seconds: u64,
    #[arg(long, default_value = "worker-local")]
    pub(crate) worker_id: String,
    #[arg(long)]
    pub(crate) artifact_master_key: Option<PathBuf>,
    #[arg(long)]
    pub(crate) artifact_s3_bucket: Option<String>,
    #[arg(long, default_value = "us-east-1")]
    pub(crate) artifact_s3_region: String,
    #[arg(long)]
    pub(crate) artifact_s3_endpoint: Option<String>,
    #[arg(long, default_value = "runtrue-sandboxd/v1")]
    pub(crate) artifact_s3_prefix: String,
    #[arg(long)]
    pub(crate) artifact_s3_virtual_hosted: bool,
    #[arg(long)]
    pub(crate) artifact_s3_allow_http_for_local_testing: bool,
    #[arg(long)]
    pub(crate) artifact_s3_credentials_file: Option<PathBuf>,
    #[arg(long, default_value = "/var/lib/runtrue-sandboxd/state")]
    pub(crate) state_root: PathBuf,
    #[arg(long, default_value = "/var/lib/runtrue-sandboxd/images")]
    pub(crate) image_store: PathBuf,
    #[arg(long, default_value = "/usr/bin/ctr")]
    pub(crate) ctr: PathBuf,
    #[arg(long, default_value = "/run/containerd/containerd.sock")]
    pub(crate) containerd_address: PathBuf,
    #[arg(long, default_value = "runtrue-sandboxd")]
    pub(crate) containerd_namespace: String,
    #[arg(long, default_value = "overlayfs")]
    pub(crate) snapshotter: String,
    #[arg(long, default_value = "linux/amd64")]
    pub(crate) image_platform: String,
    #[arg(long, default_value = "/usr/local/bin/runsc")]
    pub(crate) runsc: PathBuf,
    #[arg(long, default_value = "/usr/sbin/ip")]
    pub(crate) ip: PathBuf,
}
