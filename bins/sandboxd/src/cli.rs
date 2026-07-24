use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

pub(crate) const DEFAULT_SOCKET: &str = "/run/runtrue-sandboxd/control.sock";

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum NetworkMode {
    Private,
    Loopback,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum CgroupMode {
    Managed,
    External,
}

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
    /// Fail unless this worker is a clean, unleased scheduling target.
    Ready {
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
    /// Verify and publish a host file for read-only artifact volumes.
    PublishArtifact {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        digest: String,
    },
    /// Remove unreferenced artifact-volume content older than the grace period.
    GarbageCollectArtifacts {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long, default_value_t = 86_400)]
        minimum_age_seconds: u64,
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
    /// Shared socket GID. Avoids CAP_CHOWN when the runtime directory already has this group.
    #[arg(long)]
    pub(crate) broker_gid: Option<u32>,
    #[arg(long)]
    pub(crate) work_order_key: Option<PathBuf>,
    #[arg(long, default_value_t = 64)]
    pub(crate) maximum_connections: usize,
    #[arg(long, default_value_t = 5)]
    pub(crate) io_timeout_seconds: u64,
    #[arg(long, default_value = "worker-local")]
    pub(crate) worker_id: String,
    /// Operator-reviewed aggregate sandbox budget enforced by the worker Pod.
    #[arg(long, default_value = "standard-v1")]
    pub(crate) resource_shape: String,
    #[arg(long, default_value_t = 1_000)]
    pub(crate) sandbox_cpu_millis: u32,
    #[arg(long, default_value_t = 1024 * 1024 * 1024)]
    pub(crate) sandbox_memory_bytes: u64,
    #[arg(long, default_value_t = 256)]
    pub(crate) sandbox_pids: u32,
    #[arg(long, default_value_t = 2 * 1024 * 1024 * 1024)]
    pub(crate) sandbox_ephemeral_storage_bytes: u64,
    #[arg(long, default_value_t = 8)]
    pub(crate) maximum_services: u16,
    /// Enable an additional reviewed guest profile (root-in-sandbox-v1 or oci-compat-v1).
    #[arg(long = "guest-profile")]
    pub(crate) guest_profiles: Vec<String>,
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
    #[arg(long, default_value = "/usr/sbin/mkfs.ext4")]
    pub(crate) mkfs_ext4: PathBuf,
    #[arg(long, default_value = "/usr/sbin/losetup")]
    pub(crate) losetup: PathBuf,
    #[arg(long, default_value = "/run/containerd/containerd.sock")]
    pub(crate) containerd_address: PathBuf,
    #[arg(long, default_value = "runtrue-sandboxd")]
    pub(crate) containerd_namespace: String,
    #[arg(long, default_value = "overlayfs")]
    pub(crate) snapshotter: String,
    #[arg(long, default_value = "linux/amd64")]
    pub(crate) image_platform: String,
    /// Use one pre-installed, image-identity-bound root filesystem instead of containerd.
    #[arg(long, requires = "fixed_topology_lock")]
    pub(crate) fixed_rootfs: Option<PathBuf>,
    /// Lock file whose single image is bound to --fixed-rootfs.
    #[arg(long, requires = "fixed_rootfs")]
    pub(crate) fixed_topology_lock: Option<PathBuf>,
    /// Prevalidated fixed-rootfs digest; all three measurement fields are required together.
    #[arg(
        long,
        requires_all = ["fixed_rootfs", "fixed_rootfs_entries", "fixed_rootfs_bytes"]
    )]
    pub(crate) fixed_rootfs_digest: Option<String>,
    #[arg(
        long,
        requires_all = ["fixed_rootfs", "fixed_rootfs_digest", "fixed_rootfs_bytes"]
    )]
    pub(crate) fixed_rootfs_entries: Option<usize>,
    #[arg(
        long,
        requires_all = ["fixed_rootfs", "fixed_rootfs_digest", "fixed_rootfs_entries"]
    )]
    pub(crate) fixed_rootfs_bytes: Option<u64>,
    /// Guest network implementation.
    #[arg(long, value_enum, default_value_t = NetworkMode::Private)]
    pub(crate) network_mode: NetworkMode,
    /// Resource accounting boundary: direct per-sandbox cgroups or the enclosing workload.
    #[arg(long, value_enum, default_value_t = CgroupMode::Managed)]
    pub(crate) cgroup_mode: CgroupMode,
    #[arg(long, default_value = "/usr/local/bin/runsc")]
    pub(crate) runsc: PathBuf,
    #[arg(long, default_value = "/usr/sbin/ip")]
    pub(crate) ip: PathBuf,
    #[arg(long, default_value = "/usr/sbin/nft")]
    pub(crate) nft: PathBuf,
}
