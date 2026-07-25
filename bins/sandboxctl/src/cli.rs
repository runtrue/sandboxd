use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "runtrue-sandboxctl",
    about = "Build and execute restricted OCI sandbox topologies"
)]
pub(crate) struct Cli {
    #[arg(long, global = true, default_value = "/usr/bin/ctr")]
    pub(crate) ctr: PathBuf,
    #[arg(long, global = true, default_value = "/run/containerd/containerd.sock")]
    pub(crate) containerd_address: PathBuf,
    #[arg(long, global = true, default_value = "runtrue-sandboxd")]
    pub(crate) containerd_namespace: String,
    #[arg(long, global = true, default_value = "overlayfs")]
    pub(crate) snapshotter: String,
    #[arg(long, global = true, default_value = "linux/amd64")]
    pub(crate) image_platform: String,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Generate an Ed25519 image-attestation keypair without exposing the private seed.
    GenerateImageAttestationKey {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Resolve OCI descriptors and compile restricted Compose into an immutable lock.
    Lock {
        #[arg(long)]
        compose: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "/var/lib/runtrue-sandboxd/images")]
        image_store: PathBuf,
    },
    /// Pull and mount one pinned image through containerd.
    PrepareImage {
        #[arg(long)]
        reference: String,
        #[arg(long, default_value = "/var/lib/runtrue-sandboxd/images")]
        image_store: PathBuf,
    },
    /// Prepare, measure, sign, and atomically publish one immutable root artifact.
    PublishAttestedRoot {
        #[arg(long)]
        reference: String,
        #[arg(long, default_value = "/var/lib/runtrue-sandboxd/images")]
        image_store: PathBuf,
        #[arg(long)]
        cache: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        preparation_policy: String,
        #[arg(long)]
        toolchain_digest: String,
        #[arg(long)]
        sbom: PathBuf,
        #[arg(long)]
        provenance: PathBuf,
        #[arg(long)]
        vulnerability_policy: String,
        #[arg(long)]
        registry_credential: Option<PathBuf>,
        /// Hard limit on immutable artifact directories in the cache.
        #[arg(long, default_value_t = 1024)]
        maximum_cache_artifacts: usize,
        /// Hard limit on logical root and evidence bytes in the cache.
        #[arg(long, default_value_t = 68_719_476_736_u64)]
        maximum_cache_bytes: u64,
    },
    /// Verify every retained root and report cache, revocation, and pool impact.
    AuditAttestedCache {
        #[arg(long)]
        cache: PathBuf,
        #[arg(long)]
        trust_policy: PathBuf,
        #[arg(long)]
        prepared_root_catalog: PathBuf,
        #[arg(long)]
        worker_pool_catalog: PathBuf,
        #[arg(long, default_value_t = 1024)]
        maximum_cache_artifacts: usize,
        #[arg(long, default_value_t = 68_719_476_736_u64)]
        maximum_cache_bytes: u64,
        /// Return nonzero after emitting JSON when a reviewed root is unhealthy.
        #[arg(long)]
        require_healthy: bool,
    },
    /// Plan or execute deletion of old roots not referenced by any reviewed cohort.
    GarbageCollectAttestedCache {
        #[arg(long)]
        cache: PathBuf,
        #[arg(long)]
        prepared_root_catalog: PathBuf,
        #[arg(long, default_value_t = 1024)]
        maximum_cache_artifacts: usize,
        #[arg(long, default_value_t = 68_719_476_736_u64)]
        maximum_cache_bytes: u64,
        #[arg(long, default_value_t = 86_400)]
        minimum_age_seconds: u64,
        /// Execute the reported plan. Omit for a read-only dry run.
        #[arg(long)]
        delete: bool,
    },
    /// Diagnostic-only Docker export; not accepted by the production runtime.
    PrepareDockerImage {
        #[arg(long, default_value = "/usr/bin/docker")]
        docker: PathBuf,
        #[arg(long)]
        reference: String,
        #[arg(long, default_value = "/var/lib/runtrue-sandboxd/docker-diagnostic")]
        image_store: PathBuf,
        #[arg(long, default_value = "/usr/bin/tar")]
        tar: PathBuf,
    },
    /// Sign a canonical image-preparation attestation with an owner-only Ed25519 key.
    SignImageAttestation {
        #[arg(long)]
        attestation: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a signed image-preparation attestation.
    VerifyImageAttestation {
        #[arg(long)]
        attestation: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
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
        #[arg(long, default_value = "/usr/sbin/nft")]
        nft: PathBuf,
    },
}
