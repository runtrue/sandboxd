use runtrue_sandbox_core::{GuestProfile, WorkerId, WorkerResourceShape, STRICT_GUEST_PROFILE};
use runtrue_sandbox_gvisor::executor::ExecutorConfiguration;
use runtrue_sandbox_oci::provider::FixedRootfsConfig;
use runtrue_sandbox_oci::SandboxError;
use std::{path::PathBuf, time::Duration};

pub(crate) struct ServerConfig {
    pub(crate) operator_socket: PathBuf,
    pub(crate) workload_socket: Option<PathBuf>,
    pub(crate) broker_uid: Option<u32>,
    pub(crate) work_order_key: Option<PathBuf>,
    pub(crate) worker_id: WorkerId,
    pub(crate) resource_shape: WorkerResourceShape,
    pub(crate) guest_profiles: Vec<GuestProfile>,
    pub(crate) artifact_master_key: Option<PathBuf>,
    pub(crate) artifact_s3_bucket: Option<String>,
    pub(crate) artifact_s3_region: String,
    pub(crate) artifact_s3_endpoint: Option<String>,
    pub(crate) artifact_s3_prefix: String,
    pub(crate) artifact_s3_virtual_hosted: bool,
    pub(crate) artifact_s3_allow_http_for_local_testing: bool,
    pub(crate) artifact_s3_credentials_file: Option<PathBuf>,
    pub(crate) state_root: PathBuf,
    pub(crate) image_store: PathBuf,
    pub(crate) ctr: PathBuf,
    pub(crate) mkfs_ext4: PathBuf,
    pub(crate) losetup: PathBuf,
    pub(crate) containerd_address: PathBuf,
    pub(crate) containerd_namespace: String,
    pub(crate) snapshotter: String,
    pub(crate) image_platform: String,
    pub(crate) fixed_rootfs: Option<FixedRootfsConfig>,
    pub(crate) executor: ExecutorConfiguration,
    pub(crate) runsc: PathBuf,
    pub(crate) ip: PathBuf,
    pub(crate) nft: PathBuf,
    pub(crate) maximum_connections: usize,
    pub(crate) io_timeout: Duration,
}

impl ServerConfig {
    pub(crate) fn validate(&self) -> Result<(), SandboxError> {
        let workload_values = [
            self.workload_socket.is_some(),
            self.broker_uid.is_some(),
            self.work_order_key.is_some(),
        ];
        if workload_values.iter().any(|value| *value) && !workload_values.iter().all(|value| *value)
        {
            return Err(SandboxError::Runtime(
                "workload socket, broker UID, and work-order key must be configured together"
                    .to_owned(),
            ));
        }
        if self.broker_uid == Some(0) {
            return Err(SandboxError::Runtime(
                "workload broker UID must be a non-root identity".to_owned(),
            ));
        }
        if self.workload_socket.as_ref() == Some(&self.operator_socket) {
            return Err(SandboxError::Runtime(
                "operator and workload sockets must be different".to_owned(),
            ));
        }
        if self.maximum_connections == 0 || self.maximum_connections > 4_096 {
            return Err(SandboxError::Runtime(
                "maximum connections must be between 1 and 4096".to_owned(),
            ));
        }
        if self.io_timeout.is_zero() || self.io_timeout > Duration::from_secs(60) {
            return Err(SandboxError::Runtime(
                "I/O timeout must be between 1 and 60 seconds".to_owned(),
            ));
        }
        if self.artifact_s3_bucket.is_some() && self.artifact_master_key.is_none() {
            return Err(SandboxError::Runtime(
                "S3 artifact storage requires an explicit shared artifact master key".to_owned(),
            ));
        }
        if self.artifact_s3_bucket.is_none()
            && (self.artifact_s3_endpoint.is_some()
                || self.artifact_s3_virtual_hosted
                || self.artifact_s3_allow_http_for_local_testing
                || self.artifact_s3_credentials_file.is_some())
        {
            return Err(SandboxError::Runtime(
                "S3 artifact options require --artifact-s3-bucket".to_owned(),
            ));
        }
        if self.guest_profiles.is_empty()
            || self.guest_profiles[0].identity.canonical() != STRICT_GUEST_PROFILE
            || self
                .guest_profiles
                .iter()
                .enumerate()
                .any(|(index, profile)| {
                    GuestProfile::reviewed(&profile.identity).as_ref() != Some(profile)
                        || self.guest_profiles[..index]
                            .iter()
                            .any(|prior| prior.identity == profile.identity)
                })
        {
            return Err(SandboxError::Runtime(
                "installed guest profiles must be unique reviewed definitions with strict-v1 first"
                    .to_owned(),
            ));
        }
        self.resource_shape
            .validate()
            .map_err(|error| SandboxError::Runtime(error.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_sandbox_core::WORKER_RESOURCE_SHAPE_VERSION;

    fn config() -> ServerConfig {
        ServerConfig {
            operator_socket: PathBuf::from("/run/sandboxd/operator.sock"),
            workload_socket: Some(PathBuf::from("/run/sandboxd/workload.sock")),
            broker_uid: Some(991),
            work_order_key: Some(PathBuf::from("/etc/sandboxd/work-order.key")),
            worker_id: WorkerId::parse("worker-a").expect("worker ID"),
            resource_shape: WorkerResourceShape {
                schema_version: WORKER_RESOURCE_SHAPE_VERSION,
                name: "standard-v1".to_owned(),
                sandbox_cpu_millis: 1_000,
                sandbox_memory_bytes: 1024 * 1024 * 1024,
                sandbox_pids: 256,
                sandbox_ephemeral_storage_bytes: 2 * 1024 * 1024 * 1024,
                maximum_services: 8,
            },
            guest_profiles: vec![GuestProfile::strict()],
            artifact_master_key: None,
            artifact_s3_bucket: None,
            artifact_s3_region: "us-east-1".to_owned(),
            artifact_s3_endpoint: None,
            artifact_s3_prefix: "runtrue-sandboxd/v1".to_owned(),
            artifact_s3_virtual_hosted: false,
            artifact_s3_allow_http_for_local_testing: false,
            artifact_s3_credentials_file: None,
            state_root: PathBuf::from("/var/lib/sandboxd/state"),
            image_store: PathBuf::from("/var/lib/sandboxd/images"),
            ctr: PathBuf::from("/usr/bin/ctr"),
            mkfs_ext4: PathBuf::from("/usr/sbin/mkfs.ext4"),
            losetup: PathBuf::from("/usr/sbin/losetup"),
            containerd_address: PathBuf::from("/run/containerd/containerd.sock"),
            containerd_namespace: "runtrue-sandboxd".to_owned(),
            snapshotter: "overlayfs".to_owned(),
            image_platform: "linux/amd64".to_owned(),
            fixed_rootfs: None,
            executor: ExecutorConfiguration::default(),
            runsc: PathBuf::from("/usr/local/bin/runsc"),
            ip: PathBuf::from("/usr/sbin/ip"),
            nft: PathBuf::from("/usr/sbin/nft"),
            maximum_connections: 64,
            io_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn workload_endpoint_requires_a_complete_non_root_identity() {
        config().validate().expect("valid configuration");

        let mut root_broker = config();
        root_broker.broker_uid = Some(0);
        assert!(root_broker.validate().is_err());

        let mut incomplete = config();
        incomplete.work_order_key = None;
        assert!(incomplete.validate().is_err());
    }

    #[test]
    fn s3_artifacts_require_an_explicit_shared_master_key() {
        let mut s3 = config();
        s3.artifact_s3_bucket = Some("sandbox-artifacts".to_owned());
        assert!(s3.validate().is_err());

        s3.artifact_master_key = Some(PathBuf::from("/etc/sandboxd/artifact-master.key"));
        s3.validate().expect("complete S3 configuration");

        let mut stray_endpoint = config();
        stray_endpoint.artifact_s3_endpoint = Some("https://s3.example.com".to_owned());
        assert!(stray_endpoint.validate().is_err());
    }

    #[test]
    fn guest_profiles_are_exact_reviewed_operator_policy() {
        let mut enabled = config();
        enabled.guest_profiles.push(
            GuestProfile::reviewed_named(runtrue_sandbox_core::ROOT_GUEST_PROFILE)
                .expect("root profile"),
        );
        enabled.validate().expect("reviewed profile set");

        let mut duplicate = config();
        duplicate.guest_profiles.push(GuestProfile::strict());
        assert!(duplicate.validate().is_err());

        let mut tampered = config();
        tampered.guest_profiles[0]
            .restrictions
            .effective_capabilities
            .push("CAP_SYS_ADMIN".to_owned());
        assert!(tampered.validate().is_err());
    }
}
