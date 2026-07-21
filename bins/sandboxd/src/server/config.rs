use runtrue_sandbox_core::WorkerId;
use runtrue_sandbox_oci::SandboxError;
use std::{path::PathBuf, time::Duration};

pub(crate) struct ServerConfig {
    pub(crate) operator_socket: PathBuf,
    pub(crate) workload_socket: Option<PathBuf>,
    pub(crate) broker_uid: Option<u32>,
    pub(crate) work_order_key: Option<PathBuf>,
    pub(crate) worker_id: WorkerId,
    pub(crate) artifact_master_key: Option<PathBuf>,
    pub(crate) state_root: PathBuf,
    pub(crate) image_store: PathBuf,
    pub(crate) ctr: PathBuf,
    pub(crate) containerd_address: PathBuf,
    pub(crate) containerd_namespace: String,
    pub(crate) snapshotter: String,
    pub(crate) image_platform: String,
    pub(crate) runsc: PathBuf,
    pub(crate) ip: PathBuf,
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ServerConfig {
        ServerConfig {
            operator_socket: PathBuf::from("/run/sandboxd/operator.sock"),
            workload_socket: Some(PathBuf::from("/run/sandboxd/workload.sock")),
            broker_uid: Some(991),
            work_order_key: Some(PathBuf::from("/etc/sandboxd/work-order.key")),
            worker_id: WorkerId::parse("worker-a").expect("worker ID"),
            artifact_master_key: None,
            state_root: PathBuf::from("/var/lib/sandboxd/state"),
            image_store: PathBuf::from("/var/lib/sandboxd/images"),
            ctr: PathBuf::from("/usr/bin/ctr"),
            containerd_address: PathBuf::from("/run/containerd/containerd.sock"),
            containerd_namespace: "runtrue-sandboxd".to_owned(),
            snapshotter: "overlayfs".to_owned(),
            image_platform: "linux/amd64".to_owned(),
            runsc: PathBuf::from("/usr/local/bin/runsc"),
            ip: PathBuf::from("/usr/sbin/ip"),
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
}
