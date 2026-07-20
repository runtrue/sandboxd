use crate::{RuntimeError, SnapshotRequest, StagedArtifact};
use runtrue_sandbox_core::{BackendKind, LifecycleState, SandboxId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceStatus {
    pub sandbox_id: SandboxId,
    pub backend: BackendKind,
    pub state: LifecycleState,
    pub generation: u64,
    pub running_containers: usize,
}

pub trait SandboxInstance: Send {
    fn status(&self) -> Result<InstanceStatus, RuntimeError>;

    fn pause(&mut self) -> Result<InstanceStatus, RuntimeError>;

    fn resume(&mut self) -> Result<InstanceStatus, RuntimeError>;

    fn snapshot(&mut self, request: SnapshotRequest) -> Result<Vec<StagedArtifact>, RuntimeError>;

    fn stop(&mut self) -> Result<InstanceStatus, RuntimeError>;
}
