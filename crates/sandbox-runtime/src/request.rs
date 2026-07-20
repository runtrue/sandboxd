use crate::ArtifactStaging;
use runtrue_sandbox_core::{SandboxId, SandboxSpec, SnapshotManifest, SnapshotMode, WorkerId};

#[derive(Debug, Clone)]
pub struct CreateRequest {
    pub sandbox_id: SandboxId,
    pub worker_id: WorkerId,
    pub assignment_epoch: u64,
    pub specification: SandboxSpec,
}

#[derive(Debug, Clone)]
pub struct SnapshotRequest {
    pub mode: SnapshotMode,
    pub staging: ArtifactStaging,
}

#[derive(Debug, Clone)]
pub struct RestoreRequest {
    pub worker_id: WorkerId,
    pub assignment_epoch: u64,
    pub specification: SandboxSpec,
    pub manifest: SnapshotManifest,
    pub materialized_objects: ArtifactStaging,
}
