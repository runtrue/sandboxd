use runtrue_sandbox_core::{ArtifactRole, ContainerId, SnapshotId};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactStaging {
    snapshot_id: SnapshotId,
    directory: PathBuf,
}

impl ArtifactStaging {
    #[must_use]
    pub fn new(snapshot_id: SnapshotId, directory: PathBuf) -> Self {
        Self {
            snapshot_id,
            directory,
        }
    }

    #[must_use]
    pub fn snapshot_id(&self) -> &SnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedArtifact {
    pub role: ArtifactRole,
    pub container: Option<ContainerId>,
    pub path: PathBuf,
    pub media_type: String,
}
