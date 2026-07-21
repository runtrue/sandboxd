use crate::ArtifactError;
use runtrue_sandbox_core::{
    ArtifactRole, ContainerId, SnapshotId, SnapshotManifest, TenantId, WorkspaceId,
};
use serde::Serialize;
use std::{path::PathBuf, time::Duration};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactScope {
    tenant_id: TenantId,
    workspace_id: WorkspaceId,
}

impl ArtifactScope {
    #[must_use]
    pub fn new(tenant_id: TenantId, workspace_id: WorkspaceId) -> Self {
        Self {
            tenant_id,
            workspace_id,
        }
    }

    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    pub(crate) fn validate_manifest(
        &self,
        manifest: &SnapshotManifest,
    ) -> Result<(), ArtifactError> {
        if manifest.tenant_id != self.tenant_id || manifest.workspace_id != self.workspace_id {
            return Err(ArtifactError::AccessDenied(
                "snapshot manifest belongs to another tenant scope".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn storage_prefix(&self) -> String {
        format!(
            "tenants/{}/workspaces/{}",
            self.tenant_id.as_str(),
            self.workspace_id.as_str()
        )
    }

    pub(crate) fn binding(&self) -> String {
        format!("{}/{}", self.tenant_id.as_str(), self.workspace_id.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactLimits {
    pub maximum_object_bytes: u64,
    pub maximum_snapshot_bytes: u64,
    pub maximum_objects: usize,
    pub maximum_listing_entries: usize,
    pub maximum_concurrency: usize,
    pub operation_timeout: Duration,
    pub garbage_collection_grace: Duration,
}

impl Default for ArtifactLimits {
    fn default() -> Self {
        Self {
            maximum_object_bytes: 16 * 1024 * 1024 * 1024,
            maximum_snapshot_bytes: 64 * 1024 * 1024 * 1024,
            maximum_objects: 1_024,
            maximum_listing_entries: 100_000,
            maximum_concurrency: 4,
            operation_timeout: Duration::from_secs(300),
            garbage_collection_grace: Duration::from_secs(60 * 60),
        }
    }
}

impl ArtifactLimits {
    pub(crate) fn validate(&self) -> Result<(), ArtifactError> {
        if self.maximum_object_bytes == 0
            || self.maximum_snapshot_bytes < self.maximum_object_bytes
            || self.maximum_objects == 0
            || self.maximum_objects > 100_000
            || self.maximum_listing_entries < self.maximum_objects
            || self.maximum_listing_entries > 1_000_000
            || self.maximum_concurrency == 0
            || self.maximum_concurrency > 64
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(3_600)
            || self.garbage_collection_grace < self.operation_timeout
        {
            return Err(ArtifactError::Invalid(
                "artifact-store limits are invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct StagedSnapshotObject {
    pub role: ArtifactRole,
    pub container: Option<ContainerId>,
    pub name: String,
    pub path: PathBuf,
    pub media_type: String,
}

#[derive(Debug, Clone)]
pub struct SnapshotPublication {
    pub scope: ArtifactScope,
    pub manifest: SnapshotManifest,
    pub objects: Vec<StagedSnapshotObject>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicationMetrics {
    pub snapshot_id: SnapshotId,
    pub object_count: usize,
    pub logical_bytes: u64,
    pub transferred_bytes: u64,
    pub reused_objects: usize,
    pub publish_millis: u128,
}

#[derive(Debug, Clone)]
pub struct MaterializedSnapshot {
    pub manifest: SnapshotManifest,
    pub directory: PathBuf,
    pub transferred_bytes: u64,
    pub materialization_millis: u128,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct GarbageCollectionReport {
    pub removed_staging_objects: usize,
    pub removed_unreferenced_objects: usize,
    pub retained_objects: usize,
}
