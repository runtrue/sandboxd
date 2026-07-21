use crate::{
    specification::validate_digest, BackendDescriptor, ContainerId, CoreError, LifecycleState,
    SandboxId, SnapshotId, SnapshotPortability, TenantId, WorkerId, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SNAPSHOT_MANIFEST_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotMode {
    Live,
    StopAndMove,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub schema_version: u32,
    pub snapshot_id: SnapshotId,
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub sandbox_id: SandboxId,
    pub sandbox_spec_digest: String,
    pub source_worker: WorkerId,
    pub source_assignment_epoch: u64,
    pub created_unix_millis: u64,
    pub captured_from: LifecycleState,
    pub restore_state: LifecycleState,
    pub mode: SnapshotMode,
    pub backend: BackendDescriptor,
    pub restore_requirements: RestoreRequirements,
    pub containers: BTreeMap<ContainerId, Vec<SnapshotObject>>,
    pub sandbox_objects: Vec<SnapshotObject>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequirements {
    pub architecture: String,
    pub operating_system: String,
    pub minimum_backend_version: String,
    pub portability: SnapshotPortability,
    pub required_cpu_features: Vec<String>,
    pub cpu_features_digest: String,
    pub preserves_internal_connections: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotObject {
    pub name: String,
    pub role: ArtifactRole,
    pub artifact: ArtifactDescriptor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    RuntimeState,
    MemoryPages,
    WritableFilesystem,
    BackendMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptor {
    pub digest: String,
    pub size_bytes: u64,
    pub media_type: String,
}

impl SnapshotManifest {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.schema_version != SNAPSHOT_MANIFEST_VERSION {
            return Err(CoreError::InvalidSnapshot(
                "unsupported schema version".to_owned(),
            ));
        }
        if self.source_assignment_epoch == 0 || self.created_unix_millis == 0 {
            return Err(CoreError::InvalidSnapshot(
                "snapshot provenance is incomplete".to_owned(),
            ));
        }
        validate_digest("backend configuration", &self.backend.configuration_digest)
            .map_err(|error| CoreError::InvalidSnapshot(error.to_string()))?;
        validate_digest("sandbox spec", &self.sandbox_spec_digest)
            .map_err(|error| CoreError::InvalidSnapshot(error.to_string()))?;
        validate_digest(
            "CPU feature profile",
            &self.restore_requirements.cpu_features_digest,
        )
        .map_err(|error| CoreError::InvalidSnapshot(error.to_string()))?;
        if !matches!(
            self.captured_from,
            LifecycleState::Running | LifecycleState::Paused
        ) || !matches!(
            self.restore_state,
            LifecycleState::Running | LifecycleState::Paused
        ) {
            return Err(CoreError::InvalidSnapshot(
                "snapshot lifecycle state is not restorable".to_owned(),
            ));
        }
        if self.restore_requirements.operating_system != "linux"
            || self.restore_requirements.architecture.is_empty()
            || self.restore_requirements.minimum_backend_version.is_empty()
        {
            return Err(CoreError::InvalidSnapshot(
                "restore requirements are incomplete".to_owned(),
            ));
        }
        let objects = self
            .containers
            .values()
            .flatten()
            .chain(self.sandbox_objects.iter());
        let mut names = BTreeSet::new();
        for object in objects {
            if object.name.is_empty()
                || object.name.len() > 128
                || !object
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err(CoreError::InvalidSnapshot(
                    "snapshot object name is invalid".to_owned(),
                ));
            }
            if !names.insert(&object.name) {
                return Err(CoreError::InvalidSnapshot(
                    "snapshot object names must be unique".to_owned(),
                ));
            }
            validate_digest("snapshot object", &object.artifact.digest)
                .map_err(|error| CoreError::InvalidSnapshot(error.to_string()))?;
            if object.artifact.size_bytes == 0 || object.artifact.media_type.is_empty() {
                return Err(CoreError::InvalidSnapshot(
                    "snapshot object metadata is incomplete".to_owned(),
                ));
            }
        }
        if self.containers.is_empty()
            || self.containers.values().any(Vec::is_empty)
            || self.sandbox_objects.is_empty()
        {
            return Err(CoreError::InvalidSnapshot(
                "snapshot omitted container or sandbox state".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BackendKind, SnapshotPortability};

    fn object(role: ArtifactRole, byte: char) -> SnapshotObject {
        SnapshotObject {
            name: format!("object-{byte}"),
            role,
            artifact: ArtifactDescriptor {
                digest: format!("sha256:{}", byte.to_string().repeat(64)),
                size_bytes: 1,
                media_type: "application/vnd.runtrue.snapshot.test".to_owned(),
            },
        }
    }

    fn manifest() -> SnapshotManifest {
        SnapshotManifest {
            schema_version: SNAPSHOT_MANIFEST_VERSION,
            snapshot_id: SnapshotId::parse("snapshot-a").expect("snapshot id"),
            tenant_id: TenantId::parse("tenant-a").expect("tenant id"),
            workspace_id: WorkspaceId::parse("workspace-a").expect("workspace id"),
            sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox id"),
            sandbox_spec_digest: format!("sha256:{}", "a".repeat(64)),
            source_worker: WorkerId::parse("worker-a").expect("worker id"),
            source_assignment_epoch: 7,
            created_unix_millis: 1,
            captured_from: LifecycleState::Paused,
            restore_state: LifecycleState::Paused,
            mode: SnapshotMode::StopAndMove,
            backend: BackendDescriptor {
                kind: BackendKind::Gvisor,
                implementation: "runsc".to_owned(),
                implementation_version: "test".to_owned(),
                state_format_version: 1,
                configuration_digest: format!("sha256:{}", "b".repeat(64)),
            },
            restore_requirements: RestoreRequirements {
                architecture: "amd64".to_owned(),
                operating_system: "linux".to_owned(),
                minimum_backend_version: "test".to_owned(),
                portability: SnapshotPortability::CrossWorkerSameBackend,
                required_cpu_features: Vec::new(),
                cpu_features_digest: format!("sha256:{}", "e".repeat(64)),
                preserves_internal_connections: true,
            },
            containers: BTreeMap::from([(
                ContainerId::parse("server").expect("container id"),
                vec![object(ArtifactRole::WritableFilesystem, 'c')],
            )]),
            sandbox_objects: vec![object(ArtifactRole::RuntimeState, 'd')],
        }
    }

    #[test]
    fn portable_manifest_contains_descriptors_without_worker_paths() {
        let manifest = manifest();
        manifest.validate().expect("manifest is valid");
        let encoded = serde_json::to_string(&manifest).expect("serialize manifest");
        assert!(!encoded.contains("/tmp"));
        assert!(!encoded.contains("/var"));
        assert!(encoded.contains("cross_worker_same_backend"));
    }

    #[test]
    fn manifest_rejects_missing_container_artifacts() {
        let mut manifest = manifest();
        manifest
            .containers
            .values_mut()
            .next()
            .expect("container")
            .clear();
        assert!(manifest.validate().is_err());
    }
}
