use crate::{
    specification::validate_digest, BackendDescriptor, ContainerId, CoreError, LifecycleState,
    SandboxId, SnapshotId, SnapshotPortability, TenantId, VolumeId, VolumeSnapshotDescriptor,
    WorkerId, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SNAPSHOT_MANIFEST_VERSION: u32 = 3;

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
    pub volumes: BTreeMap<VolumeId, VolumeSnapshotDescriptor>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreTarget {
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub sandbox_id: SandboxId,
    pub worker_id: WorkerId,
    pub assignment_epoch: crate::AssignmentEpoch,
    pub artifact_portability: SnapshotPortability,
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
    VolumeData,
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
        for (volume_id, volume) in &self.volumes {
            volume.validate()?;
            let matching = self
                .sandbox_objects
                .iter()
                .filter(|object| {
                    object.name == volume.object_name
                        && object.role == ArtifactRole::VolumeData
                        && object.artifact == volume.artifact
                })
                .count();
            if matching != 1 {
                return Err(CoreError::InvalidSnapshot(format!(
                    "volume `{volume_id}` does not reference exactly one volume snapshot object"
                )));
            }
        }
        let described_volume_objects = self
            .sandbox_objects
            .iter()
            .filter(|object| object.role == ArtifactRole::VolumeData)
            .count();
        if described_volume_objects != self.volumes.len() {
            return Err(CoreError::InvalidSnapshot(
                "volume snapshot objects and descriptors do not match".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_restore_target(&self, target: &RestoreTarget) -> Result<(), CoreError> {
        if self.tenant_id != target.tenant_id || self.workspace_id != target.workspace_id {
            return Err(CoreError::InvalidSnapshot(
                "restore target belongs to another tenant scope".to_owned(),
            ));
        }
        let moves_worker = self.source_worker != target.worker_id;
        let reuses_identity = self.sandbox_id == target.sandbox_id;
        if moves_worker {
            if self.mode != SnapshotMode::StopAndMove {
                return Err(CoreError::InvalidSnapshot(
                    "cross-worker restore requires a stop-and-move snapshot".to_owned(),
                ));
            }
            if !reuses_identity {
                return Err(CoreError::InvalidSnapshot(
                    "cross-worker restore must preserve the sandbox identity".to_owned(),
                ));
            }
            if !self.restore_requirements.portability.permits_cross_worker()
                || !target.artifact_portability.permits_cross_worker()
            {
                return Err(CoreError::InvalidSnapshot(
                    "snapshot or artifact provider does not permit cross-worker restore".to_owned(),
                ));
            }
            if self
                .volumes
                .values()
                .any(|volume| !volume.portability.permits_cross_worker())
            {
                return Err(CoreError::InvalidSnapshot(
                    "a captured volume does not permit cross-worker restore".to_owned(),
                ));
            }
        }
        if reuses_identity && target.assignment_epoch.get() <= self.source_assignment_epoch {
            return Err(CoreError::InvalidSnapshot(
                "restore must advance the source assignment epoch".to_owned(),
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
            volumes: BTreeMap::new(),
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

    #[test]
    fn cross_worker_restore_requires_fenced_identity_and_newer_epoch() {
        let manifest = manifest();
        let mut target = RestoreTarget {
            tenant_id: manifest.tenant_id.clone(),
            workspace_id: manifest.workspace_id.clone(),
            sandbox_id: manifest.sandbox_id.clone(),
            worker_id: WorkerId::parse("worker-b").expect("worker"),
            assignment_epoch: crate::AssignmentEpoch::new(8).expect("epoch"),
            artifact_portability: SnapshotPortability::CrossWorkerSameBackend,
        };
        manifest
            .validate_restore_target(&target)
            .expect("fenced migration target");

        target.assignment_epoch = crate::AssignmentEpoch::new(7).expect("epoch");
        assert!(manifest.validate_restore_target(&target).is_err());
        target.assignment_epoch = crate::AssignmentEpoch::new(8).expect("epoch");
        target.artifact_portability = SnapshotPortability::SameWorker;
        assert!(manifest.validate_restore_target(&target).is_err());

        let mut live = manifest;
        live.mode = SnapshotMode::Live;
        target.artifact_portability = SnapshotPortability::CrossWorkerSameBackend;
        assert!(live.validate_restore_target(&target).is_err());
    }

    #[test]
    fn same_worker_copy_can_use_a_new_sandbox_identity() {
        let manifest = manifest();
        let target = RestoreTarget {
            tenant_id: manifest.tenant_id.clone(),
            workspace_id: manifest.workspace_id.clone(),
            sandbox_id: SandboxId::parse("sandbox-copy").expect("sandbox"),
            worker_id: manifest.source_worker.clone(),
            assignment_epoch: crate::AssignmentEpoch::new(1).expect("epoch"),
            artifact_portability: SnapshotPortability::SameWorker,
        };
        manifest
            .validate_restore_target(&target)
            .expect("same-worker copy target");
    }

    #[test]
    fn volume_snapshot_is_bound_to_one_typed_object() {
        let mut manifest = manifest();
        let object = object(ArtifactRole::VolumeData, 'f');
        manifest.volumes.insert(
            VolumeId::parse("database").expect("volume"),
            VolumeSnapshotDescriptor {
                provider_id: "local-loopback-v1".to_owned(),
                persistence_class: crate::VolumePersistenceClass::Persistent,
                portability: SnapshotPortability::CrossWorkerSameBackend,
                object_name: object.name.clone(),
                artifact: object.artifact.clone(),
            },
        );
        manifest.sandbox_objects.push(object);
        manifest.validate().expect("volume manifest");

        manifest
            .volumes
            .values_mut()
            .next()
            .expect("descriptor")
            .persistence_class = crate::VolumePersistenceClass::Secret;
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn nonportable_volume_rejects_cross_worker_restore() {
        let mut manifest = manifest();
        let object = object(ArtifactRole::VolumeData, 'f');
        manifest.volumes.insert(
            VolumeId::parse("database").expect("volume"),
            VolumeSnapshotDescriptor {
                provider_id: "worker-local-v1".to_owned(),
                persistence_class: crate::VolumePersistenceClass::Persistent,
                portability: SnapshotPortability::SameWorker,
                object_name: object.name.clone(),
                artifact: object.artifact.clone(),
            },
        );
        manifest.sandbox_objects.push(object);
        manifest.validate().expect("volume manifest");
        let target = RestoreTarget {
            tenant_id: manifest.tenant_id.clone(),
            workspace_id: manifest.workspace_id.clone(),
            sandbox_id: manifest.sandbox_id.clone(),
            worker_id: WorkerId::parse("worker-b").expect("worker"),
            assignment_epoch: crate::AssignmentEpoch::new(8).expect("epoch"),
            artifact_portability: SnapshotPortability::CrossWorkerSameBackend,
        };
        assert!(manifest.validate_restore_target(&target).is_err());
    }
}
