use crate::{io_error, SandboxError};
use runtrue_sandbox_artifact::{
    ArtifactScope, ArtifactStore, MaterializedSnapshot, SnapshotPublication, StagedSnapshotObject,
};
use runtrue_sandbox_core::{
    ArtifactRole, AssignmentEpoch, BackendDescriptor, BackendKind, ContainerId, LifecycleState,
    RestoreRequirements, SandboxId, SnapshotId, SnapshotManifest, SnapshotMode,
    SnapshotPortability, TenantId, WorkerId, WorkspaceId, SNAPSHOT_MANIFEST_VERSION,
};
use runtrue_sandbox_oci::provider::{ImageProvider, WritableRootfs, WritableRootfsExport};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const METADATA_VERSION: u32 = 2;
const CHECKPOINT_MEDIA_TYPE: &str = "application/vnd.runtrue.gvisor.checkpoint";
const METADATA_MEDIA_TYPE: &str = "application/vnd.runtrue.gvisor.metadata.v2+json";
const WRITABLE_DIFF_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";

#[derive(Debug, Clone)]
pub struct SnapshotProvenance {
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub sandbox_id: SandboxId,
    pub source_worker: WorkerId,
    pub source_assignment_epoch: AssignmentEpoch,
}

impl SnapshotProvenance {
    pub fn scope(&self) -> ArtifactScope {
        ArtifactScope::new(self.tenant_id.clone(), self.workspace_id.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GvisorSnapshotMetadata {
    pub(super) schema_version: u32,
    pub(super) topology_digest: String,
    pub(super) mode: SnapshotMode,
    pub(super) created_unix_millis: u64,
    pub(super) runsc_version: String,
    pub(super) runtime_configuration_digest: String,
    pub(super) cpu_features_digest: String,
    pub(super) root_service: String,
    pub(super) services: Vec<String>,
    pub(super) service_states: BTreeMap<String, String>,
    pub(super) writable_services: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotSummary {
    pub snapshot_id: SnapshotId,
    pub source_sandbox: String,
    pub topology_digest: String,
    pub mode: SnapshotMode,
    pub files: usize,
    pub size_bytes: u64,
    pub transferred_bytes: u64,
    pub reused_objects: usize,
    pub checkpoint_millis: u128,
    pub writable_export_millis: u128,
    pub publish_millis: u128,
    pub source_cleanup_millis: u128,
    pub runtime_configuration_digest: String,
}

pub(super) struct SnapshotStaging {
    temporary: tempfile::TempDir,
    image_path: PathBuf,
}

impl SnapshotStaging {
    pub(super) fn create(parent: &Path) -> Result<Self, SandboxError> {
        if !parent.is_absolute() {
            return Err(SandboxError::Runtime(
                "snapshot staging root must be absolute".to_owned(),
            ));
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|error| io_error(parent, error))?;
        let temporary = tempfile::Builder::new()
            .prefix("checkpoint-")
            .tempdir_in(parent)
            .map_err(|error| io_error(parent, error))?;
        let image_path = temporary.path().join("runtime");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&image_path)
            .map_err(|error| io_error(&image_path, error))?;
        Ok(Self {
            temporary,
            image_path,
        })
    }

    pub(super) fn image_path(&self) -> &Path {
        &self.image_path
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn publication(
        &self,
        snapshot_id: SnapshotId,
        provenance: &SnapshotProvenance,
        topology_digest: String,
        mode: SnapshotMode,
        captured_from: LifecycleState,
        runsc_version: String,
        runtime_configuration_digest: String,
        cpu_features_digest: String,
        root_service: String,
        services: Vec<String>,
        service_states: BTreeMap<String, String>,
        writable_services: BTreeMap<String, u64>,
        mut writable_objects: Vec<StagedSnapshotObject>,
    ) -> Result<(SnapshotPublication, GvisorSnapshotMetadata), SandboxError> {
        let created_unix_millis = unix_millis()?;
        let metadata = GvisorSnapshotMetadata {
            schema_version: METADATA_VERSION,
            topology_digest: topology_digest.clone(),
            mode,
            created_unix_millis,
            runsc_version: runsc_version.clone(),
            runtime_configuration_digest: runtime_configuration_digest.clone(),
            cpu_features_digest: cpu_features_digest.clone(),
            root_service,
            services,
            service_states,
            writable_services,
        };
        validate_metadata(&metadata)?;
        let mut objects = checkpoint_objects(&self.image_path)?;
        objects.append(&mut writable_objects);
        for service in &metadata.services {
            let container = ContainerId::parse(service.clone())
                .map_err(|error| SandboxError::Runtime(error.to_string()))?;
            let name = format!("rtmeta-{service}.json");
            let path = self.temporary.path().join(&name);
            write_json(&path, &metadata)?;
            objects.push(StagedSnapshotObject {
                role: ArtifactRole::BackendMetadata,
                container: Some(container),
                name,
                path,
                media_type: METADATA_MEDIA_TYPE.to_owned(),
            });
        }
        let manifest = SnapshotManifest {
            schema_version: SNAPSHOT_MANIFEST_VERSION,
            snapshot_id,
            tenant_id: provenance.tenant_id.clone(),
            workspace_id: provenance.workspace_id.clone(),
            sandbox_id: provenance.sandbox_id.clone(),
            sandbox_spec_digest: topology_digest,
            source_worker: provenance.source_worker.clone(),
            source_assignment_epoch: provenance.source_assignment_epoch.get(),
            created_unix_millis,
            captured_from,
            restore_state: captured_from,
            mode,
            backend: BackendDescriptor {
                kind: BackendKind::Gvisor,
                implementation: "runsc".to_owned(),
                implementation_version: runsc_version.clone(),
                state_format_version: 1,
                configuration_digest: runtime_configuration_digest,
            },
            restore_requirements: RestoreRequirements {
                architecture: std::env::consts::ARCH.to_owned(),
                operating_system: std::env::consts::OS.to_owned(),
                minimum_backend_version: runsc_version,
                portability: SnapshotPortability::CrossWorkerSameBackend,
                required_cpu_features: Vec::new(),
                cpu_features_digest,
                preserves_internal_connections: true,
            },
            containers: BTreeMap::new(),
            sandbox_objects: Vec::new(),
        };
        Ok((
            SnapshotPublication {
                scope: provenance.scope(),
                manifest,
                objects,
            },
            metadata,
        ))
    }

    pub(super) fn stage_writable_rootfs(
        &self,
        service: &str,
        provider: &dyn ImageProvider,
        rootfs: &WritableRootfs,
    ) -> Result<(StagedSnapshotObject, WritableRootfsExport), SandboxError> {
        validate_name(service)?;
        let name = format!("rootfs-{service}.tar");
        let path = self.temporary.path().join(&name);
        let exported = provider.export_writable_rootfs(rootfs, &path)?;
        Ok((
            StagedSnapshotObject {
                role: ArtifactRole::WritableFilesystem,
                container: Some(
                    ContainerId::parse(service.to_owned())
                        .map_err(|error| SandboxError::Runtime(error.to_string()))?,
                ),
                name,
                path,
                media_type: WRITABLE_DIFF_MEDIA_TYPE.to_owned(),
            },
            exported,
        ))
    }
}

pub(super) struct RestoredSnapshot {
    _temporary: tempfile::TempDir,
    pub(super) manifest: SnapshotManifest,
    pub(super) metadata: GvisorSnapshotMetadata,
    pub(super) image_path: PathBuf,
    pub(super) writable_diffs: BTreeMap<String, PathBuf>,
    pub(super) transferred_bytes: u64,
    pub(super) materialization_millis: u128,
}

impl Drop for RestoredSnapshot {
    fn drop(&mut self) {
        let _ = make_cleanup_writable(self._temporary.path());
    }
}

pub(super) fn materialize(
    store: &dyn ArtifactStore,
    scope: &ArtifactScope,
    snapshot_id: &SnapshotId,
    staging_root: &Path,
) -> Result<RestoredSnapshot, SandboxError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(staging_root)
        .map_err(|error| io_error(staging_root, error))?;
    let temporary = tempfile::Builder::new()
        .prefix("restore-")
        .tempdir_in(staging_root)
        .map_err(|error| io_error(staging_root, error))?;
    let materialized_path = temporary.path().join("materialized");
    let materialized = store
        .materialize(scope, snapshot_id, &materialized_path)
        .map_err(artifact_error)?;
    let transferred_bytes = materialized.transferred_bytes;
    let materialization_millis = materialized.materialization_millis;
    let metadata = load_metadata(&materialized)?;
    let writable_diffs = writable_diff_paths(&materialized, &metadata)?;
    let image_path = temporary.path().join("runtime");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&image_path)
        .map_err(|error| io_error(&image_path, error))?;
    for object in &materialized.manifest.sandbox_objects {
        if !matches!(
            object.role,
            ArtifactRole::RuntimeState
                | ArtifactRole::MemoryPages
                | ArtifactRole::WritableFilesystem
        ) {
            continue;
        }
        let source = materialized_path.join(&object.name);
        let destination = image_path.join(&object.name);
        fs::hard_link(&source, &destination)
            .or_else(|_| fs::copy(&source, &destination).map(|_| ()))
            .map_err(|error| io_error(&destination, error))?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o400))
            .map_err(|error| io_error(&destination, error))?;
    }
    if fs::read_dir(&image_path)
        .map_err(|error| io_error(&image_path, error))?
        .next()
        .is_none()
    {
        return Err(SandboxError::Runtime(
            "portable snapshot contains no gVisor runtime objects".to_owned(),
        ));
    }
    fs::set_permissions(&image_path, fs::Permissions::from_mode(0o500))
        .map_err(|error| io_error(&image_path, error))?;
    Ok(RestoredSnapshot {
        _temporary: temporary,
        manifest: materialized.manifest,
        metadata,
        image_path,
        writable_diffs,
        transferred_bytes,
        materialization_millis,
    })
}

fn load_metadata(
    materialized: &MaterializedSnapshot,
) -> Result<GvisorSnapshotMetadata, SandboxError> {
    if materialized.manifest.sandbox_objects.iter().any(|object| {
        object.artifact.media_type != CHECKPOINT_MEDIA_TYPE
            || !matches!(
                object.role,
                ArtifactRole::RuntimeState | ArtifactRole::MemoryPages
            )
    }) {
        return Err(SandboxError::Runtime(
            "snapshot contains an invalid gVisor runtime object".to_owned(),
        ));
    }
    let mut descriptor = None;
    let mut name = None;
    for (container, objects) in &materialized.manifest.containers {
        let backend_objects = objects
            .iter()
            .filter(|object| object.role == ArtifactRole::BackendMetadata)
            .collect::<Vec<_>>();
        let writable_objects = objects
            .iter()
            .filter(|object| object.role == ArtifactRole::WritableFilesystem)
            .collect::<Vec<_>>();
        if backend_objects.len() != 1
            || backend_objects[0].artifact.media_type != METADATA_MEDIA_TYPE
            || writable_objects.len() > 1
            || objects.len() != backend_objects.len() + writable_objects.len()
            || writable_objects
                .first()
                .is_some_and(|object| object.artifact.media_type != WRITABLE_DIFF_MEDIA_TYPE)
        {
            return Err(SandboxError::Runtime(format!(
                "snapshot container `{container}` has invalid backend metadata"
            )));
        }
        let backend = backend_objects[0];
        if let Some(expected) = &descriptor {
            if expected != &backend.artifact {
                return Err(SandboxError::Runtime(
                    "snapshot container metadata is inconsistent".to_owned(),
                ));
            }
        } else {
            descriptor = Some(backend.artifact.clone());
            name = Some(backend.name.clone());
        }
    }
    let name = name.ok_or_else(|| {
        SandboxError::Runtime("snapshot contains no container metadata".to_owned())
    })?;
    let path = materialized.directory.join(name);
    let metadata: GvisorSnapshotMetadata =
        serde_json::from_slice(&fs::read(&path).map_err(|error| io_error(&path, error))?)
            .map_err(|error| SandboxError::Runtime(format!("decode gVisor metadata: {error}")))?;
    validate_metadata(&metadata)?;
    let containers = materialized
        .manifest
        .containers
        .keys()
        .map(ContainerId::as_str)
        .collect::<BTreeSet<_>>();
    let services = metadata
        .services
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if containers != services {
        return Err(SandboxError::Runtime(
            "snapshot service metadata does not match its container map".to_owned(),
        ));
    }
    Ok(metadata)
}

fn validate_metadata(metadata: &GvisorSnapshotMetadata) -> Result<(), SandboxError> {
    if metadata.schema_version != METADATA_VERSION
        || metadata.created_unix_millis == 0
        || metadata.topology_digest.is_empty()
        || metadata.runsc_version.is_empty()
        || metadata.runtime_configuration_digest.is_empty()
        || metadata.cpu_features_digest.is_empty()
        || metadata.services.is_empty()
        || metadata.root_service.is_empty()
        || !metadata.services.contains(&metadata.root_service)
        || metadata.service_states.len() != metadata.services.len()
        || metadata
            .services
            .iter()
            .any(|service| !metadata.service_states.contains_key(service))
        || metadata
            .service_states
            .values()
            .any(|state| !matches!(state.as_str(), "running" | "paused" | "stopped"))
        || metadata
            .writable_services
            .iter()
            .any(|(service, quota)| *quota == 0 || !metadata.services.contains(service))
    {
        return Err(SandboxError::Runtime(
            "gVisor snapshot metadata is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn writable_diff_paths(
    materialized: &MaterializedSnapshot,
    metadata: &GvisorSnapshotMetadata,
) -> Result<BTreeMap<String, PathBuf>, SandboxError> {
    let mut result = BTreeMap::new();
    for (container, objects) in &materialized.manifest.containers {
        let writable = objects
            .iter()
            .filter(|object| object.role == ArtifactRole::WritableFilesystem)
            .collect::<Vec<_>>();
        let expected = metadata.writable_services.contains_key(container.as_str());
        if expected != (writable.len() == 1) {
            return Err(SandboxError::Runtime(format!(
                "snapshot container `{container}` has inconsistent writable-root state"
            )));
        }
        if let Some(object) = writable.first() {
            result.insert(
                container.as_str().to_owned(),
                materialized.directory.join(&object.name),
            );
        }
    }
    Ok(result)
}

fn checkpoint_objects(directory: &Path) -> Result<Vec<StagedSnapshotObject>, SandboxError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| io_error(directory, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error(directory, error))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    if entries.is_empty() {
        return Err(SandboxError::Runtime(
            "runsc checkpoint produced no files".to_owned(),
        ));
    }
    entries
        .into_iter()
        .map(|entry| {
            if !entry
                .file_type()
                .map_err(|error| io_error(entry.path(), error))?
                .is_file()
            {
                return Err(SandboxError::Runtime(
                    "runsc checkpoint contains a non-file entry".to_owned(),
                ));
            }
            let name = entry.file_name().into_string().map_err(|_| {
                SandboxError::Runtime("checkpoint filename is not UTF-8".to_owned())
            })?;
            validate_name(&name)?;
            Ok(StagedSnapshotObject {
                role: ArtifactRole::RuntimeState,
                container: None,
                name,
                path: entry.path(),
                media_type: CHECKPOINT_MEDIA_TYPE.to_owned(),
            })
        })
        .collect()
}

fn make_cleanup_writable(path: &Path) -> Result<(), SandboxError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if metadata.file_type().is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| io_error(path, error))?;
        for entry in fs::read_dir(path).map_err(|error| io_error(path, error))? {
            let entry = entry.map_err(|error| io_error(path, error))?;
            make_cleanup_writable(&entry.path())?;
        }
    } else if metadata.file_type().is_file() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| io_error(path, error))?;
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), SandboxError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(SandboxError::Runtime(
            "checkpoint filename is unsafe".to_owned(),
        ));
    }
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), SandboxError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| SandboxError::Runtime(format!("encode gVisor metadata: {error}")))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)
        .map_err(|error| io_error(path, error))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(path, error))
}

fn unix_millis() -> Result<u64, SandboxError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SandboxError::Runtime("system clock predates the Unix epoch".to_owned()))?
        .as_millis()
        .try_into()
        .map_err(|_| SandboxError::Runtime("snapshot timestamp overflow".to_owned()))
}

fn artifact_error(error: runtrue_sandbox_artifact::ArtifactError) -> SandboxError {
    SandboxError::Runtime(format!("artifact store: {error}"))
}

pub(super) fn publish(
    store: &dyn ArtifactStore,
    publication: SnapshotPublication,
    metadata: &GvisorSnapshotMetadata,
) -> Result<SnapshotSummary, SandboxError> {
    let source_sandbox = publication.manifest.sandbox_id.as_str().to_owned();
    let snapshot_id = publication.manifest.snapshot_id.clone();
    let files = publication.objects.len();
    let metrics = store.publish(publication).map_err(artifact_error)?;
    Ok(SnapshotSummary {
        snapshot_id,
        source_sandbox,
        topology_digest: metadata.topology_digest.clone(),
        mode: metadata.mode,
        files,
        size_bytes: metrics.logical_bytes,
        transferred_bytes: metrics.transferred_bytes,
        reused_objects: metrics.reused_objects,
        checkpoint_millis: 0,
        writable_export_millis: 0,
        publish_millis: metrics.publish_millis,
        source_cleanup_millis: 0,
        runtime_configuration_digest: metadata.runtime_configuration_digest.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_listing_rejects_nested_entries() {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::create_dir(directory.path().join("nested")).expect("nested directory");
        assert!(checkpoint_objects(directory.path()).is_err());
    }

    #[test]
    fn metadata_rejects_incomplete_service_state() {
        let metadata = GvisorSnapshotMetadata {
            schema_version: METADATA_VERSION,
            topology_digest: format!("sha256:{}", "a".repeat(64)),
            mode: SnapshotMode::StopAndMove,
            created_unix_millis: 1,
            runsc_version: "runsc test".to_owned(),
            runtime_configuration_digest: format!("sha256:{}", "b".repeat(64)),
            cpu_features_digest: format!("sha256:{}", "c".repeat(64)),
            root_service: "server".to_owned(),
            services: vec!["server".to_owned()],
            service_states: BTreeMap::new(),
            writable_services: BTreeMap::new(),
        };
        assert!(validate_metadata(&metadata).is_err());
    }
}
