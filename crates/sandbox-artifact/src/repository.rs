use crate::{
    backend::{BlobBackend, PutStatus},
    crypto::{describe, maximum_envelope_bytes, open, seal, EnvelopeKey},
    error::io_error,
    ArtifactError, ArtifactLimits, ArtifactScope, GarbageCollectionReport, MaterializedSnapshot,
    PublicationMetrics, SnapshotPublication, SnapshotTransferClaim, SnapshotTransferGrant,
};
use runtrue_sandbox_core::{
    ArtifactDescriptor, RestoreTarget, SnapshotId, SnapshotManifest, SnapshotObject,
    SnapshotPortability, VolumeSnapshotDescriptor,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder, OpenOptions},
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
    sync::{Arc, Condvar, Mutex},
    time::{Instant, SystemTime},
};

const POINTER_VERSION: u32 = 1;
const MANIFEST_MEDIA_TYPE: &str = "application/vnd.runtrue.snapshot.manifest.v4+json";
const MAXIMUM_POINTER_BYTES: u64 = 64 * 1024;
const MAXIMUM_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

pub trait ArtifactStore: Send + Sync {
    fn snapshot_portability(&self) -> SnapshotPortability;

    fn publish_transfer_grant(
        &self,
        scope: &ArtifactScope,
        snapshot_id: &SnapshotId,
    ) -> Result<SnapshotTransferGrant, ArtifactError>;

    fn claim_transfer(
        &self,
        scope: &ArtifactScope,
        snapshot_id: &SnapshotId,
        target: &RestoreTarget,
    ) -> Result<SnapshotTransferClaim, ArtifactError>;

    fn publish(
        &self,
        publication: SnapshotPublication,
    ) -> Result<PublicationMetrics, ArtifactError>;

    fn materialize(
        &self,
        scope: &ArtifactScope,
        snapshot_id: &SnapshotId,
        destination: &Path,
    ) -> Result<MaterializedSnapshot, ArtifactError>;

    fn exists(
        &self,
        scope: &ArtifactScope,
        snapshot_id: &SnapshotId,
    ) -> Result<bool, ArtifactError>;

    fn remove_reference(
        &self,
        scope: &ArtifactScope,
        snapshot_id: &SnapshotId,
    ) -> Result<(), ArtifactError>;

    fn garbage_collect(
        &self,
        scope: &ArtifactScope,
    ) -> Result<GarbageCollectionReport, ArtifactError>;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPointer {
    schema_version: u32,
    snapshot_id: SnapshotId,
    manifest: ArtifactDescriptor,
}

pub(crate) struct ArtifactRepository {
    backend: Arc<dyn BlobBackend>,
    envelope_key: EnvelopeKey,
    limits: ArtifactLimits,
    operations: OperationLimiter,
}

impl ArtifactRepository {
    pub(crate) fn new(
        backend: Arc<dyn BlobBackend>,
        master_key: [u8; 32],
        limits: ArtifactLimits,
    ) -> Result<Self, ArtifactError> {
        limits.validate()?;
        Ok(Self {
            backend,
            envelope_key: EnvelopeKey::new(master_key),
            operations: OperationLimiter::new(limits.maximum_concurrency),
            limits,
        })
    }

    pub(crate) fn publish(
        &self,
        mut publication: SnapshotPublication,
    ) -> Result<PublicationMetrics, ArtifactError> {
        let started = Instant::now();
        let deadline = deadline(started, self.limits.operation_timeout)?;
        let _permit = self.operations.acquire(deadline)?;
        publication.scope.validate_manifest(&publication.manifest)?;
        validate_unpopulated_manifest(&publication.manifest)?;
        if publication.objects.is_empty() || publication.objects.len() > self.limits.maximum_objects
        {
            return Err(ArtifactError::Invalid(
                "snapshot object count is outside the configured limit".to_owned(),
            ));
        }
        if self.backend.exists(
            &pointer_key(&publication.scope, &publication.manifest.snapshot_id),
            deadline,
        )? {
            return Err(ArtifactError::AlreadyExists(
                publication.manifest.snapshot_id.to_string(),
            ));
        }

        let temporary = tempfile::Builder::new()
            .prefix("sandbox-artifact-publish-")
            .tempdir()
            .map_err(|error| io_error("artifact publication staging", error))?;
        let mut logical_bytes = 0_u64;
        let mut transferred_bytes = 0_u64;
        let mut reused_objects = 0_usize;
        let mut names = BTreeSet::new();
        let mut containers = BTreeMap::new();
        let mut sandbox_objects = Vec::new();
        let mut volumes = BTreeMap::new();

        for (index, staged) in publication.objects.iter().enumerate() {
            check_deadline(deadline, "publish snapshot objects")?;
            validate_name(&staged.name)?;
            if staged.media_type.is_empty() || staged.media_type.len() > 256 {
                return Err(ArtifactError::Invalid(
                    "snapshot object media type is invalid".to_owned(),
                ));
            }
            if !names.insert(staged.name.clone()) {
                return Err(ArtifactError::Invalid(format!(
                    "duplicate snapshot object name `{}`",
                    staged.name
                )));
            }
            let metadata = fs::symlink_metadata(&staged.path)
                .map_err(|error| io_error(&staged.path, error))?;
            if !metadata.file_type().is_file() {
                return Err(ArtifactError::Invalid(
                    "snapshot object must be a regular file".to_owned(),
                ));
            }
            let mut descriptor = describe(&staged.path, self.limits.maximum_object_bytes)?;
            descriptor.media_type.clone_from(&staged.media_type);
            logical_bytes = logical_bytes
                .checked_add(descriptor.size_bytes)
                .ok_or_else(|| ArtifactError::Invalid("snapshot size overflow".to_owned()))?;
            if logical_bytes > self.limits.maximum_snapshot_bytes {
                return Err(ArtifactError::Invalid(
                    "snapshot exceeds the configured byte limit".to_owned(),
                ));
            }
            let sealed = temporary.path().join(format!("object-{index}.envelope"));
            let encrypted_bytes = seal(
                &staged.path,
                &sealed,
                &publication.scope,
                &descriptor,
                &self.envelope_key,
                deadline,
            )?;
            match self.backend.put_if_absent(
                &object_key(&publication.scope, &descriptor),
                &sealed,
                deadline,
            )? {
                PutStatus::Created => transferred_bytes += encrypted_bytes,
                PutStatus::Reused => reused_objects += 1,
            }
            let object = SnapshotObject {
                name: staged.name.clone(),
                role: staged.role,
                artifact: descriptor,
            };
            if let Some(volume) = &staged.volume {
                if staged.container.is_some()
                    || staged.role != runtrue_sandbox_core::ArtifactRole::VolumeData
                {
                    return Err(ArtifactError::Invalid(
                        "volume snapshot object has an invalid role or container".to_owned(),
                    ));
                }
                if volumes
                    .insert(
                        volume.volume_id.clone(),
                        VolumeSnapshotDescriptor {
                            schema_version: volume.schema_version,
                            provider_id: volume.provider_id.clone(),
                            persistence_class: volume.persistence_class,
                            portability: volume.portability,
                            object_name: staged.name.clone(),
                            artifact: object.artifact.clone(),
                        },
                    )
                    .is_some()
                {
                    return Err(ArtifactError::Invalid(format!(
                        "duplicate volume snapshot `{}`",
                        volume.volume_id
                    )));
                }
            } else if staged.role == runtrue_sandbox_core::ArtifactRole::VolumeData {
                return Err(ArtifactError::Invalid(
                    "volume snapshot object omitted its volume metadata".to_owned(),
                ));
            }
            if let Some(container) = &staged.container {
                containers
                    .entry(container.clone())
                    .or_insert_with(Vec::new)
                    .push(object);
            } else {
                sandbox_objects.push(object);
            }
        }
        publication.manifest.containers = containers;
        publication.manifest.sandbox_objects = sandbox_objects;
        publication.manifest.volumes = volumes;
        publication
            .manifest
            .validate()
            .map_err(|error| ArtifactError::Invalid(error.to_string()))?;

        let manifest_path = temporary.path().join("manifest.json");
        write_json(&manifest_path, &publication.manifest)?;
        let mut manifest_descriptor = describe(&manifest_path, MAXIMUM_MANIFEST_BYTES)?;
        manifest_descriptor.media_type = MANIFEST_MEDIA_TYPE.to_owned();
        let sealed_manifest = temporary.path().join("manifest.envelope");
        let manifest_encrypted_bytes = seal(
            &manifest_path,
            &sealed_manifest,
            &publication.scope,
            &manifest_descriptor,
            &self.envelope_key,
            deadline,
        )?;
        match self.backend.put_if_absent(
            &object_key(&publication.scope, &manifest_descriptor),
            &sealed_manifest,
            deadline,
        )? {
            PutStatus::Created => transferred_bytes += manifest_encrypted_bytes,
            PutStatus::Reused => reused_objects += 1,
        }

        let pointer = SnapshotPointer {
            schema_version: POINTER_VERSION,
            snapshot_id: publication.manifest.snapshot_id.clone(),
            manifest: manifest_descriptor,
        };
        let pointer_path = temporary.path().join("pointer.json");
        write_json(&pointer_path, &pointer)?;
        if fs::metadata(&pointer_path)
            .map_err(|error| io_error(&pointer_path, error))?
            .len()
            > MAXIMUM_POINTER_BYTES
        {
            return Err(ArtifactError::Invalid(
                "snapshot pointer exceeds its byte limit".to_owned(),
            ));
        }
        if self.backend.put_if_absent(
            &pointer_key(&publication.scope, &publication.manifest.snapshot_id),
            &pointer_path,
            deadline,
        )? == PutStatus::Reused
        {
            return Err(ArtifactError::AlreadyExists(
                publication.manifest.snapshot_id.to_string(),
            ));
        }
        transferred_bytes += fs::metadata(&pointer_path)
            .map_err(|error| io_error(&pointer_path, error))?
            .len();

        Ok(PublicationMetrics {
            snapshot_id: publication.manifest.snapshot_id,
            object_count: publication.objects.len(),
            logical_bytes,
            transferred_bytes,
            reused_objects,
            publish_millis: started.elapsed().as_millis(),
        })
    }

    pub(crate) fn publish_transfer_grant(
        &self,
        scope: &ArtifactScope,
        snapshot_id: &SnapshotId,
    ) -> Result<SnapshotTransferGrant, ArtifactError> {
        let deadline = deadline(Instant::now(), self.limits.operation_timeout)?;
        let _permit = self.operations.acquire(deadline)?;
        let temporary = tempfile::Builder::new()
            .prefix("sandbox-artifact-transfer-")
            .tempdir()
            .map_err(|error| io_error("artifact transfer staging", error))?;
        let (manifest, _) = self.load_manifest(scope, snapshot_id, temporary.path(), deadline)?;
        crate::transfer::publish_grant(
            self.backend.as_ref(),
            &self.envelope_key,
            scope,
            &manifest,
            temporary.path(),
            deadline,
        )
    }

    pub(crate) fn claim_transfer(
        &self,
        scope: &ArtifactScope,
        snapshot_id: &SnapshotId,
        target: &RestoreTarget,
    ) -> Result<SnapshotTransferClaim, ArtifactError> {
        let deadline = deadline(Instant::now(), self.limits.operation_timeout)?;
        let _permit = self.operations.acquire(deadline)?;
        let temporary = tempfile::Builder::new()
            .prefix("sandbox-artifact-claim-")
            .tempdir()
            .map_err(|error| io_error("artifact claim staging", error))?;
        let (manifest, _) = self.load_manifest(scope, snapshot_id, temporary.path(), deadline)?;
        crate::transfer::claim(
            self.backend.as_ref(),
            &self.envelope_key,
            scope,
            &manifest,
            target,
            temporary.path(),
            deadline,
        )
    }

    pub(crate) fn materialize(
        &self,
        scope: &ArtifactScope,
        snapshot_id: &SnapshotId,
        destination: &Path,
    ) -> Result<MaterializedSnapshot, ArtifactError> {
        let started = Instant::now();
        let deadline = deadline(started, self.limits.operation_timeout)?;
        let _permit = self.operations.acquire(deadline)?;
        if !destination.is_absolute() || destination.exists() {
            return Err(ArtifactError::Invalid(
                "materialization destination must be an absent absolute path".to_owned(),
            ));
        }
        let parent = destination.parent().ok_or_else(|| {
            ArtifactError::Invalid("materialization destination has no parent".to_owned())
        })?;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|error| io_error(parent, error))?;
        let temporary = tempfile::Builder::new()
            .prefix(".sandbox-artifact-restore-")
            .tempdir_in(parent)
            .map_err(|error| io_error(parent, error))?;
        let (manifest, mut transferred_bytes) =
            self.load_manifest(scope, snapshot_id, temporary.path(), deadline)?;
        let objects = manifest
            .containers
            .values()
            .flatten()
            .chain(manifest.sandbox_objects.iter())
            .collect::<Vec<_>>();
        if objects.len() > self.limits.maximum_objects {
            return Err(ArtifactError::Invalid(
                "snapshot object count exceeds the configured limit".to_owned(),
            ));
        }
        let total = objects.iter().try_fold(0_u64, |total, object| {
            if object.artifact.size_bytes > self.limits.maximum_object_bytes {
                return Err(ArtifactError::Invalid(
                    "snapshot object exceeds the configured byte limit".to_owned(),
                ));
            }
            total
                .checked_add(object.artifact.size_bytes)
                .ok_or_else(|| ArtifactError::Invalid("snapshot size overflow".to_owned()))
        })?;
        if total > self.limits.maximum_snapshot_bytes {
            return Err(ArtifactError::Invalid(
                "snapshot exceeds the configured byte limit".to_owned(),
            ));
        }
        let output = temporary.path().join("runtime");
        DirBuilder::new()
            .mode(0o700)
            .create(&output)
            .map_err(|error| io_error(&output, error))?;
        let mut names = BTreeSet::new();
        for (index, object) in objects.iter().enumerate() {
            check_deadline(deadline, "materialize snapshot objects")?;
            validate_name(&object.name)?;
            if !names.insert(object.name.clone()) {
                return Err(ArtifactError::Integrity(
                    "snapshot manifest contains duplicate object names".to_owned(),
                ));
            }
            let encrypted = temporary.path().join(format!("download-{index}.envelope"));
            transferred_bytes += self.backend.get(
                &object_key(scope, &object.artifact),
                &encrypted,
                maximum_envelope_bytes(object.artifact.size_bytes)?,
                deadline,
            )?;
            let plaintext = output.join(&object.name);
            open(
                &encrypted,
                &plaintext,
                scope,
                &object.artifact,
                &self.envelope_key,
                deadline,
            )?;
            fs::set_permissions(&plaintext, fs::Permissions::from_mode(0o400))
                .map_err(|error| io_error(&plaintext, error))?;
        }
        fs::File::open(&output)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error(&output, error))?;
        fs::rename(&output, destination).map_err(|error| io_error(destination, error))?;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o500))
            .map_err(|error| io_error(destination, error))?;
        fs::File::open(destination)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error(destination, error))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error(parent, error))?;
        Ok(MaterializedSnapshot {
            manifest,
            directory: destination.to_owned(),
            transferred_bytes,
            materialization_millis: started.elapsed().as_millis(),
        })
    }

    pub(crate) fn exists(
        &self,
        scope: &ArtifactScope,
        snapshot_id: &SnapshotId,
    ) -> Result<bool, ArtifactError> {
        let deadline = deadline(Instant::now(), self.limits.operation_timeout)?;
        self.backend
            .exists(&pointer_key(scope, snapshot_id), deadline)
    }

    pub(crate) fn remove_reference(
        &self,
        scope: &ArtifactScope,
        snapshot_id: &SnapshotId,
    ) -> Result<(), ArtifactError> {
        let deadline = deadline(Instant::now(), self.limits.operation_timeout)?;
        let _permit = self.operations.acquire(deadline)?;
        self.backend
            .delete(&pointer_key(scope, snapshot_id), deadline)
    }

    pub(crate) fn garbage_collect(
        &self,
        scope: &ArtifactScope,
    ) -> Result<GarbageCollectionReport, ArtifactError> {
        let started = Instant::now();
        let deadline = deadline(started, self.limits.operation_timeout)?;
        let _permit = self.operations.acquire(deadline)?;
        let temporary = tempfile::Builder::new()
            .prefix("sandbox-artifact-gc-")
            .tempdir()
            .map_err(|error| io_error("artifact garbage collection", error))?;
        let mut reachable = BTreeSet::new();
        let mut referenced_snapshots = BTreeSet::new();
        for pointer in self.backend.list(
            &snapshot_prefix(scope),
            self.limits.maximum_listing_entries,
            deadline,
        )? {
            check_deadline(deadline, "scan snapshot references")?;
            let snapshot_id = snapshot_id_from_pointer_key(&pointer.key)?;
            referenced_snapshots.insert(snapshot_id.clone());
            let (manifest, _) =
                self.load_manifest(scope, &snapshot_id, temporary.path(), deadline)?;
            let (pointer, _) =
                self.read_pointer(scope, &snapshot_id, temporary.path(), deadline)?;
            reachable.insert(object_key(scope, &pointer.manifest));
            for object in manifest
                .containers
                .values()
                .flatten()
                .chain(manifest.sandbox_objects.iter())
            {
                reachable.insert(object_key(scope, &object.artifact));
            }
        }
        let cutoff = SystemTime::now()
            .checked_sub(self.limits.garbage_collection_grace)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let mut report = GarbageCollectionReport::default();
        for object in self.backend.list(
            &object_prefix(scope),
            self.limits.maximum_listing_entries,
            deadline,
        )? {
            check_deadline(deadline, "collect snapshot objects")?;
            if reachable.contains(&object.key) || object.modified > cutoff {
                report.retained_objects += 1;
            } else {
                self.backend.delete(&object.key, deadline)?;
                report.removed_unreferenced_objects += 1;
            }
        }
        for object in self.backend.list(
            &staging_prefix(scope),
            self.limits.maximum_listing_entries,
            deadline,
        )? {
            check_deadline(deadline, "collect abandoned staging objects")?;
            if object.modified <= cutoff {
                self.backend.delete(&object.key, deadline)?;
                report.removed_staging_objects += 1;
            }
        }
        for object in self.backend.list(
            &transfer_prefix(scope),
            self.limits.maximum_listing_entries,
            deadline,
        )? {
            check_deadline(deadline, "collect snapshot transfer records")?;
            let snapshot_id = snapshot_id_from_transfer_key(scope, &object.key)?;
            if referenced_snapshots.contains(&snapshot_id) || object.modified > cutoff {
                report.retained_transfer_objects += 1;
            } else {
                self.backend.delete(&object.key, deadline)?;
                report.removed_transfer_objects += 1;
            }
        }
        Ok(report)
    }

    fn load_manifest(
        &self,
        scope: &ArtifactScope,
        snapshot_id: &SnapshotId,
        temporary: &Path,
        deadline: Instant,
    ) -> Result<(SnapshotManifest, u64), ArtifactError> {
        let (pointer, pointer_bytes) =
            self.read_pointer(scope, snapshot_id, temporary, deadline)?;
        if pointer.manifest.media_type != MANIFEST_MEDIA_TYPE
            || pointer.manifest.size_bytes > MAXIMUM_MANIFEST_BYTES
        {
            return Err(ArtifactError::Integrity(
                "snapshot manifest descriptor is invalid".to_owned(),
            ));
        }
        let encrypted = temporary.join(format!("manifest-{}.envelope", snapshot_id.as_str()));
        let transferred = pointer_bytes
            + self.backend.get(
                &object_key(scope, &pointer.manifest),
                &encrypted,
                maximum_envelope_bytes(pointer.manifest.size_bytes)?,
                deadline,
            )?;
        let plaintext = temporary.join(format!("manifest-{}.json", snapshot_id.as_str()));
        open(
            &encrypted,
            &plaintext,
            scope,
            &pointer.manifest,
            &self.envelope_key,
            deadline,
        )?;
        let bytes = fs::read(&plaintext).map_err(|error| io_error(&plaintext, error))?;
        let manifest: SnapshotManifest = serde_json::from_slice(&bytes).map_err(|error| {
            ArtifactError::Integrity(format!("decode snapshot manifest: {error}"))
        })?;
        if &manifest.snapshot_id != snapshot_id {
            return Err(ArtifactError::Integrity(
                "snapshot manifest identity does not match its reference".to_owned(),
            ));
        }
        scope.validate_manifest(&manifest)?;
        manifest
            .validate()
            .map_err(|error| ArtifactError::Integrity(error.to_string()))?;
        Ok((manifest, transferred))
    }

    fn read_pointer(
        &self,
        scope: &ArtifactScope,
        snapshot_id: &SnapshotId,
        temporary: &Path,
        deadline: Instant,
    ) -> Result<(SnapshotPointer, u64), ArtifactError> {
        let path = temporary.join(format!("pointer-{}.json", snapshot_id.as_str()));
        if path.exists() {
            fs::remove_file(&path).map_err(|error| io_error(&path, error))?;
        }
        let bytes = self.backend.get(
            &pointer_key(scope, snapshot_id),
            &path,
            MAXIMUM_POINTER_BYTES,
            deadline,
        )?;
        if bytes > MAXIMUM_POINTER_BYTES {
            return Err(ArtifactError::Integrity(
                "snapshot pointer exceeds its byte limit".to_owned(),
            ));
        }
        let pointer: SnapshotPointer =
            serde_json::from_slice(&fs::read(&path).map_err(|error| io_error(&path, error))?)
                .map_err(|error| {
                    ArtifactError::Integrity(format!("decode snapshot pointer: {error}"))
                })?;
        if pointer.schema_version != POINTER_VERSION || &pointer.snapshot_id != snapshot_id {
            return Err(ArtifactError::Integrity(
                "snapshot pointer identity is invalid".to_owned(),
            ));
        }
        Ok((pointer, bytes))
    }
}

fn validate_unpopulated_manifest(manifest: &SnapshotManifest) -> Result<(), ArtifactError> {
    if !manifest.containers.is_empty()
        || !manifest.sandbox_objects.is_empty()
        || !manifest.volumes.is_empty()
    {
        return Err(ArtifactError::Invalid(
            "publication manifest must not contain caller-supplied object descriptors".to_owned(),
        ));
    }
    if manifest.schema_version != runtrue_sandbox_core::SNAPSHOT_MANIFEST_VERSION
        || manifest.source_assignment_epoch == 0
        || manifest.created_unix_millis == 0
    {
        return Err(ArtifactError::Invalid(
            "snapshot manifest provenance is incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), ArtifactError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ArtifactError::Invalid(
            "snapshot object name is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), ArtifactError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ArtifactError::Storage(format!("encode artifact metadata: {error}")))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| io_error(path, error))?;
    file.write_all(&bytes)
        .map_err(|error| io_error(path, error))?;
    file.sync_all().map_err(|error| io_error(path, error))
}

fn object_key(scope: &ArtifactScope, descriptor: &ArtifactDescriptor) -> String {
    let digest = descriptor
        .digest
        .strip_prefix("sha256:")
        .unwrap_or("invalid");
    let media = Sha256::digest(descriptor.media_type.as_bytes());
    format!(
        "{}/objects/sha256/{}/{}.envelope",
        scope.storage_prefix(),
        digest,
        hex::encode(&media[..8])
    )
}

fn object_prefix(scope: &ArtifactScope) -> String {
    format!("{}/objects", scope.storage_prefix())
}

fn pointer_key(scope: &ArtifactScope, snapshot_id: &SnapshotId) -> String {
    format!(
        "{}/snapshots/{}.json",
        scope.storage_prefix(),
        snapshot_id.as_str()
    )
}

fn snapshot_prefix(scope: &ArtifactScope) -> String {
    format!("{}/snapshots", scope.storage_prefix())
}

pub(crate) fn staging_prefix(scope: &ArtifactScope) -> String {
    format!("{}/staging", scope.storage_prefix())
}

fn transfer_prefix(scope: &ArtifactScope) -> String {
    format!("{}/transfers", scope.storage_prefix())
}

fn snapshot_id_from_transfer_key(
    scope: &ArtifactScope,
    key: &str,
) -> Result<SnapshotId, ArtifactError> {
    let prefix = format!("{}/transfers/", scope.storage_prefix());
    let suffix = key.strip_prefix(&prefix).ok_or_else(|| {
        ArtifactError::Integrity("snapshot transfer key escaped its tenant scope".to_owned())
    })?;
    let (snapshot_id, name) = suffix
        .split_once('/')
        .ok_or_else(|| ArtifactError::Integrity("snapshot transfer key is malformed".to_owned()))?;
    if !matches!(name, "grant.json" | "grant.envelope" | "claim.envelope") {
        return Err(ArtifactError::Integrity(
            "snapshot transfer key is malformed".to_owned(),
        ));
    }
    SnapshotId::parse(snapshot_id).map_err(|error| ArtifactError::Integrity(error.to_string()))
}

fn snapshot_id_from_pointer_key(key: &str) -> Result<SnapshotId, ArtifactError> {
    let name = key
        .rsplit('/')
        .next()
        .ok_or_else(|| ArtifactError::Integrity("snapshot pointer key is malformed".to_owned()))?;
    let value = name
        .strip_suffix(".json")
        .ok_or_else(|| ArtifactError::Integrity("snapshot pointer key is malformed".to_owned()))?;
    SnapshotId::parse(value).map_err(|error| ArtifactError::Integrity(error.to_string()))
}

fn deadline(started: Instant, timeout: std::time::Duration) -> Result<Instant, ArtifactError> {
    started
        .checked_add(timeout)
        .ok_or_else(|| ArtifactError::Invalid("artifact operation deadline overflow".to_owned()))
}

fn check_deadline(deadline: Instant, operation: &str) -> Result<(), ArtifactError> {
    if Instant::now() >= deadline {
        return Err(ArtifactError::Timeout(operation.to_owned()));
    }
    Ok(())
}

struct OperationLimiter {
    maximum: usize,
    active: Mutex<usize>,
    available: Condvar,
}

impl OperationLimiter {
    fn new(maximum: usize) -> Self {
        Self {
            maximum,
            active: Mutex::new(0),
            available: Condvar::new(),
        }
    }

    fn acquire(&self, deadline: Instant) -> Result<OperationPermit<'_>, ArtifactError> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        while *active >= self.maximum {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ArtifactError::Timeout(
                    "wait for artifact-store concurrency permit".to_owned(),
                ));
            }
            let (guard, wait) = self
                .available
                .wait_timeout(active, remaining)
                .unwrap_or_else(|error| error.into_inner());
            active = guard;
            if wait.timed_out() && *active >= self.maximum {
                return Err(ArtifactError::Timeout(
                    "wait for artifact-store concurrency permit".to_owned(),
                ));
            }
        }
        *active += 1;
        Ok(OperationPermit { limiter: self })
    }
}

struct OperationPermit<'a> {
    limiter: &'a OperationLimiter,
}

impl Drop for OperationPermit<'_> {
    fn drop(&mut self) {
        let mut active = self
            .limiter
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *active -= 1;
        self.limiter.available.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalArtifactStore, StagedSnapshotObject, StagedVolumeMetadata};
    use runtrue_sandbox_core::{
        ArtifactRole, BackendDescriptor, BackendKind, ContainerId, LifecycleState, SandboxId,
        SnapshotMode, SnapshotPortability, TenantId, VolumeId, VolumePersistenceClass, WorkerId,
        WorkspaceId,
    };
    use std::{
        fs,
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
        thread,
        time::{Duration, SystemTime},
    };

    const MASTER_KEY: [u8; 32] = [0x5a; 32];

    struct Fixture {
        _directory: tempfile::TempDir,
        publication: SnapshotPublication,
        expected: BTreeMap<String, Vec<u8>>,
    }

    fn scope(tenant: &str) -> ArtifactScope {
        ArtifactScope::new(
            TenantId::parse(tenant).expect("tenant"),
            WorkspaceId::parse("team-a").expect("workspace"),
        )
    }

    fn fixture(snapshot: &str, tenant: &str) -> Fixture {
        let directory = tempfile::tempdir().expect("fixture directory");
        let runtime = directory.path().join("state.img");
        let metadata = directory.path().join("service.json");
        let runtime_bytes = vec![0x41; 1024 * 1024 + 17];
        let metadata_bytes = br#"{"state":"paused"}"#.to_vec();
        fs::write(&runtime, &runtime_bytes).expect("runtime object");
        fs::write(&metadata, &metadata_bytes).expect("metadata object");
        let scope = scope(tenant);
        let manifest = SnapshotManifest {
            schema_version: runtrue_sandbox_core::SNAPSHOT_MANIFEST_VERSION,
            snapshot_id: SnapshotId::parse(snapshot).expect("snapshot"),
            tenant_id: scope.tenant_id().clone(),
            workspace_id: scope.workspace_id().clone(),
            sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox"),
            sandbox_spec_digest: format!("sha256:{}", "a".repeat(64)),
            source_worker: WorkerId::parse("worker-a").expect("worker"),
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
            restore_requirements: runtrue_sandbox_core::RestoreRequirements {
                architecture: "amd64".to_owned(),
                operating_system: "linux".to_owned(),
                minimum_backend_version: "test".to_owned(),
                portability: SnapshotPortability::CrossWorkerSameBackend,
                required_cpu_features: Vec::new(),
                cpu_features_digest: format!("sha256:{}", "c".repeat(64)),
                preserves_internal_connections: true,
                guest_profile: runtrue_sandbox_core::GuestProfile::strict().identity,
            },
            containers: BTreeMap::new(),
            sandbox_objects: Vec::new(),
            volumes: BTreeMap::new(),
        };
        Fixture {
            _directory: directory,
            publication: SnapshotPublication {
                scope,
                manifest,
                objects: vec![
                    StagedSnapshotObject {
                        role: ArtifactRole::RuntimeState,
                        container: None,
                        name: "state.img".to_owned(),
                        path: runtime,
                        media_type: "application/vnd.runtrue.test.runtime".to_owned(),
                        volume: None,
                    },
                    StagedSnapshotObject {
                        role: ArtifactRole::BackendMetadata,
                        container: Some(ContainerId::parse("server").expect("container")),
                        name: "service.json".to_owned(),
                        path: metadata,
                        media_type: "application/vnd.runtrue.test.metadata+json".to_owned(),
                        volume: None,
                    },
                ],
            },
            expected: BTreeMap::from([
                ("state.img".to_owned(), runtime_bytes),
                ("service.json".to_owned(), metadata_bytes),
            ]),
        }
    }

    fn assert_conformance(store: &dyn ArtifactStore, fixture: &Fixture, destination: &Path) {
        let metrics = store
            .publish(fixture.publication.clone())
            .expect("publish snapshot");
        assert_eq!(metrics.object_count, 2);
        assert!(store
            .exists(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id
            )
            .expect("snapshot existence"));
        assert!(matches!(
            store.publish(fixture.publication.clone()),
            Err(ArtifactError::AlreadyExists(_))
        ));
        let materialized = store
            .materialize(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
                destination,
            )
            .expect("materialize snapshot");
        assert_eq!(
            materialized.manifest.snapshot_id,
            fixture.publication.manifest.snapshot_id
        );
        for (name, bytes) in &fixture.expected {
            let path = destination.join(name);
            assert_eq!(fs::read(&path).expect("object"), *bytes);
            assert_eq!(
                fs::metadata(path)
                    .expect("object metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
        }
        assert_eq!(
            fs::metadata(destination)
                .expect("materialized directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o500
        );
    }

    #[test]
    fn local_backend_conforms_to_publish_and_materialize_contract() {
        let directory = tempfile::tempdir().expect("artifact root parent");
        let store = LocalArtifactStore::new(
            directory.path().join("artifacts"),
            MASTER_KEY,
            ArtifactLimits::default(),
        )
        .expect("local store");
        assert_eq!(
            store.snapshot_portability(),
            SnapshotPortability::SameWorker
        );
        let fixture = fixture("snapshot-local", "tenant-a");
        assert_conformance(&store, &fixture, &directory.path().join("materialized"));
        let grant = store
            .publish_transfer_grant(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
            )
            .expect("local transfer grant");
        store
            .claim_transfer(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
                &RestoreTarget {
                    tenant_id: grant.tenant_id,
                    workspace_id: grant.workspace_id,
                    sandbox_id: grant.sandbox_id,
                    worker_id: WorkerId::parse("worker-b").expect("worker"),
                    assignment_epoch: runtrue_sandbox_core::AssignmentEpoch::new(8).expect("epoch"),
                    artifact_portability: SnapshotPortability::CrossWorkerSameBackend,
                    guest_profile: runtrue_sandbox_core::GuestProfile::strict().identity,
                    fenced_source_epoch: None,
                },
            )
            .expect("local transfer claim contract");
    }

    #[test]
    fn publication_binds_volume_metadata_to_its_content_object() {
        let directory = tempfile::tempdir().expect("artifact root parent");
        let store = LocalArtifactStore::new(
            directory.path().join("artifacts"),
            MASTER_KEY,
            ArtifactLimits::default(),
        )
        .expect("local store");
        let mut fixture = fixture("snapshot-volume", "tenant-a");
        let volume_path = fixture._directory.path().join("volume.ext4");
        fs::write(&volume_path, vec![0x5a; 4096]).expect("volume object");
        fixture.publication.objects.push(StagedSnapshotObject {
            role: ArtifactRole::VolumeData,
            container: None,
            name: "volume-database.ext4".to_owned(),
            path: volume_path,
            media_type: "application/vnd.runtrue.volume.ext4.v1".to_owned(),
            volume: Some(StagedVolumeMetadata {
                schema_version: 1,
                volume_id: VolumeId::parse("database").expect("volume"),
                provider_id: "local-loopback-v1".to_owned(),
                persistence_class: VolumePersistenceClass::Persistent,
                portability: SnapshotPortability::CrossWorkerSameBackend,
            }),
        });
        store
            .publish(fixture.publication.clone())
            .expect("publish volume snapshot");
        let materialized = store
            .materialize(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
                &directory.path().join("materialized-volume"),
            )
            .expect("materialize volume snapshot");
        let descriptor =
            &materialized.manifest.volumes[&VolumeId::parse("database").expect("volume")];
        assert_eq!(descriptor.object_name, "volume-database.ext4");
        assert_eq!(descriptor.artifact.size_bytes, 4096);
    }

    #[test]
    fn tenant_scope_is_cryptographically_bound() {
        let directory = tempfile::tempdir().expect("artifact root parent");
        let root = directory.path().join("artifacts");
        let store = LocalArtifactStore::new(root.clone(), MASTER_KEY, ArtifactLimits::default())
            .expect("local store");
        let fixture = fixture("snapshot-scope", "tenant-a");
        store
            .publish(fixture.publication.clone())
            .expect("publish snapshot");
        let source = root.join("tenants/tenant-a/workspaces/team-a");
        let target = root.join("tenants/tenant-b/workspaces/team-a");
        copy_tree(&source, &target);
        let result = store.materialize(
            &scope("tenant-b"),
            &fixture.publication.manifest.snapshot_id,
            &directory.path().join("cross-tenant"),
        );
        assert!(matches!(
            result,
            Err(ArtifactError::Integrity(_) | ArtifactError::AccessDenied(_))
        ));
    }

    #[test]
    fn corrupted_envelope_is_rejected_and_destination_is_not_published() {
        use std::io::{Read as _, Seek as _, SeekFrom};

        let directory = tempfile::tempdir().expect("artifact root parent");
        let root = directory.path().join("artifacts");
        let store = LocalArtifactStore::new(root.clone(), MASTER_KEY, ArtifactLimits::default())
            .expect("local store");
        let fixture = fixture("snapshot-corrupt", "tenant-a");
        store
            .publish(fixture.publication.clone())
            .expect("publish snapshot");
        let objects = root.join("tenants/tenant-a/workspaces/team-a/objects");
        let envelope = regular_files(&objects)
            .into_iter()
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("envelope"))
            .expect("encrypted object");
        fs::set_permissions(&envelope, fs::Permissions::from_mode(0o600))
            .expect("make disposable envelope writable");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&envelope)
            .expect("open envelope");
        file.seek(SeekFrom::End(-1)).expect("seek envelope");
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).expect("read envelope byte");
        file.seek(SeekFrom::End(-1)).expect("seek envelope");
        file.write_all(&[byte[0] ^ 0xff]).expect("corrupt envelope");
        file.sync_all().expect("sync corruption");
        let destination = directory.path().join("corrupted-restore");
        assert!(store
            .materialize(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
                &destination,
            )
            .is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn truncated_envelope_is_rejected() {
        let directory = tempfile::tempdir().expect("artifact root parent");
        let root = directory.path().join("artifacts");
        let store = LocalArtifactStore::new(root.clone(), MASTER_KEY, ArtifactLimits::default())
            .expect("local store");
        let fixture = fixture("snapshot-truncated", "tenant-a");
        store
            .publish(fixture.publication.clone())
            .expect("publish snapshot");
        let envelope = regular_files(&root.join("tenants/tenant-a/workspaces/team-a/objects"))
            .into_iter()
            .next()
            .expect("encrypted object");
        fs::set_permissions(&envelope, fs::Permissions::from_mode(0o600))
            .expect("make disposable envelope writable");
        let length = fs::metadata(&envelope).expect("envelope metadata").len();
        OpenOptions::new()
            .write(true)
            .open(&envelope)
            .expect("open envelope")
            .set_len(length - 1)
            .expect("truncate envelope");
        assert!(matches!(
            store.materialize(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
                &directory.path().join("truncated-restore"),
            ),
            Err(ArtifactError::Integrity(_))
        ));
    }

    #[test]
    fn concurrent_duplicate_publication_has_one_winner() {
        let directory = tempfile::tempdir().expect("artifact root parent");
        let store = Arc::new(
            LocalArtifactStore::new(
                directory.path().join("artifacts"),
                MASTER_KEY,
                ArtifactLimits::default(),
            )
            .expect("local store"),
        );
        let fixture = fixture("snapshot-race", "tenant-a");
        let publications = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                let publication = fixture.publication.clone();
                thread::spawn(move || store.publish(publication))
            })
            .collect::<Vec<_>>();
        let results = publications
            .into_iter()
            .map(|thread| thread.join().expect("publisher thread"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ArtifactError::AlreadyExists(_))))
                .count(),
            7
        );
    }

    #[test]
    fn unreferenced_objects_are_garbage_collected() {
        let directory = tempfile::tempdir().expect("artifact root parent");
        let limits = ArtifactLimits {
            operation_timeout: Duration::from_secs(2),
            garbage_collection_grace: Duration::from_secs(2),
            ..ArtifactLimits::default()
        };
        let store = LocalArtifactStore::new(directory.path().join("artifacts"), MASTER_KEY, limits)
            .expect("local store");
        let fixture = fixture("snapshot-gc", "tenant-a");
        store
            .publish(fixture.publication.clone())
            .expect("publish snapshot");
        let grant = store
            .publish_transfer_grant(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
            )
            .expect("publish transfer grant");
        store
            .claim_transfer(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
                &RestoreTarget {
                    tenant_id: grant.tenant_id,
                    workspace_id: grant.workspace_id,
                    sandbox_id: grant.sandbox_id,
                    worker_id: WorkerId::parse("worker-b").expect("worker"),
                    assignment_epoch: runtrue_sandbox_core::AssignmentEpoch::new(8).expect("epoch"),
                    artifact_portability: SnapshotPortability::CrossWorkerSameBackend,
                    guest_profile: runtrue_sandbox_core::GuestProfile::strict().identity,
                    fenced_source_epoch: None,
                },
            )
            .expect("claim transfer");
        store
            .remove_reference(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
            )
            .expect("remove reference");
        thread::sleep(Duration::from_millis(2_100));
        let report = store
            .garbage_collect(&fixture.publication.scope)
            .expect("garbage collection");
        assert!(report.removed_unreferenced_objects >= 3);
        assert_eq!(report.removed_transfer_objects, 3);
        assert_eq!(report.retained_objects, 0);
        assert_eq!(report.retained_transfer_objects, 0);
    }

    #[test]
    fn interrupted_publication_never_creates_a_snapshot_reference() {
        let backend = Arc::new(FaultBackend::new(2));
        let limits = ArtifactLimits::default();
        let repository =
            ArtifactRepository::new(backend, MASTER_KEY, limits).expect("artifact repository");
        let fixture = fixture("snapshot-interrupted", "tenant-a");
        assert!(matches!(
            repository.publish(fixture.publication.clone()),
            Err(ArtifactError::Storage(_))
        ));
        assert!(!repository
            .exists(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id
            )
            .expect("snapshot existence"));
        let report = repository
            .garbage_collect(&fixture.publication.scope)
            .expect("garbage collection");
        assert_eq!(report.removed_unreferenced_objects, 1);
    }

    #[test]
    fn interrupted_download_never_publishes_a_partial_directory() {
        let backend = Arc::new(FaultBackend::new(usize::MAX));
        let repository =
            ArtifactRepository::new(backend.clone(), MASTER_KEY, ArtifactLimits::default())
                .expect("artifact repository");
        let fixture = fixture("snapshot-download", "tenant-a");
        repository
            .publish(fixture.publication.clone())
            .expect("publish snapshot");
        backend.interrupt_next_download();
        let directory = tempfile::tempdir().expect("restore parent");
        let destination = directory.path().join("interrupted");
        assert!(repository
            .materialize(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
                &destination,
            )
            .is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn transfer_claim_has_one_destination_and_is_idempotent_for_its_owner() {
        let backend = Arc::new(FaultBackend::new(usize::MAX));
        let repository = ArtifactRepository::new(backend, MASTER_KEY, ArtifactLimits::default())
            .expect("artifact repository");
        let fixture = fixture("snapshot-transfer", "tenant-a");
        repository
            .publish(fixture.publication.clone())
            .expect("publish snapshot");
        let grant = repository
            .publish_transfer_grant(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
            )
            .expect("publish transfer grant");
        assert_eq!(grant.source_assignment_epoch.get(), 7);
        let target = RestoreTarget {
            tenant_id: grant.tenant_id.clone(),
            workspace_id: grant.workspace_id.clone(),
            sandbox_id: grant.sandbox_id.clone(),
            worker_id: WorkerId::parse("worker-b").expect("worker"),
            assignment_epoch: runtrue_sandbox_core::AssignmentEpoch::new(8).expect("epoch"),
            artifact_portability: SnapshotPortability::CrossWorkerSameBackend,
            guest_profile: runtrue_sandbox_core::GuestProfile::strict().identity,
            fenced_source_epoch: None,
        };
        let claim = repository
            .claim_transfer(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
                &target,
            )
            .expect("claim transfer");
        assert_eq!(claim.destination_worker, target.worker_id);
        assert_eq!(
            repository
                .claim_transfer(
                    &fixture.publication.scope,
                    &fixture.publication.manifest.snapshot_id,
                    &target,
                )
                .expect("repeat owner claim"),
            claim
        );

        let competing = RestoreTarget {
            worker_id: WorkerId::parse("worker-c").expect("worker"),
            assignment_epoch: runtrue_sandbox_core::AssignmentEpoch::new(9).expect("epoch"),
            ..target
        };
        assert!(matches!(
            repository.claim_transfer(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
                &competing,
            ),
            Err(ArtifactError::AlreadyExists(_))
        ));
    }

    #[test]
    fn live_snapshot_cannot_receive_a_transfer_grant() {
        let backend = Arc::new(FaultBackend::new(usize::MAX));
        let repository = ArtifactRepository::new(backend, MASTER_KEY, ArtifactLimits::default())
            .expect("artifact repository");
        let mut fixture = fixture("snapshot-live", "tenant-a");
        fixture.publication.manifest.mode = SnapshotMode::Live;
        repository
            .publish(fixture.publication.clone())
            .expect("publish snapshot");
        assert!(matches!(
            repository.publish_transfer_grant(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
            ),
            Err(ArtifactError::Invalid(_))
        ));
    }

    #[test]
    fn interrupted_transfer_grant_never_becomes_claimable() {
        let backend = Arc::new(FaultBackend::new(6));
        let repository = ArtifactRepository::new(backend, MASTER_KEY, ArtifactLimits::default())
            .expect("artifact repository");
        let fixture = fixture("snapshot-transfer-interrupted", "tenant-a");
        repository
            .publish(fixture.publication.clone())
            .expect("publish snapshot");
        assert!(repository
            .publish_transfer_grant(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
            )
            .is_err());
        let target = RestoreTarget {
            tenant_id: fixture.publication.manifest.tenant_id.clone(),
            workspace_id: fixture.publication.manifest.workspace_id.clone(),
            sandbox_id: fixture.publication.manifest.sandbox_id.clone(),
            worker_id: WorkerId::parse("worker-b").expect("worker"),
            assignment_epoch: runtrue_sandbox_core::AssignmentEpoch::new(8).expect("epoch"),
            artifact_portability: SnapshotPortability::CrossWorkerSameBackend,
            guest_profile: runtrue_sandbox_core::GuestProfile::strict().identity,
            fenced_source_epoch: None,
        };
        assert!(repository
            .claim_transfer(
                &fixture.publication.scope,
                &fixture.publication.manifest.snapshot_id,
                &target,
            )
            .is_err());
    }

    #[test]
    fn garbage_collection_keeps_objects_referenced_by_another_snapshot() {
        let directory = tempfile::tempdir().expect("artifact root parent");
        let limits = ArtifactLimits {
            operation_timeout: Duration::from_secs(2),
            garbage_collection_grace: Duration::from_secs(2),
            ..ArtifactLimits::default()
        };
        let store = LocalArtifactStore::new(directory.path().join("artifacts"), MASTER_KEY, limits)
            .expect("local store");
        let first = fixture("snapshot-first", "tenant-a");
        let second = fixture("snapshot-second", "tenant-a");
        store
            .publish(first.publication.clone())
            .expect("publish first snapshot");
        store
            .publish(second.publication.clone())
            .expect("publish second snapshot");
        store
            .remove_reference(
                &first.publication.scope,
                &first.publication.manifest.snapshot_id,
            )
            .expect("remove first reference");
        thread::sleep(Duration::from_millis(2_100));
        let report = store
            .garbage_collect(&first.publication.scope)
            .expect("garbage collection");
        assert!(report.removed_unreferenced_objects >= 1);
        store
            .materialize(
                &second.publication.scope,
                &second.publication.manifest.snapshot_id,
                &directory.path().join("second-restore"),
            )
            .expect("second snapshot remains restorable");
    }

    #[test]
    fn concurrency_wait_is_bounded_by_the_operation_deadline() {
        let limiter = OperationLimiter::new(1);
        let _first = limiter
            .acquire(Instant::now() + std::time::Duration::from_secs(1))
            .expect("first permit");
        let result = limiter.acquire(Instant::now() + std::time::Duration::from_millis(1));
        assert!(matches!(result, Err(ArtifactError::Timeout(_))));
    }

    struct FaultBackend {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        puts: AtomicUsize,
        fail_put: usize,
        interrupt_download: AtomicBool,
    }

    impl FaultBackend {
        fn new(fail_put: usize) -> Self {
            Self {
                objects: Mutex::new(BTreeMap::new()),
                puts: AtomicUsize::new(0),
                fail_put,
                interrupt_download: AtomicBool::new(false),
            }
        }

        fn interrupt_next_download(&self) {
            self.interrupt_download.store(true, Ordering::SeqCst);
        }
    }

    impl BlobBackend for FaultBackend {
        fn put_if_absent(
            &self,
            key: &str,
            source: &Path,
            _deadline: Instant,
        ) -> Result<PutStatus, ArtifactError> {
            let attempt = self.puts.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt == self.fail_put {
                return Err(ArtifactError::Storage(
                    "injected publication interruption".to_owned(),
                ));
            }
            let mut objects = self.objects.lock().expect("fault backend lock");
            if objects.contains_key(key) {
                return Ok(PutStatus::Reused);
            }
            objects.insert(
                key.to_owned(),
                fs::read(source).map_err(|error| io_error(source, error))?,
            );
            Ok(PutStatus::Created)
        }

        fn get(
            &self,
            key: &str,
            destination: &Path,
            maximum_bytes: u64,
            _deadline: Instant,
        ) -> Result<u64, ArtifactError> {
            let objects = self.objects.lock().expect("fault backend lock");
            let bytes = objects
                .get(key)
                .ok_or_else(|| ArtifactError::NotFound(key.to_owned()))?;
            if bytes.len() as u64 > maximum_bytes {
                return Err(ArtifactError::Integrity(
                    "fault-backend object exceeds its limit".to_owned(),
                ));
            }
            if self.interrupt_download.swap(false, Ordering::SeqCst) {
                fs::write(destination, &bytes[..bytes.len() / 2])
                    .map_err(|error| io_error(destination, error))?;
                return Err(ArtifactError::Storage(
                    "injected download interruption".to_owned(),
                ));
            }
            fs::write(destination, bytes).map_err(|error| io_error(destination, error))?;
            Ok(bytes.len() as u64)
        }

        fn exists(&self, key: &str, _deadline: Instant) -> Result<bool, ArtifactError> {
            Ok(self
                .objects
                .lock()
                .expect("fault backend lock")
                .contains_key(key))
        }

        fn list(
            &self,
            prefix: &str,
            maximum_entries: usize,
            _deadline: Instant,
        ) -> Result<Vec<crate::backend::StoredObject>, ArtifactError> {
            let objects = self
                .objects
                .lock()
                .expect("fault backend lock")
                .keys()
                .filter(|key| key.starts_with(prefix))
                .map(|key| crate::backend::StoredObject {
                    key: key.clone(),
                    modified: SystemTime::UNIX_EPOCH,
                })
                .collect::<Vec<_>>();
            if objects.len() > maximum_entries {
                return Err(ArtifactError::Invalid(
                    "fault-backend listing exceeds its limit".to_owned(),
                ));
            }
            Ok(objects)
        }

        fn delete(&self, key: &str, _deadline: Instant) -> Result<(), ArtifactError> {
            self.objects.lock().expect("fault backend lock").remove(key);
            Ok(())
        }
    }

    fn copy_tree(source: &Path, target: &Path) {
        fs::create_dir_all(target).expect("target directory");
        for entry in fs::read_dir(source).expect("source directory") {
            let entry = entry.expect("source entry");
            let destination = target.join(entry.file_name());
            if entry.file_type().expect("entry type").is_dir() {
                copy_tree(&entry.path(), &destination);
            } else {
                fs::copy(entry.path(), destination).expect("copy artifact");
            }
        }
    }

    fn regular_files(root: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for entry in fs::read_dir(root).expect("artifact directory") {
            let entry = entry.expect("artifact entry");
            if entry.file_type().expect("artifact type").is_dir() {
                files.extend(regular_files(&entry.path()));
            } else {
                files.push(entry.path());
            }
        }
        files
    }
}
