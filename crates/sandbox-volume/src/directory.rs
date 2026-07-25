use crate::{
    error::io_error, model::validate_handle_spec, AttachmentOwner, LocalVolumeProvider,
    MountedVolume, VolumeAttachment, VolumeCleanupReport, VolumeError, VolumeHandle,
    VolumeProvider, VolumeProviderCapabilities, VolumeScope, VolumeSnapshot,
};
use nix::libc;
use runtrue_sandbox_core::{
    SnapshotPortability, VolumePersistenceClass, VolumeSpec, VOLUME_SPEC_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read as _, Write},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const DIRECTORY_VOLUME_PROVIDER_ID: &str = "directory-pvc-v1";
const RECORD_VERSION: u32 = 1;
const SNAPSHOT_VERSION: u32 = 2;
const SNAPSHOT_FORMAT: &str = "application/vnd.runtrue.volume.directory.tar.v1";
const MAXIMUM_RECORD_BYTES: u64 = 256 * 1024;
const MAXIMUM_ENTRIES: usize = 100_000;
const MAXIMUM_PATH_BYTES: usize = 4_096;
const MAXIMUM_PATH_DEPTH: usize = 64;
const LINUX_CAP_DAC_OVERRIDE: u32 = 1;

#[derive(Debug, Clone)]
pub struct DirectoryVolumeConfig {
    pub root: PathBuf,
    pub minimum_quota_bytes: u64,
    pub maximum_quota_bytes: u64,
    pub operation_timeout: Duration,
}

impl DirectoryVolumeConfig {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            minimum_quota_bytes: runtrue_sandbox_core::MINIMUM_NAMED_VOLUME_BYTES,
            maximum_quota_bytes: 1024 * 1024 * 1024 * 1024,
            operation_timeout: Duration::from_secs(300),
        }
    }
}

pub struct DirectoryVolumeProvider {
    config: DirectoryVolumeConfig,
    auxiliary: Arc<LocalVolumeProvider>,
    gofer_access: bool,
    ownership_restore: bool,
    operations: Mutex<()>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VolumeRecord {
    schema_version: u32,
    provider_id: String,
    key: String,
    tenant: String,
    workspace: String,
    volume_id: String,
    persistence_class: VolumePersistenceClass,
    quota_bytes: u64,
    frozen: bool,
    attachments: BTreeMap<String, AttachmentRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentRecord {
    sandbox: String,
    container: String,
    destination: String,
    read_only: bool,
}

impl DirectoryVolumeProvider {
    pub fn open(
        mut config: DirectoryVolumeConfig,
        auxiliary: Arc<LocalVolumeProvider>,
    ) -> Result<Self, VolumeError> {
        if !config.root.is_absolute()
            || config.minimum_quota_bytes < runtrue_sandbox_core::MINIMUM_NAMED_VOLUME_BYTES
            || config.maximum_quota_bytes < config.minimum_quota_bytes
            || config.operation_timeout.is_zero()
            || config.operation_timeout > Duration::from_secs(3_600)
        {
            return Err(VolumeError::Invalid(
                "directory volume provider configuration is invalid".to_owned(),
            ));
        }
        fs::create_dir_all(&config.root).map_err(|error| io_error(&config.root, error))?;
        config.root =
            fs::canonicalize(&config.root).map_err(|error| io_error(&config.root, error))?;
        let metadata = fs::metadata(&config.root).map_err(|error| io_error(&config.root, error))?;
        if !metadata.is_dir() || metadata.uid() != nix::unistd::geteuid().as_raw() {
            return Err(VolumeError::AccessDenied(
                "directory volume root must be owned by the worker identity".to_owned(),
            ));
        }
        fs::set_permissions(&config.root, fs::Permissions::from_mode(0o700))
            .map_err(|error| io_error(&config.root, error))?;
        let ownership_restore = ownership_probe(&config.root);
        let provider = Self {
            config,
            auxiliary,
            gofer_access: effective_capability(LINUX_CAP_DAC_OVERRIDE),
            ownership_restore,
            operations: Mutex::new(()),
        };
        provider.cleanup()?;
        Ok(provider)
    }

    fn create_named(
        &self,
        scope: &VolumeScope,
        specification: &VolumeSpec,
    ) -> Result<VolumeHandle, VolumeError> {
        if !self.gofer_access || !self.ownership_restore {
            return Err(VolumeError::Unsupported(
                "named writable volumes require CHOWN and DAC_OVERRIDE or an idmapped storage backend"
                    .to_owned(),
            ));
        }
        specification
            .validate()
            .map_err(|error| VolumeError::Invalid(error.to_string()))?;
        if !matches!(
            specification.persistence_class,
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent
        ) || !(self.config.minimum_quota_bytes..=self.config.maximum_quota_bytes)
            .contains(&specification.quota_bytes)
        {
            return Err(VolumeError::Unsupported(
                "directory provider accepts bounded ephemeral or persistent volumes".to_owned(),
            ));
        }
        let key = volume_key(scope, specification.volume_id.as_str());
        let directory = self.config.root.join(&key);
        if directory.exists() {
            reconcile_volume_metadata(&directory)?;
            reconcile_data_directory(&directory)?;
            let record = self.read_record(&directory)?;
            self.validate_record(&record, scope, specification, &key)?;
            if specification.persistence_class != VolumePersistenceClass::Persistent
                || record.frozen
                || !record.attachments.is_empty()
            {
                return Err(VolumeError::AlreadyExists(
                    specification.volume_id.to_string(),
                ));
            }
            return Ok(handle(scope, specification, key));
        }
        fs::create_dir(&directory).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                VolumeError::AlreadyExists(specification.volume_id.to_string())
            } else {
                io_error(&directory, error)
            }
        })?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| io_error(&directory, error))?;
        let data = directory.join("data");
        let result = (|| {
            fs::create_dir(&data).map_err(|error| io_error(&data, error))?;
            // The owner-only parent and exact OCI bind source are the host
            // boundary. The sticky data root admits reviewed guest profiles;
            // files retain the creating guest's identity and normal modes.
            fs::set_permissions(&data, fs::Permissions::from_mode(0o1777))
                .map_err(|error| io_error(&data, error))?;
            self.write_record_new(
                &directory,
                &VolumeRecord {
                    schema_version: RECORD_VERSION,
                    provider_id: DIRECTORY_VOLUME_PROVIDER_ID.to_owned(),
                    key: key.clone(),
                    tenant: scope.tenant_id().to_string(),
                    workspace: scope.workspace_id().to_string(),
                    volume_id: specification.volume_id.to_string(),
                    persistence_class: specification.persistence_class,
                    quota_bytes: specification.quota_bytes,
                    frozen: false,
                    attachments: BTreeMap::new(),
                },
            )?;
            sync_directory(&directory)?;
            sync_directory(&self.config.root)
        })();
        if let Err(error) = result {
            let _ = fs::remove_dir_all(&directory);
            return Err(error);
        }
        Ok(handle(scope, specification, key))
    }

    fn validate_record(
        &self,
        record: &VolumeRecord,
        scope: &VolumeScope,
        specification: &VolumeSpec,
        key: &str,
    ) -> Result<(), VolumeError> {
        if record.schema_version != RECORD_VERSION
            || record.provider_id != DIRECTORY_VOLUME_PROVIDER_ID
            || record.key != key
            || record.tenant != scope.tenant_id().as_str()
            || record.workspace != scope.workspace_id().as_str()
            || record.volume_id != specification.volume_id.as_str()
            || record.persistence_class != specification.persistence_class
            || record.quota_bytes != specification.quota_bytes
            || record.attachments.len() > 32
        {
            return Err(VolumeError::Integrity(
                "directory volume metadata does not match its identity".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_handle(&self, handle: &VolumeHandle) -> Result<VolumeRecord, VolumeError> {
        if handle.provider_id != DIRECTORY_VOLUME_PROVIDER_ID
            || handle.key != volume_key(&handle.scope, handle.volume_id.as_str())
        {
            return Err(VolumeError::AccessDenied(
                "volume handle belongs to another provider".to_owned(),
            ));
        }
        let record = self.read_record(&self.config.root.join(&handle.key))?;
        let specification = VolumeSpec {
            schema_version: VOLUME_SPEC_VERSION,
            volume_id: handle.volume_id.clone(),
            destination: "/volume".to_owned(),
            read_only: false,
            persistence_class: handle.persistence_class,
            snapshot_policy: runtrue_sandbox_core::VolumeSnapshotPolicy::BestEffort,
            quota_bytes: handle.quota_bytes,
            content_digest: handle.content_digest.clone(),
        };
        self.validate_record(&record, &handle.scope, &specification, &handle.key)?;
        Ok(record)
    }

    fn validate_attachment(
        &self,
        attachment: &VolumeAttachment,
    ) -> Result<VolumeRecord, VolumeError> {
        let record = self.validate_handle(&attachment.handle)?;
        let expected = AttachmentRecord {
            sandbox: attachment.owner.sandbox_id.to_string(),
            container: attachment.owner.container_id.to_string(),
            destination: attachment.destination.clone(),
            read_only: attachment.read_only,
        };
        if record.attachments.get(&attachment.attachment_id) != Some(&expected) {
            return Err(VolumeError::AccessDenied(
                "volume attachment does not match its provider record".to_owned(),
            ));
        }
        Ok(record)
    }

    fn read_record(&self, directory: &Path) -> Result<VolumeRecord, VolumeError> {
        let path = directory.join("volume.json");
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| io_error(&path, error))?;
        let metadata = file.metadata().map_err(|error| io_error(&path, error))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAXIMUM_RECORD_BYTES {
            return Err(VolumeError::Integrity(
                "directory volume record is not a bounded regular file".to_owned(),
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(|error| io_error(&path, error))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| VolumeError::Integrity(format!("decode volume record: {error}")))
    }

    fn write_record_new(&self, directory: &Path, record: &VolumeRecord) -> Result<(), VolumeError> {
        write_json(&directory.join("volume.json"), record, true)
    }

    fn replace_record(&self, directory: &Path, record: &VolumeRecord) -> Result<(), VolumeError> {
        let temporary = directory.join("volume.json.new");
        write_json(&temporary, record, true)?;
        let path = directory.join("volume.json");
        if let Err(error) = fs::rename(&temporary, &path) {
            let _ = fs::remove_file(&temporary);
            return Err(io_error(&path, error));
        }
        sync_directory(directory)
    }

    fn named(&self, handle: &VolumeHandle) -> bool {
        handle.provider_id == DIRECTORY_VOLUME_PROVIDER_ID
    }
}

impl VolumeProvider for DirectoryVolumeProvider {
    fn provider_id(&self) -> &str {
        DIRECTORY_VOLUME_PROVIDER_ID
    }

    fn capabilities(&self) -> VolumeProviderCapabilities {
        let mut persistence_classes = BTreeSet::from([
            VolumePersistenceClass::Artifact,
            VolumePersistenceClass::Secret,
        ]);
        if self.gofer_access && self.ownership_restore {
            persistence_classes.extend([
                VolumePersistenceClass::Ephemeral,
                VolumePersistenceClass::Persistent,
            ]);
        }
        VolumeProviderCapabilities {
            persistence_classes,
            snapshot: self.gofer_access && self.ownership_restore,
            clone: false,
            snapshot_portability: SnapshotPortability::CrossWorkerSameBackend,
        }
    }

    fn create(
        &self,
        scope: &VolumeScope,
        specification: &VolumeSpec,
    ) -> Result<VolumeHandle, VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        if matches!(
            specification.persistence_class,
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent
        ) {
            self.create_named(scope, specification)
        } else {
            self.auxiliary.create(scope, specification)
        }
    }

    fn attach(
        &self,
        handle: &VolumeHandle,
        owner: AttachmentOwner,
        specification: &VolumeSpec,
    ) -> Result<VolumeAttachment, VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        if !self.named(handle) {
            return self.auxiliary.attach(handle, owner, specification);
        }
        validate_handle_spec(handle, specification)?;
        let mut record = self.validate_handle(handle)?;
        if record.frozen || record.attachments.len() >= 32 {
            return Err(VolumeError::Invalid(
                "directory volume is frozen or at its attachment limit".to_owned(),
            ));
        }
        let attachment_id = attachment_key(handle, &owner, &specification.destination);
        let attachment_record = AttachmentRecord {
            sandbox: owner.sandbox_id.to_string(),
            container: owner.container_id.to_string(),
            destination: specification.destination.clone(),
            read_only: specification.read_only,
        };
        if record
            .attachments
            .insert(attachment_id.clone(), attachment_record.clone())
            .is_some_and(|existing| existing != attachment_record)
        {
            return Err(VolumeError::AccessDenied(
                "volume attachment identity collision".to_owned(),
            ));
        }
        self.replace_record(&self.config.root.join(&handle.key), &record)?;
        Ok(VolumeAttachment {
            handle: handle.clone(),
            attachment_id,
            owner,
            destination: specification.destination.clone(),
            read_only: specification.read_only,
            snapshot_policy: specification.snapshot_policy,
        })
    }

    fn mount(&self, attachment: &VolumeAttachment) -> Result<MountedVolume, VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        if !self.named(&attachment.handle) {
            return self.auxiliary.mount(attachment);
        }
        let record = self.validate_attachment(attachment)?;
        if record.frozen {
            return Err(VolumeError::Invalid(
                "cannot mount a frozen directory volume".to_owned(),
            ));
        }
        let source =
            fs::canonicalize(self.config.root.join(&attachment.handle.key).join("data"))
                .map_err(|error| io_error(self.config.root.join(&attachment.handle.key), error))?;
        if !source.starts_with(&self.config.root) {
            return Err(VolumeError::AccessDenied(
                "directory volume escaped its provider root".to_owned(),
            ));
        }
        Ok(MountedVolume {
            attachment: attachment.clone(),
            source,
        })
    }

    fn detach(&self, attachment: &VolumeAttachment) -> Result<(), VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        if !self.named(&attachment.handle) {
            return self.auxiliary.detach(attachment);
        }
        let mut record = self.validate_attachment(attachment)?;
        record.attachments.remove(&attachment.attachment_id);
        self.replace_record(&self.config.root.join(&attachment.handle.key), &record)
    }

    fn freeze(&self, attachment: &VolumeAttachment) -> Result<(), VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        if !self.named(&attachment.handle) {
            return self.auxiliary.freeze(attachment);
        }
        if !self.ownership_restore {
            return Err(VolumeError::Unsupported(
                "directory snapshots require CHOWN or an idmapped storage backend".to_owned(),
            ));
        }
        let mut record = self.validate_attachment(attachment)?;
        record.frozen = true;
        self.replace_record(&self.config.root.join(&attachment.handle.key), &record)
    }

    fn thaw(&self, attachment: &VolumeAttachment) -> Result<(), VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        if !self.named(&attachment.handle) {
            return self.auxiliary.thaw(attachment);
        }
        let mut record = self.validate_attachment(attachment)?;
        record.frozen = false;
        self.replace_record(&self.config.root.join(&attachment.handle.key), &record)
    }

    fn snapshot(
        &self,
        attachment: &VolumeAttachment,
        destination: &Path,
    ) -> Result<VolumeSnapshot, VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        if !self.named(&attachment.handle) {
            return self.auxiliary.snapshot(attachment, destination);
        }
        let record = self.validate_attachment(attachment)?;
        if !record.frozen || !self.ownership_restore {
            return Err(VolumeError::Unsupported(
                "directory volume snapshot ownership is unavailable".to_owned(),
            ));
        }
        export_directory(
            &self.config.root.join(&attachment.handle.key).join("data"),
            destination,
            record.quota_bytes,
            self.config.operation_timeout,
        )?;
        let (digest, size_bytes) = digest_file(destination)?;
        Ok(VolumeSnapshot {
            schema_version: SNAPSHOT_VERSION,
            provider_id: DIRECTORY_VOLUME_PROVIDER_ID.to_owned(),
            volume_id: attachment.handle.volume_id.clone(),
            persistence_class: record.persistence_class,
            digest,
            size_bytes,
            quota_bytes: record.quota_bytes,
            format: SNAPSHOT_FORMAT.to_owned(),
            portability: SnapshotPortability::CrossWorkerSameBackend,
        })
    }

    fn restore(
        &self,
        scope: &VolumeScope,
        specification: &VolumeSpec,
        snapshot: &VolumeSnapshot,
        source: &Path,
    ) -> Result<VolumeHandle, VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        if !matches!(
            specification.persistence_class,
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent
        ) {
            return self
                .auxiliary
                .restore(scope, specification, snapshot, source);
        }
        if !self.gofer_access
            || !self.ownership_restore
            || snapshot.schema_version != SNAPSHOT_VERSION
            || snapshot.provider_id != DIRECTORY_VOLUME_PROVIDER_ID
            || snapshot.volume_id != specification.volume_id
            || snapshot.persistence_class != specification.persistence_class
            || snapshot.quota_bytes != specification.quota_bytes
            || snapshot.format != SNAPSHOT_FORMAT
            || !snapshot.portability.permits_cross_worker()
        {
            return Err(VolumeError::Unsupported(
                "directory volume snapshot is incompatible or ownership restore is unavailable"
                    .to_owned(),
            ));
        }
        let (digest, size) = digest_file(source)?;
        if digest != snapshot.digest
            || size != snapshot.size_bytes
            || size > specification.quota_bytes.saturating_mul(2)
        {
            return Err(VolumeError::Integrity(
                "directory volume snapshot content changed".to_owned(),
            ));
        }
        validate_archive(
            source,
            specification.quota_bytes,
            self.config.operation_timeout,
        )?;
        let handle = self.create_named(scope, specification)?;
        let directory = self.config.root.join(&handle.key);
        let data = directory.join("data");
        let restored = directory.join("data.restoring");
        let result = (|| {
            fs::create_dir(&restored).map_err(|error| io_error(&restored, error))?;
            let file = open_regular_nofollow(source)?;
            let mut archive = tar::Archive::new(file);
            archive.set_preserve_permissions(true);
            archive.set_preserve_ownerships(true);
            archive
                .unpack(&restored)
                .map_err(|error| io_error(&restored, error))?;
            fs::set_permissions(&restored, fs::Permissions::from_mode(0o1777))
                .map_err(|error| io_error(&restored, error))?;
            let old = directory.join("data.replaced");
            fs::rename(&data, &old).map_err(|error| io_error(&data, error))?;
            if let Err(error) = fs::rename(&restored, &data) {
                let rollback = fs::rename(&old, &data);
                return Err(match rollback {
                    Ok(()) => io_error(&data, error),
                    Err(rollback) => VolumeError::Integrity(format!(
                        "volume restore failed and rollback failed: {error}; {rollback}"
                    )),
                });
            }
            sync_directory(&directory)?;
            fs::remove_dir_all(&old).map_err(|error| io_error(&old, error))?;
            sync_directory(&directory)?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_dir_all(&restored);
            return Err(error);
        }
        Ok(handle)
    }

    fn unmount(&self, mounted: &MountedVolume) -> Result<(), VolumeError> {
        self.detach(&mounted.attachment)
    }

    fn delete(&self, handle: &VolumeHandle) -> Result<(), VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        if !self.named(handle) {
            return self.auxiliary.delete(handle);
        }
        let record = self.validate_handle(handle)?;
        if !record.attachments.is_empty() || record.frozen {
            return Err(VolumeError::Invalid(
                "cannot delete an attached or frozen volume".to_owned(),
            ));
        }
        if record.persistence_class == VolumePersistenceClass::Persistent {
            return Ok(());
        }
        let directory = self.config.root.join(&handle.key);
        fs::remove_dir_all(&directory).map_err(|error| io_error(&directory, error))?;
        sync_directory(&self.config.root)
    }

    fn cleanup(&self) -> Result<VolumeCleanupReport, VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        let mut report = self.auxiliary.cleanup()?;
        let mut entries = fs::read_dir(&self.config.root)
            .map_err(|error| io_error(&self.config.root, error))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| io_error(&self.config.root, error))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| io_error(entry.path(), error))?;
            let key = entry.file_name();
            let valid_key = key.len() == 64
                && key
                    .as_encoded_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
            if !metadata.is_dir() || !valid_key {
                return Err(VolumeError::Integrity(format!(
                    "unexpected directory volume entry `{}`",
                    entry.path().display()
                )));
            }
            reconcile_volume_metadata(&entry.path())?;
            let mut record = self.read_record(&entry.path())?;
            validate_stored_record(&record, key.as_encoded_bytes())?;
            reconcile_data_directory(&entry.path())?;
            report.cleared_attachments += record.attachments.len();
            record.attachments.clear();
            record.frozen = false;
            if record.persistence_class == VolumePersistenceClass::Ephemeral {
                fs::remove_dir_all(entry.path()).map_err(|error| io_error(entry.path(), error))?;
                sync_directory(&self.config.root)?;
                report.removed_ephemeral_volumes += 1;
            } else {
                self.replace_record(&entry.path(), &record)?;
                report.retained_persistent_volumes += 1;
            }
        }
        Ok(report)
    }
}

fn handle(scope: &VolumeScope, specification: &VolumeSpec, key: String) -> VolumeHandle {
    VolumeHandle {
        provider_id: DIRECTORY_VOLUME_PROVIDER_ID.to_owned(),
        key,
        scope: scope.clone(),
        volume_id: specification.volume_id.clone(),
        persistence_class: specification.persistence_class,
        quota_bytes: specification.quota_bytes,
        content_digest: specification.content_digest.clone(),
    }
}

fn reconcile_volume_metadata(directory: &Path) -> Result<(), VolumeError> {
    let record = directory.join("volume.json");
    let pending = directory.join("volume.json.new");
    let record_metadata = fs::symlink_metadata(&record);
    let pending_metadata = fs::symlink_metadata(&pending);
    match (record_metadata, pending_metadata) {
        (Ok(record_metadata), Ok(pending_metadata))
            if record_metadata.is_file() && pending_metadata.is_file() =>
        {
            fs::remove_file(&pending).map_err(|error| io_error(&pending, error))?;
            sync_directory(directory)
        }
        (Ok(record_metadata), Err(error))
            if record_metadata.is_file() && error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(())
        }
        (Err(error), Ok(pending_metadata))
            if error.kind() == std::io::ErrorKind::NotFound && pending_metadata.is_file() =>
        {
            fs::rename(&pending, &record).map_err(|error| io_error(&record, error))?;
            sync_directory(directory)
        }
        (Err(record_error), Err(pending_error))
            if record_error.kind() == std::io::ErrorKind::NotFound
                && pending_error.kind() == std::io::ErrorKind::NotFound =>
        {
            Err(VolumeError::Integrity(
                "directory volume metadata is missing".to_owned(),
            ))
        }
        _ => Err(VolumeError::Integrity(
            "directory volume metadata is not a regular file".to_owned(),
        )),
    }
}

fn validate_stored_record(record: &VolumeRecord, key: &[u8]) -> Result<(), VolumeError> {
    let expected = volume_key_values(&record.tenant, &record.workspace, &record.volume_id);
    if record.schema_version != RECORD_VERSION
        || record.provider_id != DIRECTORY_VOLUME_PROVIDER_ID
        || record.key.as_bytes() != key
        || expected.as_bytes() != key
        || !matches!(
            record.persistence_class,
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent
        )
        || record.quota_bytes < runtrue_sandbox_core::MINIMUM_NAMED_VOLUME_BYTES
        || record.attachments.len() > 32
    {
        return Err(VolumeError::Integrity(
            "stored directory volume record is inconsistent".to_owned(),
        ));
    }
    Ok(())
}

fn reconcile_data_directory(directory: &Path) -> Result<(), VolumeError> {
    let data = directory.join("data");
    let restoring = directory.join("data.restoring");
    let replaced = directory.join("data.replaced");
    if restoring.exists() {
        fs::remove_dir_all(&restoring).map_err(|error| io_error(&restoring, error))?;
    }
    if data.exists() {
        if replaced.exists() {
            fs::remove_dir_all(&replaced).map_err(|error| io_error(&replaced, error))?;
        }
    } else if replaced.exists() {
        fs::rename(&replaced, &data).map_err(|error| io_error(&data, error))?;
    } else {
        return Err(VolumeError::Integrity(
            "directory volume has no recoverable data root".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(&data).map_err(|error| io_error(&data, error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(VolumeError::Integrity(
            "directory volume data root is not a directory".to_owned(),
        ));
    }
    Ok(())
}

fn volume_key(scope: &VolumeScope, volume: &str) -> String {
    volume_key_values(
        scope.tenant_id().as_str(),
        scope.workspace_id().as_str(),
        volume,
    )
}

fn volume_key_values(tenant: &str, workspace: &str, volume: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"runtrue-sandboxd/directory-volume/v1\0");
    digest.update(tenant.len().to_be_bytes());
    digest.update(tenant.as_bytes());
    digest.update(workspace.len().to_be_bytes());
    digest.update(workspace.as_bytes());
    digest.update(volume.len().to_be_bytes());
    digest.update(volume.as_bytes());
    hex::encode(digest.finalize())
}

fn sync_directory(path: &Path) -> Result<(), VolumeError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| io_error(path, error))
}

fn attachment_key(handle: &VolumeHandle, owner: &AttachmentOwner, destination: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"runtrue-sandboxd/directory-attachment/v1\0");
    for value in [
        handle.key.as_str(),
        owner.sandbox_id.as_str(),
        owner.container_id.as_str(),
        destination,
    ] {
        digest.update(value.len().to_be_bytes());
        digest.update(value.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn write_json<T: Serialize>(path: &Path, value: &T, create_new: bool) -> Result<(), VolumeError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| VolumeError::Integrity(format!("encode volume record: {error}")))?;
    let mut options = OpenOptions::new();
    options.write(true).mode(0o600);
    if create_new {
        options.create_new(true);
    }
    let mut file = options.open(path).map_err(|error| io_error(path, error))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(path, error))
}

fn effective_capability(capability: u32) -> bool {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .is_some_and(|mask| mask & (1_u64 << capability) != 0)
}

fn ownership_probe(root: &Path) -> bool {
    let path = root.join(format!(".ownership-probe-{}", std::process::id()));
    let result = (|| {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.sync_all()?;
        std::os::unix::fs::chown(&path, Some(65_534), Some(65_534))?;
        Ok::<_, std::io::Error>(())
    })();
    let _ = fs::remove_file(path);
    result.is_ok()
}

fn collect_paths(
    root: &Path,
    directory: &Path,
    paths: &mut Vec<PathBuf>,
) -> Result<(), VolumeError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| io_error(directory, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error(directory, error))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| VolumeError::Integrity("volume path escaped its root".to_owned()))?
            .to_owned();
        if relative.as_os_str().as_encoded_bytes().len() > MAXIMUM_PATH_BYTES
            || relative.components().count() > MAXIMUM_PATH_DEPTH
        {
            return Err(VolumeError::Invalid(
                "volume snapshot path exceeds its length or depth limit".to_owned(),
            ));
        }
        paths.push(relative);
        if paths.len() > MAXIMUM_ENTRIES {
            return Err(VolumeError::Invalid(
                "volume snapshot has too many entries".to_owned(),
            ));
        }
        if fs::symlink_metadata(&path)
            .map_err(|error| io_error(&path, error))?
            .is_dir()
        {
            collect_paths(root, &path, paths)?;
        }
    }
    Ok(())
}

fn export_directory(
    root: &Path,
    destination: &Path,
    quota_bytes: u64,
    timeout: Duration,
) -> Result<(), VolumeError> {
    if destination.exists() {
        return Err(VolumeError::AlreadyExists(
            destination.display().to_string(),
        ));
    }
    let started = Instant::now();
    let mut paths = Vec::new();
    collect_paths(root, root, &mut paths)?;
    paths.sort();
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|error| io_error(destination, error))?;
    let mut destination_guard = CreatedFileGuard::new(destination);
    let writer = BoundedWriter::new(output, quota_bytes.saturating_mul(2));
    let mut archive = tar::Builder::new(writer);
    archive.follow_symlinks(false);
    let mut logical_bytes = 0_u64;
    for relative in paths {
        if started.elapsed() > timeout {
            return Err(VolumeError::Timeout(
                "directory volume snapshot timed out".to_owned(),
            ));
        }
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(&path).map_err(|error| io_error(&path, error))?;
        if xattr::list(&path)
            .map_err(|error| io_error(&path, error))?
            .next()
            .is_some()
        {
            return Err(VolumeError::Unsupported(
                "directory snapshot does not support extended attributes".to_owned(),
            ));
        }
        if metadata.is_file() {
            if metadata.nlink() != 1 {
                return Err(VolumeError::Unsupported(
                    "directory snapshot does not support hard links".to_owned(),
                ));
            }
            if metadata.len() > 0 && metadata.blocks().saturating_mul(512) < metadata.len() {
                return Err(VolumeError::Unsupported(
                    "directory snapshot does not support sparse files".to_owned(),
                ));
            }
            logical_bytes = logical_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| VolumeError::Invalid("volume size overflow".to_owned()))?;
            if logical_bytes > quota_bytes {
                return Err(VolumeError::Invalid(
                    "directory content exceeds its declared quota".to_owned(),
                ));
            }
        } else if !metadata.is_dir() && !metadata.file_type().is_symlink() {
            return Err(VolumeError::Unsupported(
                "directory snapshot contains a special file".to_owned(),
            ));
        }
        archive
            .append_path_with_name(&path, &relative)
            .map_err(|error| io_error(&path, error))?;
    }
    let result = archive
        .finish()
        .map_err(|error| io_error(destination, error))
        .and_then(|()| {
            archive
                .into_inner()
                .map_err(|error| io_error(destination, error))
        })
        .and_then(|writer| {
            writer
                .inner
                .sync_all()
                .map_err(|error| io_error(destination, error))
        });
    if result.is_ok() {
        destination_guard.preserve();
    }
    result
}

fn validate_archive(source: &Path, quota_bytes: u64, timeout: Duration) -> Result<(), VolumeError> {
    let started = Instant::now();
    let metadata = fs::symlink_metadata(source).map_err(|error| io_error(source, error))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > quota_bytes.saturating_mul(2)
    {
        return Err(VolumeError::Integrity(
            "directory snapshot is not a bounded regular file".to_owned(),
        ));
    }
    let file = open_regular_nofollow(source)?;
    let mut archive = tar::Archive::new(file);
    let mut seen = BTreeSet::new();
    let mut symlinks = BTreeSet::new();
    let mut logical_bytes = 0_u64;
    for entry in archive.entries().map_err(|error| io_error(source, error))? {
        if started.elapsed() > timeout {
            return Err(VolumeError::Timeout(
                "directory snapshot validation timed out".to_owned(),
            ));
        }
        let mut entry = entry.map_err(|error| io_error(source, error))?;
        if seen.len() >= MAXIMUM_ENTRIES {
            return Err(VolumeError::Invalid(
                "directory snapshot has too many entries".to_owned(),
            ));
        }
        let path = entry
            .path()
            .map_err(|error| io_error(source, error))?
            .into_owned();
        if path.as_os_str().as_encoded_bytes().len() > MAXIMUM_PATH_BYTES
            || path.components().count() > MAXIMUM_PATH_DEPTH
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || path
                .ancestors()
                .skip(1)
                .any(|ancestor| symlinks.contains(ancestor))
            || !seen.insert(path.clone())
        {
            return Err(VolumeError::Integrity(
                "directory snapshot path is unsafe or duplicated".to_owned(),
            ));
        }
        let kind = entry.header().entry_type();
        if !matches!(
            kind,
            tar::EntryType::Regular | tar::EntryType::Directory | tar::EntryType::Symlink
        ) {
            return Err(VolumeError::Unsupported(
                "directory snapshot contains an unsupported entry".to_owned(),
            ));
        }
        if let Some(extensions) = entry
            .pax_extensions()
            .map_err(|error| io_error(source, error))?
        {
            for extension in extensions {
                let extension = extension.map_err(|error| io_error(source, error))?;
                let key = extension.key().map_err(|_| {
                    VolumeError::Integrity(
                        "directory snapshot extended metadata is not UTF-8".to_owned(),
                    )
                })?;
                if !matches!(key, "path" | "linkpath") {
                    return Err(VolumeError::Unsupported(
                        "directory snapshot contains unsupported extended metadata".to_owned(),
                    ));
                }
            }
        }
        if kind == tar::EntryType::Symlink {
            let target = entry
                .link_name()
                .map_err(|error| io_error(source, error))?
                .ok_or_else(|| {
                    VolumeError::Integrity("directory snapshot symlink has no target".to_owned())
                })?;
            if target.as_os_str().as_encoded_bytes().len() > MAXIMUM_PATH_BYTES
                || target.components().count() > MAXIMUM_PATH_DEPTH
                || target
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(VolumeError::Integrity(
                    "directory snapshot symlink target is unsafe".to_owned(),
                ));
            }
            symlinks.insert(path);
        }
        logical_bytes = logical_bytes
            .checked_add(
                entry
                    .header()
                    .size()
                    .map_err(|error| io_error(source, error))?,
            )
            .ok_or_else(|| VolumeError::Invalid("volume size overflow".to_owned()))?;
        if logical_bytes > quota_bytes {
            return Err(VolumeError::Invalid(
                "directory snapshot content exceeds its quota".to_owned(),
            ));
        }
    }
    Ok(())
}

fn digest_file(path: &Path) -> Result<(String, u64), VolumeError> {
    let mut file = open_regular_nofollow(path)?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_error(path, error))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| VolumeError::Invalid("volume size overflow".to_owned()))?;
        digest.update(&buffer[..read]);
    }
    Ok((format!("sha256:{:x}", digest.finalize()), total))
}

fn open_regular_nofollow(path: &Path) -> Result<File, VolumeError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| io_error(path, error))?;
    if !file
        .metadata()
        .map_err(|error| io_error(path, error))?
        .is_file()
    {
        return Err(VolumeError::Integrity(
            "directory snapshot source is not a regular file".to_owned(),
        ));
    }
    Ok(file)
}

struct BoundedWriter<W> {
    inner: W,
    maximum: u64,
    bytes: u64,
}

struct CreatedFileGuard<'a> {
    path: &'a Path,
    preserve: bool,
}

impl<'a> CreatedFileGuard<'a> {
    const fn new(path: &'a Path) -> Self {
        Self {
            path,
            preserve: false,
        }
    }

    fn preserve(&mut self) {
        self.preserve = true;
    }
}

impl Drop for CreatedFileGuard<'_> {
    fn drop(&mut self) {
        if !self.preserve {
            let _ = fs::remove_file(self.path);
        }
    }
}

impl<W> BoundedWriter<W> {
    const fn new(inner: W, maximum: u64) -> Self {
        Self {
            inner,
            maximum,
            bytes: 0,
        }
    }
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let remaining = self.maximum.saturating_sub(self.bytes);
        if buffer.len() as u64 > remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "directory snapshot exceeds its archive limit",
            ));
        }
        let written = self.inner.write(buffer)?;
        self.bytes = self.bytes.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_sandbox_core::{
        ContainerId, SandboxId, TenantId, VolumeId, VolumeSnapshotPolicy, WorkspaceId,
    };

    fn scope(tenant: &str) -> VolumeScope {
        VolumeScope::new(
            TenantId::parse(tenant).expect("tenant"),
            WorkspaceId::parse("workspace").expect("workspace"),
        )
    }

    fn specification(class: VolumePersistenceClass) -> VolumeSpec {
        VolumeSpec {
            schema_version: VOLUME_SPEC_VERSION,
            volume_id: VolumeId::parse("cache").expect("volume"),
            destination: "/var/lib/cache".to_owned(),
            read_only: false,
            persistence_class: class,
            snapshot_policy: VolumeSnapshotPolicy::Required,
            quota_bytes: runtrue_sandbox_core::MINIMUM_NAMED_VOLUME_BYTES,
            content_digest: None,
        }
    }

    fn owner() -> AttachmentOwner {
        AttachmentOwner {
            sandbox_id: SandboxId::parse("sandbox").expect("sandbox"),
            container_id: ContainerId::parse("service").expect("container"),
        }
    }

    fn provider(root: &Path) -> (DirectoryVolumeProvider, Arc<LocalVolumeProvider>) {
        let auxiliary = Arc::new(
            LocalVolumeProvider::open(crate::LocalVolumeConfig::new(root.join("auxiliary")))
                .expect("auxiliary"),
        );
        let mut provider = DirectoryVolumeProvider::open(
            DirectoryVolumeConfig::new(root.join("directory")),
            Arc::clone(&auxiliary),
        )
        .expect("directory provider");
        // Unit tests exercise provider semantics independently of the test
        // runner's outer capability mask. The live k3s suite verifies the
        // production capability probe and each independent removal failure.
        provider.gofer_access = true;
        provider.ownership_restore = true;
        (provider, auxiliary)
    }

    #[test]
    fn persistent_directory_is_tenant_scoped_and_survives_reopen() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let (provider, auxiliary) = provider(temporary.path());
        let specification = specification(VolumePersistenceClass::Persistent);
        let first = provider
            .create(&scope("tenant-a"), &specification)
            .expect("first");
        let other = provider
            .create(&scope("tenant-b"), &specification)
            .expect("other tenant");
        assert_ne!(first.key(), other.key());
        drop(provider);

        let mut reopened = DirectoryVolumeProvider::open(
            DirectoryVolumeConfig::new(temporary.path().join("directory")),
            auxiliary,
        )
        .expect("reopen");
        reopened.gofer_access = true;
        reopened.ownership_restore = true;
        let retained = reopened
            .create(&scope("tenant-a"), &specification)
            .expect("retained");
        assert_eq!(retained.key(), first.key());
        assert_eq!(
            reopened
                .cleanup()
                .expect("cleanup")
                .retained_persistent_volumes,
            2
        );
    }

    #[test]
    fn mount_is_a_direct_directory_and_snapshot_restore_is_bounded() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let (provider, _) = provider(temporary.path());
        if !provider.ownership_restore {
            return;
        }
        let specification = specification(VolumePersistenceClass::Persistent);
        let scope = scope("tenant");
        let handle = provider.create(&scope, &specification).expect("create");
        let attachment = provider
            .attach(&handle, owner(), &specification)
            .expect("attach");
        let mounted = provider.mount(&attachment).expect("mount");
        assert!(mounted.source().is_dir());
        assert!(!mounted.source().join("quota.ext4").exists());
        fs::write(mounted.source().join("value"), b"before").expect("write");

        provider.freeze(&attachment).expect("freeze");
        let archive = temporary.path().join("volume.tar");
        let snapshot = provider.snapshot(&attachment, &archive).expect("snapshot");
        provider.thaw(&attachment).expect("thaw");
        provider.unmount(&mounted).expect("unmount");
        fs::write(
            temporary
                .path()
                .join("directory")
                .join(handle.key())
                .join("data/value"),
            b"after",
        )
        .expect("change");

        let restored = provider
            .restore(&scope, &specification, &snapshot, &archive)
            .expect("restore");
        assert_eq!(restored.key(), handle.key());
        assert_eq!(
            fs::read(
                temporary
                    .path()
                    .join("directory")
                    .join(handle.key())
                    .join("data/value")
            )
            .expect("restored value"),
            b"before"
        );
    }

    #[test]
    fn provider_requires_exact_named_volume_authority() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let (mut provider, _) = provider(temporary.path());
        provider.ownership_restore = false;
        let capabilities = provider.capabilities();
        assert!(!capabilities.snapshot);
        assert!(!capabilities
            .persistence_classes
            .contains(&VolumePersistenceClass::Persistent));
        let specification = specification(VolumePersistenceClass::Persistent);
        assert!(matches!(
            provider.create(&scope("tenant"), &specification),
            Err(VolumeError::Unsupported(_))
        ));

        provider.gofer_access = false;
        let capabilities = provider.capabilities();
        assert!(!capabilities
            .persistence_classes
            .contains(&VolumePersistenceClass::Persistent));
    }

    #[test]
    fn cleanup_recovers_an_interrupted_directory_swap() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let (provider, _) = provider(temporary.path());
        let specification = specification(VolumePersistenceClass::Persistent);
        let scope = scope("tenant");
        let handle = provider.create(&scope, &specification).expect("create");
        let directory = temporary.path().join("directory").join(handle.key());
        fs::write(directory.join("data/value"), b"retained").expect("marker");
        fs::rename(directory.join("data"), directory.join("data.replaced"))
            .expect("interrupted swap");

        let reopened = provider.create(&scope, &specification).expect("recover");
        assert_eq!(reopened.key(), handle.key());
        assert_eq!(
            fs::read(directory.join("data/value")).expect("retained marker"),
            b"retained"
        );
        assert!(!directory.join("data.replaced").exists());
    }

    #[test]
    fn portable_archive_rejects_sparse_and_hostile_content() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("root");
        fs::create_dir(&root).expect("root");
        let extended = root.join("extended");
        fs::write(&extended, b"value").expect("extended file");
        xattr::set(&extended, "user.runtrue-test", b"value").expect("extended attribute");
        let partial = temporary.path().join("partial.tar");
        assert!(matches!(
            export_directory(&root, &partial, 4 * 1024 * 1024, Duration::from_secs(1)),
            Err(VolumeError::Unsupported(_))
        ));
        assert!(!partial.exists());
        fs::remove_file(&extended).expect("remove extended file");

        let sparse = File::create(root.join("sparse")).expect("sparse");
        sparse.set_len(2 * 1024 * 1024).expect("sparse length");
        assert!(matches!(
            export_directory(&root, &partial, 4 * 1024 * 1024, Duration::from_secs(1)),
            Err(VolumeError::Unsupported(_))
        ));
        assert!(!partial.exists());

        let hostile = temporary.path().join("hostile.tar");
        let output = File::create(&hostile).expect("hostile archive");
        let mut builder = tar::Builder::new(output);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("../escape").expect("link target");
        header.set_cksum();
        builder
            .append_data(&mut header, "unsafe-link", std::io::empty())
            .expect("append hostile link");
        builder.finish().expect("finish hostile archive");
        assert!(matches!(
            validate_archive(&hostile, 4 * 1024 * 1024, Duration::from_secs(1)),
            Err(VolumeError::Integrity(_))
        ));
    }
}
