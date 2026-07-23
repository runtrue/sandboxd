use crate::{
    error::io_error, model::validate_handle_spec, ArtifactGarbageCollectionReport,
    ArtifactPublication, ArtifactPublicationStatus, ArtifactVolumeStore, AttachmentOwner,
    MountedVolume, SecretResolver, VolumeAttachment, VolumeCleanupReport, VolumeError,
    VolumeHandle, VolumeProvider, VolumeProviderCapabilities, VolumeScope, VolumeSnapshot,
};
use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{openat, OFlag};
use nix::libc;
use nix::mount::{mount, umount, MsFlags};
use nix::sys::stat::Mode;
use runtrue_sandbox_core::{
    SnapshotPortability, VolumePersistenceClass, VolumeSnapshotPolicy, VolumeSpec,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write as _},
    os::fd::OwnedFd,
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
};
use tempfile::Builder;
use zeroize::Zeroizing;

pub const LOCAL_VOLUME_PROVIDER_ID: &str = "local-loopback-v1";
const RECORD_VERSION: u32 = 1;
pub const VOLUME_SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct LocalVolumeConfig {
    pub root: PathBuf,
    pub minimum_quota_bytes: u64,
    pub maximum_quota_bytes: u64,
    pub operation_timeout: Duration,
    pub maximum_output_bytes: usize,
    pub mkfs_ext4_program: PathBuf,
    pub losetup_program: PathBuf,
    pub fsfreeze_program: PathBuf,
    pub copy_program: PathBuf,
}

impl LocalVolumeConfig {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            minimum_quota_bytes: runtrue_sandbox_core::MINIMUM_NAMED_VOLUME_BYTES,
            maximum_quota_bytes: 1024 * 1024 * 1024 * 1024,
            operation_timeout: Duration::from_secs(300),
            maximum_output_bytes: 1024 * 1024,
            mkfs_ext4_program: PathBuf::from("/usr/sbin/mkfs.ext4"),
            losetup_program: PathBuf::from("/usr/sbin/losetup"),
            fsfreeze_program: PathBuf::from("/usr/sbin/fsfreeze"),
            copy_program: PathBuf::from("/bin/cp"),
        }
    }

    fn validate(&self) -> Result<(), VolumeError> {
        if !self.root.is_absolute()
            || self.minimum_quota_bytes < runtrue_sandbox_core::MINIMUM_NAMED_VOLUME_BYTES
            || self.maximum_quota_bytes < self.minimum_quota_bytes
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(3_600)
            || self.maximum_output_bytes == 0
            || self.maximum_output_bytes > 16 * 1024 * 1024
            || [
                &self.mkfs_ext4_program,
                &self.losetup_program,
                &self.fsfreeze_program,
                &self.copy_program,
            ]
            .iter()
            .any(|program| !program.is_absolute())
        {
            return Err(VolumeError::Invalid(
                "local volume provider configuration is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

pub struct LocalVolumeProvider {
    config: LocalVolumeConfig,
    secret_resolver: Option<Arc<dyn SecretResolver>>,
    operations: Mutex<()>,
}

pub struct LocalSecretResolver {
    root: PathBuf,
    root_directory: File,
    maximum_total_bytes: u64,
}

impl LocalSecretResolver {
    pub fn open(root: PathBuf, maximum_total_bytes: u64) -> Result<Self, VolumeError> {
        if !root.is_absolute() || maximum_total_bytes == 0 {
            return Err(VolumeError::Invalid(
                "local secret resolver configuration is invalid".to_owned(),
            ));
        }
        create_private_directory(&root)?;
        let root = fs::canonicalize(&root).map_err(|error| io_error(&root, error))?;
        let root_directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&root)
            .map_err(|error| io_error(&root, error))?;
        let metadata = root_directory
            .metadata()
            .map_err(|error| io_error(&root, error))?;
        if !metadata.is_dir()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(VolumeError::AccessDenied(
                "local secret root must be owner-only".to_owned(),
            ));
        }
        Ok(Self {
            root,
            root_directory,
            maximum_total_bytes,
        })
    }

    fn open_scoped_directory(
        &self,
        scope: &VolumeScope,
        volume_id: &runtrue_sandbox_core::VolumeId,
    ) -> Result<(Dir, PathBuf), VolumeError> {
        let components = [
            "tenants",
            scope.tenant_id().as_str(),
            "workspaces",
            scope.workspace_id().as_str(),
            volume_id.as_str(),
        ];
        let mut path = self.root.clone();
        let mut directory: OwnedFd = self
            .root_directory
            .try_clone()
            .map_err(|error| io_error(&self.root, error))?
            .into();
        // A one-component-at-a-time dirfd walk provides the relevant openat2
        // RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS guarantees on supported Unix targets.
        for component in components {
            path.push(component);
            directory = openat(
                &directory,
                component,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| match error {
                Errno::ENOENT => VolumeError::NotFound(volume_id.to_string()),
                Errno::EACCES | Errno::ELOOP | Errno::ENOTDIR => VolumeError::AccessDenied(
                    "secret source path must not contain symbolic links".to_owned(),
                ),
                _ => io_error(&path, error.into()),
            })?;
        }
        let metadata =
            nix::sys::stat::fstat(&directory).map_err(|error| io_error(&path, error.into()))?;
        if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
            || metadata.st_uid != nix::unistd::geteuid().as_raw()
            || metadata.st_mode & 0o077 != 0
        {
            return Err(VolumeError::AccessDenied(
                "secret source directory must be owner-only".to_owned(),
            ));
        }
        let directory = Dir::from_fd(directory).map_err(|error| io_error(&path, error.into()))?;
        Ok((directory, path))
    }
}

impl SecretResolver for LocalSecretResolver {
    fn resolve(
        &self,
        scope: &VolumeScope,
        volume_id: &runtrue_sandbox_core::VolumeId,
    ) -> Result<Vec<crate::SecretFile>, VolumeError> {
        let (mut directory, directory_path) = self.open_scoped_directory(scope, volume_id)?;
        let mut entries = Vec::new();
        for entry in directory.iter() {
            let entry = entry.map_err(|error| io_error(&directory_path, error.into()))?;
            let filename = entry.file_name();
            if filename.to_bytes() == b"." || filename.to_bytes() == b".." {
                continue;
            }
            let name = filename
                .to_str()
                .map_err(|_| VolumeError::Invalid("secret filename is not UTF-8".to_owned()))?
                .to_owned();
            validate_secret_name(&name)?;
            entries.push((name, filename.to_owned(), entry.ino()));
            if entries.len() > 1_024 {
                return Err(VolumeError::Invalid(
                    "secret source contains an invalid file count".to_owned(),
                ));
            }
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        if entries.is_empty() || entries.len() > 1_024 {
            return Err(VolumeError::Invalid(
                "secret source contains an invalid file count".to_owned(),
            ));
        }
        let mut total = 0_u64;
        let mut files = Vec::with_capacity(entries.len());
        for (name, filename, inode) in entries {
            let path = directory_path.join(&name);
            let descriptor = openat(
                &directory,
                filename.as_c_str(),
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
                Mode::empty(),
            )
            .map_err(|error| match error {
                Errno::EACCES | Errno::ELOOP => VolumeError::AccessDenied(
                    "secret source must not contain symbolic links".to_owned(),
                ),
                _ => io_error(&path, error.into()),
            })?;
            let mut file = File::from(descriptor);
            let metadata = file.metadata().map_err(|error| io_error(&path, error))?;
            total = total
                .checked_add(metadata.len())
                .ok_or_else(|| VolumeError::Invalid("secret size overflow".to_owned()))?;
            if !metadata.file_type().is_file()
                || metadata.ino() != inode
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.permissions().mode() & 0o077 != 0
                || total > self.maximum_total_bytes
            {
                return Err(VolumeError::AccessDenied(
                    "secret source must contain bounded owner-only regular files".to_owned(),
                ));
            }
            let capacity = usize::try_from(metadata.len())
                .map_err(|_| VolumeError::Invalid("secret file is too large".to_owned()))?;
            let mut contents = Zeroizing::new(Vec::with_capacity(capacity));
            std::io::Read::by_ref(&mut file)
                .take(metadata.len().saturating_add(1))
                .read_to_end(&mut contents)
                .map_err(|error| io_error(&path, error))?;
            if contents.len() != capacity {
                return Err(VolumeError::Integrity(
                    "secret file changed while it was materialized".to_owned(),
                ));
            }
            files.push(crate::SecretFile { name, contents });
        }
        Ok(files)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VolumeRecord {
    schema_version: u32,
    provider_id: String,
    key: String,
    tenant_id: String,
    workspace_id: String,
    volume_id: String,
    persistence_class: VolumePersistenceClass,
    quota_bytes: u64,
    content_digest: Option<String>,
    frozen: bool,
    attachments: BTreeMap<String, AttachmentRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentRecord {
    sandbox_id: String,
    container_id: String,
    destination: String,
    read_only: bool,
    snapshot_policy: VolumeSnapshotPolicy,
}

fn record_freeze<Freeze, Persist, Thaw>(
    record: &mut VolumeRecord,
    freeze: Freeze,
    persist: Persist,
    thaw: Thaw,
) -> Result<(), VolumeError>
where
    Freeze: FnOnce() -> Result<(), VolumeError>,
    Persist: FnOnce(&VolumeRecord) -> Result<(), VolumeError>,
    Thaw: FnOnce() -> Result<(), VolumeError>,
{
    if record.frozen {
        return Ok(());
    }
    freeze()?;
    record.frozen = true;
    if let Err(error) = persist(record) {
        let thaw = thaw();
        if thaw.is_ok() {
            record.frozen = false;
        }
        return match thaw {
            Ok(()) => Err(error),
            Err(thaw_error) => Err(VolumeError::Mount(format!(
                "record frozen volume failed: {error}; unfreeze failed: {thaw_error}"
            ))),
        };
    }
    Ok(())
}

fn record_thaw<Thaw, Persist>(
    record: &mut VolumeRecord,
    thaw: Thaw,
    persist: Persist,
) -> Result<(), VolumeError>
where
    Thaw: FnOnce() -> Result<(), VolumeError>,
    Persist: FnOnce(&VolumeRecord) -> Result<(), VolumeError>,
{
    if !record.frozen {
        return Ok(());
    }
    thaw()?;
    record.frozen = false;
    if let Err(error) = persist(record) {
        record.frozen = true;
        return Err(error);
    }
    Ok(())
}

impl LocalVolumeProvider {
    pub fn open(config: LocalVolumeConfig) -> Result<Self, VolumeError> {
        Self::open_with_secret_resolver(config, None)
    }

    pub fn open_with_secret_resolver(
        config: LocalVolumeConfig,
        secret_resolver: Option<Arc<dyn SecretResolver>>,
    ) -> Result<Self, VolumeError> {
        config.validate()?;
        create_private_directory(&config.root)?;
        let root = fs::canonicalize(&config.root).map_err(|error| io_error(&config.root, error))?;
        let metadata = fs::metadata(&root).map_err(|error| io_error(&root, error))?;
        if !metadata.is_dir() || metadata.uid() != nix::unistd::geteuid().as_raw() {
            return Err(VolumeError::AccessDenied(
                "local volume root must be owned by the provider UID".to_owned(),
            ));
        }
        for child in ["volumes", "artifacts"] {
            create_private_directory(&root.join(child))?;
        }
        let provider = Self {
            config: LocalVolumeConfig { root, ..config },
            secret_resolver,
            operations: Mutex::new(()),
        };
        provider.cleanup()?;
        Ok(provider)
    }

    pub fn publish_artifact(
        &self,
        source: &Path,
        expected_digest: &str,
    ) -> Result<ArtifactPublication, VolumeError> {
        self.publish_artifact_impl(source, expected_digest)
    }

    fn publish_artifact_impl(
        &self,
        source: &Path,
        expected_digest: &str,
    ) -> Result<ArtifactPublication, VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        let canonical_digest = canonical_artifact_digest(expected_digest).ok_or_else(|| {
            VolumeError::Invalid("artifact digest is not a sha256 identity".to_owned())
        })?;
        let destination = self
            .artifact_path(&canonical_digest)
            .expect("canonical artifact digest");
        let artifact_root = self.config.root.join("artifacts");
        if destination.exists() {
            let size_bytes = verify_artifact(&destination, &canonical_digest)?;
            sync_directory(&artifact_root)?;
            return Ok(ArtifactPublication {
                digest: canonical_digest,
                size_bytes,
                status: ArtifactPublicationStatus::Reused,
            });
        }
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(source)
            .map_err(|error| io_error(source, error))?;
        if !input
            .metadata()
            .map_err(|error| io_error(source, error))?
            .is_file()
        {
            return Err(VolumeError::Invalid(
                "artifact source must be a regular file".to_owned(),
            ));
        }
        let mut temporary = Builder::new()
            .prefix(".artifact-")
            .tempfile_in(&artifact_root)
            .map_err(|error| io_error(&artifact_root, error))?;
        let mut digest = Sha256::new();
        let mut bytes = 0_u64;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = input
                .read(&mut buffer)
                .map_err(|error| io_error(source, error))?;
            if read == 0 {
                break;
            }
            bytes = bytes
                .checked_add(read as u64)
                .ok_or_else(|| VolumeError::Invalid("artifact size overflow".to_owned()))?;
            if bytes > self.config.maximum_quota_bytes {
                return Err(VolumeError::Invalid(
                    "artifact exceeds the provider byte limit".to_owned(),
                ));
            }
            digest.update(&buffer[..read]);
            temporary
                .write_all(&buffer[..read])
                .map_err(|error| io_error(&artifact_root, error))?;
        }
        let actual = format!("sha256:{}", hex::encode(digest.finalize()));
        if actual != canonical_digest {
            return Err(VolumeError::Integrity(
                "artifact source does not match its expected digest".to_owned(),
            ));
        }
        temporary
            .as_file_mut()
            .sync_all()
            .and_then(|()| {
                temporary
                    .as_file_mut()
                    .set_permissions(fs::Permissions::from_mode(0o444))
            })
            .and_then(|()| temporary.as_file_mut().sync_all())
            .map_err(|error| io_error(&artifact_root, error))?;
        match temporary.persist_noclobber(&destination) {
            Ok(_) => {
                sync_directory(&artifact_root)?;
                Ok(ArtifactPublication {
                    digest: canonical_digest,
                    size_bytes: bytes,
                    status: ArtifactPublicationStatus::Published,
                })
            }
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                let size_bytes = verify_artifact(&destination, &canonical_digest)?;
                sync_directory(&artifact_root)?;
                Ok(ArtifactPublication {
                    digest: canonical_digest,
                    size_bytes,
                    status: ArtifactPublicationStatus::Reused,
                })
            }
            Err(error) => Err(io_error(&destination, error.error)),
        }
    }

    #[must_use]
    pub fn artifact_path(&self, digest: &str) -> Option<PathBuf> {
        canonical_artifact_digest(digest)
            .and_then(|digest| digest.strip_prefix("sha256:").map(str::to_owned))
            .map(|value| self.config.root.join("artifacts").join(value))
    }

    pub fn garbage_collect_artifacts(
        &self,
        minimum_age: Duration,
    ) -> Result<ArtifactGarbageCollectionReport, VolumeError> {
        self.garbage_collect_artifacts_impl(minimum_age)
    }

    fn garbage_collect_artifacts_impl(
        &self,
        minimum_age: Duration,
    ) -> Result<ArtifactGarbageCollectionReport, VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        let mut referenced = BTreeSet::new();
        let volume_root = self.config.root.join("volumes");
        for entry in fs::read_dir(&volume_root).map_err(|error| io_error(&volume_root, error))? {
            let entry = entry.map_err(|error| io_error(&volume_root, error))?;
            let record = self.read_record(&entry.path())?;
            if record.persistence_class == VolumePersistenceClass::Artifact {
                if let Some(digest) = record.content_digest {
                    let digest = canonical_artifact_digest(&digest).ok_or_else(|| {
                        VolumeError::Integrity(
                            "artifact volume record contains a malformed digest".to_owned(),
                        )
                    })?;
                    referenced.insert(digest);
                }
            }
        }

        let artifact_root = self.config.root.join("artifacts");
        let now = SystemTime::now();
        let mut report = ArtifactGarbageCollectionReport::default();
        for entry in
            fs::read_dir(&artifact_root).map_err(|error| io_error(&artifact_root, error))?
        {
            let entry = entry.map_err(|error| io_error(&artifact_root, error))?;
            let name = entry.file_name().into_string().map_err(|_| {
                VolumeError::Integrity("artifact store contains a non-UTF-8 entry".to_owned())
            })?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| io_error(entry.path(), error))?;
            if !metadata.file_type().is_file() {
                return Err(VolumeError::Integrity(
                    "artifact store contains a non-regular entry".to_owned(),
                ));
            }
            let old_enough = metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age >= minimum_age);
            if name.starts_with(".artifact-") {
                if old_enough {
                    fs::remove_file(entry.path()).map_err(|error| io_error(entry.path(), error))?;
                    report.removed_staging_files += 1;
                } else {
                    report.retained_staging_files += 1;
                }
                continue;
            }
            let digest = canonical_artifact_digest(&format!("sha256:{name}")).ok_or_else(|| {
                VolumeError::Integrity("artifact store contains an unexpected entry".to_owned())
            })?;
            if referenced.contains(&digest) || !old_enough {
                report.retained_artifacts += 1;
            } else {
                fs::remove_file(entry.path()).map_err(|error| io_error(entry.path(), error))?;
                report.removed_artifacts += 1;
            }
        }
        if report.removed_artifacts > 0 || report.removed_staging_files > 0 {
            sync_directory(&artifact_root)?;
        }
        Ok(report)
    }

    fn create_locked(
        &self,
        scope: &VolumeScope,
        specification: &VolumeSpec,
    ) -> Result<VolumeHandle, VolumeError> {
        specification
            .validate()
            .map_err(|error| VolumeError::Invalid(error.to_string()))?;
        if matches!(
            specification.persistence_class,
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent
        ) && (specification.quota_bytes < self.config.minimum_quota_bytes
            || specification.quota_bytes > self.config.maximum_quota_bytes)
        {
            return Err(VolumeError::Invalid(
                "named volume quota is outside provider limits".to_owned(),
            ));
        }
        if specification.persistence_class == VolumePersistenceClass::Secret
            && specification.quota_bytes > self.config.maximum_quota_bytes
        {
            return Err(VolumeError::Invalid(
                "secret tmpfs quota exceeds the provider limit".to_owned(),
            ));
        }
        let key = volume_key(scope, specification.volume_id.as_str());
        let directory = self.volume_directory(&key);
        if directory.exists() {
            let record = self.read_record(&directory)?;
            self.validate_record(scope, specification, &key, &record)?;
            return Ok(handle(scope, specification, key));
        }
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    VolumeError::AlreadyExists(specification.volume_id.to_string())
                } else {
                    io_error(&directory, error)
                }
            })?;
        let result = self.initialize_volume(&directory, scope, specification, &key);
        if result.is_err() {
            let _ = self.cleanup_directory(&directory, specification.persistence_class);
        }
        result.map(|()| handle(scope, specification, key))
    }

    fn initialize_volume(
        &self,
        directory: &Path,
        scope: &VolumeScope,
        specification: &VolumeSpec,
        key: &str,
    ) -> Result<(), VolumeError> {
        match specification.persistence_class {
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent => {
                self.initialize_named(directory, key, specification.quota_bytes)?;
            }
            VolumePersistenceClass::Artifact => {
                let digest = specification
                    .content_digest
                    .as_deref()
                    .expect("validated artifact digest");
                let artifact = self
                    .artifact_path(digest)
                    .expect("validated artifact digest syntax");
                verify_artifact(&artifact, digest)?;
            }
            VolumePersistenceClass::Secret => {
                self.initialize_secret(directory, scope, specification)?;
            }
        }
        self.write_record(
            directory,
            &VolumeRecord {
                schema_version: RECORD_VERSION,
                provider_id: LOCAL_VOLUME_PROVIDER_ID.to_owned(),
                key: key.to_owned(),
                tenant_id: scope.tenant_id().to_string(),
                workspace_id: scope.workspace_id().to_string(),
                volume_id: specification.volume_id.to_string(),
                persistence_class: specification.persistence_class,
                quota_bytes: specification.quota_bytes,
                content_digest: specification.content_digest.clone(),
                frozen: false,
                attachments: BTreeMap::new(),
            },
        )
    }

    fn initialize_named(&self, directory: &Path, key: &str, quota: u64) -> Result<(), VolumeError> {
        let backing = directory.join("quota.ext4");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&backing)
            .map_err(|error| io_error(&backing, error))?;
        file.set_len(quota)
            .map_err(|error| io_error(&backing, error))?;
        file.sync_all().map_err(|error| io_error(&backing, error))?;
        let uuid = filesystem_uuid(key);
        self.run_external(
            &self.config.mkfs_ext4_program,
            &[
                "-q",
                "-F",
                "-m",
                "0",
                "-U",
                &uuid,
                backing.to_str().ok_or_else(|| {
                    VolumeError::Invalid("volume backing path is not UTF-8".to_owned())
                })?,
            ],
            "format named volume",
        )?;
        DirBuilder::new()
            .mode(0o700)
            .create(directory.join("data"))
            .map_err(|error| io_error(directory.join("data"), error))
    }

    fn initialize_secret(
        &self,
        directory: &Path,
        scope: &VolumeScope,
        specification: &VolumeSpec,
    ) -> Result<(), VolumeError> {
        let resolver = self.secret_resolver.as_ref().ok_or_else(|| {
            VolumeError::Unsupported("secret resolver is not configured".to_owned())
        })?;
        let data = directory.join("data");
        DirBuilder::new()
            .mode(0o700)
            .create(&data)
            .map_err(|error| io_error(&data, error))?;
        let options = format!("size={},mode=0700", specification.quota_bytes);
        mount(
            Some("tmpfs"),
            &data,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            Some(options.as_str()),
        )
        .map_err(|error| VolumeError::Mount(format!("mount secret tmpfs: {error}")))?;
        let files = resolver.resolve(scope, &specification.volume_id)?;
        if files.is_empty() || files.len() > 1_024 {
            return Err(VolumeError::Invalid(
                "secret resolver returned an invalid file count".to_owned(),
            ));
        }
        let mut names = BTreeSet::new();
        for secret in files {
            validate_secret_name(&secret.name)?;
            if !names.insert(secret.name.clone()) {
                return Err(VolumeError::Invalid(
                    "secret resolver returned duplicate names".to_owned(),
                ));
            }
            let path = data.join(&secret.name);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .open(&path)
                .map_err(|error| io_error(&path, error))?;
            file.write_all(&secret.contents)
                .and_then(|()| file.set_permissions(fs::Permissions::from_mode(0o444)))
                .and_then(|()| file.sync_all())
                .map_err(|error| io_error(&path, error))?;
        }
        fs::set_permissions(&data, fs::Permissions::from_mode(0o555))
            .map_err(|error| io_error(&data, error))?;
        Ok(())
    }

    fn validate_record(
        &self,
        scope: &VolumeScope,
        specification: &VolumeSpec,
        key: &str,
        record: &VolumeRecord,
    ) -> Result<(), VolumeError> {
        if record.schema_version != RECORD_VERSION
            || record.provider_id != LOCAL_VOLUME_PROVIDER_ID
            || record.key != key
            || record.tenant_id != scope.tenant_id().as_str()
            || record.workspace_id != scope.workspace_id().as_str()
            || record.volume_id != specification.volume_id.as_str()
            || record.persistence_class != specification.persistence_class
            || record.quota_bytes != specification.quota_bytes
            || record.content_digest != specification.content_digest
        {
            return Err(VolumeError::AccessDenied(
                "volume identity or tenant scope does not match provider state".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_handle(&self, handle: &VolumeHandle) -> Result<VolumeRecord, VolumeError> {
        if handle.provider_id != LOCAL_VOLUME_PROVIDER_ID
            || handle.key != volume_key(&handle.scope, handle.volume_id.as_str())
        {
            return Err(VolumeError::AccessDenied(
                "volume handle belongs to another provider".to_owned(),
            ));
        }
        let directory = self.volume_directory(&handle.key);
        let record = self.read_record(&directory)?;
        let synthetic = VolumeSpec {
            schema_version: runtrue_sandbox_core::VOLUME_SPEC_VERSION,
            volume_id: handle.volume_id.clone(),
            destination: "/volume-handle-validation".to_owned(),
            read_only: matches!(
                handle.persistence_class,
                VolumePersistenceClass::Artifact | VolumePersistenceClass::Secret
            ),
            persistence_class: handle.persistence_class,
            snapshot_policy: if handle.persistence_class == VolumePersistenceClass::Secret {
                VolumeSnapshotPolicy::Excluded
            } else {
                VolumeSnapshotPolicy::BestEffort
            },
            quota_bytes: handle.quota_bytes,
            content_digest: handle.content_digest.clone(),
        };
        self.validate_record(&handle.scope, &synthetic, &handle.key, &record)?;
        Ok(record)
    }

    fn validate_attachment(
        &self,
        attachment: &VolumeAttachment,
    ) -> Result<VolumeRecord, VolumeError> {
        let record = self.validate_handle(&attachment.handle)?;
        let expected = AttachmentRecord {
            sandbox_id: attachment.owner.sandbox_id.to_string(),
            container_id: attachment.owner.container_id.to_string(),
            destination: attachment.destination.clone(),
            read_only: attachment.read_only,
            snapshot_policy: attachment.snapshot_policy,
        };
        if record
            .attachments
            .get(&attachment.attachment_id)
            .is_none_or(|value| {
                value.sandbox_id != expected.sandbox_id
                    || value.container_id != expected.container_id
                    || value.destination != expected.destination
                    || value.read_only != expected.read_only
                    || value.snapshot_policy != expected.snapshot_policy
            })
        {
            return Err(VolumeError::AccessDenied(
                "volume attachment ownership does not match provider state".to_owned(),
            ));
        }
        Ok(record)
    }

    fn mount_named(&self, directory: &Path) -> Result<PathBuf, VolumeError> {
        let data = directory.join("data");
        if is_mount(&data)? {
            return fs::canonicalize(&data).map_err(|error| io_error(&data, error));
        }
        let backing = directory.join("quota.ext4");
        let result = self.run_external(
            &self.config.losetup_program,
            &[
                "--find",
                "--show",
                "--nooverlap",
                backing.to_str().ok_or_else(|| {
                    VolumeError::Invalid("volume backing path is not UTF-8".to_owned())
                })?,
            ],
            "attach named volume loop device",
        )?;
        let device = parse_loop_device(&result.stdout)?;
        let mounted = mount(
            Some(device.as_path()),
            &data,
            Some("ext4"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("errors=remount-ro"),
        );
        if let Err(error) = mounted {
            let _ = self.run_external(
                &self.config.losetup_program,
                &["--detach", device.to_string_lossy().as_ref()],
                "detach failed named volume loop device",
            );
            return Err(VolumeError::Mount(format!("mount named volume: {error}")));
        }
        fs::canonicalize(&data).map_err(|error| io_error(&data, error))
    }

    fn storage_path(
        &self,
        handle: &VolumeHandle,
        directory: &Path,
    ) -> Result<PathBuf, VolumeError> {
        match handle.persistence_class {
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent => {
                self.mount_named(directory)
            }
            VolumePersistenceClass::Artifact => {
                let digest = handle.content_digest.as_deref().ok_or_else(|| {
                    VolumeError::Integrity("artifact handle omitted its digest".to_owned())
                })?;
                let path = self.artifact_path(digest).ok_or_else(|| {
                    VolumeError::Integrity("artifact handle digest is malformed".to_owned())
                })?;
                verify_artifact(&path, digest)?;
                Ok(path)
            }
            VolumePersistenceClass::Secret => {
                let data = directory.join("data");
                if !is_mount(&data)? {
                    return Err(VolumeError::Integrity(
                        "secret tmpfs is no longer mounted".to_owned(),
                    ));
                }
                fs::canonicalize(&data).map_err(|error| io_error(&data, error))
            }
        }
    }

    fn thaw(&self, directory: &Path, record: &mut VolumeRecord) -> Result<(), VolumeError> {
        if !record.frozen {
            return Ok(());
        }
        let data = directory.join("data");
        let mounted = is_mount(&data)?;
        record_thaw(
            record,
            || {
                if mounted {
                    self.unfreeze(&data, "unfreeze named volume")
                } else {
                    Ok(())
                }
            },
            |record| self.write_record(directory, record),
        )
    }

    fn recover_named_mount(&self, directory: &Path) -> Result<(), VolumeError> {
        let data = directory.join("data");
        if !is_mount(&data)? {
            return Ok(());
        }
        let thaw = self.unfreeze(&data, "unfreeze volume during recovery");
        let unmount = umount(&data).map_err(|error| {
            VolumeError::Mount(format!("unmount volume during recovery: {error}"))
        });
        finish_mount_recovery(thaw, unmount)
    }

    fn unmount_storage(&self, directory: &Path) -> Result<(), VolumeError> {
        let data = directory.join("data");
        if is_mount(&data)? {
            umount(&data)
                .map_err(|error| VolumeError::Mount(format!("unmount named volume: {error}")))?;
        }
        let backing = directory.join("quota.ext4");
        if backing.exists() {
            for device in self.associated_loop_devices(&backing)? {
                self.run_external(
                    &self.config.losetup_program,
                    &["--detach", device.to_string_lossy().as_ref()],
                    "detach named volume loop device",
                )?;
            }
        }
        Ok(())
    }

    fn cleanup_directory(
        &self,
        directory: &Path,
        class: VolumePersistenceClass,
    ) -> Result<(), VolumeError> {
        let data = directory.join("data");
        if data.exists() && is_mount(&data)? {
            umount(&data).map_err(|error| {
                VolumeError::Mount(format!("unmount volume during cleanup: {error}"))
            })?;
        }
        if matches!(
            class,
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent
        ) {
            let backing = directory.join("quota.ext4");
            if backing.exists() {
                for device in self.associated_loop_devices(&backing)? {
                    self.run_external(
                        &self.config.losetup_program,
                        &["--detach", device.to_string_lossy().as_ref()],
                        "detach volume during cleanup",
                    )?;
                }
            }
        }
        if directory.exists() {
            fs::remove_dir_all(directory).map_err(|error| io_error(directory, error))?;
            File::open(self.config.root.join("volumes"))
                .and_then(|root| root.sync_all())
                .map_err(|error| io_error(self.config.root.join("volumes"), error))?;
        }
        Ok(())
    }

    fn cleanup_orphan_directory(&self, directory: &Path) -> Result<(), VolumeError> {
        let data = directory.join("data");
        if data.exists() && is_mount(&data)? {
            umount(&data)
                .map_err(|error| VolumeError::Mount(format!("unmount orphaned volume: {error}")))?;
        }
        let backing = directory.join("quota.ext4");
        if backing.exists() {
            for device in self.associated_loop_devices(&backing)? {
                self.run_external(
                    &self.config.losetup_program,
                    &["--detach", device.to_string_lossy().as_ref()],
                    "detach orphaned volume loop device",
                )?;
            }
        }
        fs::remove_dir_all(directory).map_err(|error| io_error(directory, error))
    }

    fn restore_backing_atomically(
        &self,
        directory: &Path,
        source: &Path,
        snapshot: &VolumeSnapshot,
    ) -> Result<(), VolumeError> {
        let staging = directory.join("quota.restore");
        if staging.exists() {
            fs::remove_file(&staging).map_err(|error| io_error(&staging, error))?;
        }
        let copied = self.run_external(
            &self.config.copy_program,
            &[
                "--sparse=always",
                "--reflink=auto",
                source.to_string_lossy().as_ref(),
                staging.to_string_lossy().as_ref(),
            ],
            "stage named volume restore",
        );
        if let Err(error) = copied {
            let _ = fs::remove_file(&staging);
            return Err(error);
        }
        let (digest, size) = match digest_file(&staging) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                let _ = fs::remove_file(&staging);
                return Err(error);
            }
        };
        if digest != snapshot.digest || size != snapshot.size_bytes {
            let _ = fs::remove_file(&staging);
            return Err(VolumeError::Integrity(
                "restored volume changed while it was staged".to_owned(),
            ));
        }
        fs::rename(&staging, directory.join("quota.ext4"))
            .map_err(|error| io_error(&staging, error))?;
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error(directory, error))
    }

    fn associated_loop_devices(&self, backing: &Path) -> Result<Vec<PathBuf>, VolumeError> {
        let output = self.run_external(
            &self.config.losetup_program,
            &[
                "--associated",
                backing.to_string_lossy().as_ref(),
                "--output",
                "NAME",
                "--noheadings",
            ],
            "list named volume loop devices",
        )?;
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| parse_loop_device(line.as_bytes()))
            .collect()
    }

    fn volume_directory(&self, key: &str) -> PathBuf {
        self.config.root.join("volumes").join(key)
    }

    fn read_record(&self, directory: &Path) -> Result<VolumeRecord, VolumeError> {
        let path = directory.join("volume.json");
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                VolumeError::NotFound(directory.display().to_string())
            } else {
                io_error(&path, error)
            }
        })?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(VolumeError::Integrity(
                "volume record is not an owner-only regular file".to_owned(),
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| io_error(&path, error))?;
        serde_json::from_reader(file)
            .map_err(|error| VolumeError::Integrity(format!("decode volume record: {error}")))
    }

    fn write_record(&self, directory: &Path, record: &VolumeRecord) -> Result<(), VolumeError> {
        let bytes = serde_json::to_vec(record)
            .map_err(|error| VolumeError::Integrity(format!("encode volume record: {error}")))?;
        if bytes.len() > 1024 * 1024 {
            return Err(VolumeError::Invalid(
                "volume attachment record exceeds 1 MiB".to_owned(),
            ));
        }
        let mut temporary = Builder::new()
            .prefix(".volume-record-")
            .tempfile_in(directory)
            .map_err(|error| io_error(directory, error))?;
        temporary
            .as_file_mut()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|()| temporary.write_all(&bytes))
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|error| io_error(directory, error))?;
        let path = directory.join("volume.json");
        temporary
            .persist(&path)
            .map_err(|error| io_error(&path, error.error))?;
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error(directory, error))
    }

    fn run_external_status(
        &self,
        program: &Path,
        arguments: &[&str],
        operation: &str,
    ) -> Result<std::process::Output, VolumeError> {
        let mut child = Command::new(program)
            .args(arguments)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| io_error(program, error))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| VolumeError::Invalid(format!("{operation} stdout is unavailable")))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| VolumeError::Invalid(format!("{operation} stderr is unavailable")))?;
        let output_limit = self.config.maximum_output_bytes;
        let stdout_reader = thread::spawn(move || read_bounded(stdout, output_limit));
        let stderr_reader = thread::spawn(move || read_bounded(stderr, output_limit));
        let deadline = Instant::now() + self.config.operation_timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(VolumeError::Timeout(operation.to_owned()));
                }
                Err(error) => {
                    let error = io_error(program, error);
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(error);
                }
            }
        };
        let stdout = stdout_reader.join();
        let stderr = stderr_reader.join();
        let stdout = stdout
            .map_err(|_| VolumeError::Invalid(format!("{operation} stdout reader panicked")))?;
        let stderr = stderr
            .map_err(|_| VolumeError::Invalid(format!("{operation} stderr reader panicked")))?;
        let status = status?;
        let stdout = stdout.map_err(|error| io_error(program, error))?;
        let stderr = stderr.map_err(|error| io_error(program, error))?;
        let output_exceeded =
            stdout.observed_bytes.saturating_add(stderr.observed_bytes) > output_limit;
        if output_exceeded {
            let detail = format_stderr(&stderr.bytes, stderr.truncated);
            let suffix = if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            };
            return Err(VolumeError::Invalid(format!(
                "{operation} output exceeded its byte limit{suffix}"
            )));
        }
        Ok(std::process::Output {
            status,
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        })
    }

    fn run_external(
        &self,
        program: &Path,
        arguments: &[&str],
        operation: &str,
    ) -> Result<std::process::Output, VolumeError> {
        let output = self.run_external_status(program, arguments, operation)?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(external_status_error(operation, &output))
        }
    }

    fn unfreeze(&self, data: &Path, operation: &str) -> Result<(), VolumeError> {
        let output = self.run_external_status(
            &self.config.fsfreeze_program,
            &["--unfreeze", data.to_string_lossy().as_ref()],
            operation,
        )?;
        if output.status.success() || is_already_thawed(&output) {
            Ok(())
        } else {
            Err(external_status_error(operation, &output))
        }
    }

    fn release_attachment_locked(&self, attachment: &VolumeAttachment) -> Result<(), VolumeError> {
        let mut record = self.validate_attachment(attachment)?;
        record.attachments.remove(&attachment.attachment_id);
        let directory = self.volume_directory(&attachment.handle.key);
        if record.attachments.is_empty() {
            if record.frozen {
                self.thaw(&directory, &mut record)?;
            }
            match record.persistence_class {
                VolumePersistenceClass::Persistent => {
                    self.unmount_storage(&directory)?;
                    self.write_record(&directory, &record)?;
                }
                VolumePersistenceClass::Ephemeral
                | VolumePersistenceClass::Artifact
                | VolumePersistenceClass::Secret => {
                    self.cleanup_directory(&directory, record.persistence_class)?;
                }
            }
        } else {
            self.write_record(&directory, &record)?;
        }
        Ok(())
    }
}

impl ArtifactVolumeStore for LocalVolumeProvider {
    fn publish_artifact(
        &self,
        source: &Path,
        expected_digest: &str,
    ) -> Result<ArtifactPublication, VolumeError> {
        self.publish_artifact_impl(source, expected_digest)
    }

    fn garbage_collect_artifacts(
        &self,
        minimum_age: Duration,
    ) -> Result<ArtifactGarbageCollectionReport, VolumeError> {
        self.garbage_collect_artifacts_impl(minimum_age)
    }
}

impl VolumeProvider for LocalVolumeProvider {
    fn provider_id(&self) -> &str {
        LOCAL_VOLUME_PROVIDER_ID
    }

    fn capabilities(&self) -> VolumeProviderCapabilities {
        VolumeProviderCapabilities {
            persistence_classes: BTreeSet::from([
                VolumePersistenceClass::Ephemeral,
                VolumePersistenceClass::Persistent,
                VolumePersistenceClass::Artifact,
                VolumePersistenceClass::Secret,
            ]),
            snapshot: true,
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
        self.create_locked(scope, specification)
    }

    fn attach(
        &self,
        handle: &VolumeHandle,
        owner: AttachmentOwner,
        specification: &VolumeSpec,
    ) -> Result<VolumeAttachment, VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        validate_handle_spec(handle, specification)?;
        let mut record = self.validate_handle(handle)?;
        if record.frozen {
            return Err(VolumeError::Invalid(
                "cannot attach a frozen volume".to_owned(),
            ));
        }
        if record.attachments.len() >= 1_024 {
            return Err(VolumeError::Invalid(
                "volume attachment limit exceeded".to_owned(),
            ));
        }
        let id = attachment_key(handle, &owner, &specification.destination);
        let attachment_record = AttachmentRecord {
            sandbox_id: owner.sandbox_id.to_string(),
            container_id: owner.container_id.to_string(),
            destination: specification.destination.clone(),
            read_only: specification.read_only,
            snapshot_policy: specification.snapshot_policy,
        };
        if record
            .attachments
            .insert(id.clone(), attachment_record.clone())
            .is_some_and(|existing| {
                existing.sandbox_id != attachment_record.sandbox_id
                    || existing.container_id != attachment_record.container_id
                    || existing.destination != attachment_record.destination
                    || existing.read_only != attachment_record.read_only
                    || existing.snapshot_policy != attachment_record.snapshot_policy
            })
        {
            return Err(VolumeError::AccessDenied(
                "volume attachment identity collision".to_owned(),
            ));
        }
        self.write_record(&self.volume_directory(&handle.key), &record)?;
        Ok(VolumeAttachment {
            handle: handle.clone(),
            attachment_id: id,
            owner,
            destination: specification.destination.clone(),
            read_only: specification.read_only,
            snapshot_policy: specification.snapshot_policy,
        })
    }

    fn mount(&self, attachment: &VolumeAttachment) -> Result<MountedVolume, VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        let record = self.validate_attachment(attachment)?;
        if record.frozen {
            return Err(VolumeError::Invalid(
                "cannot mount a frozen volume".to_owned(),
            ));
        }
        let directory = self.volume_directory(&attachment.handle.key);
        let source = self.storage_path(&attachment.handle, &directory)?;
        Ok(MountedVolume {
            attachment: attachment.clone(),
            source,
        })
    }

    fn detach(&self, attachment: &VolumeAttachment) -> Result<(), VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        self.release_attachment_locked(attachment)
    }

    fn freeze(&self, attachment: &VolumeAttachment) -> Result<(), VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        let mut record = self.validate_attachment(attachment)?;
        match record.persistence_class {
            VolumePersistenceClass::Artifact => return Ok(()),
            VolumePersistenceClass::Secret => {
                return Err(VolumeError::Unsupported(
                    "secret volumes are excluded from snapshots".to_owned(),
                ));
            }
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent => {}
        }
        if !record.frozen {
            let directory = self.volume_directory(&attachment.handle.key);
            let data = directory.join("data");
            if !is_mount(&data)? {
                return Err(VolumeError::Integrity(
                    "cannot freeze an unmounted named volume".to_owned(),
                ));
            }
            record_freeze(
                &mut record,
                || {
                    self.run_external(
                        &self.config.fsfreeze_program,
                        &["--freeze", data.to_string_lossy().as_ref()],
                        "freeze named volume",
                    )?;
                    Ok(())
                },
                |record| self.write_record(&directory, record),
                || self.unfreeze(&data, "unfreeze named volume after record failure"),
            )?;
        }
        Ok(())
    }

    fn thaw(&self, attachment: &VolumeAttachment) -> Result<(), VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        let mut record = self.validate_attachment(attachment)?;
        if matches!(
            record.persistence_class,
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent
        ) {
            self.thaw(&self.volume_directory(&attachment.handle.key), &mut record)?;
        }
        Ok(())
    }

    fn snapshot(
        &self,
        attachment: &VolumeAttachment,
        destination: &Path,
    ) -> Result<VolumeSnapshot, VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        let mut record = self.validate_attachment(attachment)?;
        if !matches!(
            record.persistence_class,
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent
        ) {
            return Err(VolumeError::Unsupported(
                "only named volumes produce writable snapshot objects".to_owned(),
            ));
        }
        if !record.frozen {
            return Err(VolumeError::Invalid(
                "named volume must be frozen before snapshot".to_owned(),
            ));
        }
        if destination.exists() {
            return Err(VolumeError::AlreadyExists(
                destination.display().to_string(),
            ));
        }
        let directory = self.volume_directory(&attachment.handle.key);
        let backing = directory.join("quota.ext4");
        let copied = self.run_external(
            &self.config.copy_program,
            &[
                "--sparse=always",
                "--reflink=auto",
                backing.to_string_lossy().as_ref(),
                destination.to_string_lossy().as_ref(),
            ],
            "copy named volume snapshot",
        );
        let snapshot = copied.and_then(|_| {
            let (digest, size_bytes) = digest_file(destination)?;
            Ok(VolumeSnapshot {
                schema_version: VOLUME_SNAPSHOT_VERSION,
                provider_id: LOCAL_VOLUME_PROVIDER_ID.to_owned(),
                volume_id: attachment.handle.volume_id.clone(),
                persistence_class: record.persistence_class,
                digest,
                size_bytes,
                quota_bytes: record.quota_bytes,
                format: "application/vnd.runtrue.volume.ext4.v1".to_owned(),
                portability: SnapshotPortability::CrossWorkerSameBackend,
            })
        });
        let thaw = self.thaw(&directory, &mut record);
        match (snapshot, thaw) {
            (Ok(snapshot), Ok(())) => Ok(snapshot),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(thaw_error)) => Err(VolumeError::Mount(format!(
                "snapshot failed: {error}; unfreeze failed: {thaw_error}"
            ))),
        }
    }

    fn restore(
        &self,
        scope: &VolumeScope,
        specification: &VolumeSpec,
        snapshot: &VolumeSnapshot,
        source: &Path,
    ) -> Result<VolumeHandle, VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        specification
            .validate()
            .map_err(|error| VolumeError::Invalid(error.to_string()))?;
        if snapshot.schema_version != VOLUME_SNAPSHOT_VERSION
            || snapshot.provider_id != LOCAL_VOLUME_PROVIDER_ID
            || snapshot.volume_id != specification.volume_id
            || snapshot.persistence_class != specification.persistence_class
            || snapshot.quota_bytes != specification.quota_bytes
            || snapshot.format != "application/vnd.runtrue.volume.ext4.v1"
            || !snapshot.portability.permits_cross_worker()
            || !matches!(
                specification.persistence_class,
                VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent
            )
        {
            return Err(VolumeError::Invalid(
                "volume snapshot is incompatible with the restore request".to_owned(),
            ));
        }
        let metadata = fs::symlink_metadata(source).map_err(|error| io_error(source, error))?;
        let (digest, size) = digest_file(source)?;
        if !metadata.file_type().is_file()
            || digest != snapshot.digest
            || size != snapshot.size_bytes
            || size != specification.quota_bytes
        {
            return Err(VolumeError::Integrity(
                "volume snapshot content does not match its descriptor".to_owned(),
            ));
        }
        let key = volume_key(scope, specification.volume_id.as_str());
        let directory = self.volume_directory(&key);
        if directory.exists() {
            let record = self.read_record(&directory)?;
            self.validate_record(scope, specification, &key, &record)?;
            if record.persistence_class != VolumePersistenceClass::Persistent
                || record.frozen
                || !record.attachments.is_empty()
            {
                return Err(VolumeError::AlreadyExists(
                    specification.volume_id.to_string(),
                ));
            }
            self.unmount_storage(&directory)?;
            self.restore_backing_atomically(&directory, source, snapshot)?;
            return Ok(handle(scope, specification, key));
        }
        let handle = self.create_locked(scope, specification)?;
        let backing = directory.join("quota.ext4");
        let copied = self.run_external(
            &self.config.copy_program,
            &[
                "--sparse=always",
                "--reflink=auto",
                source.to_string_lossy().as_ref(),
                backing.to_string_lossy().as_ref(),
            ],
            "restore named volume snapshot",
        );
        if let Err(error) = copied {
            let _ = self.cleanup_directory(&directory, specification.persistence_class);
            return Err(error);
        }
        let (restored_digest, restored_size) = digest_file(&backing)?;
        if restored_digest != snapshot.digest || restored_size != snapshot.size_bytes {
            let _ = self.cleanup_directory(&directory, specification.persistence_class);
            return Err(VolumeError::Integrity(
                "restored volume changed while it was copied".to_owned(),
            ));
        }
        Ok(handle)
    }

    fn unmount(&self, mounted: &MountedVolume) -> Result<(), VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        self.release_attachment_locked(&mounted.attachment)
    }

    fn delete(&self, handle: &VolumeHandle) -> Result<(), VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        let mut record = self.validate_handle(handle)?;
        if !record.attachments.is_empty() {
            return Err(VolumeError::Invalid(
                "cannot delete an attached volume".to_owned(),
            ));
        }
        let directory = self.volume_directory(&handle.key);
        if record.frozen {
            self.thaw(&directory, &mut record)?;
        }
        self.cleanup_directory(&directory, record.persistence_class)
    }

    fn cleanup(&self) -> Result<VolumeCleanupReport, VolumeError> {
        let _guard = self.operations.lock().expect("volume operation lock");
        let root = self.config.root.join("volumes");
        let mut report = VolumeCleanupReport::default();
        for entry in fs::read_dir(&root).map_err(|error| io_error(&root, error))? {
            let entry = entry.map_err(|error| io_error(&root, error))?;
            let metadata = entry
                .metadata()
                .map_err(|error| io_error(entry.path(), error))?;
            if !metadata.is_dir()
                || entry.file_name().to_str().is_none_or(|name| {
                    name.len() != 64 || !name.bytes().all(|b| b.is_ascii_hexdigit())
                })
            {
                return Err(VolumeError::Integrity(format!(
                    "unexpected entry in local volume root: {}",
                    entry.path().display()
                )));
            }
            let mut record = match self.read_record(&entry.path()) {
                Ok(record) => record,
                Err(VolumeError::NotFound(_)) => {
                    self.cleanup_orphan_directory(&entry.path())?;
                    report.removed_ephemeral_volumes += 1;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if record.schema_version != RECORD_VERSION
                || record.provider_id != LOCAL_VOLUME_PROVIDER_ID
                || record.key != entry.file_name().to_string_lossy()
            {
                return Err(VolumeError::Integrity(
                    "local volume record is invalid".to_owned(),
                ));
            }
            report.cleared_attachments += record.attachments.len();
            record.attachments.clear();
            if matches!(
                record.persistence_class,
                VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent
            ) {
                self.recover_named_mount(&entry.path())?;
            }
            record.frozen = false;
            match record.persistence_class {
                VolumePersistenceClass::Persistent => {
                    self.unmount_storage(&entry.path())?;
                    let restore_staging = entry.path().join("quota.restore");
                    if restore_staging.exists() {
                        fs::remove_file(&restore_staging)
                            .map_err(|error| io_error(&restore_staging, error))?;
                    }
                    self.write_record(&entry.path(), &record)?;
                    report.retained_persistent_volumes += 1;
                }
                VolumePersistenceClass::Ephemeral => {
                    self.cleanup_directory(&entry.path(), record.persistence_class)?;
                    report.removed_ephemeral_volumes += 1;
                }
                VolumePersistenceClass::Secret => {
                    self.cleanup_directory(&entry.path(), record.persistence_class)?;
                    report.removed_secret_volumes += 1;
                }
                VolumePersistenceClass::Artifact => {
                    self.cleanup_directory(&entry.path(), record.persistence_class)?;
                }
            }
        }
        Ok(report)
    }
}

fn handle(scope: &VolumeScope, specification: &VolumeSpec, key: String) -> VolumeHandle {
    VolumeHandle {
        provider_id: LOCAL_VOLUME_PROVIDER_ID.to_owned(),
        key,
        scope: scope.clone(),
        volume_id: specification.volume_id.clone(),
        persistence_class: specification.persistence_class,
        quota_bytes: specification.quota_bytes,
        content_digest: specification.content_digest.clone(),
    }
}

fn volume_key(scope: &VolumeScope, volume_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(scope.tenant_id().as_str().as_bytes());
    digest.update([0]);
    digest.update(scope.workspace_id().as_str().as_bytes());
    digest.update([0]);
    digest.update(volume_id.as_bytes());
    hex::encode(digest.finalize())
}

fn attachment_key(handle: &VolumeHandle, owner: &AttachmentOwner, destination: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(handle.key.as_bytes());
    digest.update([0]);
    digest.update(owner.sandbox_id.as_str().as_bytes());
    digest.update([0]);
    digest.update(owner.container_id.as_str().as_bytes());
    digest.update([0]);
    digest.update(destination.as_bytes());
    hex::encode(digest.finalize())
}

fn filesystem_uuid(key: &str) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        &key[0..8],
        &key[8..12],
        &key[12..16],
        &key[16..20],
        &key[20..32]
    )
}

fn create_private_directory(path: &Path) -> Result<(), VolumeError> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|error| io_error(path, error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| io_error(path, error))
}

fn sync_directory(path: &Path) -> Result<(), VolumeError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error(path, error))
}

fn validate_secret_name(name: &str) -> Result<(), VolumeError> {
    if name.is_empty()
        || name.len() > 255
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || matches!(name, "." | "..")
    {
        return Err(VolumeError::Invalid(
            "secret filename is not a bounded path-safe name".to_owned(),
        ));
    }
    Ok(())
}

fn parse_loop_device(output: &[u8]) -> Result<PathBuf, VolumeError> {
    let value = String::from_utf8_lossy(output).trim().to_owned();
    let path = PathBuf::from(&value);
    if !value.starts_with("/dev/loop")
        || value.len() <= 9
        || value.len() > 64
        || !value[9..].bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(VolumeError::Integrity(
            "losetup returned an invalid loop device".to_owned(),
        ));
    }
    Ok(path)
}

fn is_mount(path: &Path) -> Result<bool, VolumeError> {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mounts = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| io_error("/proc/self/mountinfo", error))?;
    Ok(mounts.lines().any(|line| {
        line.split_whitespace()
            .nth(4)
            .is_some_and(|mountpoint| decode_mount_path(mountpoint) == canonical)
    }))
}

fn decode_mount_path(value: &str) -> PathBuf {
    PathBuf::from(
        value
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\"),
    )
}

struct BoundedOutput {
    bytes: Vec<u8>,
    observed_bytes: usize,
    truncated: bool,
}

fn read_bounded(mut reader: impl Read, maximum: usize) -> Result<BoundedOutput, std::io::Error> {
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    let mut observed_bytes = 0_usize;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        observed_bytes = observed_bytes
            .saturating_add(read)
            .min(maximum.saturating_add(1));
        let retained = maximum.saturating_sub(bytes.len()).min(read);
        bytes.write_all(&buffer[..retained])?;
    }
    Ok(BoundedOutput {
        truncated: observed_bytes > bytes.len(),
        bytes,
        observed_bytes,
    })
}

fn format_stderr(stderr: &[u8], truncated: bool) -> String {
    let suffix = if truncated { " [truncated]" } else { "" };
    format!("{}{suffix}", String::from_utf8_lossy(stderr).trim())
}

fn external_status_error(operation: &str, output: &std::process::Output) -> VolumeError {
    VolumeError::Mount(format!(
        "{operation} exited {}: {}",
        output.status,
        format_stderr(&output.stderr, false)
    ))
}

fn is_already_thawed(output: &std::process::Output) -> bool {
    output.status.code() == Some(1)
        && String::from_utf8_lossy(&output.stderr)
            .lines()
            .next_back()
            .is_some_and(|line| line.ends_with(": Invalid argument"))
}

fn finish_mount_recovery(
    thaw: Result<(), VolumeError>,
    unmount: Result<(), VolumeError>,
) -> Result<(), VolumeError> {
    match (thaw, unmount) {
        (_, Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(error),
        (Err(thaw_error), Err(unmount_error)) => Err(VolumeError::Mount(format!(
            "unfreeze volume during recovery failed: {thaw_error}; {unmount_error}"
        ))),
    }
}

fn digest_file(path: &Path) -> Result<(String, u64), VolumeError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| io_error(path, error))?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_error(path, error))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| VolumeError::Integrity("volume size overflow".to_owned()))?;
        digest.update(&buffer[..read]);
    }
    Ok((format!("sha256:{}", hex::encode(digest.finalize())), size))
}

fn canonical_artifact_digest(digest: &str) -> Option<String> {
    digest
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(|value| format!("sha256:{}", value.to_ascii_lowercase()))
}

fn verify_artifact(path: &Path, expected: &str) -> Result<u64, VolumeError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            VolumeError::NotFound(expected.to_owned())
        } else {
            io_error(path, error)
        }
    })?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o222 != 0 {
        return Err(VolumeError::Integrity(
            "artifact must be an immutable regular file".to_owned(),
        ));
    }
    let canonical_expected = canonical_artifact_digest(expected)
        .ok_or_else(|| VolumeError::Integrity("artifact content digest is malformed".to_owned()))?;
    let (actual, size_bytes) = digest_file(path)?;
    if actual != canonical_expected {
        return Err(VolumeError::Integrity(
            "artifact content digest does not match the volume specification".to_owned(),
        ));
    }
    if metadata.permissions().mode() & 0o777 != 0o444 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o444))
            .and_then(|()| File::open(path)?.sync_all())
            .map_err(|error| io_error(path, error))?;
    }
    Ok(size_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_sandbox_core::{TenantId, VolumeId, WorkspaceId};
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt as _;

    fn scope(tenant: &str) -> VolumeScope {
        VolumeScope::new(
            TenantId::parse(tenant).expect("tenant"),
            WorkspaceId::parse("workspace-a").expect("workspace"),
        )
    }

    fn test_record(frozen: bool) -> VolumeRecord {
        VolumeRecord {
            schema_version: RECORD_VERSION,
            provider_id: LOCAL_VOLUME_PROVIDER_ID.to_owned(),
            key: "a".repeat(64),
            tenant_id: "tenant-a".to_owned(),
            workspace_id: "workspace-a".to_owned(),
            volume_id: "database".to_owned(),
            persistence_class: VolumePersistenceClass::Persistent,
            quota_bytes: runtrue_sandbox_core::MINIMUM_NAMED_VOLUME_BYTES,
            content_digest: None,
            frozen,
            attachments: BTreeMap::new(),
        }
    }

    #[test]
    fn freeze_record_fault_thaws_before_returning_the_write_error() {
        let mut record = test_record(false);
        let operations = RefCell::new(Vec::new());

        let error = record_freeze(
            &mut record,
            || {
                operations.borrow_mut().push("freeze");
                Ok(())
            },
            |record| {
                assert!(record.frozen);
                operations.borrow_mut().push("persist");
                Err(VolumeError::Invalid("injected record fault".to_owned()))
            },
            || {
                operations.borrow_mut().push("thaw");
                Ok(())
            },
        )
        .expect_err("record fault must be returned");

        assert_eq!(operations.into_inner(), vec!["freeze", "persist", "thaw"]);
        assert!(!record.frozen);
        assert!(error.to_string().contains("injected record fault"));
    }

    #[test]
    fn freeze_record_fault_preserves_the_compensation_error() {
        let mut record = test_record(false);

        let error = record_freeze(
            &mut record,
            || Ok(()),
            |_| Err(VolumeError::Invalid("injected record fault".to_owned())),
            || Err(VolumeError::Mount("injected thaw fault".to_owned())),
        )
        .expect_err("both failures must be returned");
        let message = error.to_string();

        assert!(record.frozen);
        assert!(message.contains("injected record fault"));
        assert!(message.contains("injected thaw fault"));
    }

    #[test]
    fn thaw_record_fault_can_be_retried_after_the_filesystem_is_already_thawed() {
        let mut record = test_record(true);
        let thaw_calls = RefCell::new(0_u32);

        let error = record_thaw(
            &mut record,
            || {
                *thaw_calls.borrow_mut() += 1;
                Ok(())
            },
            |_| Err(VolumeError::Invalid("injected record fault".to_owned())),
        )
        .expect_err("record fault must be returned");
        assert!(record.frozen);
        assert!(error.to_string().contains("injected record fault"));

        record_thaw(
            &mut record,
            || {
                *thaw_calls.borrow_mut() += 1;
                Ok(())
            },
            |_| Ok(()),
        )
        .expect("already-thawed retry");
        assert!(!record.frozen);
        assert_eq!(thaw_calls.into_inner(), 2);
    }

    #[test]
    fn unfreeze_treats_only_einval_as_already_thawed() {
        let already_thawed = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: b"fsfreeze: /volume: unfreeze failed: Invalid argument\n".to_vec(),
        };
        let other_failure = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: b"fsfreeze: /volume: unfreeze failed: Operation not permitted\n".to_vec(),
        };

        assert!(is_already_thawed(&already_thawed));
        assert!(!is_already_thawed(&other_failure));
    }

    #[test]
    fn recovery_accepts_a_thaw_error_only_after_a_safe_unmount() {
        let thaw_error = || VolumeError::Mount("injected thaw fault".to_owned());
        let unmount_error = || VolumeError::Mount("injected unmount fault".to_owned());

        finish_mount_recovery(Err(thaw_error()), Ok(())).expect("safe unmount");
        let error = finish_mount_recovery(Err(thaw_error()), Err(unmount_error()))
            .expect_err("unsafe recovery must fail");
        let message = error.to_string();
        assert!(message.contains("injected thaw fault"));
        assert!(message.contains("injected unmount fault"));
    }

    #[test]
    fn tenant_scope_changes_the_provider_key() {
        let first = volume_key(&scope("tenant-a"), "shared");
        let second = volume_key(&scope("tenant-b"), "shared");
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn attachment_identity_includes_sandbox_container_and_destination() {
        let spec = VolumeSpec {
            schema_version: runtrue_sandbox_core::VOLUME_SPEC_VERSION,
            volume_id: VolumeId::parse("shared").expect("volume"),
            destination: "/data".to_owned(),
            read_only: false,
            persistence_class: VolumePersistenceClass::Persistent,
            snapshot_policy: VolumeSnapshotPolicy::Required,
            quota_bytes: runtrue_sandbox_core::MINIMUM_NAMED_VOLUME_BYTES,
            content_digest: None,
        };
        let handle = handle(
            &scope("tenant-a"),
            &spec,
            volume_key(&scope("tenant-a"), "shared"),
        );
        let first = AttachmentOwner {
            sandbox_id: runtrue_sandbox_core::SandboxId::parse("sandbox-a").expect("sandbox"),
            container_id: runtrue_sandbox_core::ContainerId::parse("api").expect("container"),
        };
        let second = AttachmentOwner {
            sandbox_id: runtrue_sandbox_core::SandboxId::parse("sandbox-b").expect("sandbox"),
            container_id: runtrue_sandbox_core::ContainerId::parse("api").expect("container"),
        };
        assert_ne!(
            attachment_key(&handle, &first, "/data"),
            attachment_key(&handle, &second, "/data")
        );
    }

    #[test]
    fn artifact_verification_rejects_writable_content() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let artifact = directory.path().join("artifact");
        fs::write(&artifact, b"content").expect("artifact");
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(b"content")));
        assert!(verify_artifact(&artifact, &digest).is_err());
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o400)).expect("read only");
        assert!(verify_artifact(&artifact, &digest).is_ok());
        assert_eq!(
            fs::metadata(&artifact)
                .expect("artifact metadata")
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
    }

    #[test]
    fn published_artifact_mount_is_content_addressed_and_read_only() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let source = temporary.path().join("source");
        fs::write(&source, b"dataset").expect("source");
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(b"dataset")));
        let provider =
            LocalVolumeProvider::open(LocalVolumeConfig::new(temporary.path().join("provider")))
                .expect("provider");
        let publication = provider
            .publish_artifact(&source, &digest)
            .expect("published artifact");
        assert_eq!(publication.digest, digest);
        assert_eq!(publication.size_bytes, 7);
        assert_eq!(publication.status, ArtifactPublicationStatus::Published);
        assert_eq!(
            provider
                .publish_artifact(&source, &digest)
                .expect("idempotent publication")
                .status,
            ArtifactPublicationStatus::Reused
        );
        let specification = VolumeSpec {
            schema_version: runtrue_sandbox_core::VOLUME_SPEC_VERSION,
            volume_id: VolumeId::parse("dataset").expect("volume"),
            destination: "/opt/dataset".to_owned(),
            read_only: true,
            persistence_class: VolumePersistenceClass::Artifact,
            snapshot_policy: VolumeSnapshotPolicy::Excluded,
            quota_bytes: 0,
            content_digest: Some(digest),
        };
        let handle = provider
            .create(&scope("tenant-a"), &specification)
            .expect("artifact handle");
        let attachment = provider
            .attach(
                &handle,
                AttachmentOwner {
                    sandbox_id: runtrue_sandbox_core::SandboxId::parse("sandbox-a")
                        .expect("sandbox"),
                    container_id: runtrue_sandbox_core::ContainerId::parse("api")
                        .expect("container"),
                },
                &specification,
            )
            .expect("attachment");
        let mounted = provider.mount(&attachment).expect("mounted artifact");
        assert!(mounted.read_only());
        assert_eq!(fs::read(mounted.source()).expect("artifact"), b"dataset");
        assert_eq!(
            fs::metadata(mounted.source())
                .expect("artifact metadata")
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
        provider.unmount(&mounted).expect("unmounted artifact");
    }

    #[test]
    fn artifact_garbage_collection_preserves_live_volume_references() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let provider =
            LocalVolumeProvider::open(LocalVolumeConfig::new(temporary.path().join("provider")))
                .expect("provider");
        let referenced_source = temporary.path().join("referenced");
        let unused_source = temporary.path().join("unused");
        fs::write(&referenced_source, b"referenced").expect("referenced source");
        fs::write(&unused_source, b"unused").expect("unused source");
        let referenced_digest = format!("sha256:{}", hex::encode(Sha256::digest(b"referenced")));
        let unused_digest = format!("sha256:{}", hex::encode(Sha256::digest(b"unused")));
        provider
            .publish_artifact(&referenced_source, &referenced_digest)
            .expect("publish referenced artifact");
        provider
            .publish_artifact(&unused_source, &unused_digest)
            .expect("publish unused artifact");
        let specification = VolumeSpec {
            schema_version: runtrue_sandbox_core::VOLUME_SPEC_VERSION,
            volume_id: VolumeId::parse("referenced").expect("volume"),
            destination: "/opt/referenced".to_owned(),
            read_only: true,
            persistence_class: VolumePersistenceClass::Artifact,
            snapshot_policy: VolumeSnapshotPolicy::Excluded,
            quota_bytes: 0,
            content_digest: Some(referenced_digest.clone()),
        };
        let handle = provider
            .create(&scope("tenant-a"), &specification)
            .expect("artifact handle");

        let first = provider
            .garbage_collect_artifacts(Duration::ZERO)
            .expect("first garbage collection");
        assert_eq!(first.removed_artifacts, 1);
        assert_eq!(first.retained_artifacts, 1);
        assert!(!provider
            .artifact_path(&unused_digest)
            .expect("unused artifact path")
            .exists());
        assert!(provider
            .artifact_path(&referenced_digest)
            .expect("referenced artifact path")
            .exists());

        provider.delete(&handle).expect("delete artifact handle");
        let second = provider
            .garbage_collect_artifacts(Duration::ZERO)
            .expect("second garbage collection");
        assert_eq!(second.removed_artifacts, 1);
        assert_eq!(second.retained_artifacts, 0);
    }

    #[test]
    fn loop_device_parser_rejects_command_output_injection() {
        assert_eq!(
            parse_loop_device(b"/dev/loop12\n").expect("loop device"),
            PathBuf::from("/dev/loop12")
        );
        assert!(parse_loop_device(b"/dev/loop1 --detach /dev/loop2").is_err());
        assert!(parse_loop_device(b"/tmp/loop1").is_err());
    }

    #[test]
    fn external_command_drains_output_larger_than_pipe_capacity() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut config = LocalVolumeConfig::new(temporary.path().join("provider"));
        config.operation_timeout = Duration::from_secs(10);
        config.maximum_output_bytes = 8 * 1024 * 1024;
        let provider = LocalVolumeProvider::open(config).expect("provider");

        let output = provider
            .run_external(
                Path::new("/bin/sh"),
                &[
                    "-c",
                    "head -c 4194304 /dev/zero; head -c 4194304 /dev/zero >&2",
                ],
                "produce large output",
            )
            .expect("large output command");

        assert_eq!(output.stdout.len(), 4 * 1024 * 1024);
        assert_eq!(output.stderr.len(), 4 * 1024 * 1024);
    }

    #[test]
    fn external_command_rejects_output_over_limit_with_bounded_stderr() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut config = LocalVolumeConfig::new(temporary.path().join("provider"));
        config.operation_timeout = Duration::from_secs(10);
        config.maximum_output_bytes = 1024;
        let provider = LocalVolumeProvider::open(config).expect("provider");

        let error = provider
            .run_external(
                Path::new("/bin/sh"),
                &[
                    "-c",
                    "printf 'diagnostic-start\\n' >&2; head -c 4194304 /dev/zero >&2; exit 7",
                ],
                "produce excessive output",
            )
            .expect_err("excessive output must be rejected");
        let message = error.to_string();

        assert!(message.contains("output exceeded its byte limit"));
        assert!(message.contains("diagnostic-start"));
        assert!(message.contains("[truncated]"));
        assert!(message.len() < 1200);
    }

    #[test]
    fn external_command_timeout_kills_and_reaps_while_draining_output() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut config = LocalVolumeConfig::new(temporary.path().join("provider"));
        config.operation_timeout = Duration::from_millis(50);
        config.maximum_output_bytes = 1024;
        let provider = LocalVolumeProvider::open(config).expect("provider");

        let error = provider
            .run_external(
                Path::new("/bin/sh"),
                &["-c", "while :; do printf x; done"],
                "produce output forever",
            )
            .expect_err("command must time out");

        assert!(
            matches!(error, VolumeError::Timeout(operation) if operation == "produce output forever")
        );
    }

    #[test]
    fn startup_recovery_clears_attachments_and_removes_ephemeral_state() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("provider");
        let volumes = root.join("volumes");
        fs::create_dir_all(&volumes).expect("volume root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let tenant_scope = scope("tenant-a");
        for (name, class) in [
            ("persistent", VolumePersistenceClass::Persistent),
            ("ephemeral", VolumePersistenceClass::Ephemeral),
        ] {
            let key = volume_key(&tenant_scope, name);
            let directory = volumes.join(&key);
            fs::create_dir_all(directory.join("data")).expect("volume directory");
            fs::write(directory.join("quota.ext4"), b"backing").expect("backing");
            let record = VolumeRecord {
                schema_version: RECORD_VERSION,
                provider_id: LOCAL_VOLUME_PROVIDER_ID.to_owned(),
                key,
                tenant_id: "tenant-a".to_owned(),
                workspace_id: "workspace-a".to_owned(),
                volume_id: name.to_owned(),
                persistence_class: class,
                quota_bytes: runtrue_sandbox_core::MINIMUM_NAMED_VOLUME_BYTES,
                content_digest: None,
                frozen: false,
                attachments: BTreeMap::from([(
                    "attachment".to_owned(),
                    AttachmentRecord {
                        sandbox_id: "sandbox-a".to_owned(),
                        container_id: "api".to_owned(),
                        destination: "/data".to_owned(),
                        read_only: false,
                        snapshot_policy: VolumeSnapshotPolicy::Required,
                    },
                )]),
            };
            let path = directory.join("volume.json");
            fs::write(&path, serde_json::to_vec(&record).expect("record json")).expect("record");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("record mode");
        }
        let orphan = volumes.join("f".repeat(64));
        fs::create_dir_all(orphan.join("data")).expect("orphan directory");
        let mut config = LocalVolumeConfig::new(root);
        config.mkfs_ext4_program = PathBuf::from("/bin/true");
        config.losetup_program = PathBuf::from("/bin/true");
        config.fsfreeze_program = PathBuf::from("/bin/true");
        config.copy_program = PathBuf::from("/bin/cp");
        let provider = LocalVolumeProvider::open(config).expect("provider recovery");
        let persistent = provider
            .read_record(&provider.volume_directory(&volume_key(&tenant_scope, "persistent")))
            .expect("persistent record");
        assert!(persistent.attachments.is_empty());
        assert!(!provider
            .volume_directory(&volume_key(&tenant_scope, "ephemeral"))
            .exists());
        assert!(!orphan.exists());
    }

    #[test]
    fn secret_resolver_is_scope_bound_and_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("secrets");
        let resolver = LocalSecretResolver::open(root.clone(), 1024).expect("resolver");
        let directory = root.join("tenants/tenant-a/workspaces/workspace-a/credentials");
        fs::create_dir_all(&directory).expect("secret directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("directory mode");
        let token = directory.join("token");
        fs::write(&token, b"sensitive").expect("secret");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).expect("secret mode");
        let volume_id = VolumeId::parse("credentials").expect("volume");
        let files = resolver
            .resolve(&scope("tenant-a"), &volume_id)
            .expect("resolved secret");
        assert_eq!(&*files[0].contents, b"sensitive");
        assert!(!format!("{:?}", files[0]).contains("sensitive"));
        assert!(resolver.resolve(&scope("tenant-b"), &volume_id).is_err());

        symlink(&token, directory.join("alias")).expect("secret symlink");
        assert!(resolver.resolve(&scope("tenant-a"), &volume_id).is_err());
    }

    #[test]
    fn secret_resolver_rejects_intermediate_and_final_directory_symlinks() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let outside = temporary.path().join("outside");
        let outside_secret = outside.join("tenant-a/workspaces/workspace-a/credentials");
        fs::create_dir_all(&outside_secret).expect("outside secret directory");
        fs::set_permissions(&outside_secret, fs::Permissions::from_mode(0o700))
            .expect("outside directory mode");
        let token = outside_secret.join("token");
        fs::write(&token, b"outside").expect("outside secret");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600))
            .expect("outside secret mode");
        let volume_id = VolumeId::parse("credentials").expect("volume");

        let intermediate_root = temporary.path().join("intermediate");
        let intermediate_resolver =
            LocalSecretResolver::open(intermediate_root.clone(), 1024).expect("resolver");
        symlink(&outside, intermediate_root.join("tenants")).expect("intermediate symlink");
        assert!(matches!(
            intermediate_resolver.resolve(&scope("tenant-a"), &volume_id),
            Err(VolumeError::AccessDenied(_))
        ));

        let final_root = temporary.path().join("final");
        let final_resolver = LocalSecretResolver::open(final_root.clone(), 1024).expect("resolver");
        let workspace = final_root.join("tenants/tenant-a/workspaces/workspace-a");
        fs::create_dir_all(&workspace).expect("workspace directory");
        symlink(&outside_secret, workspace.join("credentials")).expect("final symlink");
        assert!(matches!(
            final_resolver.resolve(&scope("tenant-a"), &volume_id),
            Err(VolumeError::AccessDenied(_))
        ));
    }

    #[test]
    fn secret_resolver_binds_resolution_to_opened_directories_during_replacement() {
        use std::{
            os::unix::fs::symlink,
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            },
            thread,
        };

        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("secrets");
        let resolver = LocalSecretResolver::open(root.clone(), 1024).expect("resolver");
        let directory = root.join("tenants/tenant-a/workspaces/workspace-a/credentials");
        fs::create_dir_all(&directory).expect("secret directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("directory mode");
        let token = directory.join("token");
        fs::write(&token, b"trusted").expect("trusted secret");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).expect("secret mode");

        let outside = temporary.path().join("outside");
        fs::create_dir(&outside).expect("outside directory");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700))
            .expect("outside directory mode");
        let outside_token = outside.join("token");
        fs::write(&outside_token, b"untrusted").expect("outside secret");
        fs::set_permissions(&outside_token, fs::Permissions::from_mode(0o600))
            .expect("outside secret mode");

        let saved_directory = directory.with_extension("saved");
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_directory = directory.clone();
        let worker_saved = saved_directory.clone();
        let worker_outside = outside.clone();
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                if fs::rename(&worker_directory, &worker_saved).is_ok() {
                    symlink(&worker_outside, &worker_directory).expect("replacement symlink");
                    fs::remove_file(&worker_directory).expect("remove replacement symlink");
                    fs::rename(&worker_saved, &worker_directory).expect("restore secret directory");
                }
            }
        });

        let volume_id = VolumeId::parse("credentials").expect("volume");
        for _ in 0..2_000 {
            if let Ok(files) = resolver.resolve(&scope("tenant-a"), &volume_id) {
                assert_eq!(files.len(), 1);
                assert_eq!(&*files[0].contents, b"trusted");
            }
        }
        stop.store(true, Ordering::Relaxed);
        worker.join().expect("replacement worker");
        let files = resolver
            .resolve(&scope("tenant-a"), &volume_id)
            .expect("resolved secret after replacement race");
        assert_eq!(&*files[0].contents, b"trusted");

        let saved_root = temporary.path().join("saved-root");
        fs::rename(&root, &saved_root).expect("move opened secret root");
        let replacement_root = temporary.path().join("replacement-root");
        let replacement_directory =
            replacement_root.join("tenants/tenant-a/workspaces/workspace-a/credentials");
        fs::create_dir_all(&replacement_directory).expect("replacement secret directory");
        fs::set_permissions(&replacement_directory, fs::Permissions::from_mode(0o700))
            .expect("replacement directory mode");
        let replacement_token = replacement_directory.join("token");
        fs::write(&replacement_token, b"untrusted").expect("replacement secret");
        fs::set_permissions(&replacement_token, fs::Permissions::from_mode(0o600))
            .expect("replacement secret mode");
        symlink(&replacement_root, &root).expect("replace secret root pathname");

        let files = resolver
            .resolve(&scope("tenant-a"), &volume_id)
            .expect("resolved secret from opened root");
        assert_eq!(&*files[0].contents, b"trusted");
    }

    #[test]
    #[ignore = "requires root, mount, fsfreeze, and loop-device access"]
    fn named_volume_snapshot_restores_data_and_quota() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let provider =
            LocalVolumeProvider::open(LocalVolumeConfig::new(temporary.path().join("provider")))
                .expect("provider");
        let specification = VolumeSpec {
            schema_version: runtrue_sandbox_core::VOLUME_SPEC_VERSION,
            volume_id: VolumeId::parse("database").expect("volume"),
            destination: "/var/lib/database".to_owned(),
            read_only: false,
            persistence_class: VolumePersistenceClass::Persistent,
            snapshot_policy: VolumeSnapshotPolicy::Required,
            quota_bytes: 16 * 1024 * 1024,
            content_digest: None,
        };
        let tenant_scope = scope("tenant-a");
        let handle = provider
            .create(&tenant_scope, &specification)
            .expect("volume");
        let owner = AttachmentOwner {
            sandbox_id: runtrue_sandbox_core::SandboxId::parse("sandbox-a").expect("sandbox"),
            container_id: runtrue_sandbox_core::ContainerId::parse("api").expect("container"),
        };
        let attachment = provider
            .attach(&handle, owner, &specification)
            .expect("attachment");
        let mounted = provider.mount(&attachment).expect("mount");
        fs::write(mounted.source().join("value"), b"preserved").expect("volume write");
        provider.freeze(&attachment).expect("freeze");
        let snapshot_path = temporary.path().join("database.ext4");
        let snapshot = provider
            .snapshot(&attachment, &snapshot_path)
            .expect("snapshot");
        provider.unmount(&mounted).expect("unmount");
        provider.delete(&handle).expect("delete source");

        let restored = provider
            .restore(&tenant_scope, &specification, &snapshot, &snapshot_path)
            .expect("restore");
        let attachment = provider
            .attach(
                &restored,
                AttachmentOwner {
                    sandbox_id: runtrue_sandbox_core::SandboxId::parse("sandbox-b")
                        .expect("sandbox"),
                    container_id: runtrue_sandbox_core::ContainerId::parse("api")
                        .expect("container"),
                },
                &specification,
            )
            .expect("restored attachment");
        let mounted = provider.mount(&attachment).expect("restored mount");
        assert_eq!(
            fs::read(mounted.source().join("value")).expect("restored value"),
            b"preserved"
        );
        let oversized = mounted.source().join("oversized");
        let mut file = File::create(&oversized).expect("quota test file");
        let block = vec![0_u8; 1024 * 1024];
        let mut rejected = false;
        for _ in 0..32 {
            if file.write_all(&block).is_err() {
                rejected = true;
                break;
            }
        }
        assert!(
            rejected,
            "ext4 quota allowed writes beyond its backing image"
        );
        drop(file);
        provider.unmount(&mounted).expect("restored unmount");
        provider.delete(&restored).expect("delete restored volume");
    }
}
