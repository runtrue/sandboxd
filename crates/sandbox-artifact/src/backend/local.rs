use super::{BlobBackend, PutStatus, StoredObject};
use crate::{
    error::io_error, repository::ArtifactRepository, ArtifactError, ArtifactLimits, ArtifactStore,
};
use aes_gcm::aead::rand_core::{OsRng, RngCore as _};
use nix::{
    errno::Errno,
    fcntl::{renameat2, RenameFlags, AT_FDCWD},
};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::{Instant, SystemTime},
};

pub struct LocalArtifactStore {
    repository: ArtifactRepository,
}

impl LocalArtifactStore {
    pub fn open(
        root: PathBuf,
        key_path: &Path,
        limits: ArtifactLimits,
    ) -> Result<Self, ArtifactError> {
        let master_key = load_or_create_master_key(key_path)?;
        Self::new(root, master_key, limits)
    }

    pub fn new(
        root: PathBuf,
        master_key: [u8; 32],
        limits: ArtifactLimits,
    ) -> Result<Self, ArtifactError> {
        let backend = Arc::new(LocalBackend::new(root)?);
        Ok(Self {
            repository: ArtifactRepository::new(backend, master_key, limits)?,
        })
    }
}

fn load_or_create_master_key(path: &Path) -> Result<[u8; 32], ArtifactError> {
    if !path.is_absolute() {
        return Err(ArtifactError::Invalid(
            "artifact master-key path must be absolute".to_owned(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| ArtifactError::Invalid("artifact key has no parent".to_owned()))?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|error| io_error(parent, error))?;
    let mut created = false;
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)
    {
        Ok(mut file) => {
            let mut key = [0_u8; 32];
            OsRng.fill_bytes(&mut key);
            if let Err(error) = file.write_all(&key).and_then(|()| file.sync_all()) {
                let _ = fs::remove_file(path);
                return Err(io_error(path, error));
            }
            created = true;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_error(path, error)),
    }
    if created {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error(parent, error))?;
    }
    read_master_key(path)
}

fn read_master_key(path: &Path) -> Result<[u8; 32], ArtifactError> {
    if !path.is_absolute() {
        return Err(ArtifactError::Invalid(
            "artifact master-key path must be absolute".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() != 32
    {
        return Err(ArtifactError::AccessDenied(
            "artifact master key must be a 32-byte, owner-only regular file".to_owned(),
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| io_error(path, error))?;
    let mut key = [0_u8; 32];
    file.read_exact(&mut key)
        .map_err(|error| io_error(path, error))?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| io_error(path, error))?
        != 0
    {
        return Err(ArtifactError::Integrity(
            "artifact master key contains trailing data".to_owned(),
        ));
    }
    Ok(key)
}

impl ArtifactStore for LocalArtifactStore {
    fn snapshot_portability(&self) -> runtrue_sandbox_core::SnapshotPortability {
        runtrue_sandbox_core::SnapshotPortability::SameWorker
    }

    fn publish_transfer_grant(
        &self,
        scope: &crate::ArtifactScope,
        snapshot_id: &runtrue_sandbox_core::SnapshotId,
    ) -> Result<crate::SnapshotTransferGrant, ArtifactError> {
        self.repository.publish_transfer_grant(scope, snapshot_id)
    }

    fn claim_transfer(
        &self,
        scope: &crate::ArtifactScope,
        snapshot_id: &runtrue_sandbox_core::SnapshotId,
        target: &runtrue_sandbox_core::RestoreTarget,
    ) -> Result<crate::SnapshotTransferClaim, ArtifactError> {
        self.repository.claim_transfer(scope, snapshot_id, target)
    }

    fn publish(
        &self,
        publication: crate::SnapshotPublication,
    ) -> Result<crate::PublicationMetrics, ArtifactError> {
        self.repository.publish(publication)
    }

    fn materialize(
        &self,
        scope: &crate::ArtifactScope,
        snapshot_id: &runtrue_sandbox_core::SnapshotId,
        destination: &Path,
    ) -> Result<crate::MaterializedSnapshot, ArtifactError> {
        self.repository.materialize(scope, snapshot_id, destination)
    }

    fn exists(
        &self,
        scope: &crate::ArtifactScope,
        snapshot_id: &runtrue_sandbox_core::SnapshotId,
    ) -> Result<bool, ArtifactError> {
        self.repository.exists(scope, snapshot_id)
    }

    fn remove_reference(
        &self,
        scope: &crate::ArtifactScope,
        snapshot_id: &runtrue_sandbox_core::SnapshotId,
    ) -> Result<(), ArtifactError> {
        self.repository.remove_reference(scope, snapshot_id)
    }

    fn garbage_collect(
        &self,
        scope: &crate::ArtifactScope,
    ) -> Result<crate::GarbageCollectionReport, ArtifactError> {
        self.repository.garbage_collect(scope)
    }
}

struct LocalBackend {
    root: PathBuf,
}

impl LocalBackend {
    fn new(root: PathBuf) -> Result<Self, ArtifactError> {
        if !root.is_absolute() {
            return Err(ArtifactError::Invalid(
                "local artifact root must be absolute".to_owned(),
            ));
        }
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)
            .map_err(|source| io_error(&root, source))?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_error(&root, source))?;
        let root = fs::canonicalize(&root).map_err(|source| io_error(&root, source))?;
        let metadata = fs::metadata(&root).map_err(|source| io_error(&root, source))?;
        if !metadata.is_dir() || metadata.uid() != nix::unistd::geteuid().as_raw() {
            return Err(ArtifactError::AccessDenied(
                "artifact root must be owned by the worker UID".to_owned(),
            ));
        }
        Ok(Self { root })
    }

    fn path(&self, key: &str) -> Result<PathBuf, ArtifactError> {
        if key.is_empty()
            || key.starts_with('/')
            || key
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !key.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
            })
        {
            return Err(ArtifactError::Invalid(
                "artifact storage key is invalid".to_owned(),
            ));
        }
        Ok(self.root.join(key))
    }

    fn create_parent(&self, path: &Path) -> Result<(), ArtifactError> {
        let parent = path
            .parent()
            .ok_or_else(|| ArtifactError::Invalid("artifact key has no parent".to_owned()))?;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|source| io_error(parent, source))?;
        Ok(())
    }

    fn collect(
        &self,
        directory: &Path,
        objects: &mut Vec<StoredObject>,
        maximum_entries: usize,
        deadline: Instant,
    ) -> Result<(), ArtifactError> {
        if !directory.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(directory).map_err(|source| io_error(directory, source))? {
            ensure_deadline(deadline, "list local artifacts")?;
            if objects.len() >= maximum_entries {
                return Err(ArtifactError::Invalid(
                    "artifact listing exceeds its entry limit".to_owned(),
                ));
            }
            let entry = entry.map_err(|source| io_error(directory, source))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|source| io_error(entry.path(), source))?;
            if metadata.is_dir() {
                self.collect(&entry.path(), objects, maximum_entries, deadline)?;
            } else if metadata.is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(&self.root)
                    .map_err(|_| ArtifactError::Storage("artifact escaped local root".to_owned()))?
                    .to_string_lossy()
                    .into_owned();
                objects.push(StoredObject {
                    key: relative,
                    modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                });
            } else {
                return Err(ArtifactError::Integrity(
                    "artifact store contains a special entry".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl BlobBackend for LocalBackend {
    fn put_if_absent(
        &self,
        key: &str,
        source: &Path,
        deadline: Instant,
    ) -> Result<PutStatus, ArtifactError> {
        ensure_deadline(deadline, "publish local artifact")?;
        let destination = self.path(key)?;
        self.create_parent(&destination)?;
        let parent = destination
            .parent()
            .expect("validated artifact destination has a parent");
        let staging_key = format!(
            "{}/staging/uploads/{}-{}",
            scope_prefix_from_key(key)?,
            std::process::id(),
            random_suffix()
        );
        let temporary = self.path(&staging_key)?;
        self.create_parent(&temporary)?;
        let result = (|| {
            let mut input = fs::File::open(source).map_err(|error| io_error(source, error))?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(&temporary)
                .map_err(|error| io_error(&temporary, error))?;
            let mut buffer = [0_u8; 1024 * 1024];
            loop {
                ensure_deadline(deadline, "publish local artifact")?;
                let read = input
                    .read(&mut buffer)
                    .map_err(|error| io_error(source, error))?;
                if read == 0 {
                    break;
                }
                output
                    .write_all(&buffer[..read])
                    .map_err(|error| io_error(&temporary, error))?;
            }
            output
                .sync_all()
                .map_err(|error| io_error(&temporary, error))?;
            match renameat2(
                AT_FDCWD,
                &temporary,
                AT_FDCWD,
                &destination,
                RenameFlags::RENAME_NOREPLACE,
            ) {
                Ok(()) => {
                    fs::File::open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|error| io_error(parent, error))?;
                    Ok(PutStatus::Created)
                }
                Err(Errno::EEXIST) => Ok(PutStatus::Reused),
                Err(error) => Err(ArtifactError::Storage(format!(
                    "atomically publish artifact {key}: {error}"
                ))),
            }
        })();
        if temporary.exists() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn get(
        &self,
        key: &str,
        destination: &Path,
        maximum_bytes: u64,
        deadline: Instant,
    ) -> Result<u64, ArtifactError> {
        ensure_deadline(deadline, "download local artifact")?;
        let source = self.path(key)?;
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&source)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    ArtifactError::NotFound(key.to_owned())
                } else {
                    io_error(&source, error)
                }
            })?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destination)
            .map_err(|error| io_error(destination, error))?;
        let mut bytes = 0_u64;
        let mut buffer = [0_u8; 1024 * 1024];
        loop {
            ensure_deadline(deadline, "download local artifact")?;
            let read = input
                .read(&mut buffer)
                .map_err(|error| io_error(&source, error))?;
            if read == 0 {
                break;
            }
            bytes = bytes
                .checked_add(read as u64)
                .ok_or_else(|| ArtifactError::Integrity("artifact size overflow".to_owned()))?;
            if bytes > maximum_bytes {
                return Err(ArtifactError::Integrity(
                    "stored artifact exceeds its byte limit".to_owned(),
                ));
            }
            output
                .write_all(&buffer[..read])
                .map_err(|error| io_error(destination, error))?;
        }
        output
            .sync_all()
            .map_err(|error| io_error(destination, error))?;
        Ok(bytes)
    }

    fn exists(&self, key: &str, deadline: Instant) -> Result<bool, ArtifactError> {
        ensure_deadline(deadline, "inspect local artifact")?;
        let path = self.path(key)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => Ok(true),
            Ok(_) => Err(ArtifactError::Integrity(
                "artifact store contains a non-file object".to_owned(),
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(io_error(path, error)),
        }
    }

    fn list(
        &self,
        prefix: &str,
        maximum_entries: usize,
        deadline: Instant,
    ) -> Result<Vec<StoredObject>, ArtifactError> {
        let root = self.path(prefix)?;
        let mut objects = Vec::new();
        self.collect(&root, &mut objects, maximum_entries, deadline)?;
        objects.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(objects)
    }

    fn delete(&self, key: &str, deadline: Instant) -> Result<(), ArtifactError> {
        ensure_deadline(deadline, "delete local artifact")?;
        let path = self.path(key)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(path, error)),
        }
    }
}

fn random_suffix() -> String {
    let mut value = [0_u8; 16];
    OsRng.fill_bytes(&mut value);
    hex::encode(value)
}

fn scope_prefix_from_key(key: &str) -> Result<&str, ArtifactError> {
    key.split_once("/objects/")
        .or_else(|| key.split_once("/snapshots/"))
        .or_else(|| key.split_once("/transfers/"))
        .map(|(scope, _)| scope)
        .filter(|scope| !scope.is_empty())
        .ok_or_else(|| ArtifactError::Invalid("artifact key has no tenant scope".to_owned()))
}

fn ensure_deadline(deadline: Instant, operation: &str) -> Result<(), ArtifactError> {
    if Instant::now() >= deadline {
        return Err(ArtifactError::Timeout(operation.to_owned()));
    }
    Ok(())
}
