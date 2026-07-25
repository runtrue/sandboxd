use super::{
    diff, WritableRootfs, WritableRootfsConfig, WritableRootfsIdentity,
    GVISOR_WRITABLE_ROOTFS_PROVIDER_ID,
};
use crate::{io_error, provider::ImmutableRootfs, SandboxError};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
};

const RECORD_VERSION: u32 = 1;
const MAXIMUM_RECORD_BYTES: u64 = 64 * 1024;

pub(in crate::provider) struct GvisorWritableRootfs {
    config: WritableRootfsConfig,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WritableRootfsRecord {
    schema_version: u32,
    provider: String,
    key: String,
    project: String,
    service: String,
    image_id: String,
    exact_reference: String,
    immutable_rootfs: PathBuf,
    quota_bytes: u64,
}

impl GvisorWritableRootfs {
    pub(in crate::provider) fn new(config: WritableRootfsConfig) -> Result<Self, SandboxError> {
        let manager = Self {
            config: config.validated()?,
        };
        manager.garbage_collect()?;
        Ok(manager)
    }

    pub(in crate::provider) fn create(
        &self,
        immutable: &ImmutableRootfs,
        identity: WritableRootfsIdentity,
        quota_bytes: u64,
    ) -> Result<WritableRootfs, SandboxError> {
        self.config.validate_quota(quota_bytes)?;
        let key = rootfs_key(&identity, &immutable.image().image_id);
        let directory = self.config.root.join(&key);
        fs::create_dir(&directory).map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                SandboxError::ImageProvider("writable rootfs identity is already active".to_owned())
            } else {
                io_error(&directory, source)
            }
        })?;
        fs::set_permissions(
            &directory,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .map_err(|source| io_error(&directory, source))?;
        let rootfs = fs::canonicalize(immutable.rootfs())
            .map_err(|source| io_error(immutable.rootfs(), source))?;
        let record = WritableRootfsRecord {
            schema_version: RECORD_VERSION,
            provider: GVISOR_WRITABLE_ROOTFS_PROVIDER_ID.to_owned(),
            key: key.clone(),
            project: identity.project().to_owned(),
            service: identity.service().to_owned(),
            image_id: immutable.image().image_id.clone(),
            exact_reference: immutable.image().exact_reference.clone(),
            immutable_rootfs: rootfs.clone(),
            quota_bytes,
        };
        if let Err(error) = write_record(&directory.join("rootfs.json"), &record) {
            let _ = fs::remove_dir_all(&directory);
            return Err(error);
        }
        Ok(WritableRootfs {
            provider: GVISOR_WRITABLE_ROOTFS_PROVIDER_ID.to_owned(),
            key,
            identity,
            image: immutable.image().clone(),
            rootfs,
            quota_bytes,
        })
    }

    pub(in crate::provider) fn restore(
        &self,
        immutable: &ImmutableRootfs,
        identity: WritableRootfsIdentity,
        quota_bytes: u64,
        source: &Path,
    ) -> Result<WritableRootfs, SandboxError> {
        self.config.validate_quota(quota_bytes)?;
        diff::validate_archive(source, quota_bytes, self.config.operation_timeout)?;
        self.create(immutable, identity, quota_bytes)
    }

    pub(in crate::provider) fn release(&self, rootfs: &WritableRootfs) -> Result<(), SandboxError> {
        self.validate_handle(rootfs)?;
        let directory = self.config.root.join(&rootfs.key);
        fs::remove_dir_all(&directory).map_err(|source| io_error(&directory, source))?;
        File::open(&self.config.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(&self.config.root, source))
    }

    pub(in crate::provider) fn validate_export(
        &self,
        rootfs: &WritableRootfs,
        source: &Path,
    ) -> Result<super::WritableRootfsExport, SandboxError> {
        self.validate_handle(rootfs)?;
        diff::canonicalize_runtime_archive(
            source,
            rootfs.quota_bytes,
            self.config.operation_timeout,
        )?;
        diff::measure_archive(source, rootfs.quota_bytes, self.config.operation_timeout)
    }

    pub(in crate::provider) fn garbage_collect(&self) -> Result<usize, SandboxError> {
        let mut removed = 0_usize;
        let mut entries = fs::read_dir(&self.config.root)
            .map_err(|source| io_error(&self.config.root, source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| io_error(&self.config.root, source))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|source| io_error(entry.path(), source))?;
            if !metadata.is_dir()
                || entry
                    .file_name()
                    .to_str()
                    .is_none_or(|name| !valid_key(name))
            {
                return Err(SandboxError::ImageProvider(format!(
                    "unexpected writable rootfs entry `{}`",
                    entry.path().display()
                )));
            }
            fs::remove_dir_all(entry.path()).map_err(|source| io_error(entry.path(), source))?;
            removed += 1;
        }
        if removed > 0 {
            File::open(&self.config.root)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| io_error(&self.config.root, source))?;
        }
        Ok(removed)
    }

    fn validate_handle(&self, rootfs: &WritableRootfs) -> Result<(), SandboxError> {
        if rootfs.provider != GVISOR_WRITABLE_ROOTFS_PROVIDER_ID
            || rootfs.key != rootfs_key(&rootfs.identity, &rootfs.image.image_id)
        {
            return Err(SandboxError::ImageProvider(
                "writable rootfs handle belongs to another provider".to_owned(),
            ));
        }
        let record = read_record(&self.config.root.join(&rootfs.key).join("rootfs.json"))?;
        if record.schema_version != RECORD_VERSION
            || record.provider != rootfs.provider
            || record.key != rootfs.key
            || record.project != rootfs.identity.project()
            || record.service != rootfs.identity.service()
            || record.image_id != rootfs.image.image_id
            || record.exact_reference != rootfs.image.exact_reference
            || record.immutable_rootfs != rootfs.rootfs
            || record.quota_bytes != rootfs.quota_bytes
        {
            return Err(SandboxError::ImageProvider(
                "writable rootfs metadata does not match its handle".to_owned(),
            ));
        }
        Ok(())
    }
}

fn rootfs_key(identity: &WritableRootfsIdentity, image_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"runtrue-sandboxd/gvisor-writable-rootfs/v1\0");
    digest.update(identity.project().len().to_be_bytes());
    digest.update(identity.project().as_bytes());
    digest.update(identity.service().len().to_be_bytes());
    digest.update(identity.service().as_bytes());
    digest.update(image_id.len().to_be_bytes());
    digest.update(image_id.as_bytes());
    hex::encode(digest.finalize())
}

fn write_record(path: &Path, record: &WritableRootfsRecord) -> Result<(), SandboxError> {
    let bytes = serde_json::to_vec(record)
        .map_err(|error| SandboxError::ImageProvider(format!("encode writable rootfs: {error}")))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error(path, source))?;
    File::open(path.parent().expect("record has parent"))
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

fn read_record(path: &Path) -> Result<WritableRootfsRecord, SandboxError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAXIMUM_RECORD_BYTES {
        return Err(SandboxError::ImageProvider(
            "writable rootfs record is not a bounded regular file".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        SandboxError::ImageProvider(format!("decode writable rootfs record: {error}"))
    })
}

fn valid_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{provider::ImmutableRootfs, LockedDescriptor, LockedImage};
    use std::time::Duration;

    fn image() -> LockedImage {
        let descriptor = |digit: char, media_type: &str| LockedDescriptor {
            media_type: media_type.to_owned(),
            digest: format!("sha256:{}", digit.to_string().repeat(64)),
            size: 1,
        };
        LockedImage {
            source: "example.test/image:latest".to_owned(),
            exact_reference: format!("example.test/image@sha256:{}", "a".repeat(64)),
            image_id: format!("sha256:{}", "b".repeat(64)),
            index: None,
            manifest: descriptor('a', "application/vnd.oci.image.manifest.v1+json"),
            config: descriptor('b', "application/vnd.oci.image.config.v1+json"),
            layers: vec![descriptor(
                'c',
                "application/vnd.oci.image.layer.v1.tar+gzip",
            )],
            operating_system: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            variant: None,
        }
    }

    #[test]
    fn metadata_only_root_keeps_the_immutable_lower_and_releases_cleanly() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let lower = temporary.path().join("lower");
        fs::create_dir(&lower).expect("lower");
        let manager = GvisorWritableRootfs::new(WritableRootfsConfig {
            root: temporary.path().join("records"),
            minimum_bytes: super::super::MINIMUM_WRITABLE_ROOT_BYTES,
            maximum_bytes: 1024 * 1024 * 1024,
            operation_timeout: Duration::from_secs(5),
        })
        .expect("manager");
        let immutable = ImmutableRootfs {
            provider: "test".to_owned(),
            activation_key: "activation".to_owned(),
            image: image(),
            rootfs: lower.canonicalize().expect("canonical lower"),
            rootfs_digest: format!("sha256:{}", "d".repeat(64)),
            rootfs_entries: 1,
            rootfs_bytes: 1,
        };
        let rootfs = manager
            .create(
                &immutable,
                WritableRootfsIdentity::new("project", "service").expect("identity"),
                super::super::MINIMUM_WRITABLE_ROOT_BYTES,
            )
            .expect("writable root");

        assert_eq!(rootfs.provider_id(), GVISOR_WRITABLE_ROOTFS_PROVIDER_ID);
        assert_eq!(rootfs.rootfs(), immutable.rootfs());
        assert!(manager
            .config
            .root
            .join(rootfs.key())
            .join("rootfs.json")
            .is_file());
        manager.release(&rootfs).expect("release");
        assert!(!manager.config.root.join(rootfs.key()).exists());
    }
}
