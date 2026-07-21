use super::{
    diff, WritableRootfs, WritableRootfsConfig, WritableRootfsExport, WritableRootfsIdentity,
    LOOPBACK_WRITABLE_ROOTFS_PROVIDER_ID,
};
use crate::{
    io_error,
    provider::{
        command::run_external,
        validation::{mount_is_read_only, mount_state},
        ImmutableRootfs,
    },
    SandboxError,
};
use nix::mount::{mount, umount, MsFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write as _,
    os::unix::fs::{
        chown, DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _,
        PermissionsExt as _,
    },
    path::{Path, PathBuf},
};
use tempfile::Builder;

const RECORD_VERSION: u32 = 1;

pub(in crate::provider) struct LoopbackWritableRootfs {
    config: WritableRootfsConfig,
    output_limit: usize,
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
    quota_bytes: u64,
}

impl LoopbackWritableRootfs {
    pub(in crate::provider) fn new(
        config: WritableRootfsConfig,
        output_limit: usize,
    ) -> Result<Self, SandboxError> {
        let manager = Self {
            config: config.validated()?,
            output_limit,
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
        if !mount_is_read_only(immutable.rootfs())? {
            return Err(SandboxError::ImageProvider(
                "writable rootfs lower layer is not an immutable mount".to_owned(),
            ));
        }
        validate_overlay_path(immutable.rootfs())?;
        let key = rootfs_key(&identity, &immutable.image().image_id);
        let directory = self.config.root.join(&key);
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|source| {
                if source.kind() == std::io::ErrorKind::AlreadyExists {
                    SandboxError::ImageProvider(
                        "writable rootfs identity is already active".to_owned(),
                    )
                } else {
                    io_error(&directory, source)
                }
            })?;
        let result = self.create_in_directory(
            &directory,
            immutable,
            identity.clone(),
            quota_bytes,
            key.clone(),
        );
        if result.is_err() {
            let _ = self.cleanup_directory(&directory);
        }
        result
    }

    fn create_in_directory(
        &self,
        directory: &Path,
        immutable: &ImmutableRootfs,
        identity: WritableRootfsIdentity,
        quota_bytes: u64,
        key: String,
    ) -> Result<WritableRootfs, SandboxError> {
        let backing = directory.join("quota.ext4");
        let backing_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&backing)
            .map_err(|source| io_error(&backing, source))?;
        backing_file
            .set_len(quota_bytes)
            .map_err(|source| io_error(&backing, source))?;
        backing_file
            .sync_all()
            .map_err(|source| io_error(&backing, source))?;
        let filesystem_uuid = filesystem_uuid(&key);
        run_external(
            &self.config.mkfs_ext4_program,
            &[
                "-q".to_owned(),
                "-F".to_owned(),
                "-m".to_owned(),
                "0".to_owned(),
                "-U".to_owned(),
                filesystem_uuid,
                backing.display().to_string(),
            ],
            self.config.operation_timeout,
            self.output_limit,
            "format writable rootfs quota image",
        )?;
        let loop_result = run_external(
            &self.config.losetup_program,
            &[
                "--find".to_owned(),
                "--show".to_owned(),
                "--nooverlap".to_owned(),
                backing.display().to_string(),
            ],
            self.config.operation_timeout,
            self.output_limit,
            "attach writable rootfs quota image",
        )?;
        let loop_device = parse_loop_device(&loop_result.stdout)?;
        let storage = directory.join("storage");
        let merged = directory.join("rootfs");
        DirBuilder::new()
            .mode(0o700)
            .create(&storage)
            .map_err(|source| io_error(&storage, source))?;
        DirBuilder::new()
            .mode(0o755)
            .create(&merged)
            .map_err(|source| io_error(&merged, source))?;
        mount(
            Some(loop_device.as_path()),
            &storage,
            Some("ext4"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("errors=remount-ro"),
        )
        .map_err(|error| mount_error("mount writable quota filesystem", error))?;
        let upper = storage.join("upper");
        let work = storage.join("work");
        DirBuilder::new()
            .mode(0o700)
            .create(&upper)
            .map_err(|source| io_error(&upper, source))?;
        copy_root_metadata(immutable.rootfs(), &upper)?;
        DirBuilder::new()
            .mode(0o700)
            .create(&work)
            .map_err(|source| io_error(&work, source))?;
        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            immutable.rootfs().display(),
            upper.display(),
            work.display()
        );
        mount(
            Some("overlay"),
            &merged,
            Some("overlay"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some(options.as_str()),
        )
        .map_err(|error| mount_error("mount writable rootfs overlay", error))?;
        if mount_state(&merged)? != Some(false) {
            return Err(SandboxError::ImageProvider(
                "writable rootfs overlay did not become writable".to_owned(),
            ));
        }
        let record = WritableRootfsRecord {
            schema_version: RECORD_VERSION,
            provider: LOOPBACK_WRITABLE_ROOTFS_PROVIDER_ID.to_owned(),
            key: key.clone(),
            project: identity.project().to_owned(),
            service: identity.service().to_owned(),
            image_id: immutable.image().image_id.clone(),
            exact_reference: immutable.image().exact_reference.clone(),
            quota_bytes,
        };
        write_record(directory, &record)?;
        Ok(WritableRootfs {
            provider: LOOPBACK_WRITABLE_ROOTFS_PROVIDER_ID.to_owned(),
            key,
            identity,
            image: immutable.image().clone(),
            rootfs: fs::canonicalize(&merged).map_err(|source| io_error(&merged, source))?,
            quota_bytes,
        })
    }

    pub(in crate::provider) fn release(&self, rootfs: &WritableRootfs) -> Result<(), SandboxError> {
        if rootfs.provider != LOOPBACK_WRITABLE_ROOTFS_PROVIDER_ID
            || rootfs.key != rootfs_key(&rootfs.identity, &rootfs.image.image_id)
        {
            return Err(SandboxError::ImageProvider(
                "writable rootfs handle belongs to another provider".to_owned(),
            ));
        }
        let directory = self.config.root.join(&rootfs.key);
        let expected = directory.join("rootfs");
        if rootfs.rootfs != fs::canonicalize(&expected).unwrap_or(expected) {
            return Err(SandboxError::ImageProvider(
                "writable rootfs path does not match its provider handle".to_owned(),
            ));
        }
        let record = read_record(&directory.join("rootfs.json"))?;
        if record.schema_version != RECORD_VERSION
            || record.provider != LOOPBACK_WRITABLE_ROOTFS_PROVIDER_ID
            || record.key != rootfs.key
            || record.project != rootfs.identity.project()
            || record.service != rootfs.identity.service()
            || record.image_id != rootfs.image.image_id
            || record.exact_reference != rootfs.image.exact_reference
            || record.quota_bytes != rootfs.quota_bytes
        {
            return Err(SandboxError::ImageProvider(
                "writable rootfs metadata does not match its handle".to_owned(),
            ));
        }
        self.cleanup_directory(&directory)
    }

    pub(in crate::provider) fn export(
        &self,
        rootfs: &WritableRootfs,
        destination: &Path,
    ) -> Result<WritableRootfsExport, SandboxError> {
        self.validate_handle(rootfs)?;
        diff::export(&self.config.root, rootfs, destination)
    }

    pub(in crate::provider) fn restore(
        &self,
        immutable: &ImmutableRootfs,
        identity: WritableRootfsIdentity,
        quota_bytes: u64,
        source: &Path,
    ) -> Result<WritableRootfs, SandboxError> {
        let rootfs = self.create(immutable, identity, quota_bytes)?;
        if let Err(error) = diff::import(
            &self.config.root,
            &rootfs,
            source,
            self.config.operation_timeout,
        ) {
            let cleanup = self.release(&rootfs);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(SandboxError::ImageProvider(format!(
                    "restore writable rootfs failed: {error}; cleanup failed: {cleanup_error}"
                ))),
            };
        }
        Ok(rootfs)
    }

    pub(in crate::provider) fn garbage_collect(&self) -> Result<usize, SandboxError> {
        let mut removed = 0;
        for entry in
            fs::read_dir(&self.config.root).map_err(|source| io_error(&self.config.root, source))?
        {
            let entry = entry.map_err(|source| io_error(&self.config.root, source))?;
            if !entry
                .file_type()
                .map_err(|source| io_error(entry.path(), source))?
                .is_dir()
            {
                return Err(SandboxError::ImageProvider(format!(
                    "unexpected writable rootfs entry `{}`",
                    entry.path().display()
                )));
            }
            self.cleanup_directory(&entry.path())?;
            removed += 1;
        }
        Ok(removed)
    }

    fn cleanup_directory(&self, directory: &Path) -> Result<(), SandboxError> {
        let mut first_error = None;
        for target in [directory.join("rootfs"), directory.join("storage")] {
            match mount_state(&target) {
                Ok(Some(_)) => {
                    if let Err(error) = umount(&target) {
                        first_error.get_or_insert_with(|| {
                            mount_error(&format!("unmount `{}`", target.display()), error)
                        });
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        let backing = directory.join("quota.ext4");
        if backing.exists() {
            match self.associated_loop_devices(&backing) {
                Ok(devices) => {
                    for device in devices {
                        if let Err(error) = run_external(
                            &self.config.losetup_program,
                            &["--detach".to_owned(), device.display().to_string()],
                            self.config.operation_timeout,
                            self.output_limit,
                            "detach writable rootfs quota image",
                        ) {
                            first_error.get_or_insert(error);
                        }
                    }
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if first_error.is_none() && directory.exists() {
            fs::remove_dir_all(directory).map_err(|source| io_error(directory, source))?;
            File::open(&self.config.root)
                .and_then(|root| root.sync_all())
                .map_err(|source| io_error(&self.config.root, source))?;
        }
        first_error.map_or(Ok(()), Err)
    }

    fn associated_loop_devices(&self, backing: &Path) -> Result<Vec<PathBuf>, SandboxError> {
        let result = run_external(
            &self.config.losetup_program,
            &[
                "--associated".to_owned(),
                backing.display().to_string(),
                "--output".to_owned(),
                "NAME".to_owned(),
                "--noheadings".to_owned(),
            ],
            self.config.operation_timeout,
            self.output_limit,
            "list writable rootfs loop devices",
        )?;
        String::from_utf8_lossy(&result.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| parse_loop_device(line.as_bytes()))
            .collect()
    }

    fn validate_handle(&self, rootfs: &WritableRootfs) -> Result<(), SandboxError> {
        if rootfs.provider != LOOPBACK_WRITABLE_ROOTFS_PROVIDER_ID
            || rootfs.key != rootfs_key(&rootfs.identity, &rootfs.image.image_id)
        {
            return Err(SandboxError::ImageProvider(
                "writable rootfs handle belongs to another provider".to_owned(),
            ));
        }
        let directory = self.config.root.join(&rootfs.key);
        let expected = directory.join("rootfs");
        if rootfs.rootfs != fs::canonicalize(&expected).unwrap_or(expected) {
            return Err(SandboxError::ImageProvider(
                "writable rootfs path does not match its provider handle".to_owned(),
            ));
        }
        Ok(())
    }
}

fn copy_root_metadata(lower: &Path, upper: &Path) -> Result<(), SandboxError> {
    let metadata = fs::metadata(lower).map_err(|source| io_error(lower, source))?;
    fs::set_permissions(upper, fs::Permissions::from_mode(metadata.mode() & 0o7777))
        .map_err(|source| io_error(upper, source))?;
    chown(upper, Some(metadata.uid()), Some(metadata.gid()))
        .map_err(|source| io_error(upper, source))
}

fn rootfs_key(identity: &WritableRootfsIdentity, image_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(identity.project().as_bytes());
    digest.update([0]);
    digest.update(identity.service().as_bytes());
    digest.update([0]);
    digest.update(image_id.as_bytes());
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

fn parse_loop_device(output: &[u8]) -> Result<PathBuf, SandboxError> {
    let value = String::from_utf8_lossy(output).trim().to_owned();
    let suffix = value.strip_prefix("/dev/loop").ok_or_else(|| {
        SandboxError::ImageProvider("losetup returned an invalid loop device".to_owned())
    })?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SandboxError::ImageProvider(
            "losetup returned an invalid loop device".to_owned(),
        ));
    }
    let path = PathBuf::from(value);
    let metadata = fs::metadata(&path).map_err(|source| io_error(&path, source))?;
    if !metadata.file_type().is_block_device() {
        return Err(SandboxError::ImageProvider(
            "losetup result is not a block device".to_owned(),
        ));
    }
    Ok(path)
}

fn validate_overlay_path(path: &Path) -> Result<(), SandboxError> {
    if path
        .as_os_str()
        .as_encoded_bytes()
        .iter()
        .any(|byte| matches!(byte, b',' | b':' | b'\\'))
    {
        return Err(SandboxError::ImageProvider(
            "immutable rootfs path cannot be represented as an overlay mount option".to_owned(),
        ));
    }
    Ok(())
}

fn write_record(directory: &Path, record: &WritableRootfsRecord) -> Result<(), SandboxError> {
    let bytes = serde_json::to_vec_pretty(record).map_err(|error| {
        SandboxError::ImageProvider(format!("encode writable rootfs metadata: {error}"))
    })?;
    let temporary = Builder::new()
        .prefix(".rootfs-")
        .tempfile_in(directory)
        .map_err(|source| io_error(directory, source))?;
    temporary
        .as_file()
        .set_permissions(<fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600))
        .map_err(|source| io_error(temporary.path(), source))?;
    temporary
        .as_file()
        .write_all(&bytes)
        .map_err(|source| io_error(temporary.path(), source))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| io_error(temporary.path(), source))?;
    let path = directory.join("rootfs.json");
    temporary
        .persist(&path)
        .map_err(|error| io_error(&path, error.error))?;
    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(directory, source))
}

fn read_record(path: &Path) -> Result<WritableRootfsRecord, SandboxError> {
    serde_json::from_slice(&fs::read(path).map_err(|source| io_error(path, source))?).map_err(
        |error| SandboxError::ImageProvider(format!("decode writable rootfs metadata: {error}")),
    )
}

fn mount_error(operation: &str, error: nix::errno::Errno) -> SandboxError {
    SandboxError::ImageProvider(format!("{operation}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LockedDescriptor, LockedImage};
    use nix::mount::MsFlags;

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
    fn keys_bind_project_service_and_image() {
        let identity = WritableRootfsIdentity::new("sandbox", "api").unwrap();
        assert_ne!(
            rootfs_key(&identity, "sha256:a"),
            rootfs_key(&identity, "sha256:b")
        );
        assert_eq!(rootfs_key(&identity, "sha256:a").len(), 64);
    }

    #[test]
    fn loop_device_parser_rejects_untrusted_paths_before_metadata_lookup() {
        assert!(parse_loop_device(b"/dev/sda").is_err());
        assert!(parse_loop_device(b"/dev/loop../../sda").is_err());
    }

    #[test]
    #[ignore = "requires root, mount, and loop-device access"]
    fn loopback_overlay_enforces_quota_and_cleans_up() {
        let temporary = tempfile::Builder::new()
            .prefix("sandboxd-writable-root-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let lower_source = temporary.path().join("lower-source");
        let lower_mount = temporary.path().join("lower-mount");
        fs::create_dir(&lower_source).unwrap();
        fs::create_dir(&lower_mount).unwrap();
        fs::write(lower_source.join("base"), b"immutable").unwrap();
        mount(
            Some(lower_source.as_path()),
            &lower_mount,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .unwrap();
        mount(
            Some(lower_source.as_path()),
            &lower_mount,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .unwrap();
        let immutable = ImmutableRootfs {
            provider: "test".to_owned(),
            activation_key: "test".to_owned(),
            image: image(),
            rootfs: fs::canonicalize(&lower_mount).unwrap(),
            rootfs_digest: format!("sha256:{}", "d".repeat(64)),
            rootfs_entries: 1,
            rootfs_bytes: 9,
        };
        let manager = LoopbackWritableRootfs::new(
            WritableRootfsConfig {
                root: temporary.path().join("writable"),
                mkfs_ext4_program: PathBuf::from("/usr/sbin/mkfs.ext4"),
                losetup_program: PathBuf::from("/usr/sbin/losetup"),
                minimum_bytes: 16 * 1024 * 1024,
                maximum_bytes: 64 * 1024 * 1024,
                operation_timeout: std::time::Duration::from_secs(30),
            },
            1024 * 1024,
        )
        .unwrap();
        let rootfs = manager
            .create(
                &immutable,
                WritableRootfsIdentity::new("sandbox", "api").unwrap(),
                32 * 1024 * 1024,
            )
            .unwrap();
        let lower_metadata = fs::metadata(&lower_mount).unwrap();
        let writable_metadata = fs::metadata(rootfs.rootfs()).unwrap();
        assert_eq!(
            writable_metadata.mode() & 0o7777,
            lower_metadata.mode() & 0o7777
        );
        assert_eq!(writable_metadata.uid(), lower_metadata.uid());
        assert_eq!(writable_metadata.gid(), lower_metadata.gid());
        assert_eq!(
            fs::read(rootfs.rootfs().join("base")).unwrap(),
            b"immutable"
        );
        fs::write(rootfs.rootfs().join("tenant-secret"), b"tenant-a").unwrap();
        let other = manager
            .create(
                &immutable,
                WritableRootfsIdentity::new("other", "api").unwrap(),
                32 * 1024 * 1024,
            )
            .unwrap();
        fs::write(other.rootfs().join("tenant-secret"), b"tenant-b").unwrap();
        assert_eq!(
            fs::read(rootfs.rootfs().join("tenant-secret")).unwrap(),
            b"tenant-a"
        );
        assert_eq!(
            fs::read(other.rootfs().join("tenant-secret")).unwrap(),
            b"tenant-b"
        );
        manager.release(&other).unwrap();
        let mut file = File::create(rootfs.rootfs().join("fill")).unwrap();
        let block = vec![0_u8; 1024 * 1024];
        let error = loop {
            if let Err(error) = file.write_all(&block) {
                break error;
            }
        };
        assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
        drop(file);
        manager.release(&rootfs).unwrap();
        assert!(fs::read_dir(temporary.path().join("writable"))
            .unwrap()
            .next()
            .is_none());
        umount(&lower_mount).unwrap();
    }
}
