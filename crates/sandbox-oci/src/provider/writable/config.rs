use crate::{io_error, SandboxError};
use std::{
    fs,
    os::unix::fs::{FileTypeExt as _, MetadataExt as _},
    path::{Path, PathBuf},
    time::Duration,
};

pub const MINIMUM_WRITABLE_ROOT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct WritableRootfsConfig {
    pub root: PathBuf,
    pub mkfs_ext4_program: PathBuf,
    pub losetup_program: PathBuf,
    pub minimum_bytes: u64,
    pub maximum_bytes: u64,
    pub operation_timeout: Duration,
}

impl WritableRootfsConfig {
    pub(super) fn validated(mut self) -> Result<Self, SandboxError> {
        if !self.root.is_absolute()
            || self.minimum_bytes < MINIMUM_WRITABLE_ROOT_BYTES
            || self.maximum_bytes < self.minimum_bytes
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(300)
        {
            return Err(SandboxError::ImageProvider(
                "writable rootfs configuration is invalid".to_owned(),
            ));
        }
        self.mkfs_ext4_program = validate_program(&self.mkfs_ext4_program, "mkfs.ext4")?;
        self.losetup_program = validate_program(&self.losetup_program, "losetup")?;
        fs::create_dir_all(&self.root).map_err(|source| io_error(&self.root, source))?;
        self.root = fs::canonicalize(&self.root).map_err(|source| io_error(&self.root, source))?;
        let encoded = self.root.as_os_str().as_encoded_bytes();
        if encoded
            .iter()
            .any(|byte| matches!(byte, b',' | b':' | b'\\'))
        {
            return Err(SandboxError::ImageProvider(
                "writable rootfs path cannot be represented as an overlay mount option".to_owned(),
            ));
        }
        let metadata = fs::metadata(&self.root).map_err(|source| io_error(&self.root, source))?;
        if !metadata.is_dir() || metadata.uid() != 0 {
            return Err(SandboxError::ImageProvider(
                "writable rootfs root must be a root-owned directory".to_owned(),
            ));
        }
        fs::set_permissions(
            &self.root,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .map_err(|source| io_error(&self.root, source))?;
        Ok(self)
    }

    pub(super) fn validate_quota(&self, quota_bytes: u64) -> Result<(), SandboxError> {
        if !(self.minimum_bytes..=self.maximum_bytes).contains(&quota_bytes) {
            return Err(SandboxError::ImageProvider(format!(
                "writable rootfs quota must be between {} and {} bytes",
                self.minimum_bytes, self.maximum_bytes
            )));
        }
        Ok(())
    }
}

fn validate_program(path: &Path, name: &str) -> Result<PathBuf, SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::ImageProvider(format!(
            "{name} executable must be absolute"
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    let metadata = fs::metadata(&canonical).map_err(|source| io_error(&canonical, source))?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.file_type().is_socket() {
        return Err(SandboxError::ImageProvider(format!(
            "{name} executable is not a root-owned regular file"
        )));
    }
    Ok(canonical)
}
