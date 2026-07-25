use crate::{io_error, SandboxError};
use std::{fs, os::unix::fs::MetadataExt as _, path::PathBuf, time::Duration};

pub const MINIMUM_WRITABLE_ROOT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct WritableRootfsConfig {
    pub root: PathBuf,
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
        fs::create_dir_all(&self.root).map_err(|source| io_error(&self.root, source))?;
        self.root = fs::canonicalize(&self.root).map_err(|source| io_error(&self.root, source))?;
        let metadata = fs::metadata(&self.root).map_err(|source| io_error(&self.root, source))?;
        if !metadata.is_dir() || metadata.uid() != nix::unistd::geteuid().as_raw() {
            return Err(SandboxError::ImageProvider(
                "writable rootfs root must be owned by the worker identity".to_owned(),
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
