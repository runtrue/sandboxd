use crate::{io_error, SandboxError};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePlatform {
    pub operating_system: String,
    pub architecture: String,
    pub variant: Option<String>,
}

impl ImagePlatform {
    #[must_use]
    pub fn linux_amd64() -> Self {
        Self {
            operating_system: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            variant: None,
        }
    }

    #[must_use]
    pub fn as_containerd_platform(&self) -> String {
        self.variant.as_ref().map_or_else(
            || format!("{}/{}", self.operating_system, self.architecture),
            |variant| {
                format!(
                    "{}/{}/{}",
                    self.operating_system, self.architecture, variant
                )
            },
        )
    }

    pub fn parse(value: &str) -> Result<Self, SandboxError> {
        let parts = value.split('/').collect::<Vec<_>>();
        if !(2..=3).contains(&parts.len())
            || parts.iter().any(|part| !valid_component(part))
            || parts[0] != "linux"
            || !matches!(parts[1], "amd64" | "arm64")
        {
            return Err(SandboxError::ImageProvider(format!(
                "unsupported image platform `{value}`"
            )));
        }
        Ok(Self {
            operating_system: parts[0].to_owned(),
            architecture: parts[1].to_owned(),
            variant: parts.get(2).map(|part| (*part).to_owned()),
        })
    }
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageLimits {
    pub maximum_manifest_bytes: u64,
    pub maximum_config_bytes: u64,
    pub maximum_compressed_bytes: u64,
    pub maximum_expanded_bytes: u64,
    pub maximum_layers: usize,
    pub maximum_entries: usize,
    pub maximum_path_bytes: usize,
    pub maximum_command_output_bytes: usize,
    pub operation_timeout: Duration,
}

impl Default for ImageLimits {
    fn default() -> Self {
        Self {
            maximum_manifest_bytes: 4 * 1024 * 1024,
            maximum_config_bytes: 4 * 1024 * 1024,
            maximum_compressed_bytes: 4 * 1024 * 1024 * 1024,
            maximum_expanded_bytes: 16 * 1024 * 1024 * 1024,
            maximum_layers: 128,
            maximum_entries: 500_000,
            maximum_path_bytes: 4_096,
            maximum_command_output_bytes: 1024 * 1024,
            operation_timeout: Duration::from_secs(300),
        }
    }
}

impl ImageLimits {
    pub(crate) fn validate(&self) -> Result<(), SandboxError> {
        if self.maximum_manifest_bytes == 0
            || self.maximum_manifest_bytes > 64 * 1024 * 1024
            || self.maximum_config_bytes == 0
            || self.maximum_config_bytes > 64 * 1024 * 1024
            || self.maximum_compressed_bytes == 0
            || self.maximum_expanded_bytes == 0
            || self.maximum_layers == 0
            || self.maximum_layers > 1_024
            || self.maximum_entries == 0
            || self.maximum_path_bytes == 0
            || self.maximum_command_output_bytes == 0
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(3_600)
        {
            return Err(SandboxError::ImageProvider(
                "image provider limits are invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ContainerdProviderConfig {
    pub ctr_program: PathBuf,
    pub address: PathBuf,
    pub namespace: String,
    pub snapshotter: String,
    pub mount_root: PathBuf,
    pub writable_rootfs: super::WritableRootfsConfig,
    pub platform: ImagePlatform,
    pub limits: ImageLimits,
}

impl ContainerdProviderConfig {
    pub fn validated(mut self) -> Result<Self, SandboxError> {
        if !self.ctr_program.is_absolute()
            || !self.address.is_absolute()
            || !self.mount_root.is_absolute()
        {
            return Err(SandboxError::ImageProvider(
                "containerd executable, socket, and mount root must be absolute".to_owned(),
            ));
        }
        self.ctr_program = fs::canonicalize(&self.ctr_program)
            .map_err(|source| io_error(&self.ctr_program, source))?;
        if !self.ctr_program.is_file() {
            return Err(SandboxError::ImageProvider(
                "containerd client is not a regular file".to_owned(),
            ));
        }
        let socket =
            fs::metadata(&self.address).map_err(|source| io_error(&self.address, source))?;
        if !socket.file_type().is_socket() {
            return Err(SandboxError::ImageProvider(
                "containerd address is not a Unix socket".to_owned(),
            ));
        }
        validate_identifier("containerd namespace", &self.namespace)?;
        validate_identifier("snapshotter", &self.snapshotter)?;
        self.limits.validate()?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.mount_root)
            .map_err(|source| io_error(&self.mount_root, source))?;
        self.mount_root = fs::canonicalize(&self.mount_root)
            .map_err(|source| io_error(&self.mount_root, source))?;
        let metadata =
            fs::metadata(&self.mount_root).map_err(|source| io_error(&self.mount_root, source))?;
        if !metadata.is_dir() || metadata.uid() != nix::unistd::geteuid().as_raw() {
            return Err(SandboxError::ImageProvider(
                "image-provider store must be owned by the worker UID".to_owned(),
            ));
        }
        fs::set_permissions(&self.mount_root, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_error(&self.mount_root, source))?;
        Ok(self)
    }
}

fn validate_identifier(kind: &str, value: &str) -> Result<(), SandboxError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(SandboxError::ImageProvider(format!(
            "{kind} is not a bounded identifier"
        )));
    }
    Ok(())
}

pub(crate) fn canonical_child(root: &Path, child: &Path) -> Result<PathBuf, SandboxError> {
    let canonical = fs::canonicalize(child).map_err(|source| io_error(child, source))?;
    if canonical == root || !canonical.starts_with(root) {
        return Err(SandboxError::ImageProvider(
            "provider path escaped its configured root".to_owned(),
        ));
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_is_explicit_and_bounded() {
        assert_eq!(
            ImagePlatform::parse("linux/arm64/v8")
                .unwrap()
                .as_containerd_platform(),
            "linux/arm64/v8"
        );
        assert!(ImagePlatform::parse("windows/amd64").is_err());
        assert!(ImagePlatform::parse("linux/ppc64le").is_err());
        assert!(ImagePlatform::parse("linux/amd64/../../host").is_err());
    }
}
