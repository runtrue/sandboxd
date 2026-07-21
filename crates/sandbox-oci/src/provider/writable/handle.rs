use super::WritableRootfsIdentity;
use crate::LockedImage;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritableRootfs {
    pub(super) provider: String,
    pub(super) key: String,
    pub(super) identity: WritableRootfsIdentity,
    pub(super) image: LockedImage,
    pub(super) rootfs: PathBuf,
    pub(super) quota_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritableRootfsExport {
    pub entries: usize,
    pub logical_bytes: u64,
    pub archive_bytes: u64,
}

impl WritableRootfs {
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub fn identity(&self) -> &WritableRootfsIdentity {
        &self.identity
    }

    #[must_use]
    pub fn image(&self) -> &LockedImage {
        &self.image
    }

    #[must_use]
    pub fn rootfs(&self) -> &Path {
        &self.rootfs
    }

    #[must_use]
    pub const fn quota_bytes(&self) -> u64 {
        self.quota_bytes
    }
}
