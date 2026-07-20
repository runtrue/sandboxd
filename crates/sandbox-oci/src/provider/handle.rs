use crate::{LockedDescriptor, LockedImage};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const PROVIDER_METADATA_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedImageHandle {
    pub(crate) provider: String,
    pub(crate) activation_key: String,
    pub(crate) image: LockedImage,
}

impl PreparedImageHandle {
    #[must_use]
    pub fn image(&self) -> &LockedImage {
        &self.image
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutableRootfs {
    pub(crate) provider: String,
    pub(crate) activation_key: String,
    pub(crate) image: LockedImage,
    pub(crate) rootfs: PathBuf,
    pub(crate) rootfs_digest: String,
    pub(crate) rootfs_entries: usize,
    pub(crate) rootfs_bytes: u64,
}

impl ImmutableRootfs {
    #[must_use]
    pub fn image(&self) -> &LockedImage {
        &self.image
    }

    #[must_use]
    pub fn rootfs(&self) -> &Path {
        &self.rootfs
    }

    #[must_use]
    pub fn rootfs_digest(&self) -> &str {
        &self.rootfs_digest
    }

    #[must_use]
    pub fn rootfs_entries(&self) -> usize {
        self.rootfs_entries
    }

    #[must_use]
    pub fn rootfs_bytes(&self) -> u64 {
        self.rootfs_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderMetadata {
    pub schema_version: u32,
    pub provider: String,
    pub activation_key: String,
    pub exact_reference: String,
    pub image_id: String,
    pub index: Option<LockedDescriptor>,
    pub manifest: LockedDescriptor,
    pub config: LockedDescriptor,
    pub layers: Vec<LockedDescriptor>,
    pub operating_system: String,
    pub architecture: String,
    pub variant: Option<String>,
    pub rootfs_digest: String,
    pub rootfs_entries: usize,
    pub rootfs_bytes: u64,
}

impl ProviderMetadata {
    pub(crate) fn from_rootfs(rootfs: &ImmutableRootfs) -> Self {
        Self {
            schema_version: PROVIDER_METADATA_SCHEMA_VERSION,
            provider: rootfs.provider.clone(),
            activation_key: rootfs.activation_key.clone(),
            exact_reference: rootfs.image.exact_reference.clone(),
            image_id: rootfs.image.image_id.clone(),
            index: rootfs.image.index.clone(),
            manifest: rootfs.image.manifest.clone(),
            config: rootfs.image.config.clone(),
            layers: rootfs.image.layers.clone(),
            operating_system: rootfs.image.operating_system.clone(),
            architecture: rootfs.image.architecture.clone(),
            variant: rootfs.image.variant.clone(),
            rootfs_digest: rootfs.rootfs_digest.clone(),
            rootfs_entries: rootfs.rootfs_entries,
            rootfs_bytes: rootfs.rootfs_bytes,
        }
    }

    pub(crate) fn matches(
        &self,
        provider: &str,
        activation_key: &str,
        image: &LockedImage,
    ) -> bool {
        self.schema_version == PROVIDER_METADATA_SCHEMA_VERSION
            && self.provider == provider
            && self.activation_key == activation_key
            && self.exact_reference == image.exact_reference
            && self.image_id == image.image_id
            && self.index == image.index
            && self.manifest == image.manifest
            && self.config == image.config
            && self.layers == image.layers
            && self.operating_system == image.operating_system
            && self.architecture == image.architecture
            && self.variant == image.variant
    }
}
