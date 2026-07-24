mod command;
mod config;
mod containerd;
mod credentials;
mod handle;
mod layer;
mod validation;
mod writable;

pub use config::{
    ContainerdProviderConfig, FixedRootfsConfig, FixedRootfsMeasurement, ImageLimits, ImagePlatform,
};
pub use containerd::ContainerdImageProvider;
pub use credentials::RegistryCredential;
pub use handle::{ImmutableRootfs, PreparedImageHandle};
pub use writable::{
    WritableRootfs, WritableRootfsConfig, WritableRootfsExport, WritableRootfsIdentity,
    LOOPBACK_WRITABLE_ROOTFS_PROVIDER_ID, MINIMUM_WRITABLE_ROOT_BYTES,
};

use crate::{LockedImage, SandboxError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparationStatus {
    Prepared,
    Reused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GarbageCollectionReport {
    pub stale_staging_directories: usize,
    pub stale_mounts: usize,
    pub stale_writable_roots: usize,
}

pub trait ImageProvider: Send + Sync {
    fn resolve(
        &self,
        source: &str,
        credential: Option<&RegistryCredential>,
    ) -> Result<LockedImage, SandboxError>;

    fn pull(
        &self,
        image: &LockedImage,
        credential: Option<&RegistryCredential>,
    ) -> Result<PreparationStatus, SandboxError>;

    fn verify(&self, image: &LockedImage) -> Result<(), SandboxError>;

    fn unpack(&self, image: &LockedImage) -> Result<(), SandboxError>;

    fn activate(&self, image: &LockedImage) -> Result<PreparedImageHandle, SandboxError>;

    fn mount(&self, image: &PreparedImageHandle) -> Result<ImmutableRootfs, SandboxError>;

    fn release(&self, rootfs: &ImmutableRootfs) -> Result<(), SandboxError>;

    fn create_writable_rootfs(
        &self,
        immutable: &ImmutableRootfs,
        identity: WritableRootfsIdentity,
        quota_bytes: u64,
    ) -> Result<WritableRootfs, SandboxError> {
        let _ = (immutable, identity, quota_bytes);
        Err(SandboxError::Unsupported(
            "image provider does not support quota-backed writable roots".to_owned(),
        ))
    }

    fn release_writable_rootfs(&self, rootfs: &WritableRootfs) -> Result<(), SandboxError> {
        let _ = rootfs;
        Err(SandboxError::Unsupported(
            "image provider does not support quota-backed writable roots".to_owned(),
        ))
    }

    fn export_writable_rootfs(
        &self,
        rootfs: &WritableRootfs,
        destination: &std::path::Path,
    ) -> Result<WritableRootfsExport, SandboxError> {
        let _ = (rootfs, destination);
        Err(SandboxError::Unsupported(
            "image provider does not support writable-root export".to_owned(),
        ))
    }

    fn restore_writable_rootfs(
        &self,
        immutable: &ImmutableRootfs,
        identity: WritableRootfsIdentity,
        quota_bytes: u64,
        diff: &std::path::Path,
    ) -> Result<WritableRootfs, SandboxError> {
        let _ = (immutable, identity, quota_bytes, diff);
        Err(SandboxError::Unsupported(
            "image provider does not support writable-root restore".to_owned(),
        ))
    }

    fn garbage_collect(&self) -> Result<GarbageCollectionReport, SandboxError>;

    fn prepare(
        &self,
        image: &LockedImage,
        credential: Option<&RegistryCredential>,
    ) -> Result<(PreparationStatus, ImmutableRootfs), SandboxError> {
        let status = self.pull(image, credential)?;
        self.verify(image)?;
        self.unpack(image)?;
        let activated = self.activate(image)?;
        let rootfs = self.mount(&activated)?;
        Ok((status, rootfs))
    }

    fn admit(&self, image: &LockedImage) -> Result<ImmutableRootfs, SandboxError> {
        self.verify(image)?;
        self.unpack(image)?;
        let activated = self.activate(image)?;
        self.mount(&activated)
    }
}
