mod command;
mod config;
mod containerd;
mod credentials;
mod handle;
mod layer;
mod validation;

pub use config::{ContainerdProviderConfig, ImageLimits, ImagePlatform};
pub use containerd::ContainerdImageProvider;
pub use credentials::RegistryCredential;
pub use handle::{ImmutableRootfs, PreparedImageHandle};

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
