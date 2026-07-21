use crate::{
    AttachmentOwner, MountedVolume, VolumeAttachment, VolumeCleanupReport, VolumeError,
    VolumeHandle, VolumeProviderCapabilities, VolumeScope, VolumeSnapshot,
};
use runtrue_sandbox_core::VolumeSpec;
use std::path::Path;

pub trait VolumeProvider: Send + Sync {
    fn provider_id(&self) -> &str;

    fn capabilities(&self) -> VolumeProviderCapabilities;

    fn create(
        &self,
        scope: &VolumeScope,
        specification: &VolumeSpec,
    ) -> Result<VolumeHandle, VolumeError>;

    fn attach(
        &self,
        handle: &VolumeHandle,
        owner: AttachmentOwner,
        specification: &VolumeSpec,
    ) -> Result<VolumeAttachment, VolumeError>;

    fn mount(&self, attachment: &VolumeAttachment) -> Result<MountedVolume, VolumeError>;

    fn detach(&self, attachment: &VolumeAttachment) -> Result<(), VolumeError>;

    fn freeze(&self, attachment: &VolumeAttachment) -> Result<(), VolumeError>;

    fn thaw(&self, attachment: &VolumeAttachment) -> Result<(), VolumeError>;

    fn snapshot(
        &self,
        attachment: &VolumeAttachment,
        destination: &Path,
    ) -> Result<VolumeSnapshot, VolumeError>;

    fn restore(
        &self,
        scope: &VolumeScope,
        specification: &VolumeSpec,
        snapshot: &VolumeSnapshot,
        source: &Path,
    ) -> Result<VolumeHandle, VolumeError>;

    fn unmount(&self, mounted: &MountedVolume) -> Result<(), VolumeError>;

    fn delete(&self, handle: &VolumeHandle) -> Result<(), VolumeError>;

    fn cleanup(&self) -> Result<VolumeCleanupReport, VolumeError>;
}
