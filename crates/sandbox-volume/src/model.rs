use crate::VolumeError;
use runtrue_sandbox_core::{
    ContainerId, SandboxId, SnapshotPortability, TenantId, VolumeId, VolumePersistenceClass,
    VolumeSpec, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt, path::Path, path::PathBuf};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VolumeScope {
    tenant_id: TenantId,
    workspace_id: WorkspaceId,
}

impl VolumeScope {
    #[must_use]
    pub fn new(tenant_id: TenantId, workspace_id: WorkspaceId) -> Self {
        Self {
            tenant_id,
            workspace_id,
        }
    }

    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentOwner {
    pub sandbox_id: SandboxId,
    pub container_id: ContainerId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeProviderCapabilities {
    pub persistence_classes: BTreeSet<VolumePersistenceClass>,
    pub snapshot: bool,
    pub clone: bool,
    pub snapshot_portability: SnapshotPortability,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeHandle {
    pub(crate) provider_id: String,
    pub(crate) key: String,
    pub(crate) scope: VolumeScope,
    pub(crate) volume_id: VolumeId,
    pub(crate) persistence_class: VolumePersistenceClass,
    pub(crate) quota_bytes: u64,
    pub(crate) content_digest: Option<String>,
}

impl VolumeHandle {
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub fn scope(&self) -> &VolumeScope {
        &self.scope
    }

    #[must_use]
    pub fn volume_id(&self) -> &VolumeId {
        &self.volume_id
    }

    #[must_use]
    pub const fn persistence_class(&self) -> VolumePersistenceClass {
        self.persistence_class
    }

    #[must_use]
    pub const fn quota_bytes(&self) -> u64 {
        self.quota_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeAttachment {
    pub(crate) handle: VolumeHandle,
    pub(crate) attachment_id: String,
    pub(crate) owner: AttachmentOwner,
    pub(crate) destination: String,
    pub(crate) read_only: bool,
    pub(crate) snapshot_policy: runtrue_sandbox_core::VolumeSnapshotPolicy,
}

impl VolumeAttachment {
    #[must_use]
    pub fn handle(&self) -> &VolumeHandle {
        &self.handle
    }

    #[must_use]
    pub fn attachment_id(&self) -> &str {
        &self.attachment_id
    }

    #[must_use]
    pub const fn snapshot_policy(&self) -> runtrue_sandbox_core::VolumeSnapshotPolicy {
        self.snapshot_policy
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedVolume {
    pub(crate) attachment: VolumeAttachment,
    pub(crate) source: PathBuf,
}

impl MountedVolume {
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    #[must_use]
    pub fn destination(&self) -> &str {
        &self.attachment.destination
    }

    #[must_use]
    pub const fn read_only(&self) -> bool {
        self.attachment.read_only
    }

    #[must_use]
    pub fn attachment(&self) -> &VolumeAttachment {
        &self.attachment
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeSnapshot {
    pub schema_version: u32,
    pub provider_id: String,
    pub volume_id: VolumeId,
    pub persistence_class: VolumePersistenceClass,
    pub digest: String,
    pub size_bytes: u64,
    pub quota_bytes: u64,
    pub format: String,
    pub portability: SnapshotPortability,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeCleanupReport {
    pub cleared_attachments: usize,
    pub removed_ephemeral_volumes: usize,
    pub retained_persistent_volumes: usize,
    pub removed_secret_volumes: usize,
}

pub struct SecretFile {
    pub name: String,
    pub contents: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SecretFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretFile")
            .field("name", &self.name)
            .field("contents", &"<redacted>")
            .finish()
    }
}

pub trait SecretResolver: Send + Sync {
    fn resolve(
        &self,
        scope: &VolumeScope,
        volume_id: &VolumeId,
    ) -> Result<Vec<SecretFile>, VolumeError>;
}

pub(crate) fn validate_handle_spec(
    handle: &VolumeHandle,
    spec: &VolumeSpec,
) -> Result<(), VolumeError> {
    spec.validate()
        .map_err(|error| VolumeError::Invalid(error.to_string()))?;
    if handle.volume_id != spec.volume_id
        || handle.persistence_class != spec.persistence_class
        || handle.quota_bytes != spec.quota_bytes
        || handle.content_digest != spec.content_digest
    {
        return Err(VolumeError::Invalid(
            "attachment specification does not match its volume handle".to_owned(),
        ));
    }
    Ok(())
}
