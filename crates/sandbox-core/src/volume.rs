use crate::{
    specification::validate_digest, ArtifactDescriptor, CoreError, SnapshotPortability, VolumeId,
};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

pub const VOLUME_SPEC_VERSION: u32 = 1;
pub const MINIMUM_NAMED_VOLUME_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumePersistenceClass {
    Ephemeral,
    Persistent,
    Artifact,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeSnapshotPolicy {
    Required,
    BestEffort,
    Excluded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeSpec {
    pub schema_version: u32,
    pub volume_id: VolumeId,
    pub destination: String,
    pub read_only: bool,
    pub persistence_class: VolumePersistenceClass,
    pub snapshot_policy: VolumeSnapshotPolicy,
    pub quota_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeSnapshotDescriptor {
    pub provider_id: String,
    pub persistence_class: VolumePersistenceClass,
    pub portability: SnapshotPortability,
    pub object_name: String,
    pub artifact: ArtifactDescriptor,
}

impl VolumeSnapshotDescriptor {
    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        if !matches!(
            self.persistence_class,
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent
        ) {
            return Err(CoreError::InvalidSnapshot(
                "secret or immutable artifact entered the volume snapshot manifest".to_owned(),
            ));
        }
        if self.provider_id.is_empty()
            || self.provider_id.len() > 128
            || !self
                .provider_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || self.object_name.is_empty()
            || self.object_name.len() > 128
            || !self
                .object_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(CoreError::InvalidSnapshot(
                "volume snapshot provider or object identity is invalid".to_owned(),
            ));
        }
        validate_digest("volume snapshot", &self.artifact.digest)
            .map_err(|error| CoreError::InvalidSnapshot(error.to_string()))?;
        if self.artifact.size_bytes == 0 || self.artifact.media_type.is_empty() {
            return Err(CoreError::InvalidSnapshot(
                "volume snapshot object metadata is incomplete".to_owned(),
            ));
        }
        Ok(())
    }
}

impl VolumeSpec {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.schema_version != VOLUME_SPEC_VERSION {
            return Err(invalid("unsupported volume schema version"));
        }
        validate_destination(&self.destination)?;
        match self.persistence_class {
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent => {
                if self.quota_bytes < MINIMUM_NAMED_VOLUME_BYTES {
                    return Err(invalid("named volume quota is below the minimum"));
                }
                if self.content_digest.is_some() {
                    return Err(invalid("named volume cannot contain an artifact digest"));
                }
            }
            VolumePersistenceClass::Artifact => {
                if !self.read_only {
                    return Err(invalid("artifact volume must be read-only"));
                }
                if self.snapshot_policy == VolumeSnapshotPolicy::Required {
                    return Err(invalid(
                        "immutable artifact volume cannot require a writable snapshot",
                    ));
                }
                let digest = self
                    .content_digest
                    .as_deref()
                    .ok_or_else(|| invalid("artifact volume requires a content digest"))?;
                validate_digest("artifact volume", digest)
                    .map_err(|error| invalid(&error.to_string()))?;
            }
            VolumePersistenceClass::Secret => {
                if !self.read_only {
                    return Err(invalid("secret volume must be read-only"));
                }
                if self.snapshot_policy != VolumeSnapshotPolicy::Excluded {
                    return Err(invalid("secret volume must be excluded from snapshots"));
                }
                if self.quota_bytes == 0 {
                    return Err(invalid("secret tmpfs quota must be nonzero"));
                }
                if self.content_digest.is_some() {
                    return Err(invalid("secret volume cannot contain a content digest"));
                }
            }
        }
        Ok(())
    }
}

fn validate_destination(destination: &str) -> Result<(), CoreError> {
    if destination.len() > 4_096
        || !destination.starts_with('/')
        || destination.contains('\0')
        || destination.contains("//")
    {
        return Err(invalid(
            "volume destination must be a normalized absolute path",
        ));
    }
    let path = Path::new(destination);
    if destination == "/"
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        return Err(invalid(
            "volume destination must be a normalized guest path",
        ));
    }
    let reserved = ["/proc", "/sys", "/dev"];
    if reserved
        .iter()
        .any(|prefix| destination == *prefix || destination.starts_with(&format!("{prefix}/")))
    {
        return Err(invalid(
            "volume destination overlaps a protected guest mount",
        ));
    }
    if matches!(
        destination,
        "/tmp" | "/work" | "/etc/hosts" | "/etc/resolv.conf"
    ) {
        return Err(invalid(
            "volume destination shadows a runtime-owned guest mount",
        ));
    }
    Ok(())
}

fn invalid(message: &str) -> CoreError {
    CoreError::InvalidSpecification(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(class: VolumePersistenceClass) -> VolumeSpec {
        VolumeSpec {
            schema_version: VOLUME_SPEC_VERSION,
            volume_id: VolumeId::parse("shared").expect("volume id"),
            destination: "/var/lib/data".to_owned(),
            read_only: false,
            persistence_class: class,
            snapshot_policy: VolumeSnapshotPolicy::Required,
            quota_bytes: MINIMUM_NAMED_VOLUME_BYTES,
            content_digest: None,
        }
    }

    #[test]
    fn named_volume_contains_no_host_path() {
        assert!(named(VolumePersistenceClass::Persistent).validate().is_ok());
        let mut invalid = named(VolumePersistenceClass::Persistent);
        invalid.destination = "../../host".to_owned();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn artifact_is_content_addressed_and_read_only() {
        let mut artifact = named(VolumePersistenceClass::Artifact);
        artifact.read_only = true;
        artifact.snapshot_policy = VolumeSnapshotPolicy::Excluded;
        artifact.quota_bytes = 0;
        artifact.content_digest = Some(format!("sha256:{}", "a".repeat(64)));
        assert!(artifact.validate().is_ok());
        artifact.read_only = false;
        assert!(artifact.validate().is_err());
    }

    #[test]
    fn secrets_are_always_read_only_and_snapshot_excluded() {
        let mut secret = named(VolumePersistenceClass::Secret);
        secret.read_only = true;
        secret.snapshot_policy = VolumeSnapshotPolicy::Excluded;
        assert!(secret.validate().is_ok());
        secret.snapshot_policy = VolumeSnapshotPolicy::BestEffort;
        assert!(secret.validate().is_err());
    }

    #[test]
    fn protected_mounts_cannot_be_shadowed() {
        for destination in [
            "/",
            "/proc",
            "/proc/sys",
            "/sys/fs",
            "/dev/shm",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/tmp",
            "/work",
        ] {
            let mut volume = named(VolumePersistenceClass::Ephemeral);
            volume.destination = destination.to_owned();
            assert!(volume.validate().is_err(), "accepted {destination}");
        }
    }
}
