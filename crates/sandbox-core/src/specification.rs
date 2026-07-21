use crate::{ContainerId, CoreError, GuestProfileIdentity, NetworkId, VolumeSpec};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SANDBOX_SPEC_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSpec {
    pub schema_version: u32,
    pub spec_digest: String,
    pub guest_profile: GuestProfileIdentity,
    pub containers: BTreeMap<ContainerId, ContainerSpec>,
    pub networks: BTreeMap<NetworkId, NetworkSpec>,
    pub startup_order: Vec<ContainerId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerSpec {
    pub image: ContainerImage,
    pub argv: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub dependencies: Vec<ContainerDependency>,
    pub networks: Vec<NetworkId>,
    pub resources: ResourceSpec,
    #[serde(default)]
    pub volumes: Vec<VolumeSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerImage {
    pub exact_reference: String,
    pub image_digest: String,
    pub rootfs_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerDependency {
    pub container: ContainerId,
    pub requires_healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSpec {
    pub internal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSpec {
    pub memory_bytes: u64,
    pub cpu_millis: u32,
    pub guest_processes: u32,
    pub host_tasks: u32,
    pub writable_bytes: u64,
    pub output_bytes: u64,
}

impl SandboxSpec {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.schema_version != SANDBOX_SPEC_VERSION {
            return Err(CoreError::InvalidSpecification(
                "unsupported schema version".to_owned(),
            ));
        }
        validate_digest("spec", &self.spec_digest)?;
        if GuestProfileIdentity::parse(&self.guest_profile.canonical()).as_ref()
            != Ok(&self.guest_profile)
        {
            return Err(CoreError::InvalidSpecification(
                "sandbox has an invalid guest profile identity".to_owned(),
            ));
        }
        if self.containers.is_empty() || self.containers.len() > 64 {
            return Err(CoreError::InvalidSpecification(
                "sandbox must contain between 1 and 64 containers".to_owned(),
            ));
        }
        if self.networks.len() > 16 {
            return Err(CoreError::InvalidSpecification(
                "sandbox contains more than 16 networks".to_owned(),
            ));
        }
        let startup = self.startup_order.iter().collect::<BTreeSet<_>>();
        if startup.len() != self.containers.len()
            || startup != self.containers.keys().collect::<BTreeSet<&ContainerId>>()
        {
            return Err(CoreError::InvalidSpecification(
                "startup order must contain every container exactly once".to_owned(),
            ));
        }
        for (id, container) in &self.containers {
            validate_digest("image", &container.image.image_digest)?;
            validate_digest("rootfs", &container.image.rootfs_digest)?;
            if container.image.exact_reference.is_empty()
                || container.argv.is_empty()
                || container.argv.len() > 256
                || container.environment.len() > 256
            {
                return Err(CoreError::InvalidSpecification(format!(
                    "container `{id}` has invalid image, argv, or environment"
                )));
            }
            if container.resources.memory_bytes == 0
                || container.resources.cpu_millis == 0
                || container.resources.guest_processes == 0
                || container.resources.host_tasks < container.resources.guest_processes
                || container.resources.writable_bytes == 0
                || container.resources.output_bytes == 0
            {
                return Err(CoreError::InvalidSpecification(format!(
                    "container `{id}` has invalid resource limits"
                )));
            }
            if container
                .networks
                .iter()
                .any(|network| !self.networks.contains_key(network))
            {
                return Err(CoreError::InvalidSpecification(format!(
                    "container `{id}` references an unknown network"
                )));
            }
            if container.dependencies.iter().any(|dependency| {
                dependency.container == *id || !self.containers.contains_key(&dependency.container)
            }) {
                return Err(CoreError::InvalidSpecification(format!(
                    "container `{id}` has an invalid dependency"
                )));
            }
            let mut destinations = BTreeSet::new();
            for volume in &container.volumes {
                volume.validate()?;
                if !destinations.insert(volume.destination.as_str()) {
                    return Err(CoreError::InvalidSpecification(format!(
                        "container `{id}` repeats a volume destination"
                    )));
                }
            }
        }
        let positions = self
            .startup_order
            .iter()
            .enumerate()
            .map(|(position, id)| (id, position))
            .collect::<BTreeMap<_, _>>();
        for (id, container) in &self.containers {
            if container
                .dependencies
                .iter()
                .any(|dependency| positions[&dependency.container] >= positions[id])
            {
                return Err(CoreError::InvalidSpecification(format!(
                    "container `{id}` starts before one of its dependencies"
                )));
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_digest(kind: &str, digest: &str) -> Result<(), CoreError> {
    let value = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| CoreError::InvalidSpecification(format!("{kind} digest is not sha256")))?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CoreError::InvalidSpecification(format!(
            "{kind} digest is malformed"
        )));
    }
    Ok(())
}
