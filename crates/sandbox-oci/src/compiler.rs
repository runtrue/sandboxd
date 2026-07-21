use crate::{
    model::{
        ComposeInput, DependencyCondition, DigestInput, LockedHealthcheck, LockedImage,
        LockedNetwork, LockedService, LockedVolume, RootFilesystemMode, SandboxPolicy,
        TopologyLock, LOCK_SCHEMA_VERSION, MAX_ARGUMENTS, MAX_ENVIRONMENT, MAX_NETWORKS,
        MAX_SERVICES, MAX_VALUE_BYTES, MAX_VOLUMES,
    },
    provider::{ImageProvider, RegistryCredential},
    SandboxError,
};
use runtrue_sandbox_core::{
    VolumeId, VolumePersistenceClass, VolumeSnapshotPolicy, VolumeSpec, VOLUME_SPEC_VERSION,
};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

pub fn lock_compose(
    compose_path: &Path,
    provider: &dyn ImageProvider,
    credential: Option<&RegistryCredential>,
) -> Result<TopologyLock, SandboxError> {
    let bytes =
        fs::read(compose_path).map_err(|source| crate::error::io_error(compose_path, source))?;
    if bytes.len() > 1024 * 1024 {
        return Err(SandboxError::Compose(
            "Compose input exceeds 1 MiB".to_owned(),
        ));
    }
    let input: ComposeInput =
        serde_yaml::from_slice(&bytes).map_err(|error| SandboxError::Compose(error.to_string()))?;
    let mut resolved = BTreeMap::<String, LockedImage>::new();
    compile(input, |reference| {
        if let Some(image) = resolved.get(reference) {
            return Ok(image.clone());
        }
        let image = provider.resolve(reference, credential)?;
        resolved.insert(reference.to_owned(), image.clone());
        Ok(image)
    })
}

fn compile<F>(input: ComposeInput, mut resolve: F) -> Result<TopologyLock, SandboxError>
where
    F: FnMut(&str) -> Result<LockedImage, SandboxError>,
{
    let name = input
        .name
        .ok_or_else(|| SandboxError::Compose("top-level `name` is required".to_owned()))?;
    validate_identifier("topology name", &name)?;
    if input.services.is_empty() || input.services.len() > MAX_SERVICES {
        return Err(SandboxError::Compose(format!(
            "service count must be between 1 and {MAX_SERVICES}"
        )));
    }

    if input.volumes.len() > MAX_VOLUMES {
        return Err(SandboxError::Compose(format!(
            "volume count exceeds {MAX_VOLUMES}"
        )));
    }
    let mut volumes = BTreeMap::new();
    for (name, volume) in input.volumes {
        validate_identifier("volume", &name)?;
        VolumeId::parse(name.clone()).map_err(|error| SandboxError::Compose(error.to_string()))?;
        let snapshot_policy = volume
            .snapshot_policy
            .unwrap_or(match volume.persistence_class {
                VolumePersistenceClass::Persistent => VolumeSnapshotPolicy::Required,
                VolumePersistenceClass::Ephemeral => VolumeSnapshotPolicy::BestEffort,
                VolumePersistenceClass::Artifact | VolumePersistenceClass::Secret => {
                    VolumeSnapshotPolicy::Excluded
                }
            });
        let quota_bytes = match (volume.persistence_class, volume.quota_bytes) {
            (VolumePersistenceClass::Artifact, None) => 0,
            (_, Some(quota)) => quota,
            _ => {
                return Err(SandboxError::Compose(format!(
                    "volume `{name}` requires an explicit quota_bytes"
                )));
            }
        };
        volumes.insert(
            name,
            LockedVolume {
                persistence_class: volume.persistence_class,
                snapshot_policy,
                quota_bytes,
                content_digest: volume.content_digest,
            },
        );
    }

    let network_inputs = if input.networks.is_empty() {
        BTreeMap::from([("default".to_owned(), Default::default())])
    } else {
        input.networks
    };
    if network_inputs.len() > MAX_NETWORKS {
        return Err(SandboxError::Compose(format!(
            "network count exceeds {MAX_NETWORKS}"
        )));
    }
    let mut networks = BTreeMap::new();
    for (network_name, network) in network_inputs {
        validate_identifier("network", &network_name)?;
        if network.internal == Some(false) {
            return Err(SandboxError::Unsupported(format!(
                "network `{network_name}` requests external connectivity"
            )));
        }
        if network
            .driver
            .as_deref()
            .is_some_and(|driver| driver != "bridge")
        {
            return Err(SandboxError::Unsupported(format!(
                "network `{network_name}` does not use the bridge driver"
            )));
        }
        networks.insert(
            network_name,
            LockedNetwork {
                internal: true,
                driver: "bridge".to_owned(),
            },
        );
    }

    let service_names = input.services.keys().cloned().collect::<BTreeSet<_>>();
    let mut services = BTreeMap::new();
    for (service_name, service) in input.services {
        validate_identifier("service", &service_name)?;
        validate_values("command", &service.command, MAX_ARGUMENTS)?;
        validate_values("entrypoint", &service.entrypoint, MAX_ARGUMENTS)?;
        if service.environment.len() > MAX_ENVIRONMENT {
            return Err(SandboxError::Compose(format!(
                "service `{service_name}` has too many environment entries"
            )));
        }
        for (key, value) in &service.environment {
            validate_environment(key, value)?;
        }
        let root_filesystem = if service.read_only == Some(false) {
            RootFilesystemMode::Writable
        } else {
            RootFilesystemMode::ReadOnly
        };
        if service.volumes.len() > 64 {
            return Err(SandboxError::Compose(format!(
                "service `{service_name}` has too many volume mounts"
            )));
        }
        let mut service_volumes = Vec::with_capacity(service.volumes.len());
        let mut volume_destinations = BTreeSet::new();
        for volume in service.volumes {
            let definition = volumes.get(&volume.source).ok_or_else(|| {
                SandboxError::Compose(format!(
                    "service `{service_name}` references unknown volume `{}`",
                    volume.source
                ))
            })?;
            let read_only = match definition.persistence_class {
                VolumePersistenceClass::Artifact | VolumePersistenceClass::Secret => {
                    if volume.read_only == Some(false) {
                        return Err(SandboxError::Compose(format!(
                            "service `{service_name}` requests a writable immutable volume"
                        )));
                    }
                    true
                }
                VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent => {
                    volume.read_only.unwrap_or(false)
                }
            };
            let spec = VolumeSpec {
                schema_version: VOLUME_SPEC_VERSION,
                volume_id: VolumeId::parse(volume.source.clone())
                    .map_err(|error| SandboxError::Compose(error.to_string()))?,
                destination: volume.target,
                read_only,
                persistence_class: definition.persistence_class,
                snapshot_policy: definition.snapshot_policy,
                quota_bytes: definition.quota_bytes,
                content_digest: definition.content_digest.clone(),
            };
            spec.validate()
                .map_err(|error| SandboxError::Compose(error.to_string()))?;
            if !volume_destinations.insert(spec.destination.clone()) {
                return Err(SandboxError::Compose(format!(
                    "service `{service_name}` repeats volume destination `{}`",
                    spec.destination
                )));
            }
            service_volumes.push(spec);
        }
        let user = service.user.unwrap_or_else(|| "65534:65534".to_owned());
        validate_value("user", &user)?;
        let working_dir = service.working_dir.unwrap_or_else(|| "/work".to_owned());
        if !working_dir.starts_with('/') || working_dir.contains("..") {
            return Err(SandboxError::Compose(format!(
                "service `{service_name}` working directory must be an absolute normalized path"
            )));
        }
        validate_value("working directory", &working_dir)?;

        let selected_networks = if service.networks.is_empty() {
            vec!["default".to_owned()]
        } else {
            service.networks
        };
        let mut unique_networks = BTreeSet::new();
        for network in &selected_networks {
            if !networks.contains_key(network) {
                return Err(SandboxError::Compose(format!(
                    "service `{service_name}` references unknown network `{network}`"
                )));
            }
            if !unique_networks.insert(network) {
                return Err(SandboxError::Compose(format!(
                    "service `{service_name}` repeats network `{network}`"
                )));
            }
        }

        let mut dependencies = BTreeMap::new();
        for (dependency, detail) in service.depends_on {
            if dependency == service_name || !service_names.contains(&dependency) {
                return Err(SandboxError::Compose(format!(
                    "service `{service_name}` has invalid dependency `{dependency}`"
                )));
            }
            dependencies.insert(dependency, detail.condition);
        }
        let healthcheck = match service.healthcheck {
            Some(healthcheck) => {
                if healthcheck.test.first().map(String::as_str) != Some("CMD")
                    || healthcheck.test.len() < 2
                {
                    return Err(SandboxError::Unsupported(format!(
                        "service `{service_name}` healthcheck must use exec-form `CMD`"
                    )));
                }
                let command = healthcheck.test.into_iter().skip(1).collect::<Vec<_>>();
                validate_values("healthcheck", &command, MAX_ARGUMENTS)?;
                if healthcheck.interval_ms == 0
                    || healthcheck.interval_ms > 60_000
                    || healthcheck.timeout_ms == 0
                    || healthcheck.timeout_ms > 60_000
                    || healthcheck.retries == 0
                    || healthcheck.retries > 100
                {
                    return Err(SandboxError::Compose(format!(
                        "service `{service_name}` healthcheck bounds are invalid"
                    )));
                }
                Some(LockedHealthcheck {
                    command,
                    interval_ms: healthcheck.interval_ms,
                    timeout_ms: healthcheck.timeout_ms,
                    retries: healthcheck.retries,
                })
            }
            None => None,
        };

        validate_image_reference(&service.image)?;
        services.insert(
            service_name,
            LockedService {
                image: resolve(&service.image)?,
                command: service.command,
                entrypoint: service.entrypoint,
                environment: service.environment,
                depends_on: dependencies,
                healthcheck,
                networks: selected_networks,
                user,
                working_dir,
                root_filesystem,
                volumes: service_volumes,
            },
        );
    }

    for (service_name, service) in &services {
        for (dependency, condition) in &service.depends_on {
            if *condition == DependencyCondition::Healthy
                && services[dependency].healthcheck.is_none()
            {
                return Err(SandboxError::Compose(format!(
                    "service `{service_name}` requires `{dependency}` to be healthy, but it has no healthcheck"
                )));
            }
        }
    }
    let startup_order = startup_order(&services)?;
    let mut lock = TopologyLock {
        schema_version: LOCK_SCHEMA_VERSION,
        topology_digest: String::new(),
        name,
        services,
        networks,
        volumes,
        startup_order,
        policy: SandboxPolicy::default(),
    };
    lock.topology_digest = digest(&lock.digest_input())?;
    Ok(lock)
}

pub fn verify_lock(lock: &TopologyLock) -> Result<(), SandboxError> {
    if lock.schema_version != LOCK_SCHEMA_VERSION {
        return Err(SandboxError::Lock(format!(
            "unsupported schema version {}",
            lock.schema_version
        )));
    }
    let expected = digest(&lock.digest_input())?;
    if lock.topology_digest != expected {
        return Err(SandboxError::Lock(format!(
            "topology digest mismatch: expected {expected}, found {}",
            lock.topology_digest
        )));
    }
    Ok(())
}

fn startup_order(services: &BTreeMap<String, LockedService>) -> Result<Vec<String>, SandboxError> {
    let mut remaining = services
        .iter()
        .map(|(name, service)| {
            (
                name.clone(),
                service.depends_on.keys().cloned().collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut order = Vec::with_capacity(services.len());
    while !remaining.is_empty() {
        let ready = remaining
            .iter()
            .find(|(_, dependencies)| dependencies.is_empty())
            .map(|(name, _)| name.clone())
            .ok_or_else(|| {
                SandboxError::Compose("service dependency graph contains a cycle".to_owned())
            })?;
        remaining.remove(&ready);
        for dependencies in remaining.values_mut() {
            dependencies.remove(&ready);
        }
        order.push(ready);
    }
    Ok(order)
}

fn digest(input: &DigestInput<'_>) -> Result<String, SandboxError> {
    let bytes = serde_json::to_vec(input)
        .map_err(|error| SandboxError::Lock(format!("encode canonical topology: {error}")))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn validate_identifier(kind: &str, value: &str) -> Result<(), SandboxError> {
    if value.is_empty()
        || value.len() > 32
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
        || !value.as_bytes()[0].is_ascii_lowercase()
    {
        return Err(SandboxError::Compose(format!(
            "{kind} `{value}` is not a bounded lowercase identifier"
        )));
    }
    Ok(())
}

fn validate_environment(name: &str, value: &str) -> Result<(), SandboxError> {
    if name.is_empty()
        || name.len() > 256
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || name.as_bytes()[0].is_ascii_digit()
    {
        return Err(SandboxError::Compose(format!(
            "environment name `{name}` is invalid"
        )));
    }
    validate_value("environment value", value)?;
    if value.contains(['\n', '\r']) {
        return Err(SandboxError::Compose(format!(
            "environment value for `{name}` contains a line break"
        )));
    }
    Ok(())
}

fn validate_image_reference(value: &str) -> Result<(), SandboxError> {
    validate_value("image reference", value)?;
    if value.starts_with('-')
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b':' | b'@')
        })
    {
        return Err(SandboxError::Compose(format!(
            "image reference `{value}` has unsupported syntax"
        )));
    }
    Ok(())
}

fn validate_values(kind: &str, values: &[String], maximum: usize) -> Result<(), SandboxError> {
    if values.len() > maximum {
        return Err(SandboxError::Compose(format!("too many {kind} values")));
    }
    for value in values {
        validate_value(kind, value)?;
    }
    Ok(())
}

fn validate_value(kind: &str, value: &str) -> Result<(), SandboxError> {
    if value.is_empty() || value.len() > MAX_VALUE_BYTES || value.contains('\0') {
        return Err(SandboxError::Compose(format!("invalid {kind}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(reference: &str) -> LockedImage {
        let manifest = crate::LockedDescriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
            digest: format!("sha256:{}", "1".repeat(64)),
            size: 1_024,
        };
        let config = crate::LockedDescriptor {
            media_type: "application/vnd.oci.image.config.v1+json".to_owned(),
            digest: format!("sha256:{}", "2".repeat(64)),
            size: 512,
        };
        LockedImage {
            source: reference.to_owned(),
            exact_reference: format!("example/test@{}", manifest.digest),
            image_id: config.digest.clone(),
            index: None,
            manifest,
            config,
            layers: vec![crate::LockedDescriptor {
                media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_owned(),
                digest: format!("sha256:{}", "3".repeat(64)),
                size: 4_096,
            }],
            operating_system: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            variant: None,
        }
    }

    #[test]
    fn compiles_dependency_order_and_stable_digest() {
        let input: ComposeInput = serde_yaml::from_str(
            r#"
name: example
networks:
  private: {}
services:
  server:
    image: example/server:test
    networks: [private]
    healthcheck:
      test: [CMD, /health]
  client:
    image: example/client:test
    networks: [private]
    depends_on:
      server:
        condition: service_healthy
"#,
        )
        .unwrap();
        let lock = compile(input, |reference| Ok(image(reference))).unwrap();
        assert_eq!(lock.startup_order, ["server", "client"]);
        assert!(lock
            .services
            .values()
            .all(|service| service.root_filesystem == RootFilesystemMode::ReadOnly));
        verify_lock(&lock).unwrap();
        assert_eq!(lock.topology_digest, digest(&lock.digest_input()).unwrap());
    }

    #[test]
    fn writable_root_requires_an_explicit_compose_request() {
        let input: ComposeInput = serde_yaml::from_str(
            "name: x\nservices:\n  writable:\n    image: x\n    read_only: false\n  default:\n    image: x\n",
        )
        .unwrap();
        let lock = compile(input, |reference| Ok(image(reference))).unwrap();
        assert_eq!(
            lock.services["writable"].root_filesystem,
            RootFilesystemMode::Writable
        );
        assert_eq!(
            lock.services["default"].root_filesystem,
            RootFilesystemMode::ReadOnly
        );
    }

    #[test]
    fn compiles_typed_named_volumes_without_host_paths() {
        let input: ComposeInput = serde_yaml::from_str(
            r#"
name: x
volumes:
  shared:
    persistence_class: persistent
    quota_bytes: 8388608
services:
  app:
    image: x
    volumes:
      - source: shared
        target: /var/lib/app
"#,
        )
        .expect("compose");
        let lock = compile(input, |reference| Ok(image(reference))).expect("lock");
        let mount = &lock.services["app"].volumes[0];
        assert_eq!(mount.volume_id.as_str(), "shared");
        assert_eq!(mount.destination, "/var/lib/app");
        assert!(!mount.read_only);
        assert_eq!(mount.snapshot_policy, VolumeSnapshotPolicy::Required);
        assert!(serde_json::to_string(&lock)
            .expect("lock json")
            .find("/host")
            .is_none());
        verify_lock(&lock).expect("verified lock");
    }

    #[test]
    fn rejects_bind_mounts_crossing_the_provider_boundary() {
        for source in [
            "name: x\nservices:\n  app:\n    image: x\n    volumes: [/host:/guest]\n",
            "name: x\nvolumes: {}\nservices:\n  app:\n    image: x\n    volumes:\n      - source: /host\n        target: /guest\n",
        ] {
            match serde_yaml::from_str::<ComposeInput>(source) {
                Err(_) => {}
                Ok(input) => assert!(compile(input, |reference| Ok(image(reference))).is_err()),
            }
        }
    }

    #[test]
    fn rejects_ambient_or_privileged_compose_fields() {
        for source in [
            "name: x\nservices:\n  app:\n    image: x\n    privileged: true\n",
            "name: x\nservices:\n  app:\n    image: x\n    volumes: [/host:/guest]\n",
            "name: x\nservices:\n  app:\n    image: x\n    network_mode: host\n",
        ] {
            assert!(serde_yaml::from_str::<ComposeInput>(source).is_err());
        }
    }

    #[test]
    fn rejects_environment_file_injection() {
        let input: ComposeInput = serde_yaml::from_str(
            "name: x\nservices:\n  app:\n    image: x\n    environment:\n      SAFE: |-\n        value\n        INJECTED=bad\n",
        )
        .unwrap();
        assert!(matches!(
            compile(input, |reference| Ok(image(reference))),
            Err(SandboxError::Compose(_))
        ));
    }

    #[test]
    fn rejects_external_network_and_cycles() {
        let external: ComposeInput = serde_yaml::from_str(
            "name: x\nnetworks:\n  default:\n    internal: false\nservices:\n  app:\n    image: x\n",
        )
        .unwrap();
        assert!(matches!(
            compile(external, |reference| Ok(image(reference))),
            Err(SandboxError::Unsupported(_))
        ));

        let cycle: ComposeInput = serde_yaml::from_str(
            "name: x\nservices:\n  a:\n    image: x\n    depends_on:\n      b:\n        condition: service_started\n  b:\n    image: x\n    depends_on:\n      a:\n        condition: service_started\n",
        )
        .unwrap();
        assert!(matches!(
            compile(cycle, |reference| Ok(image(reference))),
            Err(SandboxError::Compose(_))
        ));
    }
}
