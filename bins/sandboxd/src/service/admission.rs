use crate::state::DaemonState;
use runtrue_sandbox_core::{SandboxResourceDemand, VolumePersistenceClass};
use runtrue_sandbox_gvisor::executor::ImmutableRootfs;
use runtrue_sandbox_oci::{compiler, model::RootFilesystemMode, SandboxError, TopologyLock};
use std::{collections::BTreeMap, fs, sync::Arc, time::Instant};

pub(super) fn admit_topology(
    daemon: &DaemonState,
    topology: &TopologyLock,
) -> Result<BTreeMap<String, ImmutableRootfs>, SandboxError> {
    compiler::verify_lock(topology)?;
    let demand = resource_demand(topology)?;
    daemon
        .worker
        .resource_shape()
        .require_capacity(&demand)
        .map_err(|error| SandboxError::Unsupported(error.to_string()))?;
    if !daemon
        .guest_profiles
        .iter()
        .any(|profile| profile.identity == topology.policy.guest_profile)
    {
        return Err(SandboxError::Unsupported(format!(
            "guest profile `{}` is not installed on this worker",
            topology.policy.guest_profile.canonical()
        )));
    }
    validate_volume_capabilities(daemon, topology)?;
    let mut result = BTreeMap::new();
    for service in topology.services.values() {
        if result.contains_key(&service.image.image_id) {
            continue;
        }
        let mut cache = daemon.cache.lock().expect("cache lock");
        let admitted = if let Some(image) = cache.get(&service.image.image_id) {
            if image.image().exact_reference != service.image.exact_reference {
                return Err(SandboxError::Lock(
                    "cached image identity conflicts with topology".to_owned(),
                ));
            }
            daemon.counters.lock().expect("counter lock").cache_hits += 1;
            Arc::clone(image)
        } else {
            let started = Instant::now();
            let image = Arc::new(daemon.image_provider.admit(&service.image)?);
            let elapsed = started.elapsed().as_millis();
            let mut counters = daemon.counters.lock().expect("counter lock");
            counters.cache_misses += 1;
            counters.admission_ms += elapsed;
            cache.insert(service.image.image_id.clone(), Arc::clone(&image));
            image
        };
        result.insert(service.image.image_id.clone(), (*admitted).clone());
    }
    validate_volume_destinations(topology, &result)?;
    Ok(result)
}

fn validate_volume_capabilities(
    daemon: &DaemonState,
    topology: &TopologyLock,
) -> Result<(), SandboxError> {
    let capabilities = daemon.volume_provider.capabilities();
    for volume in topology.volumes.values() {
        if !capabilities
            .persistence_classes
            .contains(&volume.persistence_class)
        {
            return Err(SandboxError::Unsupported(format!(
                "volume provider does not support {:?} volumes",
                volume.persistence_class
            )));
        }
        if matches!(
            volume.persistence_class,
            VolumePersistenceClass::Ephemeral | VolumePersistenceClass::Persistent
        ) && volume.snapshot_policy != runtrue_sandbox_core::VolumeSnapshotPolicy::Excluded
            && !capabilities.snapshot
        {
            return Err(SandboxError::Unsupported(
                "named-volume snapshots require CHOWN and DAC_OVERRIDE or idmapped storage"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_volume_destinations(
    topology: &TopologyLock,
    images: &BTreeMap<String, ImmutableRootfs>,
) -> Result<(), SandboxError> {
    for (service_name, service) in &topology.services {
        let rootfs =
            fs::canonicalize(images[&service.image.image_id].rootfs()).map_err(|error| {
                SandboxError::Runtime(format!(
                    "canonicalize admitted root for service `{service_name}`: {error}"
                ))
            })?;
        for volume in &service.volumes {
            let relative = volume.destination.strip_prefix('/').ok_or_else(|| {
                SandboxError::Lock(format!(
                    "volume destination `{}` is not absolute",
                    volume.destination
                ))
            })?;
            let destination = fs::canonicalize(rootfs.join(relative)).map_err(|_| {
                SandboxError::Unsupported(format!(
                    "volume destination `{}` does not exist in the admitted image for service `{service_name}`",
                    volume.destination
                ))
            })?;
            if !destination.starts_with(&rootfs) || !destination.is_dir() {
                return Err(SandboxError::Unsupported(format!(
                    "volume destination `{}` is not a safe directory in the admitted image for service `{service_name}`",
                    volume.destination
                )));
            }
        }
    }
    Ok(())
}

fn resource_demand(topology: &TopologyLock) -> Result<SandboxResourceDemand, SandboxError> {
    let services = u64::try_from(topology.services.len())
        .map_err(|_| SandboxError::Lock("service count cannot be represented".to_owned()))?;
    let services_u16 = u16::try_from(services)
        .map_err(|_| SandboxError::Lock("service count exceeds worker policy".to_owned()))?;
    let cpu_millis = services
        .checked_mul(u64::from(topology.policy.cpu_per_service_millis))
        .ok_or_else(|| SandboxError::Lock("aggregate CPU demand overflow".to_owned()))?;
    let memory_per_service = topology
        .policy
        .memory_bytes_per_service
        .checked_add(topology.policy.tmpfs_bytes)
        .ok_or_else(|| SandboxError::Lock("aggregate memory demand overflow".to_owned()))?;
    let memory_bytes = services
        .checked_mul(memory_per_service)
        .ok_or_else(|| SandboxError::Lock("aggregate memory demand overflow".to_owned()))?;
    let pids = services
        .checked_mul(u64::from(topology.policy.pids_per_service))
        .ok_or_else(|| SandboxError::Lock("aggregate PID demand overflow".to_owned()))?;
    let writable_services = u64::try_from(
        topology
            .services
            .values()
            .filter(|service| service.root_filesystem == RootFilesystemMode::Writable)
            .count(),
    )
    .map_err(|_| SandboxError::Lock("writable service count cannot be represented".to_owned()))?;
    let writable_roots = writable_services
        .checked_mul(topology.policy.writable_root_bytes_per_service)
        .ok_or_else(|| SandboxError::Lock("writable-root demand overflow".to_owned()))?;
    let volume_bytes = topology
        .volumes
        .values()
        .filter(|volume| !matches!(volume.persistence_class, VolumePersistenceClass::Artifact))
        .try_fold(0_u64, |total, volume| {
            total
                .checked_add(volume.quota_bytes)
                .ok_or_else(|| SandboxError::Lock("volume demand overflow".to_owned()))
        })?;
    let output_bytes = u64::try_from(topology.policy.maximum_output_bytes)
        .map_err(|_| SandboxError::Lock("output demand cannot be represented".to_owned()))?;
    let ephemeral_storage_bytes = writable_roots
        .checked_add(volume_bytes)
        .and_then(|total| total.checked_add(output_bytes))
        .ok_or_else(|| SandboxError::Lock("ephemeral-storage demand overflow".to_owned()))?;
    Ok(SandboxResourceDemand {
        services: services_u16,
        cpu_millis,
        memory_bytes,
        pids,
        ephemeral_storage_bytes,
    })
}
