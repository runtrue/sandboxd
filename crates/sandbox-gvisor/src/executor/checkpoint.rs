use super::{
    bundle, create_resources, runtime_id, validate_admitted, validate_project, GvisorSandbox,
    GvisorSandboxState, ImmutableRootfs, Resources,
};
use crate::{
    compiler::verify_lock,
    model::TopologyLock,
    snapshot::{self, SnapshotProvenance, SnapshotStaging, SnapshotSummary},
    SandboxError,
};
use runtrue_sandbox_artifact::{ArtifactScope, ArtifactStore};
use runtrue_sandbox_core::{LifecycleState, SnapshotId, SnapshotMode};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[allow(clippy::too_many_arguments)]
pub fn restore_admitted(
    lock: &TopologyLock,
    project: &str,
    timeout: Duration,
    state_root: &Path,
    snapshot_staging_root: &Path,
    artifact_store: &dyn ArtifactStore,
    artifact_scope: &ArtifactScope,
    snapshot_id: &SnapshotId,
    runsc_program: &Path,
    ip_program: &Path,
    admitted: &BTreeMap<String, ImmutableRootfs>,
) -> Result<GvisorSandbox, SandboxError> {
    verify_lock(lock)?;
    validate_project(project)?;
    validate_admitted(lock, admitted)?;
    let restored = snapshot::materialize(
        artifact_store,
        artifact_scope,
        snapshot_id,
        snapshot_staging_root,
    )?;
    let manifest = &restored.manifest;
    let metadata = &restored.metadata;
    if manifest.sandbox_spec_digest != lock.topology_digest
        || manifest.backend.kind != runtrue_sandbox_core::BackendKind::Gvisor
        || manifest.backend.implementation != "runsc"
        || manifest.backend.implementation_version != metadata.runsc_version
        || manifest.backend.configuration_digest != metadata.runtime_configuration_digest
        || manifest.restore_requirements.cpu_features_digest != metadata.cpu_features_digest
        || manifest.mode != metadata.mode
        || manifest.created_unix_millis != metadata.created_unix_millis
        || manifest.restore_requirements.architecture != std::env::consts::ARCH
        || manifest.restore_requirements.operating_system != std::env::consts::OS
        || metadata.topology_digest != lock.topology_digest
        || metadata.services != lock.startup_order
        || metadata.root_service != lock.startup_order[0]
        || metadata.service_states.keys().ne(lock.services.keys())
        || metadata
            .service_states
            .values()
            .any(|state| !matches!(state.as_str(), "running" | "paused" | "stopped"))
    {
        return Err(SandboxError::Runtime(
            "snapshot is incompatible with the requested topology or host".to_owned(),
        ));
    }
    let rootfs_by_image = admitted
        .iter()
        .map(|(id, image)| (id.clone(), image.rootfs().to_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut resources = create_resources(lock, project, state_root, runsc_program, ip_program)?;
    let compatibility = (|| {
        Ok::<_, SandboxError>(
            resources.runsc.version()? == metadata.runsc_version
                && resources.runsc.configuration_digest() == metadata.runtime_configuration_digest
                && resources.runsc.cpu_features_digest()? == metadata.cpu_features_digest,
        )
    })();
    match compatibility {
        Ok(true) => {}
        Ok(false) => {
            cleanup_after_restore_error(
                &mut resources,
                SandboxError::Runtime(
                    "snapshot runtime or CPU compatibility check failed".to_owned(),
                ),
            )?;
        }
        Err(error) => cleanup_after_restore_error(&mut resources, error)?,
    }
    let deadline = Instant::now() + timeout;
    let selected_services = metadata
        .service_states
        .iter()
        .filter(|(service, state)| {
            *service == &metadata.root_service || matches!(state.as_str(), "running" | "paused")
        })
        .map(|(service, _)| service.clone())
        .collect::<BTreeSet<_>>();
    if let Err(error) = restore_services(
        &mut resources,
        lock,
        project,
        deadline,
        &rootfs_by_image,
        &restored.image_path,
        &selected_services,
    ) {
        let cleanup = resources.cleanup();
        return match cleanup {
            Ok(_) => Err(error),
            Err(cleanup_error) => Err(SandboxError::Runtime(format!(
                "restore failed: {error}; cleanup failed: {cleanup_error}"
            ))),
        };
    }
    Ok(GvisorSandbox {
        project: project.to_owned(),
        topology_digest: lock.topology_digest.clone(),
        state: GvisorSandboxState::Running,
        paused_runtime_ids: BTreeSet::new(),
        resources: Some(resources),
        snapshot_restore: Some(super::SnapshotRestoreMetrics {
            transferred_bytes: restored.transferred_bytes,
            materialization_millis: restored.materialization_millis,
        }),
    })
}

pub(super) fn snapshot(
    sandbox: &mut GvisorSandbox,
    snapshot_id: SnapshotId,
    snapshot_staging_root: &Path,
    mode: SnapshotMode,
    artifact_store: &dyn ArtifactStore,
    provenance: &SnapshotProvenance,
) -> Result<SnapshotSummary, SandboxError> {
    if !matches!(
        sandbox.state,
        GvisorSandboxState::Running | GvisorSandboxState::Paused
    ) {
        return Err(SandboxError::Runtime(
            "only a running or paused sandbox can be snapshotted".to_owned(),
        ));
    }
    if sandbox.state == GvisorSandboxState::Paused && mode == SnapshotMode::Live {
        return Err(SandboxError::Runtime(
            "a live snapshot requires a running sandbox".to_owned(),
        ));
    }
    let resources = sandbox.resources.as_mut().ok_or_else(|| {
        SandboxError::Runtime("active sandbox has no runtime resources".to_owned())
    })?;
    let control_id = resources
        .processes
        .values()
        .find(|process| {
            matches!(
                resources.runsc.state(&process.id).as_deref(),
                Ok("running" | "paused")
            )
        })
        .map(|process| process.id.clone())
        .ok_or_else(|| SandboxError::Runtime("sandbox has no checkpointable service".to_owned()))?;
    let captured_from = match sandbox.state {
        GvisorSandboxState::Running => LifecycleState::Running,
        GvisorSandboxState::Paused => LifecycleState::Paused,
        _ => unreachable!("snapshot state was validated"),
    };
    let staging = SnapshotStaging::create(snapshot_staging_root)?;
    let image_path = staging.image_path();
    let runsc_version = resources.runsc.version()?;
    let runtime_configuration_digest = resources.runsc.configuration_digest();
    let cpu_features_digest = resources.runsc.cpu_features_digest()?;
    let service_states = resources
        .service_order
        .iter()
        .map(|service| {
            let state = resources
                .processes
                .get(service)
                .and_then(|process| resources.runsc.state(&process.id).ok())
                .unwrap_or_else(|| "stopped".to_owned());
            (service.clone(), state)
        })
        .collect();
    resources
        .runsc
        .checkpoint(&control_id, image_path, true, Duration::from_secs(60))?;
    let root_service = resources
        .processes
        .iter()
        .find(|(_, process)| process.id == resources.sandbox_runtime_id)
        .map(|(service, _)| service.clone())
        .expect("sandbox runtime belongs to a service");
    let ordered_services = resources.service_order.clone();
    let (publication, metadata) = staging.publication(
        snapshot_id,
        provenance,
        sandbox.topology_digest.clone(),
        mode,
        captured_from,
        runsc_version,
        runtime_configuration_digest,
        cpu_features_digest,
        root_service,
        ordered_services,
        service_states,
    )?;
    let summary = snapshot::publish(artifact_store, publication, &metadata)?;
    if mode == SnapshotMode::StopAndMove {
        let mut resources = sandbox.resources.take().expect("resources still exist");
        resources.cleanup()?;
        sandbox.paused_runtime_ids.clear();
        sandbox.state = GvisorSandboxState::Stopped;
    } else {
        sandbox.state = GvisorSandboxState::Running;
    }
    Ok(summary)
}

fn restore_services(
    resources: &mut Resources,
    lock: &TopologyLock,
    project: &str,
    deadline: Instant,
    rootfs_by_image: &BTreeMap<String, PathBuf>,
    image_path: &Path,
    selected_services: &BTreeSet<String>,
) -> Result<(), SandboxError> {
    let sandbox_runtime_id = resources.sandbox_runtime_id.clone();
    for service_name in &lock.startup_order {
        if !selected_services.contains(service_name) {
            continue;
        }
        let service = &lock.services[service_name];
        let cgroup = resources
            .cgroups
            .as_mut()
            .expect("cgroups exist")
            .create_service(service_name, &lock.policy)?;
        let bundle_path = resources.state.join(format!("bundle-{service_name}"));
        let sandbox_network = resources
            .network
            .as_ref()
            .expect("network exists")
            .sandbox();
        let runtime_id = runtime_id(project, service_name);
        let is_root = runtime_id == sandbox_runtime_id;
        let role = if is_root {
            bundle::ContainerRole::Sandbox
        } else {
            bundle::ContainerRole::Container {
                sandbox_id: &sandbox_runtime_id,
            }
        };
        bundle::write_bundle(
            &bundle_path,
            &rootfs_by_image[&service.image.image_id],
            service_name,
            service,
            &sandbox_network.namespace,
            &sandbox_network.hosts_path,
            &sandbox_network.resolv_path,
            lock.policy.tmpfs_bytes,
            role,
        )?;
        let process = resources.runsc.spawn_restore(
            runtime_id,
            &bundle_path,
            &cgroup,
            lock.policy.maximum_output_bytes,
            image_path,
        )?;
        resources.processes.insert(service_name.clone(), process);
        if is_root {
            resources.runsc.wait_created(
                resources
                    .processes
                    .get_mut(service_name)
                    .expect("root restore process exists"),
                deadline,
            )?;
        }
    }
    for service_name in &lock.startup_order {
        if !selected_services.contains(service_name) {
            continue;
        }
        resources.runsc.wait_restored(
            resources
                .processes
                .get_mut(service_name)
                .expect("restore process exists"),
            deadline,
        )?;
    }
    if !resources
        .processes
        .values()
        .any(|process| matches!(resources.runsc.state(&process.id).as_deref(), Ok("running")))
    {
        return Err(SandboxError::Runtime(
            "restored sandbox has no running services".to_owned(),
        ));
    }
    Ok(())
}

fn cleanup_after_restore_error(
    resources: &mut Resources,
    error: SandboxError,
) -> Result<(), SandboxError> {
    match resources.cleanup() {
        Ok(_) => Err(error),
        Err(cleanup_error) => Err(SandboxError::Runtime(format!(
            "restore preflight failed: {error}; cleanup failed: {cleanup_error}"
        ))),
    }
}
