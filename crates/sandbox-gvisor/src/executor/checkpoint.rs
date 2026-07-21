use super::{
    bundle, create_resources, process::Runsc, runtime_id, validate_admitted, validate_project,
    GvisorSandbox, GvisorSandboxState, ImmutableRootfs, Resources,
};
use crate::{
    compiler::verify_lock,
    model::TopologyLock,
    snapshot::{self, SnapshotProvenance, SnapshotStaging, SnapshotSummary},
    SandboxError,
};
use runtrue_sandbox_artifact::{ArtifactScope, ArtifactStore};
use runtrue_sandbox_core::{LifecycleState, RestoreTarget, SnapshotId, SnapshotMode};
use runtrue_sandbox_oci::provider::ImageProvider;
use runtrue_sandbox_oci::RootFilesystemMode;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
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
    restore_target: &RestoreTarget,
    runsc_program: &Path,
    ip_program: &Path,
    nft_program: &Path,
    admitted: &BTreeMap<String, ImmutableRootfs>,
    rootfs_provider: Arc<dyn ImageProvider>,
) -> Result<GvisorSandbox, SandboxError> {
    let restore_started = Instant::now();
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
    let expected_writable_services = lock
        .services
        .iter()
        .filter(|(_, service)| service.root_filesystem == RootFilesystemMode::Writable)
        .map(|(service, _)| (service.clone(), lock.policy.writable_root_bytes_per_service))
        .collect::<BTreeMap<_, _>>();
    let expected_guest_profile = lock.policy.guest_profile.clone();
    let cohort_started = Instant::now();
    manifest
        .validate_restore_target(restore_target)
        .map_err(|error| SandboxError::Runtime(error.to_string()))?;
    if manifest.sandbox_spec_digest != lock.topology_digest
        || manifest.backend.kind != runtrue_sandbox_core::BackendKind::Gvisor
        || manifest.backend.implementation != "runsc"
        || manifest.backend.state_format_version != 1
        || manifest.backend.implementation_version != metadata.runsc_version
        || manifest.backend.configuration_digest != metadata.runtime_configuration_digest
        || manifest.restore_requirements.minimum_backend_version != metadata.runsc_version
        || manifest.restore_requirements.cpu_features_digest != metadata.cpu_features_digest
        || !manifest
            .restore_requirements
            .required_cpu_features
            .is_empty()
        || !manifest.restore_requirements.preserves_internal_connections
        || manifest.restore_requirements.guest_profile != expected_guest_profile
        || manifest.mode != metadata.mode
        || manifest.created_unix_millis != metadata.created_unix_millis
        || manifest.restore_requirements.architecture != std::env::consts::ARCH
        || manifest.restore_requirements.operating_system != std::env::consts::OS
        || metadata.topology_digest != lock.topology_digest
        || metadata.services != lock.startup_order
        || metadata.root_service != lock.startup_order[0]
        || metadata.service_states.keys().ne(lock.services.keys())
        || metadata.writable_services != expected_writable_services
        || metadata.guest_profile != lock.policy.guest_profile
        || metadata
            .service_states
            .values()
            .any(|state| !matches!(state.as_str(), "running" | "paused" | "stopped"))
    {
        return Err(SandboxError::Runtime(
            "snapshot is incompatible with the requested topology or host".to_owned(),
        ));
    }
    let preflight = tempfile::Builder::new()
        .prefix("restore-cohort-")
        .tempdir_in(snapshot_staging_root)
        .map_err(|error| crate::io_error(snapshot_staging_root, error))?;
    let preflight_runsc = Runsc::new(runsc_program, &preflight.path().join("runsc"))?;
    if preflight_runsc.version()? != metadata.runsc_version
        || preflight_runsc.configuration_digest() != metadata.runtime_configuration_digest
        || preflight_runsc.cpu_features_digest()? != metadata.cpu_features_digest
    {
        return Err(SandboxError::Runtime(
            "snapshot runtime or CPU compatibility check failed".to_owned(),
        ));
    }
    let mut transfer_claim_millis = 0;
    if manifest.source_worker != restore_target.worker_id {
        let claim_started = Instant::now();
        artifact_store
            .claim_transfer(artifact_scope, snapshot_id, restore_target)
            .map_err(|error| SandboxError::Runtime(format!("claim snapshot transfer: {error}")))?;
        transfer_claim_millis = claim_started.elapsed().as_millis();
    }
    let cohort_check_millis = cohort_started.elapsed().as_millis();
    let runtime_started = Instant::now();
    let mut resources = create_resources(
        lock,
        project,
        state_root,
        runsc_program,
        ip_program,
        nft_program,
        admitted,
        rootfs_provider,
        Some(&restored.writable_diffs),
    )?;
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
    let runtime_restore_millis = runtime_started.elapsed().as_millis();
    Ok(GvisorSandbox {
        project: project.to_owned(),
        topology_digest: lock.topology_digest.clone(),
        guest_profile: lock.policy.guest_profile.clone(),
        state: GvisorSandboxState::Running,
        paused_runtime_ids: BTreeSet::new(),
        resources: Some(resources),
        snapshot_restore: Some(super::SnapshotRestoreMetrics {
            transferred_bytes: restored.transferred_bytes,
            materialization_millis: restored.materialization_millis,
            cohort_check_millis,
            transfer_claim_millis,
            runtime_restore_millis,
            total_restore_millis: restore_started.elapsed().as_millis(),
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
    let resources = sandbox.resources.as_ref().ok_or_else(|| {
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
        .collect::<BTreeMap<_, _>>();
    let has_writable_rootfs = resources
        .service_rootfs
        .values()
        .any(|rootfs| rootfs.writable.is_some());
    let internally_paused = has_writable_rootfs && sandbox.state == GvisorSandboxState::Running;
    if internally_paused {
        sandbox.pause()?;
    }
    let staged = (|| {
        let resources = sandbox.resources.as_ref().ok_or_else(|| {
            SandboxError::Runtime("active sandbox has no runtime resources".to_owned())
        })?;
        let staging = SnapshotStaging::create(snapshot_staging_root)?;
        let image_path = staging.image_path();
        let runsc_version = resources.runsc.version()?;
        let runtime_configuration_digest = resources.runsc.configuration_digest();
        let cpu_features_digest = resources.runsc.cpu_features_digest()?;
        let checkpoint_started = Instant::now();
        resources
            .runsc
            .checkpoint(&control_id, image_path, true, Duration::from_secs(60))?;
        let checkpoint_millis = checkpoint_started.elapsed().as_millis();
        let writable_started = Instant::now();
        let mut writable_objects = Vec::new();
        let mut writable_services = BTreeMap::new();
        for (service, rootfs) in &resources.service_rootfs {
            let Some(writable) = &rootfs.writable else {
                continue;
            };
            let (object, _) = staging.stage_writable_rootfs(
                service,
                resources.rootfs_provider.as_ref(),
                writable,
            )?;
            writable_services.insert(service.clone(), writable.quota_bytes());
            writable_objects.push(object);
        }
        let writable_export_millis = writable_started.elapsed().as_millis();
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
            sandbox.guest_profile.clone(),
            service_states,
            writable_services,
            writable_objects,
        )?;
        Ok::<_, SandboxError>((
            staging,
            publication,
            metadata,
            checkpoint_millis,
            writable_export_millis,
        ))
    })();
    let (staging, publication, metadata, checkpoint_millis, writable_export_millis) = match staged {
        Ok(staged) => staged,
        Err(error) => return resume_after_snapshot_error(sandbox, internally_paused, error),
    };
    if internally_paused && mode == SnapshotMode::Live {
        sandbox.resume()?;
    }
    let published = snapshot::publish(artifact_store, publication, &metadata);
    drop(staging);
    let mut summary = match published {
        Ok(summary) => summary,
        Err(error) => return resume_after_snapshot_error(sandbox, internally_paused, error),
    };
    summary.checkpoint_millis = checkpoint_millis;
    summary.writable_export_millis = writable_export_millis;
    if mode == SnapshotMode::StopAndMove {
        let cleanup_started = Instant::now();
        let mut resources = sandbox.resources.take().expect("resources still exist");
        resources.cleanup()?;
        summary.source_cleanup_millis = cleanup_started.elapsed().as_millis();
        sandbox.paused_runtime_ids.clear();
        sandbox.state = GvisorSandboxState::Stopped;
    }
    Ok(summary)
}

fn resume_after_snapshot_error<T>(
    sandbox: &mut GvisorSandbox,
    internally_paused: bool,
    error: SandboxError,
) -> Result<T, SandboxError> {
    if internally_paused && sandbox.state == GvisorSandboxState::Paused {
        if let Err(resume_error) = sandbox.resume() {
            return Err(SandboxError::Runtime(format!(
                "snapshot failed: {error}; resume failed: {resume_error}"
            )));
        }
    }
    Err(error)
}

fn restore_services(
    resources: &mut Resources,
    lock: &TopologyLock,
    project: &str,
    deadline: Instant,
    image_path: &Path,
    selected_services: &BTreeSet<String>,
) -> Result<(), SandboxError> {
    let guest_profile = super::reviewed_guest_profile(lock)?;
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
            &resources.service_rootfs[service_name].path,
            resources.service_rootfs[service_name].read_only,
            service_name,
            service,
            &guest_profile,
            &sandbox_network.namespace,
            &sandbox_network.hosts_path,
            &sandbox_network.resolv_path,
            sandbox_network.http_proxy.as_deref(),
            sandbox_network.no_proxy.as_deref(),
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
