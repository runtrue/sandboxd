mod bundle;
mod cgroup;
mod checkpoint;
mod network;
mod process;
mod proxy;
mod recovery;

pub use checkpoint::restore_admitted;
pub use proxy::IngressEndpoint;
pub use recovery::{recover, RecoveryReport};
pub use runtrue_sandbox_oci::provider::ImmutableRootfs;

use crate::{
    compiler::verify_lock,
    error::io_error,
    model::{DependencyCondition, TopologyLock},
    snapshot::SnapshotSummary,
    SandboxError,
};
use cgroup::{CgroupMetrics, CgroupSet};
use network::ProjectNetwork;
use process::{Runsc, ServiceProcess};
use runtrue_sandbox_core::{
    ContainerId, GuestProfile, GuestProfileIdentity, SandboxId, SnapshotId, SnapshotMode, VolumeId,
};
use runtrue_sandbox_oci::{
    provider::{ImageProvider, WritableRootfs, WritableRootfsIdentity},
    RootFilesystemMode,
};
use runtrue_sandbox_volume::{
    AttachmentOwner, MountedVolume, VolumeHandle, VolumeProvider, VolumeScope, VolumeSnapshot,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Debug, Serialize)]
pub struct GvisorRunResult {
    topology_digest: String,
    project: String,
    profile: String,
    services: usize,
    networks: usize,
    preflight_ms: u128,
    infrastructure_ms: u128,
    startup_ms: u128,
    completion_ms: u128,
    total_ms: u128,
    cleanup_ms: u128,
    wait_service: String,
    wait_exit_code: i32,
    stdout: String,
    stderr: String,
    output_truncated: bool,
    image_integrity_verified: bool,
    cleanup_verified: bool,
    host_task_limit: u32,
    cgroups: BTreeMap<String, CgroupMetrics>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    #[default]
    Private,
    Loopback,
    Userspace,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupMode {
    #[default]
    Managed,
    External,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExecutorConfiguration {
    pub network_mode: NetworkMode,
    pub cgroup_mode: CgroupMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GvisorSandboxState {
    Running,
    Paused,
    Stopped,
    Failed,
}

#[derive(Debug, Serialize)]
pub struct GvisorSandboxStatus {
    pub project: String,
    pub topology_digest: String,
    pub state: GvisorSandboxState,
    pub running_services: usize,
    pub paused_services: usize,
    pub stopped_services: usize,
    pub ingress_endpoints: Vec<IngressEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_restore: Option<SnapshotRestoreMetrics>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotRestoreMetrics {
    pub transferred_bytes: u64,
    pub materialization_millis: u128,
    pub cohort_check_millis: u128,
    pub transfer_claim_millis: u128,
    pub runtime_restore_millis: u128,
    pub total_restore_millis: u128,
}

#[derive(Debug, Serialize)]
pub struct ServiceOutput {
    pub service: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

pub struct GvisorSandbox {
    project: String,
    topology_digest: String,
    guest_profile: GuestProfileIdentity,
    state: GvisorSandboxState,
    paused_runtime_ids: BTreeSet<String>,
    resources: Option<Resources>,
    snapshot_restore: Option<SnapshotRestoreMetrics>,
}

struct Resources {
    state: PathBuf,
    runsc: Runsc,
    sandbox_runtime_id: String,
    service_order: Vec<String>,
    cgroups: Option<CgroupSet>,
    network: Option<ProjectNetwork>,
    processes: BTreeMap<String, ServiceProcess>,
    rootfs_provider: Arc<dyn ImageProvider>,
    service_rootfs: BTreeMap<String, ServiceRootfs>,
    volume_provider: Arc<dyn VolumeProvider>,
    service_volumes: BTreeMap<String, Vec<MountedVolume>>,
}

struct ServiceRootfs {
    path: PathBuf,
    read_only: bool,
    writable: Option<WritableRootfs>,
    restore_diff: Option<PathBuf>,
}

struct ExecutionOutput {
    startup_ms: u128,
    wait_exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
}

type RestoredVolumes = BTreeMap<VolumeId, (VolumeSnapshot, PathBuf)>;

#[allow(clippy::too_many_arguments)]
pub fn run_admitted(
    lock: &TopologyLock,
    project: &str,
    wait_for: &str,
    timeout: Duration,
    state_root: &Path,
    runsc_program: &Path,
    ip_program: &Path,
    nft_program: &Path,
    admitted: &BTreeMap<String, ImmutableRootfs>,
    rootfs_provider: Arc<dyn ImageProvider>,
    volume_scope: &VolumeScope,
    volume_provider: Arc<dyn VolumeProvider>,
    configuration: ExecutorConfiguration,
) -> Result<GvisorRunResult, SandboxError> {
    let overall_started = Instant::now();
    verify_lock(lock)?;
    validate_project(project)?;
    if !lock.services.contains_key(wait_for) {
        return Err(SandboxError::Lock(format!(
            "wait service `{wait_for}` is absent"
        )));
    }
    validate_admitted(lock, admitted)?;
    let preflight_ms = overall_started.elapsed().as_millis();
    run_admitted_inner(
        lock,
        project,
        wait_for,
        timeout,
        state_root,
        runsc_program,
        ip_program,
        nft_program,
        admitted,
        rootfs_provider,
        volume_scope,
        volume_provider,
        configuration,
        preflight_ms,
        overall_started,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_admitted_inner(
    lock: &TopologyLock,
    project: &str,
    wait_for: &str,
    timeout: Duration,
    state_root: &Path,
    runsc_program: &Path,
    ip_program: &Path,
    nft_program: &Path,
    admitted: &BTreeMap<String, ImmutableRootfs>,
    rootfs_provider: Arc<dyn ImageProvider>,
    volume_scope: &VolumeScope,
    volume_provider: Arc<dyn VolumeProvider>,
    configuration: ExecutorConfiguration,
    preflight_ms: u128,
    overall_started: Instant,
) -> Result<GvisorRunResult, SandboxError> {
    let infrastructure_started = Instant::now();
    let mut resources = create_resources(
        lock,
        project,
        state_root,
        runsc_program,
        ip_program,
        nft_program,
        admitted,
        rootfs_provider,
        volume_scope,
        volume_provider,
        configuration,
        None,
        None,
    )?;
    let infrastructure_ms = infrastructure_started.elapsed().as_millis();
    let started = Instant::now();
    let deadline = started + timeout;
    let execution = execute(&mut resources, lock, project, wait_for, deadline);
    let cleanup_started = Instant::now();
    let cleanup = resources.cleanup();
    let cleanup_ms = cleanup_started.elapsed().as_millis();
    match (execution, cleanup) {
        (Ok(output), Ok(metrics)) => Ok(GvisorRunResult {
            topology_digest: lock.topology_digest.clone(),
            project: project.to_owned(),
            profile: "gvisor".to_owned(),
            services: lock.services.len(),
            networks: lock.networks.len(),
            preflight_ms,
            infrastructure_ms,
            startup_ms: output.startup_ms,
            completion_ms: started.elapsed().as_millis(),
            total_ms: overall_started.elapsed().as_millis(),
            cleanup_ms,
            wait_service: wait_for.to_owned(),
            wait_exit_code: output.wait_exit_code,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            output_truncated: output.truncated,
            image_integrity_verified: true,
            cleanup_verified: true,
            host_task_limit: lock.policy.pids_per_service,
            cgroups: metrics,
        }),
        (Err(error), Ok(metrics)) => Err(SandboxError::Runtime(format!(
            "{error}; cgroups={}",
            serde_json::to_string(&metrics).unwrap_or_else(|_| "<encoding failed>".to_owned())
        ))),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(SandboxError::Docker(format!(
            "direct execution failed: {error}; cleanup also failed: {cleanup_error}"
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn start_admitted(
    lock: &TopologyLock,
    project: &str,
    timeout: Duration,
    state_root: &Path,
    runsc_program: &Path,
    ip_program: &Path,
    nft_program: &Path,
    admitted: &BTreeMap<String, ImmutableRootfs>,
    rootfs_provider: Arc<dyn ImageProvider>,
    volume_scope: &VolumeScope,
    volume_provider: Arc<dyn VolumeProvider>,
    configuration: ExecutorConfiguration,
) -> Result<GvisorSandbox, SandboxError> {
    verify_lock(lock)?;
    validate_project(project)?;
    validate_admitted(lock, admitted)?;
    let mut resources = create_resources(
        lock,
        project,
        state_root,
        runsc_program,
        ip_program,
        nft_program,
        admitted,
        rootfs_provider,
        volume_scope,
        volume_provider,
        configuration,
        None,
        None,
    )?;
    let deadline = Instant::now() + timeout;
    if let Err(error) = start_services(&mut resources, lock, project, deadline) {
        let cleanup = resources.cleanup();
        return match cleanup {
            Ok(_) => Err(error),
            Err(cleanup_error) => Err(SandboxError::Runtime(format!(
                "startup failed: {error}; cleanup failed: {cleanup_error}"
            ))),
        };
    }
    Ok(GvisorSandbox {
        project: project.to_owned(),
        topology_digest: lock.topology_digest.clone(),
        guest_profile: lock.policy.guest_profile.clone(),
        state: GvisorSandboxState::Running,
        paused_runtime_ids: BTreeSet::new(),
        resources: Some(resources),
        snapshot_restore: None,
    })
}

fn validate_admitted(
    lock: &TopologyLock,
    admitted: &BTreeMap<String, ImmutableRootfs>,
) -> Result<(), SandboxError> {
    for service in lock.services.values() {
        let image = admitted.get(&service.image.image_id).ok_or_else(|| {
            SandboxError::Lock(format!(
                "image `{}` was not admitted by sandboxd",
                service.image.image_id
            ))
        })?;
        if image.image().exact_reference != service.image.exact_reference
            || image.image().image_id != service.image.image_id
            || !image.rootfs().is_dir()
        {
            return Err(SandboxError::Lock(
                "cached image handle does not match the topology".to_owned(),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_resources(
    lock: &TopologyLock,
    project: &str,
    state_root: &Path,
    runsc_program: &Path,
    ip_program: &Path,
    nft_program: &Path,
    admitted: &BTreeMap<String, ImmutableRootfs>,
    rootfs_provider: Arc<dyn ImageProvider>,
    volume_scope: &VolumeScope,
    volume_provider: Arc<dyn VolumeProvider>,
    configuration: ExecutorConfiguration,
    writable_diffs: Option<&BTreeMap<String, PathBuf>>,
    volume_snapshots: Option<&RestoredVolumes>,
) -> Result<Resources, SandboxError> {
    let state = prepare_state(state_root, project)?;
    if let Err(error) = recovery::write_recovery_record(&state, project, lock, configuration) {
        let _ = fs::remove_dir_all(&state);
        return Err(error);
    }
    let cgroups = if configuration.cgroup_mode == CgroupMode::External {
        None
    } else {
        match CgroupSet::create(project) {
            Ok(cgroups) => Some(cgroups),
            Err(error) => {
                let _ = fs::remove_dir_all(&state);
                return Err(error);
            }
        }
    };
    let network = match ProjectNetwork::create(
        ip_program,
        nft_program,
        project,
        lock,
        &state,
        configuration,
    ) {
        Ok(network) => network,
        Err(error) => {
            if let Some(cgroups) = cgroups {
                let _ = cgroups.cleanup();
            }
            let _ = fs::remove_dir_all(&state);
            return Err(error);
        }
    };
    let has_writable_rootfs = lock
        .services
        .values()
        .any(|service| service.root_filesystem == RootFilesystemMode::Writable);
    let overlay = has_writable_rootfs.then(|| {
        (
            state.join("rootfs-overlay"),
            lock.policy.writable_root_bytes_per_service,
        )
    });
    let runsc = match Runsc::new(
        runsc_program,
        &state.join("runsc"),
        configuration.network_mode,
        overlay
            .as_ref()
            .map(|(directory, maximum_bytes)| (directory.as_path(), *maximum_bytes)),
    ) {
        Ok(runsc) => runsc,
        Err(error) => {
            let mut network = network;
            let _ = network.cleanup();
            if let Some(cgroups) = cgroups {
                let _ = cgroups.cleanup();
            }
            let _ = fs::remove_dir_all(&state);
            return Err(error);
        }
    };
    let mut resources = Resources {
        state,
        runsc,
        sandbox_runtime_id: runtime_id(project, &lock.startup_order[0]),
        service_order: lock.startup_order.clone(),
        cgroups,
        network: Some(network),
        processes: BTreeMap::new(),
        rootfs_provider,
        service_rootfs: BTreeMap::new(),
        volume_provider,
        service_volumes: BTreeMap::new(),
    };
    if let Err(error) = resources.prepare_service_rootfs(lock, project, admitted, writable_diffs) {
        return match resources.cleanup() {
            Ok(_) => Err(error),
            Err(cleanup_error) => Err(SandboxError::Runtime(format!(
                "prepare writable roots failed: {error}; cleanup failed: {cleanup_error}"
            ))),
        };
    }
    if let Err(error) = resources.prepare_volumes(lock, project, volume_scope, volume_snapshots) {
        return match resources.cleanup() {
            Ok(_) => Err(error),
            Err(cleanup_error) => Err(SandboxError::Runtime(format!(
                "prepare volumes failed: {error}; cleanup failed: {cleanup_error}"
            ))),
        };
    }
    let writable_recovery = resources
        .service_rootfs
        .iter()
        .filter_map(|(service, rootfs)| {
            rootfs
                .writable
                .as_ref()
                .map(|writable| recovery::WritableRootfsRecovery {
                    service: service.clone(),
                    provider: writable.provider_id().to_owned(),
                    key: writable.key().to_owned(),
                    quota_bytes: writable.quota_bytes(),
                })
        })
        .collect();
    if let Err(error) = recovery::write_writable_rootfs(&resources.state, writable_recovery) {
        return match resources.cleanup() {
            Ok(_) => Err(error),
            Err(cleanup_error) => Err(SandboxError::Runtime(format!(
                "record writable roots failed: {error}; cleanup failed: {cleanup_error}"
            ))),
        };
    }
    Ok(resources)
}

fn execute(
    resources: &mut Resources,
    lock: &TopologyLock,
    project: &str,
    wait_for: &str,
    deadline: Instant,
) -> Result<ExecutionOutput, SandboxError> {
    let startup_ms = start_services(resources, lock, project, deadline)?;
    let wait_process = resources
        .processes
        .get_mut(wait_for)
        .expect("wait service was started");
    let status = wait_process.wait_until(deadline)?;
    let code = status.code().unwrap_or(255);
    let captured = wait_process.finish_capture()?;
    let stdout = captured.stdout.clone();
    let stderr = captured.stderr.clone();
    let truncated = captured.truncated;
    if !status.success() {
        return Err(SandboxError::Docker(format!(
            "wait service `{wait_for}` exited {code}: {}",
            String::from_utf8_lossy(&stderr).trim()
        )));
    }
    Ok(ExecutionOutput {
        startup_ms,
        wait_exit_code: code,
        stdout,
        stderr,
        truncated,
    })
}

fn start_services(
    resources: &mut Resources,
    lock: &TopologyLock,
    project: &str,
    deadline: Instant,
) -> Result<u128, SandboxError> {
    let guest_profile = reviewed_guest_profile(lock)?;
    let startup = Instant::now();
    let sandbox_runtime_id = resources.sandbox_runtime_id.clone();
    for service_name in &lock.startup_order {
        let service = &lock.services[service_name];
        for (dependency, condition) in &service.depends_on {
            if *condition == DependencyCondition::CompletedSuccessfully {
                let dependency_process =
                    resources.processes.get_mut(dependency).ok_or_else(|| {
                        SandboxError::Docker(format!("dependency `{dependency}` was not started"))
                    })?;
                let status = dependency_process.wait_until(deadline)?;
                if !status.success() {
                    return Err(SandboxError::Docker(format!(
                        "dependency `{dependency}` exited {:?}",
                        status.code()
                    )));
                }
            }
        }
        let cgroup = match resources.cgroups.as_mut() {
            Some(cgroups) => cgroups.create_service(service_name, &lock.policy)?,
            None => PathBuf::new(),
        };
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
            resources.service_rootfs[service_name]
                .restore_diff
                .as_deref()
                .zip(
                    resources.service_rootfs[service_name]
                        .writable
                        .as_ref()
                        .map(|rootfs| rootfs.quota_bytes().saturating_mul(2)),
                ),
            service_name,
            service,
            &guest_profile,
            &sandbox_network.namespace,
            &sandbox_network.hosts_path,
            &sandbox_network.resolv_path,
            sandbox_network.http_proxy.as_deref(),
            sandbox_network.no_proxy.as_deref(),
            sandbox_network.userspace_socket.as_deref(),
            lock.policy.tmpfs_bytes,
            lock.policy.pids_per_service,
            &resources.service_volumes[service_name],
            role,
        )?;
        let process = resources.runsc.spawn(
            runtime_id,
            &bundle_path,
            &cgroup,
            lock.policy.maximum_output_bytes,
        )?;
        resources.processes.insert(service_name.clone(), process);
        resources.runsc.wait_running(
            resources
                .processes
                .get_mut(service_name)
                .expect("process was inserted"),
            deadline,
        )?;
        if let Some(healthcheck) = &service.healthcheck {
            let mut healthy = false;
            for _ in 0..healthcheck.retries {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let health_user = format!(
                    "{}:{}",
                    guest_profile.restrictions.uid, guest_profile.restrictions.gid
                );
                if resources.runsc.health(
                    &resources.processes[service_name].id,
                    &health_user,
                    &healthcheck.command,
                    remaining.min(Duration::from_millis(healthcheck.timeout_ms)),
                )? {
                    healthy = true;
                    break;
                }
                let process = resources
                    .processes
                    .get_mut(service_name)
                    .expect("service process exists");
                if let Some(status) = process.poll()? {
                    let output = process.finish_capture()?;
                    return Err(SandboxError::Runtime(format!(
                        "service `{service_name}` exited {:?} before becoming healthy: {}",
                        status.code(),
                        String::from_utf8_lossy(&output.stderr).trim()
                    )));
                }
                std::thread::sleep(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(healthcheck.interval_ms)),
                );
            }
            if !healthy {
                return Err(SandboxError::Timeout(format!(
                    "service `{service_name}` did not become healthy"
                )));
            }
        }
    }
    Ok(startup.elapsed().as_millis())
}

fn reviewed_guest_profile(lock: &TopologyLock) -> Result<GuestProfile, SandboxError> {
    GuestProfile::reviewed(&lock.policy.guest_profile).ok_or_else(|| {
        SandboxError::Unsupported(format!(
            "guest profile `{}` is not reviewed by this worker build",
            lock.policy.guest_profile.canonical()
        ))
    })
}

impl Resources {
    fn prepare_volumes(
        &mut self,
        lock: &TopologyLock,
        project: &str,
        scope: &VolumeScope,
        snapshots: Option<&RestoredVolumes>,
    ) -> Result<(), SandboxError> {
        prepare_service_volumes(
            self.volume_provider.as_ref(),
            &mut self.service_volumes,
            lock,
            project,
            scope,
            snapshots,
        )
    }

    fn prepare_service_rootfs(
        &mut self,
        lock: &TopologyLock,
        project: &str,
        admitted: &BTreeMap<String, ImmutableRootfs>,
        writable_diffs: Option<&BTreeMap<String, PathBuf>>,
    ) -> Result<(), SandboxError> {
        if let Some(diffs) = writable_diffs {
            let expected = lock
                .services
                .iter()
                .filter(|(_, service)| service.root_filesystem == RootFilesystemMode::Writable)
                .map(|(service, _)| service)
                .collect::<BTreeSet<_>>();
            if expected != diffs.keys().collect::<BTreeSet<_>>() {
                return Err(SandboxError::Runtime(
                    "writable rootfs diffs do not match the restore topology".to_owned(),
                ));
            }
        }
        for service_name in &lock.startup_order {
            let service = &lock.services[service_name];
            let immutable = &admitted[&service.image.image_id];
            let rootfs = match service.root_filesystem {
                RootFilesystemMode::ReadOnly => ServiceRootfs {
                    path: immutable.rootfs().to_owned(),
                    read_only: true,
                    writable: None,
                    restore_diff: None,
                },
                RootFilesystemMode::Writable => {
                    let identity = WritableRootfsIdentity::new(project, service_name)?;
                    let writable = if let Some(diff) =
                        writable_diffs.and_then(|diffs| diffs.get(service_name))
                    {
                        self.rootfs_provider.restore_writable_rootfs(
                            immutable,
                            identity,
                            lock.policy.writable_root_bytes_per_service,
                            diff,
                        )?
                    } else {
                        self.rootfs_provider.create_writable_rootfs(
                            immutable,
                            identity,
                            lock.policy.writable_root_bytes_per_service,
                        )?
                    };
                    ServiceRootfs {
                        path: writable.rootfs().to_owned(),
                        read_only: false,
                        writable: Some(writable),
                        restore_diff: writable_diffs
                            .and_then(|diffs| diffs.get(service_name))
                            .cloned(),
                    }
                }
            };
            self.service_rootfs.insert(service_name.clone(), rootfs);
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<BTreeMap<String, CgroupMetrics>, SandboxError> {
        let mut first_error = None;
        let mut services = self.processes.keys().cloned().collect::<Vec<_>>();
        services.sort_by_key(|service| self.processes[service].id == self.sandbox_runtime_id);
        let runtime_ids = services
            .iter()
            .map(|service| self.processes[service].id.clone())
            .filter(|id| self.runsc.state(id).is_ok())
            .collect::<Vec<_>>();
        if let Err(error) = self.runsc.teardown(&runtime_ids, &self.sandbox_runtime_id) {
            first_error.get_or_insert(error);
        }
        for service in &services {
            let process = self.processes.get_mut(service).expect("service exists");
            process.reap();
        }
        self.processes.clear();
        if let Err(error) =
            cleanup_service_volumes(self.volume_provider.as_ref(), &mut self.service_volumes)
        {
            first_error.get_or_insert(error);
        }
        for (_, rootfs) in std::mem::take(&mut self.service_rootfs) {
            if let Some(writable) = rootfs.writable {
                if let Err(error) = self.rootfs_provider.release_writable_rootfs(&writable) {
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Some(network) = &mut self.network {
            if let Err(error) = network.cleanup() {
                first_error.get_or_insert(error);
            }
        }
        self.network = None;
        let metrics = match self.cgroups.take() {
            Some(cgroups) => match cgroups.cleanup() {
                Ok(metrics) => metrics,
                Err(error) => {
                    first_error.get_or_insert(error);
                    BTreeMap::new()
                }
            },
            None => BTreeMap::new(),
        };
        if first_error.is_none() {
            if let Err(source) = fs::remove_dir_all(&self.state) {
                first_error.get_or_insert_with(|| io_error(&self.state, source));
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(metrics),
        }
    }
}

fn prepare_service_volumes(
    volume_provider: &dyn VolumeProvider,
    service_volumes: &mut BTreeMap<String, Vec<MountedVolume>>,
    lock: &TopologyLock,
    project: &str,
    scope: &VolumeScope,
    snapshots: Option<&RestoredVolumes>,
) -> Result<(), SandboxError> {
    let preparation = prepare_service_volumes_inner(
        volume_provider,
        service_volumes,
        lock,
        project,
        scope,
        snapshots,
    );
    match preparation {
        Ok(()) => Ok(()),
        Err(error) => match cleanup_service_volumes(volume_provider, service_volumes) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(SandboxError::Runtime(format!(
                "prepare volumes failed: {error}; cleanup failed: {cleanup_error}"
            ))),
        },
    }
}

fn prepare_service_volumes_inner(
    volume_provider: &dyn VolumeProvider,
    service_volumes: &mut BTreeMap<String, Vec<MountedVolume>>,
    lock: &TopologyLock,
    project: &str,
    scope: &VolumeScope,
    snapshots: Option<&RestoredVolumes>,
) -> Result<(), SandboxError> {
    let sandbox_id = SandboxId::parse(project.to_owned())
        .map_err(|error| SandboxError::Runtime(error.to_string()))?;
    let mut handles = BTreeMap::<VolumeId, VolumeHandle>::new();
    let expected_snapshots = lock
        .services
        .values()
        .flat_map(|service| service.volumes.iter())
        .filter(|volume| {
            matches!(
                volume.persistence_class,
                runtrue_sandbox_core::VolumePersistenceClass::Ephemeral
                    | runtrue_sandbox_core::VolumePersistenceClass::Persistent
            ) && volume.snapshot_policy != runtrue_sandbox_core::VolumeSnapshotPolicy::Excluded
        })
        .map(|volume| &volume.volume_id)
        .collect::<BTreeSet<_>>();
    if let Some(snapshots) = snapshots {
        if snapshots.keys().collect::<BTreeSet<_>>() != expected_snapshots {
            return Err(SandboxError::Runtime(
                "volume snapshot objects do not match the restore topology".to_owned(),
            ));
        }
    }
    for service_name in &lock.startup_order {
        let container_id = ContainerId::parse(service_name.clone())
            .map_err(|error| SandboxError::Runtime(error.to_string()))?;
        for specification in &lock.services[service_name].volumes {
            let (handle, newly_created) = match handles.get(&specification.volume_id) {
                Some(handle) => (handle.clone(), false),
                None => {
                    let handle = match snapshots
                        .and_then(|snapshots| snapshots.get(&specification.volume_id))
                    {
                        Some((snapshot, path)) => volume_provider
                            .restore(scope, specification, snapshot, path)
                            .map_err(volume_error)?,
                        None => volume_provider
                            .create(scope, specification)
                            .map_err(volume_error)?,
                    };
                    handles.insert(specification.volume_id.clone(), handle.clone());
                    (handle, true)
                }
            };
            let attachment = match volume_provider.attach(
                &handle,
                AttachmentOwner {
                    sandbox_id: sandbox_id.clone(),
                    container_id: container_id.clone(),
                },
                specification,
            ) {
                Ok(attachment) => attachment,
                Err(error) => {
                    if newly_created
                        && handle.persistence_class()
                            != runtrue_sandbox_core::VolumePersistenceClass::Persistent
                    {
                        return match volume_provider.delete(&handle) {
                            Ok(()) => Err(volume_error(error)),
                            Err(cleanup_error) => Err(SandboxError::Runtime(format!(
                                "attach volume failed: {error}; delete unattached volume failed: {cleanup_error}"
                            ))),
                        };
                    }
                    return Err(volume_error(error));
                }
            };
            match volume_provider.mount(&attachment) {
                Ok(volume) => service_volumes
                    .entry(service_name.clone())
                    .or_default()
                    .push(volume),
                Err(error) => {
                    let cleanup = volume_provider.detach(&attachment);
                    return match cleanup {
                        Ok(()) => Err(volume_error(error)),
                        Err(cleanup_error) => Err(SandboxError::Runtime(format!(
                            "mount volume failed: {error}; detach failed: {cleanup_error}"
                        ))),
                    };
                }
            }
        }
        service_volumes.entry(service_name.clone()).or_default();
    }
    Ok(())
}

fn cleanup_service_volumes(
    volume_provider: &dyn VolumeProvider,
    service_volumes: &mut BTreeMap<String, Vec<MountedVolume>>,
) -> Result<(), SandboxError> {
    let mut first_error = None;
    for (_, volumes) in std::mem::take(service_volumes) {
        for volume in volumes {
            if let Err(error) = volume_provider.unmount(&volume) {
                first_error.get_or_insert_with(|| volume_error(error));
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn volume_error(error: runtrue_sandbox_volume::VolumeError) -> SandboxError {
    SandboxError::Runtime(format!("volume provider: {error}"))
}

impl GvisorSandbox {
    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.resources.is_some()
            && matches!(
                self.state,
                GvisorSandboxState::Running | GvisorSandboxState::Paused
            )
    }

    pub fn status(&self) -> Result<GvisorSandboxStatus, SandboxError> {
        let mut running_services = 0;
        let mut paused_services = 0;
        let mut stopped_services = 0;
        if let Some(resources) = &self.resources {
            for process in resources.processes.values() {
                match resources.runsc.state(&process.id).as_deref() {
                    Ok("running") => running_services += 1,
                    Ok("paused") => paused_services += 1,
                    Ok(_) | Err(_) => stopped_services += 1,
                }
            }
            stopped_services += resources
                .service_order
                .len()
                .saturating_sub(resources.processes.len());
        } else {
            stopped_services = self.paused_runtime_ids.len();
        }
        Ok(GvisorSandboxStatus {
            project: self.project.clone(),
            topology_digest: self.topology_digest.clone(),
            state: self.state,
            running_services,
            paused_services,
            stopped_services,
            ingress_endpoints: self
                .resources
                .as_ref()
                .and_then(|resources| resources.network.as_ref())
                .map_or_else(Vec::new, |network| network.ingress_endpoints().to_vec()),
            snapshot_restore: self.snapshot_restore.clone(),
        })
    }

    pub fn pause(&mut self) -> Result<GvisorSandboxStatus, SandboxError> {
        if self.state != GvisorSandboxState::Running {
            return Err(SandboxError::Runtime(
                "only a running sandbox can be paused".to_owned(),
            ));
        }
        let resources = self.resources.as_ref().ok_or_else(|| {
            SandboxError::Runtime("running sandbox has no runtime resources".to_owned())
        })?;
        if !matches!(
            resources
                .runsc
                .state(&resources.sandbox_runtime_id)
                .as_deref(),
            Ok("running")
        ) {
            self.state = GvisorSandboxState::Failed;
            return Err(SandboxError::Runtime(
                "sandbox root is not running".to_owned(),
            ));
        }
        if let Some(network) = &resources.network {
            network.set_ingress_active(false);
        }
        if let Err(error) = resources.runsc.pause(&resources.sandbox_runtime_id) {
            if let Some(network) = &resources.network {
                network.set_ingress_active(true);
            }
            return Err(error);
        }
        self.paused_runtime_ids
            .insert(resources.sandbox_runtime_id.clone());
        self.state = GvisorSandboxState::Paused;
        self.status()
    }

    pub fn resume(&mut self) -> Result<GvisorSandboxStatus, SandboxError> {
        if self.state != GvisorSandboxState::Paused {
            return Err(SandboxError::Runtime(
                "only a paused sandbox can be resumed".to_owned(),
            ));
        }
        let resources = self.resources.as_ref().ok_or_else(|| {
            SandboxError::Runtime("paused sandbox has no runtime resources".to_owned())
        })?;
        resources.runsc.resume(&resources.sandbox_runtime_id)?;
        if let Some(network) = &resources.network {
            network.set_ingress_active(true);
        }
        self.paused_runtime_ids.clear();
        self.state = GvisorSandboxState::Running;
        self.status()
    }

    pub fn stop(&mut self) -> Result<GvisorSandboxStatus, SandboxError> {
        if self.state == GvisorSandboxState::Stopped {
            return Err(SandboxError::Runtime(
                "sandbox is already stopped".to_owned(),
            ));
        }
        let mut resources = self.resources.take().ok_or_else(|| {
            SandboxError::Runtime("active sandbox has no runtime resources".to_owned())
        })?;
        if let Some(network) = &resources.network {
            network.set_ingress_active(false);
        }
        resources.cleanup()?;
        self.paused_runtime_ids.clear();
        self.state = GvisorSandboxState::Stopped;
        self.status()
    }

    pub fn fence_ingress(&self) -> Result<(), SandboxError> {
        let resources = self.resources.as_ref().ok_or_else(|| {
            SandboxError::Runtime("active sandbox has no runtime resources".to_owned())
        })?;
        if let Some(network) = &resources.network {
            network.set_ingress_active(false);
        }
        Ok(())
    }

    pub fn activate_ingress(&self) -> Result<(), SandboxError> {
        if self.state != GvisorSandboxState::Running {
            return Ok(());
        }
        let resources = self.resources.as_ref().ok_or_else(|| {
            SandboxError::Runtime("active sandbox has no runtime resources".to_owned())
        })?;
        if let Some(network) = &resources.network {
            network.set_ingress_active(true);
        }
        Ok(())
    }

    pub fn snapshot(
        &mut self,
        snapshot_id: SnapshotId,
        snapshot_staging_root: &Path,
        mode: SnapshotMode,
        artifact_store: &dyn runtrue_sandbox_artifact::ArtifactStore,
        provenance: &crate::snapshot::SnapshotProvenance,
    ) -> Result<SnapshotSummary, SandboxError> {
        checkpoint::snapshot(
            self,
            snapshot_id,
            snapshot_staging_root,
            mode,
            artifact_store,
            provenance,
        )
    }

    pub fn completed_output(
        &mut self,
        service: &str,
    ) -> Result<Option<ServiceOutput>, SandboxError> {
        let resources = self.resources.as_mut().ok_or_else(|| {
            SandboxError::Runtime("active sandbox has no runtime resources".to_owned())
        })?;
        let process = resources.processes.get_mut(service).ok_or_else(|| {
            SandboxError::Runtime(format!("service `{service}` does not exist in sandbox"))
        })?;
        let Some(status) = process.poll()? else {
            return Ok(None);
        };
        let captured = process.finish_capture()?;
        Ok(Some(ServiceOutput {
            service: service.to_owned(),
            exit_code: status.code().unwrap_or(255),
            stdout: String::from_utf8_lossy(&captured.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&captured.stderr).into_owned(),
            truncated: captured.truncated,
        }))
    }
}

impl Drop for GvisorSandbox {
    fn drop(&mut self) {
        if let Some(mut resources) = self.resources.take() {
            let _ = resources.cleanup();
        }
    }
}

pub fn enter_cgroup(path: &Path) -> Result<(), SandboxError> {
    cgroup::enter(path)
}

fn prepare_state(root: &Path, project: &str) -> Result<PathBuf, SandboxError> {
    if !root.is_absolute() {
        return Err(SandboxError::Docker(
            "direct state root must be absolute".to_owned(),
        ));
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)
        .map_err(|source| io_error(root, source))?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error(root, source))?;
    let root = fs::canonicalize(root).map_err(|source| io_error(root, source))?;
    let state = root.join(project);
    if state.exists() {
        return Err(SandboxError::Docker(format!(
            "direct project state `{}` already exists",
            state.display()
        )));
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .map_err(|source| io_error(&state, source))?;
    Ok(state)
}

fn runtime_id(project: &str, service: &str) -> String {
    format!("rts-{project}-{service}")
}

fn validate_project(project: &str) -> Result<(), SandboxError> {
    if project.is_empty()
        || project.len() > 24
        || !project
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !project.as_bytes()[0].is_ascii_lowercase()
    {
        return Err(SandboxError::Lock(
            "project must be a bounded lowercase identifier".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_sandbox_core::{
        TenantId, VolumePersistenceClass, VolumeSnapshotPolicy, VolumeSpec, WorkspaceId,
        VOLUME_SPEC_VERSION,
    };
    use runtrue_sandbox_oci::model::{LockedDescriptor, LockedImage, LockedService};
    use runtrue_sandbox_volume::{
        LocalVolumeConfig, LocalVolumeProvider, VolumeAttachment, VolumeCleanupReport, VolumeError,
        VolumeProviderCapabilities,
    };
    use sha2::{Digest as _, Sha256};
    use std::{
        path::Path,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct FailSecondMountProvider {
        inner: LocalVolumeProvider,
        mounts: AtomicUsize,
        detaches: AtomicUsize,
        unmounts: AtomicUsize,
    }

    impl VolumeProvider for FailSecondMountProvider {
        fn provider_id(&self) -> &str {
            self.inner.provider_id()
        }

        fn capabilities(&self) -> VolumeProviderCapabilities {
            self.inner.capabilities()
        }

        fn create(
            &self,
            scope: &VolumeScope,
            specification: &VolumeSpec,
        ) -> Result<VolumeHandle, VolumeError> {
            self.inner.create(scope, specification)
        }

        fn attach(
            &self,
            handle: &VolumeHandle,
            owner: AttachmentOwner,
            specification: &VolumeSpec,
        ) -> Result<VolumeAttachment, VolumeError> {
            self.inner.attach(handle, owner, specification)
        }

        fn mount(&self, attachment: &VolumeAttachment) -> Result<MountedVolume, VolumeError> {
            if self.mounts.fetch_add(1, Ordering::SeqCst) == 1 {
                return Err(VolumeError::Mount(
                    "injected second mount failure".to_owned(),
                ));
            }
            self.inner.mount(attachment)
        }

        fn detach(&self, attachment: &VolumeAttachment) -> Result<(), VolumeError> {
            self.detaches.fetch_add(1, Ordering::SeqCst);
            self.inner.detach(attachment)
        }

        fn freeze(&self, attachment: &VolumeAttachment) -> Result<(), VolumeError> {
            self.inner.freeze(attachment)
        }

        fn thaw(&self, attachment: &VolumeAttachment) -> Result<(), VolumeError> {
            self.inner.thaw(attachment)
        }

        fn snapshot(
            &self,
            attachment: &VolumeAttachment,
            destination: &Path,
        ) -> Result<VolumeSnapshot, VolumeError> {
            self.inner.snapshot(attachment, destination)
        }

        fn restore(
            &self,
            scope: &VolumeScope,
            specification: &VolumeSpec,
            snapshot: &VolumeSnapshot,
            source: &Path,
        ) -> Result<VolumeHandle, VolumeError> {
            self.inner.restore(scope, specification, snapshot, source)
        }

        fn unmount(&self, mounted: &MountedVolume) -> Result<(), VolumeError> {
            self.unmounts.fetch_add(1, Ordering::SeqCst);
            self.inner.unmount(mounted)
        }

        fn delete(&self, handle: &VolumeHandle) -> Result<(), VolumeError> {
            self.inner.delete(handle)
        }

        fn cleanup(&self) -> Result<VolumeCleanupReport, VolumeError> {
            self.inner.cleanup()
        }
    }

    fn artifact_spec(name: &str, destination: &str, digest: &str) -> VolumeSpec {
        VolumeSpec {
            schema_version: VOLUME_SPEC_VERSION,
            volume_id: VolumeId::parse(name).expect("volume id"),
            destination: destination.to_owned(),
            read_only: true,
            persistence_class: VolumePersistenceClass::Artifact,
            snapshot_policy: VolumeSnapshotPolicy::Excluded,
            quota_bytes: 0,
            content_digest: Some(digest.to_owned()),
        }
    }

    fn lock(volumes: Vec<VolumeSpec>) -> TopologyLock {
        let descriptor = LockedDescriptor {
            media_type: "test".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
            size: 1,
        };
        let service = LockedService {
            image: LockedImage {
                source: "example/test".to_owned(),
                exact_reference: format!("example/test@sha256:{}", "a".repeat(64)),
                image_id: format!("sha256:{}", "b".repeat(64)),
                index: None,
                manifest: descriptor.clone(),
                config: descriptor.clone(),
                layers: vec![descriptor],
                operating_system: "linux".to_owned(),
                architecture: "amd64".to_owned(),
                variant: None,
            },
            command: Vec::new(),
            entrypoint: vec!["/bin/true".to_owned()],
            environment: BTreeMap::new(),
            depends_on: BTreeMap::new(),
            healthcheck: None,
            networks: Vec::new(),
            working_dir: "/work".to_owned(),
            root_filesystem: RootFilesystemMode::ReadOnly,
            volumes,
        };
        TopologyLock {
            schema_version: 1,
            topology_digest: "test".to_owned(),
            name: "test".to_owned(),
            services: BTreeMap::from([("api".to_owned(), service)]),
            networks: BTreeMap::new(),
            volumes: BTreeMap::new(),
            startup_order: vec!["api".to_owned()],
            policy: Default::default(),
        }
    }

    #[test]
    fn second_mount_failure_releases_first_mount() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let source = temporary.path().join("artifact");
        fs::write(&source, b"dataset").expect("artifact source");
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(b"dataset")));
        let provider_root = temporary.path().join("provider");
        let inner = LocalVolumeProvider::open(LocalVolumeConfig::new(provider_root.clone()))
            .expect("local volume provider");
        inner
            .publish_artifact(&source, &digest)
            .expect("published artifact");
        let provider = FailSecondMountProvider {
            inner,
            mounts: AtomicUsize::new(0),
            detaches: AtomicUsize::new(0),
            unmounts: AtomicUsize::new(0),
        };
        let lock = lock(vec![
            artifact_spec("first", "/first", &digest),
            artifact_spec("second", "/second", &digest),
        ]);
        let scope = VolumeScope::new(
            TenantId::parse("tenant-a").expect("tenant"),
            WorkspaceId::parse("workspace-a").expect("workspace"),
        );
        let mut service_volumes = BTreeMap::new();

        let preparation = prepare_service_volumes(
            &provider,
            &mut service_volumes,
            &lock,
            "sandbox-a",
            &scope,
            None,
        );
        let error = preparation.expect_err("second mount must fail");
        assert!(error.to_string().contains("injected second mount failure"));

        assert_eq!(provider.mounts.load(Ordering::SeqCst), 2);
        assert_eq!(provider.detaches.load(Ordering::SeqCst), 1);
        assert_eq!(provider.unmounts.load(Ordering::SeqCst), 1);
        assert!(service_volumes.is_empty());
        assert_eq!(
            fs::read_dir(provider_root.join("volumes"))
                .expect("volume directory")
                .count(),
            0
        );
    }
}
