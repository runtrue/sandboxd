mod bundle;
mod cgroup;
mod checkpoint;
mod network;
mod process;
mod recovery;

pub use checkpoint::restore_admitted;
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
use runtrue_sandbox_core::{SnapshotId, SnapshotMode};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
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
    state: GvisorSandboxState,
    paused_runtime_ids: BTreeSet<String>,
    resources: Option<Resources>,
}

struct Resources {
    state: PathBuf,
    runsc: Runsc,
    sandbox_runtime_id: String,
    service_order: Vec<String>,
    cgroups: Option<CgroupSet>,
    network: Option<ProjectNetwork>,
    processes: BTreeMap<String, ServiceProcess>,
}

struct ExecutionOutput {
    startup_ms: u128,
    wait_exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn run_admitted(
    lock: &TopologyLock,
    project: &str,
    wait_for: &str,
    timeout: Duration,
    state_root: &Path,
    runsc_program: &Path,
    ip_program: &Path,
    admitted: &BTreeMap<String, ImmutableRootfs>,
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
        admitted,
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
    admitted: &BTreeMap<String, ImmutableRootfs>,
    preflight_ms: u128,
    overall_started: Instant,
) -> Result<GvisorRunResult, SandboxError> {
    let rootfs_by_image = admitted
        .iter()
        .map(|(id, image)| (id.clone(), image.rootfs().to_owned()))
        .collect::<BTreeMap<_, _>>();
    let infrastructure_started = Instant::now();
    let mut resources = create_resources(lock, project, state_root, runsc_program, ip_program)?;
    let infrastructure_ms = infrastructure_started.elapsed().as_millis();
    let started = Instant::now();
    let deadline = started + timeout;
    let execution = execute(
        &mut resources,
        lock,
        project,
        wait_for,
        deadline,
        &rootfs_by_image,
    );
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
    admitted: &BTreeMap<String, ImmutableRootfs>,
) -> Result<GvisorSandbox, SandboxError> {
    verify_lock(lock)?;
    validate_project(project)?;
    validate_admitted(lock, admitted)?;
    let rootfs_by_image = admitted
        .iter()
        .map(|(id, image)| (id.clone(), image.rootfs().to_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut resources = create_resources(lock, project, state_root, runsc_program, ip_program)?;
    let deadline = Instant::now() + timeout;
    if let Err(error) = start_services(&mut resources, lock, project, deadline, &rootfs_by_image) {
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
        state: GvisorSandboxState::Running,
        paused_runtime_ids: BTreeSet::new(),
        resources: Some(resources),
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

fn create_resources(
    lock: &TopologyLock,
    project: &str,
    state_root: &Path,
    runsc_program: &Path,
    ip_program: &Path,
) -> Result<Resources, SandboxError> {
    let state = prepare_state(state_root, project)?;
    if let Err(error) = recovery::write_recovery_record(&state, project, lock) {
        let _ = fs::remove_dir_all(&state);
        return Err(error);
    }
    let cgroups = match CgroupSet::create(project) {
        Ok(cgroups) => cgroups,
        Err(error) => {
            let _ = fs::remove_dir_all(&state);
            return Err(error);
        }
    };
    let network = match ProjectNetwork::create(ip_program, project, lock, &state) {
        Ok(network) => network,
        Err(error) => {
            let _ = cgroups.cleanup();
            let _ = fs::remove_dir_all(&state);
            return Err(error);
        }
    };
    let runsc = match Runsc::new(runsc_program, &state.join("runsc")) {
        Ok(runsc) => runsc,
        Err(error) => {
            let mut network = network;
            let _ = network.cleanup();
            let _ = cgroups.cleanup();
            let _ = fs::remove_dir_all(&state);
            return Err(error);
        }
    };
    Ok(Resources {
        state,
        runsc,
        sandbox_runtime_id: runtime_id(project, &lock.startup_order[0]),
        service_order: lock.startup_order.clone(),
        cgroups: Some(cgroups),
        network: Some(network),
        processes: BTreeMap::new(),
    })
}

fn execute(
    resources: &mut Resources,
    lock: &TopologyLock,
    project: &str,
    wait_for: &str,
    deadline: Instant,
    rootfs_by_image: &BTreeMap<String, PathBuf>,
) -> Result<ExecutionOutput, SandboxError> {
    let startup_ms = start_services(resources, lock, project, deadline, rootfs_by_image)?;
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
    rootfs_by_image: &BTreeMap<String, PathBuf>,
) -> Result<u128, SandboxError> {
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
                if resources.runsc.health(
                    &resources.processes[service_name].id,
                    &service.user,
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

impl Resources {
    fn cleanup(&mut self) -> Result<BTreeMap<String, CgroupMetrics>, SandboxError> {
        let mut first_error = None;
        let mut services = self.processes.keys().cloned().collect::<Vec<_>>();
        services.sort_by_key(|service| self.processes[service].id == self.sandbox_runtime_id);
        for service in services {
            let process = self.processes.get_mut(&service).expect("service exists");
            self.runsc.kill(&process.id);
            process.reap();
            if let Err(error) = self.runsc.delete(&process.id) {
                first_error.get_or_insert(error);
            }
        }
        self.processes.clear();
        if !self.runsc.is_empty().unwrap_or(false) {
            first_error.get_or_insert_with(|| {
                SandboxError::Docker("runsc state is not empty after cleanup".to_owned())
            });
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

impl GvisorSandbox {
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
        resources.runsc.pause(&resources.sandbox_runtime_id)?;
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
        resources.cleanup()?;
        self.paused_runtime_ids.clear();
        self.state = GvisorSandboxState::Stopped;
        self.status()
    }

    pub fn snapshot(
        &mut self,
        snapshot_id: SnapshotId,
        snapshot_root: &Path,
        mode: SnapshotMode,
    ) -> Result<SnapshotSummary, SandboxError> {
        checkpoint::snapshot(self, snapshot_id, snapshot_root, mode)
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
