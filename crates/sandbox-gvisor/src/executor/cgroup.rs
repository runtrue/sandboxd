use crate::{error::io_error, model::SandboxPolicy, SandboxError};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const TRUSTED_CGROUP_ROOT: &str = "/sys/fs/cgroup/runtrue-sandboxd";

#[derive(Debug)]
pub(super) struct CgroupSet {
    root: PathBuf,
    project: PathBuf,
    services: BTreeMap<String, PathBuf>,
}

#[derive(Debug, Default, Serialize)]
pub(super) struct CgroupMetrics {
    pub(super) memory_peak_bytes: u64,
    pub(super) pids_peak: u64,
    pub(super) cpu_usage_usec: u64,
    pub(super) oom_kills: u64,
    pub(super) pids_limit_hits: u64,
}

impl CgroupSet {
    pub(super) fn create(project: &str) -> Result<Self, SandboxError> {
        let root = PathBuf::from(TRUSTED_CGROUP_ROOT);
        if !root.exists() {
            fs::create_dir(&root).map_err(|source| io_error(&root, source))?;
        }
        enable_controllers(&root)?;
        let project_path = root.join(project);
        if project_path.exists() {
            return Err(SandboxError::Docker(format!(
                "direct cgroup project `{project}` already exists"
            )));
        }
        fs::create_dir(&project_path).map_err(|source| io_error(&project_path, source))?;
        enable_controllers(&project_path)?;
        Ok(Self {
            root,
            project: project_path,
            services: BTreeMap::new(),
        })
    }

    pub(super) fn create_service(
        &mut self,
        service: &str,
        policy: &SandboxPolicy,
    ) -> Result<PathBuf, SandboxError> {
        let path = self.project.join(service);
        fs::create_dir(&path).map_err(|source| io_error(&path, source))?;
        self.services.insert(service.to_owned(), path.clone());
        write(&path.join("memory.max"), policy.memory_bytes_per_service)?;
        write(&path.join("memory.swap.max"), 0_u8)?;
        write(&path.join("memory.oom.group"), 1_u8)?;
        write(&path.join("pids.max"), policy.pids_per_service)?;
        fs::write(
            path.join("cpu.max"),
            format!("{} 100000", policy.cpu_per_service_millis * 100),
        )
        .map_err(|source| io_error(path.join("cpu.max"), source))?;
        Ok(path)
    }

    pub(super) fn cleanup(mut self) -> Result<BTreeMap<String, CgroupMetrics>, SandboxError> {
        let mut metrics = BTreeMap::new();
        let mut first_error = None;
        for (service, path) in self.services.iter().rev() {
            metrics.insert(service.clone(), read_metrics(path));
            if let Err(error) = kill_and_remove(path) {
                first_error.get_or_insert(error);
            }
        }
        self.services.clear();
        if let Err(source) = fs::remove_dir(&self.project) {
            first_error.get_or_insert_with(|| io_error(&self.project, source));
        }
        let _ = fs::remove_dir(&self.root);
        match first_error {
            Some(error) => Err(error),
            None => Ok(metrics),
        }
    }
}

pub(crate) fn enter(cgroup: &Path) -> Result<(), SandboxError> {
    let trusted = Path::new(TRUSTED_CGROUP_ROOT);
    let canonical = fs::canonicalize(cgroup).map_err(|source| io_error(cgroup, source))?;
    if !canonical.starts_with(trusted) || canonical == trusted {
        return Err(SandboxError::Docker(
            "cgroup launcher target escaped the trusted root".to_owned(),
        ));
    }
    fs::write(
        canonical.join("cgroup.procs"),
        std::process::id().to_string(),
    )
    .map_err(|source| io_error(canonical.join("cgroup.procs"), source))
}

pub(super) fn recover_project(project: &str) -> Result<(), SandboxError> {
    let root = PathBuf::from(TRUSTED_CGROUP_ROOT);
    let path = root.join(project);
    if !path.exists() {
        return Ok(());
    }
    let canonical = fs::canonicalize(&path).map_err(|source| io_error(&path, source))?;
    if !canonical.starts_with(&root) || canonical == root {
        return Err(SandboxError::Runtime(
            "recovery cgroup escaped the trusted root".to_owned(),
        ));
    }
    let mut children = fs::read_dir(&canonical)
        .map_err(|source| io_error(&canonical, source))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(std::fs::FileType::is_dir)
                .map(|_| entry.path())
        })
        .collect::<Vec<_>>();
    children.sort();
    for child in children {
        kill_and_remove(&child)?;
    }
    fs::remove_dir(&canonical).map_err(|source| io_error(&canonical, source))?;
    let _ = fs::remove_dir(root);
    Ok(())
}

fn enable_controllers(path: &Path) -> Result<(), SandboxError> {
    let available = fs::read_to_string(path.join("cgroup.controllers"))
        .map_err(|source| io_error(path.join("cgroup.controllers"), source))?;
    for controller in ["cpu", "memory", "pids"] {
        if !available
            .split_ascii_whitespace()
            .any(|item| item == controller)
        {
            return Err(SandboxError::Docker(format!(
                "cgroup controller `{controller}` is not delegated"
            )));
        }
    }
    fs::write(path.join("cgroup.subtree_control"), "+cpu +memory +pids")
        .map_err(|source| io_error(path.join("cgroup.subtree_control"), source))
}

fn kill_and_remove(path: &Path) -> Result<(), SandboxError> {
    if path.join("cgroup.kill").exists() {
        fs::write(path.join("cgroup.kill"), "1")
            .map_err(|source| io_error(path.join("cgroup.kill"), source))?;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let events = fs::read_to_string(path.join("cgroup.events"))
            .map_err(|source| io_error(path.join("cgroup.events"), source))?;
        if events.lines().any(|line| line == "populated 0") {
            break;
        }
        if Instant::now() >= deadline {
            return Err(SandboxError::Timeout(format!(
                "cgroup `{}` remained populated",
                path.display()
            )));
        }
        thread::sleep(Duration::from_millis(10));
    }
    fs::remove_dir(path).map_err(|source| io_error(path, source))
}

fn read_metrics(path: &Path) -> CgroupMetrics {
    let cpu = fs::read_to_string(path.join("cpu.stat")).unwrap_or_default();
    CgroupMetrics {
        memory_peak_bytes: read_u64(path.join("memory.peak")),
        pids_peak: read_u64(path.join("pids.peak")),
        cpu_usage_usec: cpu
            .lines()
            .find_map(|line| line.strip_prefix("usage_usec "))
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        oom_kills: keyed_value(path.join("memory.events"), "oom_kill"),
        pids_limit_hits: keyed_value(path.join("pids.events"), "max"),
    }
}

fn read_u64(path: PathBuf) -> u64 {
    fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

fn keyed_value(path: PathBuf, key: &str) -> u64 {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key} ")))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn write(path: &Path, value: impl ToString) -> Result<(), SandboxError> {
    fs::write(path, value.to_string()).map_err(|source| io_error(path, source))
}
