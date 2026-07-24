use super::{
    cgroup, network, process::Runsc, runtime_id, validate_project, CgroupMode,
    ExecutorConfiguration, NetworkMode,
};
use crate::{error::io_error, model::TopologyLock, SandboxError};
use runtrue_sandbox_oci::provider::LOOPBACK_WRITABLE_ROOTFS_PROVIDER_ID;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
};

const RECOVERY_SCHEMA_VERSION: u32 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryRecord {
    schema_version: u32,
    project: String,
    topology_digest: String,
    runtime_ids: Vec<String>,
    sandbox_runtime_id: String,
    bridge: String,
    network_namespaces: Vec<String>,
    #[serde(default)]
    nft_table: String,
    #[serde(default)]
    network_mode: NetworkMode,
    #[serde(default)]
    cgroup_mode: CgroupMode,
    #[serde(default)]
    writable_rootfs: Vec<WritableRootfsRecovery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WritableRootfsRecovery {
    pub(super) service: String,
    pub(super) provider: String,
    pub(super) key: String,
    pub(super) quota_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct RecoveryReport {
    pub recovered_projects: Vec<String>,
}

pub fn recover(
    state_root: &Path,
    runsc_program: &Path,
    ip_program: &Path,
    nft_program: &Path,
) -> Result<RecoveryReport, SandboxError> {
    if !state_root.exists() {
        return Ok(RecoveryReport {
            recovered_projects: Vec::new(),
        });
    }
    let state_root = fs::canonicalize(state_root).map_err(|source| io_error(state_root, source))?;
    let mut directories = fs::read_dir(&state_root)
        .map_err(|source| io_error(&state_root, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| io_error(&state_root, source))?;
    directories.sort_by_key(fs::DirEntry::file_name);
    if directories.len() > 256 {
        return Err(SandboxError::Runtime(
            "recovery state contains more than 256 projects".to_owned(),
        ));
    }
    let mut recovered_projects = Vec::new();
    for entry in directories {
        let file_type = entry
            .file_type()
            .map_err(|source| io_error(entry.path(), source))?;
        if !file_type.is_dir() {
            return Err(SandboxError::Runtime(format!(
                "unexpected recovery state entry `{}`",
                entry.path().display()
            )));
        }
        let state = entry.path();
        let record_path = state.join("recovery.json");
        let bytes = fs::read(&record_path).map_err(|source| io_error(&record_path, source))?;
        let record: RecoveryRecord = serde_json::from_slice(&bytes)
            .map_err(|error| SandboxError::Runtime(format!("decode recovery record: {error}")))?;
        if !matches!(record.schema_version, 2 | 3 | 4 | RECOVERY_SCHEMA_VERSION)
            || state.file_name().and_then(|name| name.to_str()) != Some(&record.project)
        {
            return Err(SandboxError::Runtime(
                "recovery record identity mismatch".to_owned(),
            ));
        }
        validate_recovery_record(&record)?;
        let runsc_root = state.join("runsc");
        if runsc_root.exists() {
            let runsc = Runsc::new(runsc_program, &runsc_root, record.network_mode)?;
            let mut active_ids = Vec::new();
            for id in &record.runtime_ids {
                if runsc.state(id).is_ok() {
                    active_ids.push(id.clone());
                }
            }
            runsc.teardown(&active_ids, &record.sandbox_runtime_id)?;
        }
        if record.network_mode == NetworkMode::Private {
            network::recover(
                ip_program,
                nft_program,
                &record.bridge,
                &record.network_namespaces,
                &if record.nft_table.is_empty() {
                    network::nft_table_name(&record.project)
                } else {
                    record.nft_table.clone()
                },
            )?;
        }
        if record.cgroup_mode == CgroupMode::Managed {
            cgroup::recover_project(&record.project)?;
        }
        fs::remove_dir_all(&state).map_err(|source| io_error(&state, source))?;
        recovered_projects.push(record.project);
    }
    Ok(RecoveryReport { recovered_projects })
}

pub(super) fn write_recovery_record(
    state: &Path,
    project: &str,
    lock: &TopologyLock,
    configuration: ExecutorConfiguration,
) -> Result<(), SandboxError> {
    let (bridge, network_namespaces, nft_table) =
        network::planned_resources(project, lock, configuration.network_mode);
    let record = RecoveryRecord {
        schema_version: RECOVERY_SCHEMA_VERSION,
        project: project.to_owned(),
        topology_digest: lock.topology_digest.clone(),
        runtime_ids: lock
            .services
            .keys()
            .map(|service| runtime_id(project, service))
            .collect(),
        sandbox_runtime_id: runtime_id(project, &lock.startup_order[0]),
        bridge,
        network_namespaces,
        nft_table,
        network_mode: configuration.network_mode,
        cgroup_mode: configuration.cgroup_mode,
        writable_rootfs: Vec::new(),
    };
    let path = state.join("recovery.json");
    let bytes = serde_json::to_vec_pretty(&record)
        .map_err(|error| SandboxError::Runtime(format!("encode recovery record: {error}")))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|source| io_error(&path, source))?;
    file.write_all(&bytes)
        .map_err(|source| io_error(&path, source))?;
    file.sync_all().map_err(|source| io_error(&path, source))?;
    fs::File::open(state)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(state, source))
}

pub(super) fn write_writable_rootfs(
    state: &Path,
    roots: Vec<WritableRootfsRecovery>,
) -> Result<(), SandboxError> {
    let path = state.join("recovery.json");
    let bytes = fs::read(&path).map_err(|source| io_error(&path, source))?;
    let mut record: RecoveryRecord = serde_json::from_slice(&bytes)
        .map_err(|error| SandboxError::Runtime(format!("decode recovery record: {error}")))?;
    record.schema_version = RECOVERY_SCHEMA_VERSION;
    record.writable_rootfs = roots;
    validate_recovery_record(&record)?;
    let bytes = serde_json::to_vec_pretty(&record)
        .map_err(|error| SandboxError::Runtime(format!("encode recovery record: {error}")))?;
    let temporary = state.join("recovery.json.new");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|source| io_error(&temporary, source))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error(&temporary, source))?;
    fs::rename(&temporary, &path).map_err(|source| io_error(&path, source))?;
    fs::File::open(state)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(state, source))
}

fn validate_recovery_record(record: &RecoveryRecord) -> Result<(), SandboxError> {
    validate_project(&record.project)?;
    let valid_network_resources = if record.network_mode == NetworkMode::Loopback {
        record.network_namespaces.is_empty()
            && record.bridge.is_empty()
            && record.nft_table.is_empty()
    } else {
        record.network_namespaces.len() == 1
            && record.bridge == network::bridge_name(&record.project)
            && ((record.schema_version >= 4
                && record.nft_table == network::nft_table_name(&record.project))
                || (record.schema_version < 4 && record.nft_table.is_empty()))
    };
    if record.runtime_ids.is_empty()
        || record.runtime_ids.len() > 32
        || !valid_network_resources
        || !record.topology_digest.starts_with("sha256:")
        || record.topology_digest.len() != 71
        || (record.schema_version == 2 && !record.writable_rootfs.is_empty())
    {
        return Err(SandboxError::Runtime(
            "recovery record resource set is invalid".to_owned(),
        ));
    }
    let prefix = format!("rts-{}-", record.project);
    let mut seen = std::collections::BTreeSet::new();
    for id in &record.runtime_ids {
        let service = id.strip_prefix(&prefix).ok_or_else(|| {
            SandboxError::Runtime("recovery runtime identity is outside its project".to_owned())
        })?;
        if service.is_empty()
            || service.len() > 32
            || !service.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
            || !service.as_bytes()[0].is_ascii_lowercase()
            || !seen.insert(service)
        {
            return Err(SandboxError::Runtime(
                "recovery runtime service identity is invalid".to_owned(),
            ));
        }
    }
    if !record.runtime_ids.contains(&record.sandbox_runtime_id) {
        return Err(SandboxError::Runtime(
            "recovery sandbox identity does not match its project".to_owned(),
        ));
    }
    let runtime_services = record
        .runtime_ids
        .iter()
        .filter_map(|id| id.strip_prefix(&prefix))
        .collect::<std::collections::BTreeSet<_>>();
    let mut writable_services = std::collections::BTreeSet::new();
    for rootfs in &record.writable_rootfs {
        if !runtime_services.contains(rootfs.service.as_str())
            || !writable_services.insert(rootfs.service.as_str())
            || rootfs.provider != LOOPBACK_WRITABLE_ROOTFS_PROVIDER_ID
            || rootfs.key.len() != 64
            || !rootfs
                .key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            || rootfs.quota_bytes == 0
        {
            return Err(SandboxError::Runtime(
                "recovery writable-root identity is invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_record() -> RecoveryRecord {
        RecoveryRecord {
            schema_version: RECOVERY_SCHEMA_VERSION,
            project: "tenant-a".to_owned(),
            topology_digest: format!("sha256:{}", "a".repeat(64)),
            runtime_ids: vec!["rts-tenant-a-api_worker".to_owned()],
            sandbox_runtime_id: "rts-tenant-a-api_worker".to_owned(),
            bridge: network::bridge_name("tenant-a"),
            network_namespaces: vec![network::namespace_name("tenant-a")],
            nft_table: network::nft_table_name("tenant-a"),
            network_mode: NetworkMode::Private,
            cgroup_mode: CgroupMode::Managed,
            writable_rootfs: Vec::new(),
        }
    }

    #[test]
    fn recovery_resources_are_bound_to_project_identity() {
        assert!(validate_recovery_record(&recovery_record()).is_ok());
        let mut changed = recovery_record();
        changed.bridge = "eth0".to_owned();
        assert!(validate_recovery_record(&changed).is_err());
    }

    #[test]
    fn loopback_external_mode_records_no_host_resources() {
        let mut record = recovery_record();
        record.network_mode = NetworkMode::Loopback;
        record.cgroup_mode = CgroupMode::External;
        record.bridge.clear();
        record.network_namespaces.clear();
        record.nft_table.clear();
        assert!(validate_recovery_record(&record).is_ok());

        record.bridge = network::bridge_name(&record.project);
        assert!(validate_recovery_record(&record).is_err());
    }

    #[test]
    fn recovery_rejects_cross_project_runtime_identity() {
        let mut changed = recovery_record();
        changed.runtime_ids = vec!["rts-tenant-b-api_worker".to_owned()];
        assert!(validate_recovery_record(&changed).is_err());
    }

    #[test]
    fn recovery_binds_writable_roots_to_issued_services_and_provider() {
        let mut record = recovery_record();
        record.writable_rootfs.push(WritableRootfsRecovery {
            service: "api_worker".to_owned(),
            provider: LOOPBACK_WRITABLE_ROOTFS_PROVIDER_ID.to_owned(),
            key: "a".repeat(64),
            quota_bytes: 16 * 1024 * 1024,
        });
        assert!(validate_recovery_record(&record).is_ok());

        let mut wrong_service = record.clone();
        wrong_service.writable_rootfs[0].service = "other".to_owned();
        assert!(validate_recovery_record(&wrong_service).is_err());

        let mut wrong_provider = record.clone();
        wrong_provider.writable_rootfs[0].provider = "untrusted".to_owned();
        assert!(validate_recovery_record(&wrong_provider).is_err());

        let mut legacy = record;
        legacy.schema_version = 2;
        assert!(validate_recovery_record(&legacy).is_err());
    }
}
