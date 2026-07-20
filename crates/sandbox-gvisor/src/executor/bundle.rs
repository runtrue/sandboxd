use crate::{error::io_error, model::LockedService, SandboxError};
use serde_json::json;
use std::{collections::BTreeMap, fs, path::Path};

pub(super) enum ContainerRole<'a> {
    Sandbox,
    Container { sandbox_id: &'a str },
}

#[allow(clippy::too_many_arguments)]
pub(super) fn write_bundle(
    bundle: &Path,
    rootfs: &Path,
    service_name: &str,
    service: &LockedService,
    network_namespace: &str,
    hosts: &Path,
    resolv: &Path,
    tmpfs_bytes: u64,
    role: ContainerRole<'_>,
) -> Result<(), SandboxError> {
    fs::create_dir(bundle).map_err(|source| io_error(bundle, source))?;
    let (uid, gid) = parse_user(&service.user)?;
    if service.entrypoint.is_empty() {
        return Err(SandboxError::Unsupported(format!(
            "gVisor service `{service_name}` requires an explicit exec-form entrypoint"
        )));
    }
    let mut arguments = service.entrypoint.clone();
    arguments.extend(service.command.iter().cloned());
    let mut environment = BTreeMap::from([
        ("HOME".to_owned(), "/tmp".to_owned()),
        (
            "PATH".to_owned(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
        ),
    ]);
    environment.extend(service.environment.clone());
    let environment = environment
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>();
    let annotations = match role {
        ContainerRole::Sandbox => BTreeMap::from([
            (
                "io.kubernetes.cri.container-type".to_owned(),
                "sandbox".to_owned(),
            ),
            (
                "io.kubernetes.cri.container-name".to_owned(),
                service_name.to_owned(),
            ),
        ]),
        ContainerRole::Container { sandbox_id } => BTreeMap::from([
            (
                "io.kubernetes.cri.container-type".to_owned(),
                "container".to_owned(),
            ),
            (
                "io.kubernetes.cri.container-name".to_owned(),
                service_name.to_owned(),
            ),
            (
                "io.kubernetes.cri.sandbox-id".to_owned(),
                sandbox_id.to_owned(),
            ),
        ]),
    };
    let config = json!({
        "ociVersion": "1.2.1",
        "annotations": annotations,
        "process": {
            "terminal": false,
            "user": {"uid": uid, "gid": gid},
            "args": arguments,
            "env": environment,
            "cwd": service.working_dir,
            "noNewPrivileges": true,
            "capabilities": {
                "bounding": [], "effective": [], "inheritable": [], "permitted": [], "ambient": []
            },
            "rlimits": [
                {"type": "RLIMIT_NOFILE", "hard": 256, "soft": 256},
                {"type": "RLIMIT_CORE", "hard": 0, "soft": 0}
            ]
        },
        "root": {"path": rootfs, "readonly": true},
        "hostname": service_name,
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"]},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", format!("size={tmpfs_bytes}")]},
            {"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"]},
            {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "noexec", "mode=1777", format!("size={tmpfs_bytes}")]},
            {"destination": "/work", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "noexec", "mode=1777", format!("size={tmpfs_bytes}")]},
            {"destination": "/etc/hosts", "type": "bind", "source": hosts, "options": ["rbind", "ro", "nosuid", "nodev", "noexec"]},
            {"destination": "/etc/resolv.conf", "type": "bind", "source": resolv, "options": ["rbind", "ro", "nosuid", "nodev", "noexec"]}
        ],
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "network", "path": format!("/var/run/netns/{network_namespace}")},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "mount"}
            ],
            "resources": {},
            "maskedPaths": [
                "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
                "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/sys/firmware"
            ],
            "readonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"]
        }
    });
    let path = bundle.join("config.json");
    let bytes = serde_json::to_vec_pretty(&config)
        .map_err(|error| SandboxError::Lock(format!("encode OCI bundle: {error}")))?;
    fs::write(&path, bytes).map_err(|source| io_error(&path, source))
}

fn parse_user(user: &str) -> Result<(u32, u32), SandboxError> {
    let (uid, gid) = user
        .split_once(':')
        .ok_or_else(|| SandboxError::Unsupported("gVisor requires numeric UID:GID".to_owned()))?;
    let uid = uid
        .parse()
        .map_err(|_| SandboxError::Unsupported("gVisor requires numeric UID:GID".to_owned()))?;
    let gid = gid
        .parse()
        .map_err(|_| SandboxError::Unsupported("gVisor requires numeric UID:GID".to_owned()))?;
    Ok((uid, gid))
}
