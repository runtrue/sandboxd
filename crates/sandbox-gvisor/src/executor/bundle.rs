use crate::{error::io_error, model::LockedService, SandboxError};
use runtrue_sandbox_core::GuestProfile;
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
    rootfs_read_only: bool,
    service_name: &str,
    service: &LockedService,
    guest_profile: &GuestProfile,
    network_namespace: &str,
    hosts: &Path,
    resolv: &Path,
    tmpfs_bytes: u64,
    role: ContainerRole<'_>,
) -> Result<(), SandboxError> {
    fs::create_dir(bundle).map_err(|source| io_error(bundle, source))?;
    let restrictions = &guest_profile.restrictions;
    let uid = restrictions.uid;
    let gid = restrictions.gid;
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
            "noNewPrivileges": restrictions.no_new_privileges,
            "capabilities": {
                "bounding": restrictions.bounding_capabilities,
                "effective": restrictions.effective_capabilities,
                "inheritable": restrictions.inheritable_capabilities,
                "permitted": restrictions.permitted_capabilities,
                "ambient": restrictions.ambient_capabilities
            },
            "rlimits": [
                {"type": "RLIMIT_NOFILE", "hard": 256, "soft": 256},
                {"type": "RLIMIT_CORE", "hard": 0, "soft": 0}
            ]
        },
        "root": {"path": rootfs, "readonly": rootfs_read_only},
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
            "maskedPaths": restrictions.masked_paths,
            "readonlyPaths": restrictions.readonly_paths
        }
    });
    let path = bundle.join("config.json");
    let bytes = serde_json::to_vec_pretty(&config)
        .map_err(|error| SandboxError::Lock(format!("encode OCI bundle: {error}")))?;
    fs::write(&path, bytes).map_err(|source| io_error(&path, source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LockedDescriptor, LockedImage, RootFilesystemMode};
    use runtrue_sandbox_core::{
        GuestProfile, OCI_COMPAT_GUEST_PROFILE, ROOT_GUEST_PROFILE, STRICT_GUEST_PROFILE,
    };

    fn service() -> LockedService {
        let descriptor = LockedDescriptor {
            media_type: "test".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
            size: 1,
        };
        LockedService {
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
            networks: vec!["default".to_owned()],
            working_dir: "/work".to_owned(),
            root_filesystem: RootFilesystemMode::ReadOnly,
        }
    }

    fn generated(profile_name: &str) -> serde_json::Value {
        let directory = tempfile::tempdir().expect("temporary directory");
        let bundle = directory.path().join("bundle");
        let rootfs = directory.path().join("rootfs");
        let hosts = directory.path().join("hosts");
        let resolv = directory.path().join("resolv.conf");
        fs::create_dir(&rootfs).expect("rootfs");
        fs::write(&hosts, "127.0.0.1 localhost\n").expect("hosts");
        fs::write(&resolv, "").expect("resolv");
        let profile = GuestProfile::reviewed_named(profile_name).expect("reviewed profile");
        write_bundle(
            &bundle,
            &rootfs,
            true,
            "service",
            &service(),
            &profile,
            "test-netns",
            &hosts,
            &resolv,
            1024,
            ContainerRole::Sandbox,
        )
        .expect("write bundle");
        serde_json::from_slice(&fs::read(bundle.join("config.json")).expect("read bundle"))
            .expect("decode bundle")
    }

    #[test]
    fn strict_and_root_profiles_only_change_guest_identity() {
        let strict = generated(STRICT_GUEST_PROFILE);
        let root = generated(ROOT_GUEST_PROFILE);
        assert_eq!(
            strict["process"]["user"],
            json!({"uid": 65534, "gid": 65534})
        );
        assert_eq!(root["process"]["user"], json!({"uid": 0, "gid": 0}));
        for config in [&strict, &root] {
            assert_eq!(config["process"]["capabilities"]["bounding"], json!([]));
            assert_eq!(config["process"]["capabilities"]["ambient"], json!([]));
            assert_eq!(config["process"]["noNewPrivileges"], true);
        }
    }

    #[test]
    fn oci_compatibility_capability_fixtures_are_exact_and_ambient_stays_empty() {
        let config = generated(OCI_COMPAT_GUEST_PROFILE);
        let expected = json!([
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_SETGID",
            "CAP_SETUID"
        ]);
        for set in ["bounding", "effective", "permitted"] {
            assert_eq!(config["process"]["capabilities"][set], expected);
        }
        assert_eq!(config["process"]["capabilities"]["inheritable"], json!([]));
        assert_eq!(config["process"]["capabilities"]["ambient"], json!([]));
        let encoded = serde_json::to_string(&config).expect("encode config");
        for forbidden in [
            "CAP_SYS_ADMIN",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_SYS_MODULE",
            "CAP_SYS_PTRACE",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn every_profile_keeps_namespace_and_filesystem_boundaries() {
        for name in [
            STRICT_GUEST_PROFILE,
            ROOT_GUEST_PROFILE,
            OCI_COMPAT_GUEST_PROFILE,
        ] {
            let config = generated(name);
            assert_eq!(config["root"]["readonly"], true);
            assert_eq!(config["linux"]["namespaces"].as_array().unwrap().len(), 5);
            assert!(config["linux"]["maskedPaths"].as_array().unwrap().len() >= 9);
            assert!(config["linux"]["readonlyPaths"].as_array().unwrap().len() >= 5);
        }
    }
}
