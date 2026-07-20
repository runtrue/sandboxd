use crate::{error::io_error, model::TopologyLock, SandboxError};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug)]
pub(super) struct ProjectNetwork {
    ip: PathBuf,
    pub(super) bridge: String,
    sandbox: ServiceNetwork,
}

#[derive(Debug)]
pub(super) struct ServiceNetwork {
    pub(super) namespace: String,
    pub(super) hosts_path: PathBuf,
    pub(super) resolv_path: PathBuf,
}

impl ProjectNetwork {
    pub(super) fn create(
        ip_program: &Path,
        project: &str,
        lock: &TopologyLock,
        state: &Path,
    ) -> Result<Self, SandboxError> {
        if lock.networks.len() != 1
            || lock
                .services
                .values()
                .any(|service| service.networks.len() != 1)
        {
            return Err(SandboxError::Unsupported(
                "the gVisor backend supports one private logical network".to_owned(),
            ));
        }
        let ip = validate_ip(ip_program)?;
        let token = short_token(project);
        let bridge = format!("rtb{token}");
        checked(&ip, &["link", "add", &bridge, "type", "bridge"])?;
        if let Err(error) = checked(&ip, &["link", "set", &bridge, "up"]) {
            let _ = checked(&ip, &["link", "delete", &bridge]);
            return Err(error);
        }
        let mut network = Self {
            ip,
            bridge,
            sandbox: ServiceNetwork {
                namespace: namespace_name(project),
                hosts_path: state.join("hosts"),
                resolv_path: state.join("resolv.conf"),
            },
        };
        if let Err(error) = network.configure(project, lock) {
            let _ = network.cleanup();
            return Err(error);
        }
        Ok(network)
    }

    pub(super) fn sandbox(&self) -> &ServiceNetwork {
        &self.sandbox
    }

    pub(super) fn cleanup(&mut self) -> Result<(), SandboxError> {
        let mut first_error = None;
        if let Err(error) = checked(&self.ip, &["netns", "delete", &self.sandbox.namespace]) {
            first_error.get_or_insert(error);
        }
        if let Err(error) = checked(&self.ip, &["link", "delete", &self.bridge]) {
            first_error.get_or_insert(error);
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn configure(&mut self, project: &str, lock: &TopologyLock) -> Result<(), SandboxError> {
        let token = short_token(project);
        let namespace = self.sandbox.namespace.clone();
        let host_veth = format!("rth{token}");
        let guest_veth = format!("rtg{token}");
        let address = format!("{}.10", project_subnet(project));
        checked(&self.ip, &["netns", "add", &namespace])?;
        checked(
            &self.ip,
            &[
                "link",
                "add",
                &host_veth,
                "type",
                "veth",
                "peer",
                "name",
                &guest_veth,
            ],
        )?;
        checked(
            &self.ip,
            &["link", "set", &host_veth, "master", &self.bridge],
        )?;
        checked(&self.ip, &["link", "set", &host_veth, "up"])?;
        checked(&self.ip, &["link", "set", &guest_veth, "netns", &namespace])?;
        checked(&self.ip, &["-n", &namespace, "link", "set", "lo", "up"])?;
        checked(
            &self.ip,
            &["-n", &namespace, "link", "set", &guest_veth, "name", "eth0"],
        )?;
        checked(
            &self.ip,
            &[
                "-n",
                &namespace,
                "addr",
                "add",
                &format!("{address}/24"),
                "dev",
                "eth0",
            ],
        )?;
        checked(&self.ip, &["-n", &namespace, "link", "set", "eth0", "up"])?;
        let mut hosts = String::from("127.0.0.1 localhost\n");
        for peer in lock.services.keys() {
            hosts.push_str(&format!("127.0.0.1 {peer}\n"));
        }
        fs::write(&self.sandbox.hosts_path, hosts)
            .map_err(|source| io_error(&self.sandbox.hosts_path, source))?;
        fs::set_permissions(&self.sandbox.hosts_path, fs::Permissions::from_mode(0o444))
            .map_err(|source| io_error(&self.sandbox.hosts_path, source))?;
        fs::write(&self.sandbox.resolv_path, "options attempts:1 timeout:1\n")
            .map_err(|source| io_error(&self.sandbox.resolv_path, source))?;
        fs::set_permissions(&self.sandbox.resolv_path, fs::Permissions::from_mode(0o444))
            .map_err(|source| io_error(&self.sandbox.resolv_path, source))?;
        Ok(())
    }
}

pub(super) fn planned_resources(project: &str, lock: &TopologyLock) -> (String, Vec<String>) {
    let bridge = bridge_name(project);
    let _ = lock;
    let namespaces = vec![namespace_name(project)];
    (bridge, namespaces)
}

pub(super) fn bridge_name(project: &str) -> String {
    format!("rtb{}", short_token(project))
}

pub(super) fn namespace_name(project: &str) -> String {
    format!("rtn{}", short_token(project))
}

pub(super) fn recover(
    ip_program: &Path,
    bridge: &str,
    namespaces: &[String],
) -> Result<(), SandboxError> {
    let ip = validate_ip(ip_program)?;
    let mut first_error = None;
    for namespace in namespaces {
        if command_succeeds(&ip, &["netns", "list"]).is_some_and(|output| {
            output
                .lines()
                .any(|line| line.split_whitespace().next() == Some(namespace))
        }) {
            if let Err(error) = checked(&ip, &["netns", "delete", namespace]) {
                first_error.get_or_insert(error);
            }
        }
    }
    if command_succeeds(&ip, &["link", "show", bridge]).is_some() {
        if let Err(error) = checked(&ip, &["link", "delete", bridge]) {
            first_error.get_or_insert(error);
        }
    }
    if namespaces.iter().any(|namespace| {
        command_succeeds(&ip, &["netns", "list"]).is_some_and(|output| {
            output
                .lines()
                .any(|line| line.split_whitespace().next() == Some(namespace))
        })
    }) || command_succeeds(&ip, &["link", "show", bridge]).is_some()
    {
        first_error.get_or_insert_with(|| {
            SandboxError::Runtime("network resources remain after recovery".to_owned())
        });
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn short_token(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))[..10].to_owned()
}

fn project_subnet(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let second = 1 + u16::from(digest[0]) % 254;
    let third = digest[1];
    format!("10.{second}.{third}")
}

fn validate_ip(path: &Path) -> Result<PathBuf, SandboxError> {
    if !path.is_absolute() || path.file_name().and_then(|name| name.to_str()) != Some("ip") {
        return Err(SandboxError::Docker(
            "ip program must be an absolute `ip` path".to_owned(),
        ));
    }
    fs::canonicalize(path).map_err(|source| io_error(path, source))
}

fn checked(program: &Path, arguments: &[&str]) -> Result<(), SandboxError> {
    let output = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()
        .map_err(|source| io_error(program, source))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(SandboxError::Docker(format!(
            "`ip {}` failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn command_succeeds(program: &Path, arguments: &[&str]) -> Option<String> {
    Command::new(program)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
}
