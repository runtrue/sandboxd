use super::proxy::PolicyServices;
use crate::{error::io_error, model::TopologyLock, SandboxError};
use runtrue_sandbox_oci::{EgressLimits, NetworkProfile, TcpEgressRule};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    io::Write as _,
    net::IpAddr,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[derive(Debug)]
pub(super) struct ProjectNetwork {
    ip: PathBuf,
    nft: PathBuf,
    pub(super) bridge: String,
    nft_table: String,
    sandbox: ServiceNetwork,
    policy_services: Option<PolicyServices>,
}

#[derive(Debug)]
pub(super) struct ServiceNetwork {
    pub(super) namespace: String,
    pub(super) hosts_path: PathBuf,
    pub(super) resolv_path: PathBuf,
    pub(super) http_proxy: Option<String>,
    pub(super) no_proxy: Option<String>,
}

impl ProjectNetwork {
    pub(super) fn create(
        ip_program: &Path,
        nft_program: &Path,
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
        let nft = if lock.policy.network.profile == NetworkProfile::None
            && lock.policy.network.ingress.is_empty()
        {
            nft_program.to_path_buf()
        } else {
            validate_nft(nft_program)?
        };
        let token = short_token(project);
        let bridge = format!("rtb{token}");
        checked(&ip, &["link", "add", &bridge, "type", "bridge"])?;
        if let Err(error) = checked(&ip, &["link", "set", &bridge, "up"]) {
            let _ = checked(&ip, &["link", "delete", &bridge]);
            return Err(error);
        }
        let mut network = Self {
            ip,
            nft,
            bridge,
            nft_table: nft_table_name(project),
            sandbox: ServiceNetwork {
                namespace: namespace_name(project),
                hosts_path: state.join("hosts"),
                resolv_path: state.join("resolv.conf"),
                http_proxy: None,
                no_proxy: None,
            },
            policy_services: None,
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

    pub(super) fn set_ingress_active(&self, active: bool) {
        if let Some(services) = &self.policy_services {
            services.set_active(active);
        }
    }

    pub(super) fn ingress_endpoints(&self) -> &[super::proxy::IngressEndpoint] {
        self.policy_services
            .as_ref()
            .map_or(&[], PolicyServices::endpoints)
    }

    pub(super) fn cleanup(&mut self) -> Result<(), SandboxError> {
        let mut first_error = None;
        self.policy_services = None;
        if let Err(error) = delete_nft_table(&self.nft, &self.nft_table) {
            first_error.get_or_insert(error);
        }
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
        let gateway = format!("{}.1", project_subnet(project));
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
        let external = lock.policy.network.profile != NetworkProfile::None;
        let has_ingress = !lock.policy.network.ingress.is_empty();
        if external || has_ingress {
            checked(
                &self.ip,
                &["addr", "add", &format!("{gateway}/24"), "dev", &self.bridge],
            )?;
        }
        if external {
            checked(
                &self.ip,
                &["-n", &namespace, "route", "add", "default", "via", &gateway],
            )?;
            enable_forwarding(&self.bridge)?;
        }
        if external || has_ingress {
            install_nft_policy(
                &self.nft,
                &self.nft_table,
                &address,
                &gateway,
                &lock.policy.network.profile,
                &lock.policy.network.tcp_rules,
                &lock.policy.network.limits,
            )?;
        }
        let mut hosts = String::from("127.0.0.1 localhost\n");
        for peer in lock.services.keys() {
            hosts.push_str(&format!("127.0.0.1 {peer}\n"));
        }
        fs::write(&self.sandbox.hosts_path, hosts)
            .map_err(|source| io_error(&self.sandbox.hosts_path, source))?;
        fs::set_permissions(&self.sandbox.hosts_path, fs::Permissions::from_mode(0o444))
            .map_err(|source| io_error(&self.sandbox.hosts_path, source))?;
        let resolv = if !external {
            "options attempts:1 timeout:1\n".to_owned()
        } else {
            format!("nameserver {gateway}\noptions attempts:1 timeout:1 single-request\n")
        };
        fs::write(&self.sandbox.resolv_path, resolv)
            .map_err(|source| io_error(&self.sandbox.resolv_path, source))?;
        fs::set_permissions(&self.sandbox.resolv_path, fs::Permissions::from_mode(0o444))
            .map_err(|source| io_error(&self.sandbox.resolv_path, source))?;
        if external || has_ingress {
            let gateway_address = gateway
                .parse::<IpAddr>()
                .map_err(|error| SandboxError::Runtime(format!("parse policy gateway: {error}")))?;
            let guest_address = address
                .parse::<IpAddr>()
                .map_err(|error| SandboxError::Runtime(format!("parse guest address: {error}")))?;
            self.policy_services =
                PolicyServices::start(gateway_address, guest_address, &lock.policy.network)?;
            if lock.policy.network.profile == NetworkProfile::HttpConnect {
                self.sandbox.http_proxy = Some(format!("http://{gateway}:3128"));
                self.sandbox.no_proxy = Some(
                    std::iter::once("localhost")
                        .chain(std::iter::once("127.0.0.1"))
                        .chain(lock.services.keys().map(String::as_str))
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
        }
        Ok(())
    }
}

pub(super) fn planned_resources(
    project: &str,
    lock: &TopologyLock,
) -> (String, Vec<String>, String) {
    let bridge = bridge_name(project);
    let _ = lock;
    let namespaces = vec![namespace_name(project)];
    (bridge, namespaces, nft_table_name(project))
}

pub(super) fn bridge_name(project: &str) -> String {
    format!("rtb{}", short_token(project))
}

pub(super) fn namespace_name(project: &str) -> String {
    format!("rtn{}", short_token(project))
}

pub(super) fn recover(
    ip_program: &Path,
    nft_program: &Path,
    bridge: &str,
    namespaces: &[String],
    nft_table: &str,
) -> Result<(), SandboxError> {
    let ip = validate_ip(ip_program)?;
    let nft = nft_program.to_path_buf();
    let mut first_error = None;
    if nft_table != nft_table_from_bridge(bridge)? {
        return Err(SandboxError::Runtime(
            "recovery nftables identity does not match its bridge".to_owned(),
        ));
    }
    if let Err(error) = delete_nft_table(&nft, nft_table) {
        first_error.get_or_insert(error);
    }
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

pub(super) fn nft_table_name(project: &str) -> String {
    format!("rtn_{}", short_token(project))
}

fn nft_table_from_bridge(bridge: &str) -> Result<String, SandboxError> {
    let token = bridge.strip_prefix("rtb").ok_or_else(|| {
        SandboxError::Runtime("recovery bridge has an invalid policy identity".to_owned())
    })?;
    if token.len() != 10 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SandboxError::Runtime(
            "recovery bridge has an invalid policy identity".to_owned(),
        ));
    }
    Ok(format!("rtn_{token}"))
}

fn validate_ip(path: &Path) -> Result<PathBuf, SandboxError> {
    if !path.is_absolute() || path.file_name().and_then(|name| name.to_str()) != Some("ip") {
        return Err(SandboxError::Docker(
            "ip program must be an absolute `ip` path".to_owned(),
        ));
    }
    fs::canonicalize(path).map_err(|source| io_error(path, source))
}

fn validate_nft(path: &Path) -> Result<PathBuf, SandboxError> {
    if !path.is_absolute() || path.file_name().and_then(|name| name.to_str()) != Some("nft") {
        return Err(SandboxError::Runtime(
            "nft program must be an absolute `nft` path".to_owned(),
        ));
    }
    fs::canonicalize(path).map_err(|source| io_error(path, source))
}

fn enable_forwarding(bridge: &str) -> Result<(), SandboxError> {
    let path = PathBuf::from(format!("/proc/sys/net/ipv4/conf/{bridge}/forwarding"));
    fs::write(&path, b"1\n").map_err(|source| io_error(path, source))
}

fn install_nft_policy(
    nft: &Path,
    table: &str,
    guest_address: &str,
    gateway: &str,
    profile: &NetworkProfile,
    tcp_rules: &[TcpEgressRule],
    limits: &EgressLimits,
) -> Result<(), SandboxError> {
    let mut rules = format!(
        "add table inet {table}\n\
         add chain inet {table} input {{ type filter hook input priority -10; policy accept; }}\n\
         add chain inet {table} forward {{ type filter hook forward priority -10; policy accept; }}\n\
         add rule inet {table} input ip saddr {guest_address} ct state established,related accept\n\
         add rule inet {table} input ip saddr {guest_address} ip daddr {gateway} udp dport 53 accept\n"
    );
    match profile {
        NetworkProfile::HttpConnect => {
            rules.push_str(&format!(
                "add rule inet {table} input ip saddr {guest_address} ip daddr {gateway} tcp dport 3128 accept\n\
                 add rule inet {table} input ip saddr {guest_address} drop\n\
                 add rule inet {table} forward ip saddr {guest_address} drop\n"
            ));
        }
        NetworkProfile::RestrictedTcp => {
            rules.push_str(&format!(
                "add rule inet {table} input ip saddr {guest_address} drop\n\
                 add set inet {table} connection_limit {{ type ipv4_addr; flags dynamic; }}\n\
                 add rule inet {table} forward ip saddr {guest_address} ip daddr 10.0.0.0/8 drop\n\
                 add rule inet {table} forward ip saddr {guest_address} ct state new add @connection_limit {{ ip saddr ct count over {} }} drop\n\
                 add rule inet {table} forward ip saddr {guest_address} quota over {} bytes drop\n\
                 add rule inet {table} forward ip saddr {guest_address} limit rate over {} bytes/second drop\n",
                limits.maximum_connections,
                limits.maximum_bytes,
                limits.bandwidth_bytes_per_second,
            ));
            for rule in tcp_rules {
                let family = if rule.destination_cidr.contains(':') {
                    "ip6"
                } else {
                    "ip"
                };
                let ports = rule
                    .ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                rules.push_str(&format!(
                    "add rule inet {table} forward ip saddr {guest_address} {family} daddr {} tcp dport {{ {ports} }} accept\n",
                    rule.destination_cidr
                ));
            }
            rules.push_str(&format!(
                "add rule inet {table} forward ip saddr {guest_address} drop\n\
                 add chain inet {table} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}\n\
                 add rule inet {table} postrouting ip saddr {guest_address} masquerade\n"
            ));
        }
        NetworkProfile::None => {
            rules.push_str(&format!(
                "add rule inet {table} input ip saddr {guest_address} drop\n\
                 add rule inet {table} forward ip saddr {guest_address} drop\n"
            ));
        }
    }
    nft_batch(nft, &rules)
}

fn delete_nft_table(nft: &Path, table: &str) -> Result<(), SandboxError> {
    let output = Command::new(nft)
        .args(["list", "table", "inet", table])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()
        .map_err(|source| io_error(nft, source))?;
    if output.status.success() {
        nft_batch(nft, &format!("delete table inet {table}\n"))?;
    } else if !String::from_utf8_lossy(&output.stderr).contains("No such file or directory") {
        return Err(SandboxError::Runtime(format!(
            "inspect nftables sandbox policy: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn nft_batch(nft: &Path, input: &str) -> Result<(), SandboxError> {
    let mut child = Command::new(nft)
        .args(["-f", "-"])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| io_error(nft, source))?;
    child
        .stdin
        .take()
        .expect("nft stdin")
        .write_all(input.as_bytes())
        .map_err(|source| io_error(nft, source))?;
    let output = child
        .wait_with_output()
        .map_err(|source| io_error(nft, source))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(SandboxError::Runtime(format!(
            "install nftables sandbox policy: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
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
