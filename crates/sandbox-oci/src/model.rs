use runtrue_sandbox_core::{
    GuestProfileIdentity, VolumePersistenceClass, VolumeSnapshotPolicy, VolumeSpec,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};

pub(crate) const LOCK_SCHEMA_VERSION: u32 = 6;
pub(crate) const MAX_SERVICES: usize = 32;
pub(crate) const MAX_NETWORKS: usize = 8;
pub(crate) const MAX_VOLUMES: usize = 128;
pub(crate) const MAX_ENVIRONMENT: usize = 128;
pub(crate) const MAX_ARGUMENTS: usize = 256;
pub(crate) const MAX_VALUE_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ComposeInput {
    #[serde(default)]
    pub(crate) name: Option<String>,
    pub(crate) services: BTreeMap<String, ServiceInput>,
    #[serde(default)]
    pub(crate) networks: BTreeMap<String, NetworkInput>,
    #[serde(default)]
    pub(crate) volumes: BTreeMap<String, VolumeInput>,
    #[serde(default, rename = "x-runtrue-guest-profile")]
    pub(crate) guest_profile: Option<String>,
    #[serde(default, rename = "x-runtrue-network")]
    pub(crate) network_policy: NetworkPolicy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VolumeInput {
    pub(crate) persistence_class: VolumePersistenceClass,
    #[serde(default)]
    pub(crate) snapshot_policy: Option<VolumeSnapshotPolicy>,
    #[serde(default)]
    pub(crate) quota_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) content_digest: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceVolumeInput {
    pub(crate) source: String,
    pub(crate) target: String,
    #[serde(default)]
    pub(crate) read_only: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkInput {
    #[serde(default)]
    pub(crate) internal: Option<bool>,
    #[serde(default)]
    pub(crate) driver: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceInput {
    pub(crate) image: String,
    #[serde(default)]
    pub(crate) command: Vec<String>,
    #[serde(default)]
    pub(crate) entrypoint: Vec<String>,
    #[serde(default)]
    pub(crate) environment: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) depends_on: BTreeMap<String, DependencyInput>,
    #[serde(default)]
    pub(crate) healthcheck: Option<HealthcheckInput>,
    #[serde(default)]
    pub(crate) networks: Vec<String>,
    #[serde(default)]
    pub(crate) working_dir: Option<String>,
    #[serde(default)]
    pub(crate) read_only: Option<bool>,
    #[serde(default)]
    pub(crate) volumes: Vec<ServiceVolumeInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DependencyInput {
    pub(crate) condition: DependencyCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DependencyCondition {
    #[serde(rename = "service_started")]
    Started,
    #[serde(rename = "service_healthy")]
    Healthy,
    #[serde(rename = "service_completed_successfully")]
    CompletedSuccessfully,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HealthcheckInput {
    pub(crate) test: Vec<String>,
    #[serde(default = "default_interval_ms")]
    pub(crate) interval_ms: u64,
    #[serde(default = "default_timeout_ms")]
    pub(crate) timeout_ms: u64,
    #[serde(default = "default_retries")]
    pub(crate) retries: u32,
}

const fn default_interval_ms() -> u64 {
    100
}

const fn default_timeout_ms() -> u64 {
    1_000
}

const fn default_retries() -> u32 {
    30
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyLock {
    pub schema_version: u32,
    pub topology_digest: String,
    pub name: String,
    pub services: BTreeMap<String, LockedService>,
    pub networks: BTreeMap<String, LockedNetwork>,
    pub volumes: BTreeMap<String, LockedVolume>,
    pub startup_order: Vec<String>,
    pub policy: SandboxPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedService {
    pub image: LockedImage,
    pub command: Vec<String>,
    pub entrypoint: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub depends_on: BTreeMap<String, DependencyCondition>,
    pub healthcheck: Option<LockedHealthcheck>,
    pub networks: Vec<String>,
    pub working_dir: String,
    pub root_filesystem: RootFilesystemMode,
    pub volumes: Vec<VolumeSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedVolume {
    pub persistence_class: VolumePersistenceClass,
    pub snapshot_policy: VolumeSnapshotPolicy,
    pub quota_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootFilesystemMode {
    ReadOnly,
    Writable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedImage {
    pub source: String,
    pub exact_reference: String,
    pub image_id: String,
    pub index: Option<LockedDescriptor>,
    pub manifest: LockedDescriptor,
    pub config: LockedDescriptor,
    pub layers: Vec<LockedDescriptor>,
    pub operating_system: String,
    pub architecture: String,
    pub variant: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedNetwork {
    pub internal: bool,
    pub driver: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedHealthcheck {
    pub command: Vec<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub retries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPolicy {
    pub guest_profile: GuestProfileIdentity,
    pub runtime: String,
    pub memory_bytes_per_service: u64,
    pub cpu_per_service_millis: u32,
    pub pids_per_service: u32,
    pub tmpfs_bytes: u64,
    pub writable_root_bytes_per_service: u64,
    pub maximum_output_bytes: usize,
    pub network: NetworkPolicy,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            guest_profile: runtrue_sandbox_core::GuestProfile::strict().identity,
            runtime: "runsc".to_owned(),
            memory_bytes_per_service: 128 * 1024 * 1024,
            cpu_per_service_millis: 500,
            pids_per_service: 96,
            tmpfs_bytes: 16 * 1024 * 1024,
            writable_root_bytes_per_service: 64 * 1024 * 1024,
            maximum_output_bytes: 1024 * 1024,
            network: NetworkPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub profile: NetworkProfile,
    #[serde(default)]
    pub http_rules: Vec<HttpEgressRule>,
    #[serde(default)]
    pub tcp_rules: Vec<TcpEgressRule>,
    #[serde(default)]
    pub dns: DnsPolicy,
    #[serde(default)]
    pub limits: EgressLimits,
    #[serde(default)]
    pub ingress: Vec<IngressRule>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            profile: NetworkProfile::None,
            http_rules: Vec::new(),
            tcp_rules: Vec::new(),
            dns: DnsPolicy::default(),
            limits: EgressLimits::default(),
            ingress: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProfile {
    #[default]
    None,
    HttpConnect,
    RestrictedTcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpEgressRule {
    pub domains: Vec<String>,
    pub schemes: Vec<HttpScheme>,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpEgressRule {
    pub destination_cidr: String,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsPolicy {
    pub maximum_queries: u32,
    pub maximum_response_bytes: u32,
    pub maximum_total_bytes: u64,
}

impl Default for DnsPolicy {
    fn default() -> Self {
        Self {
            maximum_queries: 256,
            maximum_response_bytes: 4_096,
            maximum_total_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressLimits {
    pub maximum_connections: u32,
    pub maximum_bytes: u64,
    pub bandwidth_bytes_per_second: u64,
}

impl Default for EgressLimits {
    fn default() -> Self {
        Self {
            maximum_connections: 32,
            maximum_bytes: 64 * 1024 * 1024,
            bandwidth_bytes_per_second: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressRule {
    pub service: String,
    pub container_port: u16,
}

impl NetworkPolicy {
    pub fn validate(&self, services: &BTreeMap<String, LockedService>) -> Result<(), String> {
        if self.http_rules.len() > 64 || self.tcp_rules.len() > 64 || self.ingress.len() > 16 {
            return Err("network policy contains too many rules".to_owned());
        }
        match self.profile {
            NetworkProfile::None if !self.http_rules.is_empty() || !self.tcp_rules.is_empty() => {
                return Err("the none profile cannot contain egress rules".to_owned());
            }
            NetworkProfile::HttpConnect
                if self.http_rules.is_empty() || !self.tcp_rules.is_empty() =>
            {
                return Err(
                    "the http_connect profile requires HTTP rules and forbids TCP rules".to_owned(),
                );
            }
            NetworkProfile::RestrictedTcp
                if self.tcp_rules.is_empty() || !self.http_rules.is_empty() =>
            {
                return Err(
                    "the restricted_tcp profile requires TCP rules and forbids HTTP rules"
                        .to_owned(),
                );
            }
            _ => {}
        }
        for rule in &self.http_rules {
            if rule.domains.is_empty()
                || rule.domains.len() > 64
                || rule.schemes.is_empty()
                || rule.schemes.len() > 2
                || rule.ports.is_empty()
                || rule.ports.len() > 32
                || rule.ports.contains(&0)
                || has_duplicates(&rule.domains)
                || has_duplicates(&rule.schemes)
                || has_duplicates(&rule.ports)
            {
                return Err("HTTP egress rule has invalid or repeated values".to_owned());
            }
            for domain in &rule.domains {
                validate_domain_pattern(domain)?;
            }
        }
        for rule in &self.tcp_rules {
            validate_cidr(&rule.destination_cidr)?;
            let (network, prefix) = rule
                .destination_cidr
                .split_once('/')
                .expect("validated CIDR");
            let network = network.parse::<IpAddr>().expect("validated CIDR address");
            let prefix = prefix.parse::<u8>().expect("validated CIDR prefix");
            let sandbox_address = "10.0.0.1".parse().expect("static sandbox address");
            if (network.is_ipv4() && prefix < 8)
                || (network.is_ipv6() && prefix < 32)
                || matches!(network, IpAddr::V4(address) if address.octets()[0] == 10)
                || cidr_contains(&rule.destination_cidr, sandbox_address).unwrap_or(false)
            {
                return Err(
                    "TCP destination CIDR is unrestricted or overlaps sandbox infrastructure"
                        .to_owned(),
                );
            }
            if rule.ports.is_empty()
                || rule.ports.len() > 32
                || rule.ports.contains(&0)
                || rule.ports.iter().any(|port| matches!(port, 53 | 853))
                || has_duplicates(&rule.ports)
            {
                return Err("TCP egress rule has invalid or repeated ports".to_owned());
            }
        }
        if self.dns.maximum_queries == 0
            || self.dns.maximum_queries > 65_536
            || self.dns.maximum_response_bytes < 512
            || self.dns.maximum_response_bytes > 65_535
            || self.dns.maximum_total_bytes < u64::from(self.dns.maximum_response_bytes)
            || self.dns.maximum_total_bytes > 1024 * 1024 * 1024
            || self.limits.maximum_connections == 0
            || self.limits.maximum_connections > 4_096
            || self.limits.maximum_bytes == 0
            || self.limits.maximum_bytes > 1024 * 1024 * 1024 * 1024
            || self.limits.bandwidth_bytes_per_second == 0
            || self.limits.bandwidth_bytes_per_second > 10 * 1024 * 1024 * 1024
        {
            return Err("network limits are outside their accepted bounds".to_owned());
        }
        let mut ingress = std::collections::BTreeSet::new();
        for rule in &self.ingress {
            if rule.container_port == 0
                || !services.contains_key(&rule.service)
                || !ingress.insert((rule.service.as_str(), rule.container_port))
            {
                return Err(
                    "ingress rule has an unknown service, invalid port, or duplicate".to_owned(),
                );
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn permits_http(&self, domain: &str, scheme: HttpScheme, port: u16) -> bool {
        self.profile == NetworkProfile::HttpConnect
            && canonical_domain(domain).is_some_and(|domain| {
                self.http_rules.iter().any(|rule| {
                    rule.schemes.contains(&scheme)
                        && rule.ports.contains(&port)
                        && rule
                            .domains
                            .iter()
                            .any(|pattern| domain_matches(pattern, domain))
                })
            })
    }

    #[must_use]
    pub fn permits_dns_name(&self, domain: &str) -> bool {
        canonical_domain(domain).is_some_and(|domain| {
            self.http_rules
                .iter()
                .flat_map(|rule| &rule.domains)
                .any(|pattern| domain_matches(pattern, domain))
        })
    }

    #[must_use]
    pub fn permits_tcp(&self, destination: IpAddr, port: u16) -> bool {
        self.profile == NetworkProfile::RestrictedTcp
            && self.tcp_rules.iter().any(|rule| {
                rule.ports.contains(&port)
                    && cidr_contains(&rule.destination_cidr, destination).unwrap_or(false)
            })
    }
}

#[must_use]
pub fn is_protected_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let value = u32::from(address);
            address.is_unspecified()
                || address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || (value & 0xffc0_0000) == 0x6440_0000 // 100.64.0.0/10
                || (value & 0xffff_0000) == 0xc612_0000 // 198.18.0.0/15
                || (value & 0xff00_0000) == 0x0000_0000 // current network
                || (value & 0xf000_0000) == 0xf000_0000 // reserved
        }
        IpAddr::V6(address) => {
            let value = u128::from(address);
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || (value >> 121) == 0x7e // fc00::/7
                || (value >> 118) == 0x3fa // fe80::/10
                || (value >> 96) == 0x2001_0db8 // documentation
        }
    }
}

fn has_duplicates<T: Ord + Clone>(values: &[T]) -> bool {
    values
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != values.len()
}

fn validate_domain_pattern(pattern: &str) -> Result<(), String> {
    let domain = pattern.strip_prefix("*.").unwrap_or(pattern);
    if canonical_domain(domain) != Some(domain) || domain.parse::<IpAddr>().is_ok() {
        return Err(format!("domain pattern `{pattern}` is invalid"));
    }
    Ok(())
}

fn canonical_domain(domain: &str) -> Option<&str> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty()
        || domain.len() > 253
        || domain.bytes().any(|byte| byte.is_ascii_uppercase())
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        None
    } else {
        Some(domain)
    }
}

fn domain_matches(pattern: &str, domain: &str) -> bool {
    pattern
        .strip_prefix("*.")
        .map_or(pattern == domain, |suffix| {
            domain.len() > suffix.len()
                && domain.ends_with(suffix)
                && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
        })
}

fn validate_cidr(value: &str) -> Result<(), String> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| format!("destination CIDR `{value}` is invalid"))?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| format!("destination CIDR `{value}` is invalid"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| format!("destination CIDR `{value}` is invalid"))?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if prefix > maximum || network_address(address, prefix) != address {
        return Err(format!("destination CIDR `{value}` is not canonical"));
    }
    Ok(())
}

fn cidr_contains(value: &str, destination: IpAddr) -> Result<bool, String> {
    validate_cidr(value)?;
    let (address, prefix) = value.split_once('/').expect("validated CIDR");
    let address = address.parse::<IpAddr>().expect("validated address");
    let prefix = prefix.parse::<u8>().expect("validated prefix");
    Ok(address.is_ipv4() == destination.is_ipv4()
        && network_address(destination, prefix) == address)
}

fn network_address(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4((u32::from(address) & mask).into())
        }
        IpAddr::V6(address) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6((u128::from(address) & mask).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_policy() -> NetworkPolicy {
        NetworkPolicy {
            profile: NetworkProfile::HttpConnect,
            http_rules: vec![HttpEgressRule {
                domains: vec![
                    "api.example.com".to_owned(),
                    "*.services.example".to_owned(),
                ],
                schemes: vec![HttpScheme::Https],
                ports: vec![443],
            }],
            ..NetworkPolicy::default()
        }
    }

    #[test]
    fn http_policy_matches_complete_domain_labels() {
        let policy = http_policy();
        policy.validate(&BTreeMap::new()).expect("valid policy");
        assert!(policy.permits_http("api.example.com", HttpScheme::Https, 443));
        assert!(policy.permits_http("v1.services.example", HttpScheme::Https, 443));
        assert!(!policy.permits_http("services.example", HttpScheme::Https, 443));
        assert!(!policy.permits_http("evilservices.example", HttpScheme::Https, 443));
        assert!(!policy.permits_http("api.example.com", HttpScheme::Http, 443));
        assert!(!policy.permits_http("127.0.0.1", HttpScheme::Https, 443));
    }

    #[test]
    fn restricted_tcp_requires_canonical_cidrs() {
        let mut policy = NetworkPolicy {
            profile: NetworkProfile::RestrictedTcp,
            tcp_rules: vec![TcpEgressRule {
                destination_cidr: "203.0.113.0/24".to_owned(),
                ports: vec![5432],
            }],
            ..NetworkPolicy::default()
        };
        policy.validate(&BTreeMap::new()).expect("valid policy");
        assert!(policy.permits_tcp("203.0.113.7".parse().expect("IP"), 5432));
        assert!(!policy.permits_tcp("203.0.114.7".parse().expect("IP"), 5432));
        policy.tcp_rules[0].destination_cidr = "203.0.113.7/24".to_owned();
        assert!(policy.validate(&BTreeMap::new()).is_err());
        policy.tcp_rules[0].destination_cidr = "10.20.0.0/16".to_owned();
        assert!(policy.validate(&BTreeMap::new()).is_err());
    }

    #[test]
    fn protected_destinations_cover_worker_and_metadata_ranges() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(
                is_protected_destination(address.parse().expect("IP")),
                "{address}"
            );
        }
        assert!(!is_protected_destination("8.8.8.8".parse().expect("IP")));
        assert!(!is_protected_destination(
            "2606:4700:4700::1111".parse().expect("IP")
        ));
    }
}

#[derive(Serialize)]
pub(crate) struct DigestInput<'a> {
    pub(crate) schema_version: u32,
    pub(crate) name: &'a str,
    pub(crate) services: &'a BTreeMap<String, LockedService>,
    pub(crate) networks: &'a BTreeMap<String, LockedNetwork>,
    pub(crate) volumes: &'a BTreeMap<String, LockedVolume>,
    pub(crate) startup_order: &'a [String],
    pub(crate) policy: &'a SandboxPolicy,
}

impl TopologyLock {
    #[must_use]
    pub(crate) fn digest_input(&self) -> DigestInput<'_> {
        DigestInput {
            schema_version: self.schema_version,
            name: &self.name,
            services: &self.services,
            networks: &self.networks,
            volumes: &self.volumes,
            startup_order: &self.startup_order,
            policy: &self.policy,
        }
    }
}
