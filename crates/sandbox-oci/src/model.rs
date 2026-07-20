use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(crate) const LOCK_SCHEMA_VERSION: u32 = 1;
pub(crate) const MAX_SERVICES: usize = 32;
pub(crate) const MAX_NETWORKS: usize = 8;
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
    pub(crate) user: Option<String>,
    #[serde(default)]
    pub(crate) working_dir: Option<String>,
    #[serde(default)]
    pub(crate) read_only: Option<bool>,
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
    pub user: String,
    pub working_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedImage {
    pub source: String,
    pub exact_reference: String,
    pub image_id: String,
    pub operating_system: String,
    pub architecture: String,
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
    pub runtime: String,
    pub memory_bytes_per_service: u64,
    pub cpu_per_service_millis: u32,
    pub pids_per_service: u32,
    pub tmpfs_bytes: u64,
    pub maximum_output_bytes: usize,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            runtime: "runsc".to_owned(),
            memory_bytes_per_service: 128 * 1024 * 1024,
            cpu_per_service_millis: 500,
            pids_per_service: 96,
            tmpfs_bytes: 16 * 1024 * 1024,
            maximum_output_bytes: 1024 * 1024,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct DigestInput<'a> {
    pub(crate) schema_version: u32,
    pub(crate) name: &'a str,
    pub(crate) services: &'a BTreeMap<String, LockedService>,
    pub(crate) networks: &'a BTreeMap<String, LockedNetwork>,
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
            startup_order: &self.startup_order,
            policy: &self.policy,
        }
    }
}
