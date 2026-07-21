use crate::{
    assignment::AssignmentLedger,
    audit::AuditLog,
    authorization::{SandboxKey, TenantScope, WorkOrderVerifier},
};
use runtrue_sandbox_artifact::ArtifactStore;
use runtrue_sandbox_core::WorkerId;
use runtrue_sandbox_gvisor::executor::{GvisorSandbox, ImmutableRootfs};
use runtrue_sandbox_oci::provider::ImageProvider;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc, Mutex},
};

#[derive(Debug, Default, Serialize)]
pub(crate) struct Counters {
    pub(crate) requests: u64,
    pub(crate) completed_runs: u64,
    pub(crate) failed_runs: u64,
    pub(crate) cache_hits: u64,
    pub(crate) cache_misses: u64,
    pub(crate) admission_ms: u128,
    pub(crate) recovered_projects: Vec<String>,
    pub(crate) rejected_connections: u64,
    pub(crate) rejected_requests: u64,
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct TenantCounters {
    pub(crate) requests: u64,
    pub(crate) completed_runs: u64,
    pub(crate) failed_runs: u64,
}

pub(crate) struct DaemonState {
    pub(crate) state_root: PathBuf,
    pub(crate) snapshot_staging_root: PathBuf,
    pub(crate) artifact_store: Arc<dyn ArtifactStore>,
    pub(crate) worker_id: WorkerId,
    pub(crate) image_provider: Arc<dyn ImageProvider>,
    pub(crate) runsc: PathBuf,
    pub(crate) ip: PathBuf,
    pub(crate) assignments: AssignmentLedger,
    pub(crate) audit: AuditLog,
    pub(crate) work_orders: Option<WorkOrderVerifier>,
    pub(crate) cache: Mutex<BTreeMap<String, Arc<ImmutableRootfs>>>,
    pub(crate) active: Mutex<BTreeSet<SandboxKey>>,
    pub(crate) sandboxes: Mutex<BTreeMap<SandboxKey, Arc<Mutex<GvisorSandbox>>>>,
    pub(crate) counters: Mutex<Counters>,
    pub(crate) tenant_counters: Mutex<BTreeMap<TenantScope, TenantCounters>>,
    pub(crate) shutdown: AtomicBool,
}
