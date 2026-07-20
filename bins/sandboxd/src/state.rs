use runtrue_sandbox_gvisor::executor::{AdmittedRootfs, GvisorSandbox};
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
}

pub(crate) struct DaemonState {
    pub(crate) state_root: PathBuf,
    pub(crate) snapshot_root: PathBuf,
    pub(crate) image_store: PathBuf,
    pub(crate) runsc: PathBuf,
    pub(crate) ip: PathBuf,
    pub(crate) cache: Mutex<BTreeMap<String, Arc<AdmittedRootfs>>>,
    pub(crate) active: Mutex<BTreeSet<String>>,
    pub(crate) sandboxes: Mutex<BTreeMap<String, Arc<Mutex<GvisorSandbox>>>>,
    pub(crate) counters: Mutex<Counters>,
    pub(crate) shutdown: AtomicBool,
}
