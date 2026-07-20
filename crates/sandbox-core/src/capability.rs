use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotPortability {
    None,
    SameWorker,
    SameBackend,
    CrossWorkerSameBackend,
    CrossBackend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendCapabilities {
    pub multi_container: bool,
    pub pause_resume: bool,
    pub live_snapshot: bool,
    pub stop_and_snapshot: bool,
    pub preserves_internal_connections: bool,
    pub snapshot_portability: SnapshotPortability,
    pub maximum_containers: u16,
}

impl BackendCapabilities {
    #[must_use]
    pub const fn gvisor_local_snapshot(maximum_containers: u16) -> Self {
        Self {
            multi_container: true,
            pause_resume: true,
            live_snapshot: true,
            stop_and_snapshot: true,
            preserves_internal_connections: true,
            snapshot_portability: SnapshotPortability::SameWorker,
            maximum_containers,
        }
    }
}
