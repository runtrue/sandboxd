use crate::GuestProfile;
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

impl SnapshotPortability {
    #[must_use]
    pub const fn permits_cross_worker(self) -> bool {
        matches!(self, Self::CrossWorkerSameBackend | Self::CrossBackend)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendCapabilities {
    pub multi_container: bool,
    pub pause_resume: bool,
    pub live_snapshot: bool,
    pub stop_and_snapshot: bool,
    pub preserves_internal_connections: bool,
    pub writable_root_filesystems: bool,
    pub writable_root_snapshots: bool,
    pub snapshot_portability: SnapshotPortability,
    pub maximum_containers: u16,
    pub maximum_writable_root_bytes: u64,
    pub guest_profiles: Vec<GuestProfile>,
}

impl BackendCapabilities {
    #[must_use]
    pub const fn gvisor_snapshot(
        maximum_containers: u16,
        maximum_writable_root_bytes: u64,
        snapshot_portability: SnapshotPortability,
        guest_profiles: Vec<GuestProfile>,
    ) -> Self {
        Self {
            multi_container: true,
            pause_resume: true,
            live_snapshot: true,
            stop_and_snapshot: true,
            preserves_internal_connections: true,
            writable_root_filesystems: true,
            writable_root_snapshots: true,
            snapshot_portability,
            maximum_containers,
            maximum_writable_root_bytes,
            guest_profiles,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gvisor_snapshot_capability_is_limited_by_the_artifact_provider() {
        let capabilities = BackendCapabilities::gvisor_snapshot(
            64,
            16 * 1024 * 1024 * 1024,
            SnapshotPortability::SameWorker,
            vec![GuestProfile::strict()],
        );
        assert_eq!(
            capabilities.snapshot_portability,
            SnapshotPortability::SameWorker
        );
        assert!(capabilities.live_snapshot);
        assert!(capabilities.stop_and_snapshot);
        assert!(capabilities.writable_root_filesystems);
        assert!(capabilities.writable_root_snapshots);
    }
}
