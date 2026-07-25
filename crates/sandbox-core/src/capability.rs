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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCapabilities {
    pub http_connect_proxy: bool,
    pub reverse_http_ingress: bool,
    pub restricted_tcp: bool,
    pub transparent_tcp: bool,
    pub udp: bool,
}

impl NetworkCapabilities {
    pub const LOOPBACK: Self = Self {
        http_connect_proxy: false,
        reverse_http_ingress: false,
        restricted_tcp: false,
        transparent_tcp: false,
        udp: false,
    };

    pub const USERSPACE: Self = Self {
        http_connect_proxy: true,
        reverse_http_ingress: true,
        restricted_tcp: false,
        transparent_tcp: false,
        udp: false,
    };

    pub const PRIVATE: Self = Self {
        http_connect_proxy: true,
        reverse_http_ingress: true,
        restricted_tcp: true,
        transparent_tcp: false,
        udp: false,
    };
}

impl Default for NetworkCapabilities {
    fn default() -> Self {
        Self::LOOPBACK
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
    pub named_volumes: bool,
    pub artifact_volumes: bool,
    pub secret_volumes: bool,
    pub volume_snapshots: bool,
    pub volume_snapshot_portability: SnapshotPortability,
    pub snapshot_portability: SnapshotPortability,
    pub maximum_containers: u16,
    pub maximum_writable_root_bytes: u64,
    pub guest_profiles: Vec<GuestProfile>,
    #[serde(default)]
    pub network: NetworkCapabilities,
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
            named_volumes: true,
            artifact_volumes: true,
            secret_volumes: true,
            volume_snapshots: true,
            volume_snapshot_portability: snapshot_portability,
            snapshot_portability,
            maximum_containers,
            maximum_writable_root_bytes,
            guest_profiles,
            network: NetworkCapabilities::LOOPBACK,
        }
    }

    #[must_use]
    pub const fn with_network(mut self, network: NetworkCapabilities) -> Self {
        self.network = network;
        self
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
        assert_eq!(capabilities.network, NetworkCapabilities::LOOPBACK);
        let mut legacy = serde_json::to_value(&capabilities).expect("serialize capabilities");
        legacy
            .as_object_mut()
            .expect("capability object")
            .remove("network");
        let decoded: BackendCapabilities =
            serde_json::from_value(legacy).expect("decode legacy capabilities");
        assert_eq!(decoded.network, NetworkCapabilities::LOOPBACK);
    }
}
