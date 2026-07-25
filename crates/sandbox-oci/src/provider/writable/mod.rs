mod config;
mod diff;
mod gvisor;
mod handle;
mod identity;

pub use config::{WritableRootfsConfig, MINIMUM_WRITABLE_ROOT_BYTES};
pub(super) use gvisor::GvisorWritableRootfs;
pub use handle::{WritableRootfs, WritableRootfsExport};
pub use identity::WritableRootfsIdentity;

pub const LOOPBACK_WRITABLE_ROOTFS_PROVIDER_ID: &str = "loopback-overlay-v1";
pub const GVISOR_WRITABLE_ROOTFS_PROVIDER_ID: &str = "gvisor-overlay-v1";
