mod config;
mod diff;
mod handle;
mod identity;
mod loopback;

pub use config::{WritableRootfsConfig, MINIMUM_WRITABLE_ROOT_BYTES};
pub use handle::{WritableRootfs, WritableRootfsExport};
pub use identity::WritableRootfsIdentity;
pub(super) use loopback::LoopbackWritableRootfs;

pub const LOOPBACK_WRITABLE_ROOTFS_PROVIDER_ID: &str = "loopback-overlay-v1";
