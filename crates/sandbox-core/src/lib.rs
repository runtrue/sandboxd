mod backend;
mod capability;
mod error;
mod identity;
mod lifecycle;
mod snapshot;
mod specification;

pub use backend::{BackendDescriptor, BackendKind};
pub use capability::{BackendCapabilities, SnapshotPortability};
pub use error::CoreError;
pub use identity::{ContainerId, NetworkId, SandboxId, SnapshotId, WorkerId};
pub use lifecycle::{Lifecycle, LifecycleState};
pub use snapshot::{
    ArtifactDescriptor, ArtifactRole, RestoreRequirements, SnapshotManifest, SnapshotMode,
    SnapshotObject,
};
pub use specification::{
    ContainerDependency, ContainerImage, ContainerSpec, NetworkSpec, ResourceSpec, SandboxSpec,
};
