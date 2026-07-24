mod assignment;
mod attestation;
mod autoscale;
mod backend;
mod capability;
mod error;
mod guest_profile;
mod identity;
mod lifecycle;
mod placement;
mod snapshot;
mod specification;
mod volume;
mod work_order;
mod worker;

pub use assignment::AssignmentEpoch;
pub use attestation::{
    sign_image_attestation, verify_image_attestation, verify_trusted_image_attestation,
    AttestationTrustPolicy, AttestedDescriptor, ImagePreparationAttestation,
    SignedImageAttestation, IMAGE_ATTESTATION_VERSION,
};
pub use autoscale::{
    reconcile as reconcile_worker_pool, AutoscaleDecision, NetworkFeatureTier, PoolObservation,
    PoolPolicy, ServiceLevelPolicy, StorageFeatureTier, WorkerPool, WorkerPoolCatalog,
    WorkerPoolKey, WorkerPoolRequest, MAXIMUM_WORKER_POOLS, WORKER_POOL_CATALOG_VERSION,
};
pub use backend::{BackendDescriptor, BackendKind};
pub use capability::{BackendCapabilities, SnapshotPortability};
pub use error::CoreError;
pub use guest_profile::{
    GuestProfile, GuestProfileIdentity, GuestProfileRestrictions, OCI_COMPAT_GUEST_PROFILE,
    ROOT_GUEST_PROFILE, STRICT_GUEST_PROFILE,
};
pub use identity::{
    ContainerId, NetworkId, SandboxId, SnapshotId, SubjectId, TenantId, VolumeId, WorkerId,
    WorkspaceId,
};
pub use lifecycle::{Lifecycle, LifecycleState};
pub use placement::{
    BoundedFairQueue, LeaseBook, LeaseRejection, LeaseState, PlacementIdentity, PlacementLease,
    QueueLimits, QueueRejection, QueuedWork,
};
pub use snapshot::{
    ArtifactDescriptor, ArtifactRole, RestoreRequirements, RestoreTarget, SnapshotManifest,
    SnapshotMode, SnapshotObject, SNAPSHOT_MANIFEST_VERSION,
};
pub use specification::{
    ContainerDependency, ContainerImage, ContainerSpec, NetworkSpec, ResourceSpec, SandboxSpec,
};
pub use volume::{
    VolumePersistenceClass, VolumeSnapshotDescriptor, VolumeSnapshotPolicy, VolumeSpec,
    MINIMUM_NAMED_VOLUME_BYTES, VOLUME_SPEC_VERSION,
};
pub use work_order::{
    ResourceCeilings, SignedWorkOrder, WorkOrderClaims, WorkOrderOperation,
    MAXIMUM_WORK_ORDER_LIFETIME_MILLIS, WORK_ORDER_VERSION,
};
pub use worker::{
    SandboxResourceDemand, WorkerResourceShape, WorkerState, WORKER_RESOURCE_SHAPE_VERSION,
};
