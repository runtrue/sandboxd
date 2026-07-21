mod backend;
mod crypto;
mod error;
mod model;
mod repository;
mod transfer;

pub use backend::LocalArtifactStore;
#[cfg(feature = "s3")]
pub use backend::{S3ArtifactConfig, S3ArtifactStore};
pub use error::ArtifactError;
pub use model::{
    ArtifactLimits, ArtifactScope, GarbageCollectionReport, MaterializedSnapshot,
    PublicationMetrics, SnapshotPublication, SnapshotTransferClaim, SnapshotTransferGrant,
    StagedSnapshotObject, StagedVolumeMetadata,
};
pub use repository::ArtifactStore;
