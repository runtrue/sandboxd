mod local;
#[cfg(feature = "s3")]
mod s3;

pub use local::LocalArtifactStore;
#[cfg(feature = "s3")]
pub use s3::{S3ArtifactConfig, S3ArtifactStore};

use crate::ArtifactError;
use std::{
    path::Path,
    time::{Instant, SystemTime},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PutStatus {
    Created,
    Reused,
}

#[derive(Debug, Clone)]
pub(crate) struct StoredObject {
    pub key: String,
    pub modified: SystemTime,
}

pub(crate) trait BlobBackend: Send + Sync {
    fn put_if_absent(
        &self,
        key: &str,
        source: &Path,
        deadline: Instant,
    ) -> Result<PutStatus, ArtifactError>;
    fn get(
        &self,
        key: &str,
        destination: &Path,
        maximum_bytes: u64,
        deadline: Instant,
    ) -> Result<u64, ArtifactError>;
    fn exists(&self, key: &str, deadline: Instant) -> Result<bool, ArtifactError>;
    fn list(
        &self,
        prefix: &str,
        maximum_entries: usize,
        deadline: Instant,
    ) -> Result<Vec<StoredObject>, ArtifactError>;
    fn delete(&self, key: &str, deadline: Instant) -> Result<(), ArtifactError>;
}
