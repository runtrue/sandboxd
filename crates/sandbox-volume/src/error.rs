use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum VolumeError {
    #[error("invalid volume request: {0}")]
    Invalid(String),
    #[error("volume access is denied: {0}")]
    AccessDenied(String),
    #[error("volume already exists: {0}")]
    AlreadyExists(String),
    #[error("volume was not found: {0}")]
    NotFound(String),
    #[error("volume provider does not support: {0}")]
    Unsupported(String),
    #[error("volume integrity verification failed: {0}")]
    Integrity(String),
    #[error("volume operation timed out: {0}")]
    Timeout(String),
    #[error("volume path `{path}` failed: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("volume mount operation failed: {0}")]
    Mount(String),
}

pub(crate) fn io_error(path: impl Into<PathBuf>, source: std::io::Error) -> VolumeError {
    VolumeError::Io {
        path: path.into(),
        source,
    }
}
