use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("artifact input is invalid: {0}")]
    Invalid(String),
    #[error("artifact access is denied: {0}")]
    AccessDenied(String),
    #[error("artifact already exists: {0}")]
    AlreadyExists(String),
    #[error("artifact was not found: {0}")]
    NotFound(String),
    #[error("artifact integrity verification failed: {0}")]
    Integrity(String),
    #[error("artifact operation timed out: {0}")]
    Timeout(String),
    #[error("artifact storage operation failed: {0}")]
    Storage(String),
    #[error("artifact path `{path}` failed: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub(crate) fn io_error(path: impl Into<PathBuf>, source: std::io::Error) -> ArtifactError {
    ArtifactError::Io {
        path: path.into(),
        source,
    }
}
