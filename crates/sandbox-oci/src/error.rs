use std::{io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("I/O failed for `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid restricted Compose input: {0}")]
    Compose(String),
    #[error("invalid topology lock: {0}")]
    Lock(String),
    #[error("local Docker operation failed: {0}")]
    Docker(String),
    #[error("OCI image provider failed: {0}")]
    ImageProvider(String),
    #[error("sandbox timed out: {0}")]
    Timeout(String),
    #[error("sandbox runtime failed: {0}")]
    Runtime(String),
    #[error("unsupported sandbox feature: {0}")]
    Unsupported(String),
}

pub fn io_error(path: impl Into<PathBuf>, source: io::Error) -> SandboxError {
    SandboxError::Io {
        path: path.into(),
        source,
    }
}
