use runtrue_sandbox_core::CoreError;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("backend does not support {0}")]
    Unsupported(&'static str),
    #[error("backend operation failed: {0}")]
    Backend(String),
    #[error("snapshot artifact operation failed for `{path}`: {source}")]
    ArtifactIo {
        path: String,
        #[source]
        source: io::Error,
    },
}
