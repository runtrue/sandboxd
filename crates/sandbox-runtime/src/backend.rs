use crate::{CreateRequest, RestoreRequest, RuntimeError, SandboxInstance};
use runtrue_sandbox_core::{BackendCapabilities, BackendDescriptor};

pub trait SandboxBackend: Send + Sync {
    fn descriptor(&self) -> &BackendDescriptor;

    fn capabilities(&self) -> &BackendCapabilities;

    fn create(&self, request: CreateRequest) -> Result<Box<dyn SandboxInstance>, RuntimeError>;

    fn restore(&self, request: RestoreRequest) -> Result<Box<dyn SandboxInstance>, RuntimeError>;
}
