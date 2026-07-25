use crate::protocol::{
    read_message, write_message, Operation, Request, RequestAuthorization, Response,
    PROTOCOL_VERSION,
};
use runtrue_sandbox_core::{SubjectId, TenantId, WorkspaceId};
use runtrue_sandbox_oci::{io_error, SandboxError, TopologyLock};
use std::{fs, os::unix::net::UnixStream, path::Path};

const OPERATOR_TENANT_ENV: &str = "RUNTRUE_SANDBOXD_OPERATOR_TENANT_ID";
const OPERATOR_WORKSPACE_ENV: &str = "RUNTRUE_SANDBOXD_OPERATOR_WORKSPACE_ID";
const OPERATOR_SUBJECT_ENV: &str = "RUNTRUE_SANDBOXD_OPERATOR_SUBJECT_ID";

pub(crate) fn send(socket: &Path, operation: Operation) -> Result<(), SandboxError> {
    let operator_value = |name: &str, default: &str| {
        std::env::var(name)
            .unwrap_or_else(|_| default.to_owned())
            .trim()
            .to_owned()
    };
    let request = Request {
        schema_version: PROTOCOL_VERSION,
        request_id: format!("client-{}", std::process::id()),
        authorization: Some(RequestAuthorization::Operator {
            tenant_id: TenantId::parse(operator_value(OPERATOR_TENANT_ENV, "local"))
                .map_err(|error| SandboxError::Runtime(error.to_string()))?,
            workspace_id: WorkspaceId::parse(operator_value(OPERATOR_WORKSPACE_ENV, "local"))
                .map_err(|error| SandboxError::Runtime(error.to_string()))?,
            subject_id: SubjectId::parse(operator_value(OPERATOR_SUBJECT_ENV, "local-root"))
                .map_err(|error| SandboxError::Runtime(error.to_string()))?,
        }),
        operation,
    };
    let mut stream = UnixStream::connect(socket).map_err(|source| io_error(socket, source))?;
    write_message(&mut stream, &request)?;
    let response = read_message::<Response>(&stream)?;
    println!(
        "{}",
        serde_json::to_string(&response)
            .map_err(|error| SandboxError::Runtime(format!("encode response: {error}")))?
    );
    if response.ok {
        Ok(())
    } else {
        Err(SandboxError::Runtime(
            response
                .error
                .unwrap_or_else(|| "daemon rejected request".to_owned()),
        ))
    }
}

pub(crate) fn read_topology(path: &Path) -> Result<TopologyLock, SandboxError> {
    let bytes = fs::read(path).map_err(|source| io_error(path, source))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| SandboxError::Lock(format!("decode topology lock: {error}")))
}
