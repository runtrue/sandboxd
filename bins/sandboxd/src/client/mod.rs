use crate::protocol::{
    read_message, write_message, Operation, Request, Response, PROTOCOL_VERSION,
};
use runtrue_sandbox_oci::{io_error, SandboxError, TopologyLock};
use std::{fs, os::unix::net::UnixStream, path::Path};

pub(crate) fn send(socket: &Path, operation: Operation) -> Result<(), SandboxError> {
    let request = Request {
        schema_version: PROTOCOL_VERSION,
        request_id: format!("client-{}", std::process::id()),
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
