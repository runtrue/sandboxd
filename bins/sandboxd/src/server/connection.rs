use crate::{
    protocol::{read_message, write_message, Request, Response, PROTOCOL_VERSION},
    service,
    state::DaemonState,
};
use runtrue_sandbox_oci::SandboxError;
use std::{os::unix::net::UnixStream, sync::Arc};

pub(super) fn serve(mut stream: UnixStream, daemon: &Arc<DaemonState>) -> Result<(), SandboxError> {
    let request = match read_message::<Request>(&stream) {
        Ok(request) => request,
        Err(error) => return write_message(&mut stream, &invalid_message(error)),
    };
    let request_id = request.request_id.clone();
    let response = match service::handle(request, daemon) {
        Ok(result) => Response {
            schema_version: PROTOCOL_VERSION,
            request_id,
            ok: true,
            result: Some(result),
            error: None,
        },
        Err(error) => Response {
            schema_version: PROTOCOL_VERSION,
            request_id,
            ok: false,
            result: None,
            error: Some(error.to_string()),
        },
    };
    write_message(&mut stream, &response)
}

fn invalid_message(error: SandboxError) -> Response {
    Response {
        schema_version: PROTOCOL_VERSION,
        request_id: "invalid-message".to_owned(),
        ok: false,
        result: None,
        error: Some(error.to_string()),
    }
}
