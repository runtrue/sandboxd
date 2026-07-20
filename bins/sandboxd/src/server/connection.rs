use crate::{
    audit::AuditOutcome,
    authorization::{authorize_peer, peer_uid, AccessContext, ConnectionEndpoint, TenantScope},
    protocol::{
        read_message, valid_request_id, write_message, Request, RequestAuthorization, Response,
        LEGACY_OPERATOR_PROTOCOL_VERSION, PROTOCOL_VERSION,
    },
    service,
    state::DaemonState,
};
use runtrue_sandbox_core::{SubjectId, TenantId, WorkspaceId};
use runtrue_sandbox_oci::SandboxError;
use std::{os::unix::net::UnixStream, sync::Arc, time::Duration};

pub(super) fn serve(
    mut stream: UnixStream,
    daemon: &Arc<DaemonState>,
    endpoint: ConnectionEndpoint,
    io_timeout: Duration,
) -> Result<(), SandboxError> {
    stream
        .set_read_timeout(Some(io_timeout))
        .and_then(|()| stream.set_write_timeout(Some(io_timeout)))
        .map_err(|source| SandboxError::Runtime(format!("configure control timeout: {source}")))?;
    let peer_uid = peer_uid(&stream)?;
    if let Err(error) = authorize_peer(peer_uid, endpoint) {
        daemon
            .counters
            .lock()
            .expect("counter lock")
            .rejected_connections += 1;
        record_audit(
            daemon,
            "peer-rejected",
            endpoint,
            peer_uid,
            None,
            None,
            AuditOutcome::Rejected,
        );
        return Err(error);
    }
    let request = match read_message::<Request>(&stream) {
        Ok(request) => request,
        Err(error) => {
            daemon
                .counters
                .lock()
                .expect("counter lock")
                .rejected_requests += 1;
            record_audit(
                daemon,
                "invalid-message",
                endpoint,
                peer_uid,
                None,
                None,
                AuditOutcome::Rejected,
            );
            return write_message(&mut stream, &invalid_message(error));
        }
    };
    let request_id = request.request_id.clone();
    let operation = request.operation.work_order_operation();
    let context = match authorize_request(&request, daemon, endpoint) {
        Ok(context) => context,
        Err(error) => {
            daemon
                .counters
                .lock()
                .expect("counter lock")
                .rejected_requests += 1;
            record_audit(
                daemon,
                &request_id,
                endpoint,
                peer_uid,
                None,
                operation,
                AuditOutcome::Rejected,
            );
            return write_message(&mut stream, &failure_response(request_id, error));
        }
    };
    let response = match service::handle(request.operation, &context, daemon) {
        Ok(result) => {
            record_audit(
                daemon,
                &request_id,
                endpoint,
                peer_uid,
                Some(&context),
                operation,
                AuditOutcome::Succeeded,
            );
            Response {
                schema_version: PROTOCOL_VERSION,
                request_id,
                ok: true,
                result: Some(result),
                error: None,
            }
        }
        Err(error) => {
            record_audit(
                daemon,
                &request_id,
                endpoint,
                peer_uid,
                Some(&context),
                operation,
                AuditOutcome::Failed,
            );
            failure_response(request_id, error)
        }
    };
    write_message(&mut stream, &response)
}

fn authorize_request(
    request: &Request,
    daemon: &DaemonState,
    endpoint: ConnectionEndpoint,
) -> Result<AccessContext, SandboxError> {
    if !valid_request_id(&request.request_id) {
        return Err(SandboxError::Runtime(
            "invalid request identifier".to_owned(),
        ));
    }
    match endpoint {
        ConnectionEndpoint::Operator => authorize_operator(request),
        ConnectionEndpoint::Workload { .. } => {
            authorize_workload(request, daemon.work_orders.as_ref())
        }
    }
}

fn authorize_operator(request: &Request) -> Result<AccessContext, SandboxError> {
    match (request.schema_version, request.authorization.as_ref()) {
        (LEGACY_OPERATOR_PROTOCOL_VERSION, None) => Ok(AccessContext::Operator {
            scope: TenantScope {
                tenant_id: TenantId::parse("local").expect("static tenant identity"),
                workspace_id: WorkspaceId::parse("local").expect("static workspace identity"),
            },
            subject_id: SubjectId::parse("legacy-root").expect("static subject identity"),
        }),
        (
            PROTOCOL_VERSION,
            Some(RequestAuthorization::Operator {
                tenant_id,
                workspace_id,
                subject_id,
            }),
        ) => Ok(AccessContext::Operator {
            scope: TenantScope {
                tenant_id: tenant_id.clone(),
                workspace_id: workspace_id.clone(),
            },
            subject_id: subject_id.clone(),
        }),
        _ => Err(SandboxError::Runtime(
            "operator request authorization is invalid".to_owned(),
        )),
    }
}

fn authorize_workload(
    request: &Request,
    verifier: Option<&crate::authorization::WorkOrderVerifier>,
) -> Result<AccessContext, SandboxError> {
    if request.schema_version != PROTOCOL_VERSION {
        return Err(SandboxError::Runtime(
            "workload endpoint requires protocol version 2".to_owned(),
        ));
    }
    let work_order = match request.authorization.as_ref() {
        Some(RequestAuthorization::WorkOrder { work_order }) => work_order,
        _ => {
            return Err(SandboxError::Runtime(
                "workload endpoint requires a signed work order".to_owned(),
            ))
        }
    };
    let verifier = verifier
        .ok_or_else(|| SandboxError::Runtime("workload endpoint is not configured".to_owned()))?;
    verifier
        .verify(request, work_order)
        .map(AccessContext::Tenant)
}

fn failure_response(request_id: String, error: SandboxError) -> Response {
    Response {
        schema_version: PROTOCOL_VERSION,
        request_id,
        ok: false,
        result: None,
        error: Some(error.to_string()),
    }
}

fn invalid_message(error: SandboxError) -> Response {
    failure_response("invalid-message".to_owned(), error)
}

#[allow(clippy::too_many_arguments)]
fn record_audit(
    daemon: &DaemonState,
    request_id: &str,
    endpoint: ConnectionEndpoint,
    peer_uid: u32,
    context: Option<&AccessContext>,
    operation: Option<runtrue_sandbox_core::WorkOrderOperation>,
    outcome: AuditOutcome,
) {
    if let Err(error) = daemon
        .audit
        .record(request_id, endpoint, peer_uid, context, operation, outcome)
    {
        eprintln!("runtrue-sandboxd audit: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Operation;

    #[test]
    fn legacy_protocol_is_operator_only() {
        let request = Request {
            schema_version: LEGACY_OPERATOR_PROTOCOL_VERSION,
            request_id: "legacy-1".to_owned(),
            authorization: None,
            operation: Operation::Ping,
        };
        assert!(authorize_operator(&request).is_ok());
    }

    #[test]
    fn workload_cannot_claim_operator_authorization() {
        let request = Request {
            schema_version: PROTOCOL_VERSION,
            request_id: "request-1".to_owned(),
            authorization: Some(RequestAuthorization::Operator {
                tenant_id: TenantId::parse("tenant-a").expect("tenant"),
                workspace_id: WorkspaceId::parse("team-a").expect("workspace"),
                subject_id: SubjectId::parse("broker-a").expect("subject"),
            }),
            operation: Operation::Shutdown,
        };
        assert!(matches!(
            request.authorization,
            Some(RequestAuthorization::Operator { .. })
        ));
        assert!(request.operation.work_order_operation().is_none());
        assert!(authorize_workload(&request, None).is_err());
    }
}
