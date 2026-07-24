use crate::protocol::BrokerRequest;
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use runtrue_sandbox_protocol::WorkloadResponse;
use serde::Serialize;
use std::{
    os::unix::fs::FileTypeExt as _,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::UnixStream,
    time::timeout,
};
use tower::limit::ConcurrencyLimitLayer;

const MAXIMUM_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_CONCURRENT_REQUESTS: usize = 32;

#[derive(Clone)]
pub(crate) struct BrokerState {
    socket: Arc<PathBuf>,
    io_timeout: Duration,
    registration_ready: Option<Arc<AtomicBool>>,
}

impl BrokerState {
    pub(crate) fn new(socket: PathBuf, io_timeout: Duration) -> Result<Self, String> {
        if !socket.is_absolute() || io_timeout.is_zero() || io_timeout > Duration::from_secs(60) {
            return Err("broker socket or I/O timeout is invalid".to_owned());
        }
        Ok(Self {
            socket: Arc::new(socket),
            io_timeout,
            registration_ready: None,
        })
    }

    pub(crate) fn require_registration(mut self, ready: Arc<AtomicBool>) -> Self {
        self.registration_ready = Some(ready);
        self
    }
}

pub(crate) fn router(state: BrokerState) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/v1/dispatch", post(dispatch))
        .layer(DefaultBodyLimit::max(MAXIMUM_MESSAGE_BYTES))
        .layer(ConcurrencyLimitLayer::new(MAXIMUM_CONCURRENT_REQUESTS))
        .with_state(state)
}

async fn live() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn ready(State(state): State<BrokerState>) -> Result<StatusCode, BrokerError> {
    if state
        .registration_ready
        .as_ref()
        .is_some_and(|ready| !ready.load(Ordering::Acquire))
    {
        return Err(BrokerError::Unavailable);
    }
    let metadata = tokio::fs::symlink_metadata(state.socket.as_ref())
        .await
        .map_err(|_| BrokerError::Unavailable)?;
    if !metadata.file_type().is_socket() {
        return Err(BrokerError::Unavailable);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn dispatch(
    State(state): State<BrokerState>,
    Json(request): Json<BrokerRequest>,
) -> Result<Json<WorkloadResponse>, BrokerError> {
    request.validate().map_err(|_| BrokerError::Invalid)?;
    let encoded = serde_json::to_vec(&request).map_err(|_| BrokerError::Invalid)?;
    if encoded.len() >= MAXIMUM_MESSAGE_BYTES {
        return Err(BrokerError::Invalid);
    }
    let response = timeout(state.io_timeout, exchange(&state.socket, &encoded))
        .await
        .map_err(|_| BrokerError::Timeout)??;
    response
        .validate_for(&request.request_id)
        .map_err(|_| BrokerError::Unavailable)?;
    Ok(Json(response))
}

async fn exchange(socket: &Path, request: &[u8]) -> Result<WorkloadResponse, BrokerError> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|_| BrokerError::Unavailable)?;
    stream
        .write_all(request)
        .await
        .map_err(|_| BrokerError::Unavailable)?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|_| BrokerError::Unavailable)?;
    stream
        .shutdown()
        .await
        .map_err(|_| BrokerError::Unavailable)?;
    let mut response = Vec::new();
    BufReader::new(stream)
        .take((MAXIMUM_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .await
        .map_err(|_| BrokerError::Unavailable)?;
    if response.is_empty()
        || response.len() > MAXIMUM_MESSAGE_BYTES
        || response.last() != Some(&b'\n')
    {
        return Err(BrokerError::Unavailable);
    }
    serde_json::from_slice(&response).map_err(|_| BrokerError::Unavailable)
}

#[derive(Debug)]
enum BrokerError {
    Invalid,
    Unavailable,
    Timeout,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

impl IntoResponse for BrokerError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid_work_order"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "worker_unavailable"),
            Self::Timeout => (StatusCode::GATEWAY_TIMEOUT, "worker_timeout"),
        };
        (status, Json(ErrorBody { error })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use runtrue_sandbox_core::{
        AssignmentEpoch, GuestProfile, ResourceCeilings, SandboxId, SignedWorkOrder, SubjectId,
        TenantId, WorkOrderClaims, WorkOrderOperation, WorkspaceId, WORK_ORDER_VERSION,
    };
    use runtrue_sandbox_protocol::{
        Operation, WorkloadAuthorization as BrokerAuthorization, PROTOCOL_VERSION,
    };
    use serde_json::Value;
    use tempfile::tempdir;
    use tokio::{io::AsyncBufReadExt as _, net::UnixListener};
    use tower::ServiceExt as _;

    fn request_body() -> Vec<u8> {
        serde_json::to_vec(&BrokerRequest {
            schema_version: PROTOCOL_VERSION,
            request_id: "request-a".to_owned(),
            authorization: BrokerAuthorization::WorkOrder {
                work_order: Box::new(SignedWorkOrder {
                    claims: WorkOrderClaims {
                        schema_version: WORK_ORDER_VERSION,
                        tenant_id: TenantId::parse("tenant-a").expect("tenant"),
                        workspace_id: WorkspaceId::parse("workspace-a").expect("workspace"),
                        subject_id: SubjectId::parse("gateway-a").expect("subject"),
                        request_id: "request-a".to_owned(),
                        operation: WorkOrderOperation::Inspect,
                        sandbox_id: Some(SandboxId::parse("sandbox-a").expect("sandbox")),
                        assignment_epoch: AssignmentEpoch::new(1).expect("epoch"),
                        issued_unix_millis: 1,
                        expires_unix_millis: 2,
                        nonce: "nonce-a".to_owned(),
                        operation_digest: format!("sha256:{}", "a".repeat(64)),
                        resource_ceilings: ResourceCeilings {
                            allowed_guest_profiles: vec![GuestProfile::strict().identity],
                            maximum_services: 1,
                            maximum_timeout_ms: 1_000,
                            memory_bytes_per_service: 1024,
                            cpu_per_service_millis: 100,
                            pids_per_service: 16,
                            tmpfs_bytes: 1024,
                            writable_root_bytes_per_service: 1024,
                            maximum_volumes: 1,
                            maximum_volume_bytes: 1024,
                            maximum_output_bytes: 1024,
                        },
                    },
                    signature: "a".repeat(64),
                }),
            },
            operation: Operation::Inspect {
                sandbox: "sandbox-a".to_owned(),
            },
        })
        .expect("request")
    }

    #[tokio::test]
    async fn operator_shape_is_rejected_before_socket_access() {
        let app = router(
            BrokerState::new(
                PathBuf::from("/unreachable/workload.sock"),
                Duration::from_secs(1),
            )
            .expect("state"),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/v1/dispatch")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "schema_version": 2,
                    "request_id": "request-a",
                    "authorization": {
                        "kind": "operator",
                        "tenant_id": "tenant-a",
                        "workspace_id": "workspace-a",
                        "subject_id": "operator-a"
                    },
                    "operation": {"kind": "shutdown"}
                })
                .to_string(),
            ))
            .expect("request");
        let response = app.oneshot(request).await.expect("response");
        assert!(matches!(
            response.status(),
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
        ));
    }

    #[tokio::test]
    async fn forwards_one_bounded_request_and_returns_worker_response() {
        let directory = tempdir().expect("temporary directory");
        let socket = directory.path().join("workload.sock");
        let listener = UnixListener::bind(&socket).expect("listen");
        let worker = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = Vec::new();
            BufReader::new(&mut stream)
                .read_until(b'\n', &mut request)
                .await
                .expect("read request");
            assert_eq!(request.last(), Some(&b'\n'));
            let decoded: Value = serde_json::from_slice(&request).expect("decode request");
            assert_eq!(decoded["request_id"], "request-a");
            assert_eq!(decoded["authorization"]["kind"], "work_order");
            assert_eq!(decoded["operation"]["kind"], "inspect");
            stream
                .write_all(
                    br#"{"schema_version":2,"request_id":"request-a","ok":true,"result":{"state":"running"}}"#,
                )
                .await
                .expect("write response");
            stream.write_all(b"\n").await.expect("terminate response");
            stream.shutdown().await.expect("close response");
        });
        let app =
            router(BrokerState::new(socket, Duration::from_secs(1)).expect("broker configuration"));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/dispatch")
                    .header("content-type", "application/json")
                    .body(Body::from(request_body()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAXIMUM_MESSAGE_BYTES)
            .await
            .expect("response body");
        let decoded: Value = serde_json::from_slice(&body).expect("response JSON");
        assert_eq!(decoded["result"]["state"], "running");
        worker.await.expect("worker task");
    }
}
