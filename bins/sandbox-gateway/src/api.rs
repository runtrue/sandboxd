use crate::auth::{AuthPolicy, Principal};
use crate::worker_auth::WorkerAuthPolicy;
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use runtrue_sandbox_core::{QueuedWork, SandboxId, WorkerId, WorkspaceId};
use runtrue_sandbox_placement::{
    EnqueueOutcome, PlacementRecord, PlacementState, PlacementStoreError, PlacementSubmission,
    PostgresPlacementStore, WorkerRegistration,
};
use runtrue_sandbox_protocol::{Operation, WorkerAdvertisement, WorkloadResponse};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::limit::ConcurrencyLimitLayer;

const MAXIMUM_BODY_BYTES: usize = 512 * 1024;
const MAXIMUM_CONCURRENT_REQUESTS: usize = 64;
const IDEMPOTENCY_KEY: &str = "idempotency-key";

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) store: Arc<PostgresPlacementStore>,
    pub(crate) auth: Arc<AuthPolicy>,
    pub(crate) worker_auth: Arc<WorkerAuthPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitRequest {
    workspace_id: WorkspaceId,
    sandbox_id: SandboxId,
    deadline_ms: u64,
    topology: String,
    resource_shape: String,
    compatibility_cohort: String,
    operation: Operation,
}

#[derive(Debug, Serialize)]
struct PlacementResponse {
    request_id: String,
    idempotency_key: String,
    workspace_id: String,
    sandbox_id: String,
    state: PlacementState,
    worker_id: Option<String>,
    assignment_epoch: Option<u64>,
    lease_expires_unix_ms: Option<u64>,
    result_digest: Option<String>,
    response: Option<WorkloadResponse>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: &'static str,
}

pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/v1/placements", post(submit))
        .route(
            "/v1/placements/{idempotency_key}",
            get(inspect).delete(cancel),
        )
        .route("/internal/v1/workers/register", post(register_worker))
        .route(
            "/internal/v1/workers/{worker_id}/heartbeat",
            post(heartbeat_worker),
        )
        .layer(DefaultBodyLimit::max(MAXIMUM_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(MAXIMUM_CONCURRENT_REQUESTS))
        .with_state(state)
}

async fn register_worker(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<WorkerAdvertisement>,
) -> Result<StatusCode, ApiError> {
    let principal = state
        .worker_auth
        .authenticate(&headers)
        .map_err(|()| ApiError::Unauthorized)?;
    principal
        .authorize(
            &request.worker_id,
            &request.topology,
            &request.resource_shape,
            &request.compatibility_cohort,
        )
        .map_err(|()| ApiError::Forbidden)?;
    state
        .store
        .register_worker(
            &WorkerRegistration {
                worker_id: request.worker_id,
                topology: request.topology,
                resource_shape: request.resource_shape,
                compatibility_cohort: request.compatibility_cohort,
                broker_address: request.broker_address,
                resource_ceilings: request.resource_ceilings,
            },
            now_unix_ms()?,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn heartbeat_worker(
    State(state): State<AppState>,
    Path(worker_id): Path<WorkerId>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    state
        .worker_auth
        .authenticate(&headers)
        .and_then(|principal| principal.authorize_worker(&worker_id))
        .map_err(|()| ApiError::Unauthorized)?;
    state
        .store
        .heartbeat_worker(&worker_id, now_unix_ms()?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn live() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn ready(State(state): State<AppState>) -> Result<StatusCode, ApiError> {
    state.store.ping().await.map_err(ApiError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SubmitRequest>,
) -> Result<(StatusCode, Json<PlacementResponse>), ApiError> {
    let principal = state
        .auth
        .authenticate(&headers)
        .map_err(|()| ApiError::Unauthorized)?;
    let idempotency_key = header_token(&headers, IDEMPOTENCY_KEY, 128)?;
    let now = now_unix_ms()?;
    principal
        .authorize(
            &request.workspace_id,
            request.deadline_ms,
            &request.topology,
            &request.resource_shape,
            &request.compatibility_cohort,
        )
        .map_err(|()| ApiError::Forbidden)?;
    let deadline_unix_ms = now
        .checked_add(request.deadline_ms)
        .ok_or(ApiError::Invalid)?;
    let submission = PlacementSubmission {
        work: QueuedWork {
            idempotency_key,
            tenant_id: principal.tenant_id,
            workspace_id: request.workspace_id,
            sandbox_id: request.sandbox_id,
            deadline_unix_ms,
        },
        subject_id: principal.subject_id,
        topology: request.topology,
        resource_shape: request.resource_shape,
        compatibility_cohort: request.compatibility_cohort,
        operation: request.operation,
    };
    let (status, record) = match state.store.enqueue(&submission, now).await? {
        EnqueueOutcome::Queued(record) => (StatusCode::ACCEPTED, record),
        EnqueueOutcome::Existing(record) => (StatusCode::OK, record),
    };
    Ok((status, Json(record.into())))
}

async fn inspect(
    State(state): State<AppState>,
    Path(idempotency_key): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PlacementResponse>, ApiError> {
    let principal = authenticate_path(&state, &headers, &idempotency_key)?;
    let record = state
        .store
        .get_by_idempotency(
            &principal.tenant_id,
            &principal.subject_id,
            &idempotency_key,
        )
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(record.into()))
}

async fn cancel(
    State(state): State<AppState>,
    Path(idempotency_key): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PlacementResponse>, ApiError> {
    let principal = authenticate_path(&state, &headers, &idempotency_key)?;
    let record = state
        .store
        .cancel(
            &principal.tenant_id,
            &principal.subject_id,
            &idempotency_key,
            now_unix_ms()?,
        )
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(record.into()))
}

fn authenticate_path(
    state: &AppState,
    headers: &HeaderMap,
    idempotency_key: &str,
) -> Result<Principal, ApiError> {
    if !valid_token(idempotency_key, 128) {
        return Err(ApiError::Invalid);
    }
    state
        .auth
        .authenticate(headers)
        .map_err(|()| ApiError::Unauthorized)
}

fn header_token(
    headers: &HeaderMap,
    name: &'static str,
    maximum: usize,
) -> Result<String, ApiError> {
    let value = headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Invalid)?;
    if !valid_token(value, maximum) {
        return Err(ApiError::Invalid);
    }
    Ok(value.to_owned())
}

fn valid_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn now_unix_ms() -> Result<u64, ApiError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ApiError::Unavailable)?
            .as_millis(),
    )
    .map_err(|_| ApiError::Unavailable)
}

impl From<PlacementRecord> for PlacementResponse {
    fn from(record: PlacementRecord) -> Self {
        Self {
            request_id: record.request_id,
            idempotency_key: record.idempotency_key,
            workspace_id: record.identity.workspace_id.to_string(),
            sandbox_id: record.identity.sandbox_id.to_string(),
            state: record.state,
            worker_id: record.worker_id.map(|worker| worker.to_string()),
            assignment_epoch: record.assignment_epoch.map(|epoch| epoch.get()),
            lease_expires_unix_ms: record.lease_expires_unix_ms,
            result_digest: record.result_digest,
            response: record.response,
        }
    }
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    Forbidden,
    Invalid,
    NotFound,
    Conflict,
    Exhausted,
    Unavailable,
}

impl From<PlacementStoreError> for ApiError {
    fn from(error: PlacementStoreError) -> Self {
        match error {
            PlacementStoreError::GlobalQueueFull | PlacementStoreError::TenantQueueFull => {
                Self::Exhausted
            }
            PlacementStoreError::SandboxConflict
            | PlacementStoreError::CompletionConflict
            | PlacementStoreError::StaleAssignment => Self::Conflict,
            PlacementStoreError::Invalid(_) => Self::Invalid,
            PlacementStoreError::Database(_)
            | PlacementStoreError::Tls(_)
            | PlacementStoreError::WorkerUnavailable => Self::Unavailable,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "conflict"),
            Self::Exhausted => (StatusCode::TOO_MANY_REQUESTS, "resource_exhausted"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        (status, Json(ErrorResponse { error })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker_auth::WorkerAuthPolicy;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use runtrue_sandbox_placement::PlacementStoreConfig;
    use std::env;
    use tower::ServiceExt as _;

    #[test]
    fn authenticated_http_is_idempotent_and_tenant_scoped() {
        let Some(url) = env::var_os("SANDBOX_PLACEMENT_POSTGRES_URL") else {
            eprintln!("SANDBOX_PLACEMENT_POSTGRES_URL is unset; skipping gateway integration");
            return;
        };
        let url = url.to_string_lossy().into_owned();
        assert!(url.contains("sandboxd_placement_test"));
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                PostgresPlacementStore::migrate_local_insecure(&url)
                    .await
                    .expect("migrate");
                let store = PostgresPlacementStore::connect_local_insecure(
                    &url,
                    PlacementStoreConfig::default(),
                )
                .await
                .expect("store");
                let suffix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos();
                let worker_id = format!("gateway-worker-{suffix}");
                let app = router(AppState {
                    store: Arc::new(store),
                    auth: Arc::new(AuthPolicy::for_test("a-secure-random-token-with-32-bytes")),
                    worker_auth: Arc::new(WorkerAuthPolicy::for_test(
                        "a-secure-worker-token-with-32-bytes",
                        &worker_id,
                    )),
                });
                let idempotency_key = format!("gateway-http-{suffix}");
                let sandbox_id = format!("gateway-sandbox-{suffix}");
                let request = || {
                    Request::builder()
                        .method("POST")
                        .uri("/v1/placements")
                        .header(
                            "authorization",
                            "Bearer key-a.a-secure-random-token-with-32-bytes",
                        )
                        .header(IDEMPOTENCY_KEY, &idempotency_key)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({
                                "workspace_id": "workspace-a",
                                "sandbox_id": sandbox_id.clone(),
                                "deadline_ms": 60_000,
                                "topology": "topology-v1",
                                "resource_shape": "standard-v1",
                                "compatibility_cohort": "runsc-v1",
                                "operation": {
                                    "kind": "inspect",
                                    "parameters": {"sandbox": sandbox_id.clone()}
                                }
                            })
                            .to_string(),
                        ))
                        .expect("request")
                };
                assert_eq!(
                    app.clone()
                        .oneshot(request())
                        .await
                        .expect("submit")
                        .status(),
                    StatusCode::ACCEPTED
                );
                assert_eq!(
                    app.clone()
                        .oneshot(request())
                        .await
                        .expect("retry")
                        .status(),
                    StatusCode::OK
                );
                let inspect = Request::builder()
                    .uri(format!("/v1/placements/{idempotency_key}"))
                    .header(
                        "authorization",
                        "Bearer key-a.a-secure-random-token-with-32-bytes",
                    )
                    .body(Body::empty())
                    .expect("inspect");
                let response = app.clone().oneshot(inspect).await.expect("inspect");
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = to_bytes(response.into_body(), 16 * 1024)
                    .await
                    .expect("body");
                let result: serde_json::Value =
                    serde_json::from_slice(&bytes).expect("JSON response");
                assert_eq!(result["state"], "queued");

                let unauthorized = Request::builder()
                    .uri(format!("/v1/placements/{idempotency_key}"))
                    .header(
                        "authorization",
                        "Bearer key-a.wrong-wrong-wrong-wrong-wrong-wrong",
                    )
                    .body(Body::empty())
                    .expect("unauthorized");
                assert_eq!(
                    app.clone()
                        .oneshot(unauthorized)
                        .await
                        .expect("unauthorized")
                        .status(),
                    StatusCode::UNAUTHORIZED
                );
                let register = Request::builder()
                    .method("POST")
                    .uri("/internal/v1/workers/register")
                    .header(
                        "authorization",
                        "Worker worker-key-a.a-secure-worker-token-with-32-bytes",
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "worker_id": worker_id,
                            "topology": "topology-v1",
                            "resource_shape": "standard-v1",
                            "compatibility_cohort": "runsc-v1",
                            "broker_address": "127.0.0.1:8081",
                            "resource_ceilings": {
                                "allowed_guest_profiles": [{"name": "strict", "version": 1}],
                                "maximum_services": 4,
                                "maximum_timeout_ms": 30000,
                                "memory_bytes_per_service": 268435456,
                                "cpu_per_service_millis": 1000,
                                "pids_per_service": 64,
                                "tmpfs_bytes": 67108864,
                                "writable_root_bytes_per_service": 67108864,
                                "maximum_volumes": 8,
                                "maximum_volume_bytes": 536870912,
                                "maximum_output_bytes": 1048576
                            }
                        })
                        .to_string(),
                    ))
                    .expect("register");
                assert_eq!(
                    app.clone()
                        .oneshot(register)
                        .await
                        .expect("register")
                        .status(),
                    StatusCode::NO_CONTENT
                );
                let heartbeat = Request::builder()
                    .method("POST")
                    .uri(format!("/internal/v1/workers/{worker_id}/heartbeat"))
                    .header(
                        "authorization",
                        "Worker worker-key-a.a-secure-worker-token-with-32-bytes",
                    )
                    .body(Body::empty())
                    .expect("heartbeat");
                assert_eq!(
                    app.clone()
                        .oneshot(heartbeat)
                        .await
                        .expect("heartbeat")
                        .status(),
                    StatusCode::NO_CONTENT
                );
                let cancel = Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/placements/{idempotency_key}"))
                    .header(
                        "authorization",
                        "Bearer key-a.a-secure-random-token-with-32-bytes",
                    )
                    .body(Body::empty())
                    .expect("cancel");
                assert_eq!(
                    app.oneshot(cancel).await.expect("cancel").status(),
                    StatusCode::OK
                );
            });
    }
}
