use crate::auth::{AuthPolicy, Principal};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use runtrue_sandbox_core::{QueuedWork, SandboxId, WorkspaceId};
use runtrue_sandbox_placement::{
    EnqueueOutcome, PlacementRecord, PlacementState, PlacementStoreError, PlacementSubmission,
    PostgresPlacementStore,
};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::limit::ConcurrencyLimitLayer;

const MAXIMUM_BODY_BYTES: usize = 16 * 1024;
const MAXIMUM_CONCURRENT_REQUESTS: usize = 256;
const IDEMPOTENCY_KEY: &str = "idempotency-key";

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) store: Arc<PostgresPlacementStore>,
    pub(crate) auth: Arc<AuthPolicy>,
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
        .layer(DefaultBodyLimit::max(MAXIMUM_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(MAXIMUM_CONCURRENT_REQUESTS))
        .with_state(state)
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
                let app = router(AppState {
                    store: Arc::new(store),
                    auth: Arc::new(AuthPolicy::for_test("a-secure-random-token-with-32-bytes")),
                });
                let suffix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos();
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
                                "compatibility_cohort": "runsc-v1"
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
