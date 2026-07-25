use crate::worker_auth::WorkerAuthPolicy;
use crate::{
    auth::{AuthPolicy, Principal},
    signer::WorkOrderSigner,
};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{any, get, post},
    Json, Router,
};
use futures_util::{stream, Stream};
use runtrue_sandbox_core::{
    NetworkFeatureTier, QueuedWork, SandboxId, WorkerId, WorkerPool, WorkerPoolCatalog, WorkspaceId,
};
use runtrue_sandbox_oci::NetworkProfile;
use runtrue_sandbox_placement::{
    EnqueueOutcome, PlacementRecord, PlacementState, PlacementStoreError, PlacementSubmission,
    PostgresPlacementStore, WorkerRegistration,
};
use runtrue_sandbox_protocol::{Operation, WorkerAdvertisement, WorkloadResponse};
use serde::{Deserialize, Serialize};
use std::{
    convert::Infallible,
    sync::atomic::AtomicU64,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::Semaphore, time::sleep};
use tower::limit::ConcurrencyLimitLayer;

const MAXIMUM_BODY_BYTES: usize = 512 * 1024;
const MAXIMUM_CONCURRENT_REQUESTS: usize = 64;
const MAXIMUM_RESULT_STREAMS: usize = 64;
const RESULT_STREAM_POLL_INTERVAL: Duration = Duration::from_millis(250);
const IDEMPOTENCY_KEY: &str = "idempotency-key";

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) store: Arc<PostgresPlacementStore>,
    pub(crate) auth: Arc<AuthPolicy>,
    pub(crate) worker_auth: Arc<WorkerAuthPolicy>,
    pub(crate) worker_pools: Arc<WorkerPoolCatalog>,
    pub(crate) result_streams: Arc<Semaphore>,
    pub(crate) result_stream_poll_interval: Duration,
    pub(crate) route_signer: Option<Arc<WorkOrderSigner>>,
    pub(crate) route_sequence: Arc<AtomicU64>,
}

impl AppState {
    pub(crate) fn new(
        store: Arc<PostgresPlacementStore>,
        auth: Arc<AuthPolicy>,
        worker_auth: Arc<WorkerAuthPolicy>,
        worker_pools: Arc<WorkerPoolCatalog>,
    ) -> Self {
        Self {
            store,
            auth,
            worker_auth,
            worker_pools,
            result_streams: Arc::new(Semaphore::new(MAXIMUM_RESULT_STREAMS)),
            result_stream_poll_interval: RESULT_STREAM_POLL_INTERVAL,
            route_signer: None,
            route_sequence: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn with_route_signer(mut self, signer: Arc<WorkOrderSigner>) -> Self {
        self.route_signer = Some(signer);
        self
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitRequest {
    workspace_id: WorkspaceId,
    sandbox_id: SandboxId,
    deadline_ms: u64,
    pool_name: String,
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
    pool_name: String,
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
        .route(
            "/v1/placements/{idempotency_key}/events",
            get(stream_placement),
        )
        .route(
            "/v1/placements/{idempotency_key}/ingress/{service}/{container_port}",
            any(crate::ingress::forward_root),
        )
        .route(
            "/v1/placements/{idempotency_key}/ingress/{service}/{container_port}/{*path}",
            any(crate::ingress::forward_path),
        )
        .route("/internal/v1/workers/register", post(register_worker))
        .route(
            "/internal/v1/workers/{worker_id}/heartbeat",
            post(heartbeat_worker),
        )
        .route("/internal/v1/workers/{worker_id}/drain", post(drain_worker))
        .route(
            "/internal/v1/workers/{worker_id}/quarantine",
            post(quarantine_worker),
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
            &request.pool_name,
            &request.topology,
            &request.resource_shape,
            &request.compatibility_cohort,
        )
        .map_err(|()| ApiError::Forbidden)?;
    let pool = state
        .worker_pools
        .pool(&request.pool_name)
        .map_err(|_| ApiError::Forbidden)?;
    if pool.key.resource_shape != request.resource_shape
        || pool.key.runtime_compatibility_cohort != request.compatibility_cohort
    {
        return Err(ApiError::Forbidden);
    }
    state
        .store
        .register_worker(
            &WorkerRegistration {
                worker_id: request.worker_id,
                pool_name: request.pool_name,
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

async fn drain_worker(
    State(state): State<AppState>,
    Path(worker_id): Path<WorkerId>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    authenticate_worker(&state, &headers, &worker_id)?;
    state.store.drain_worker(&worker_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn quarantine_worker(
    State(state): State<AppState>,
    Path(worker_id): Path<WorkerId>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    authenticate_worker(&state, &headers, &worker_id)?;
    state
        .store
        .quarantine_worker(&worker_id, now_unix_ms()?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn authenticate_worker(
    state: &AppState,
    headers: &HeaderMap,
    worker_id: &WorkerId,
) -> Result<(), ApiError> {
    state
        .worker_auth
        .authenticate(headers)
        .and_then(|principal| principal.authorize_worker(worker_id))
        .map_err(|()| ApiError::Unauthorized)
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
            &request.pool_name,
            &request.topology,
            &request.resource_shape,
            &request.compatibility_cohort,
        )
        .map_err(|()| ApiError::Forbidden)?;
    let pool = state
        .worker_pools
        .pool(&request.pool_name)
        .map_err(|_| ApiError::Forbidden)?;
    principal
        .authorize_service_level(pool)
        .map_err(|()| ApiError::Forbidden)?;
    if !pool_accepts_request(
        pool,
        &request.resource_shape,
        &request.compatibility_cohort,
        &request.operation,
    ) {
        return Err(ApiError::Forbidden);
    }
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
        pool_name: request.pool_name,
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

fn pool_accepts_request(
    pool: &WorkerPool,
    resource_shape: &str,
    compatibility_cohort: &str,
    operation: &Operation,
) -> bool {
    if pool.key.resource_shape != resource_shape
        || pool.key.runtime_compatibility_cohort != compatibility_cohort
    {
        return false;
    }
    let Some(topology) = operation.topology() else {
        return true;
    };
    if topology.policy.guest_profile != pool.key.guest_profile {
        return false;
    }
    match pool.key.network_tier {
        NetworkFeatureTier::Loopback => {
            topology.policy.network.profile == NetworkProfile::None
                && topology.policy.network.ingress.is_empty()
        }
        NetworkFeatureTier::UserspaceEgress => {
            topology.policy.network.profile != NetworkProfile::None
                && topology.policy.network.ingress.is_empty()
        }
        NetworkFeatureTier::UserspaceIngress => !topology.policy.network.ingress.is_empty(),
    }
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

async fn stream_placement(
    State(state): State<AppState>,
    Path(idempotency_key): Path<String>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let principal = authenticate_path(&state, &headers, &idempotency_key)?;
    let permit = Arc::clone(&state.result_streams)
        .try_acquire_owned()
        .map_err(|_| ApiError::Exhausted)?;
    let initial = state
        .store
        .get_by_idempotency(
            &principal.tenant_id,
            &principal.subject_id,
            &idempotency_key,
        )
        .await?
        .ok_or(ApiError::NotFound)?;
    let stream_state = PlacementStream {
        store: Arc::clone(&state.store),
        tenant_id: principal.tenant_id,
        subject_id: principal.subject_id,
        idempotency_key,
        poll_interval: state.result_stream_poll_interval,
        initial: Some(initial),
        last_event: None,
        terminal_sent: false,
        _permit: permit,
    };
    Ok(
        Sse::new(stream::unfold(stream_state, next_placement_event)).keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("placement stream"),
        ),
    )
}

struct PlacementStream {
    store: Arc<PostgresPlacementStore>,
    tenant_id: runtrue_sandbox_core::TenantId,
    subject_id: runtrue_sandbox_core::SubjectId,
    idempotency_key: String,
    poll_interval: Duration,
    initial: Option<PlacementRecord>,
    last_event: Option<String>,
    terminal_sent: bool,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

async fn next_placement_event(
    mut state: PlacementStream,
) -> Option<(Result<Event, Infallible>, PlacementStream)> {
    if state.terminal_sent {
        return None;
    }
    loop {
        let record = if let Some(initial) = state.initial.take() {
            Ok(Some(initial))
        } else {
            sleep(state.poll_interval).await;
            state
                .store
                .get_by_idempotency(&state.tenant_id, &state.subject_id, &state.idempotency_key)
                .await
        };
        let record = match record {
            Ok(Some(record)) => record,
            Ok(None) => {
                state.terminal_sent = true;
                let event = Event::default()
                    .event("error")
                    .data(r#"{"error":"not_found"}"#);
                return Some((Ok(event), state));
            }
            Err(_) => {
                state.terminal_sent = true;
                let event = Event::default()
                    .event("error")
                    .data(r#"{"error":"unavailable"}"#);
                return Some((Ok(event), state));
            }
        };
        let terminal = matches!(
            record.state,
            PlacementState::Completed | PlacementState::Cancelled | PlacementState::Expired
        );
        let encoded = match serde_json::to_string(&PlacementResponse::from(record)) {
            Ok(encoded) => encoded,
            Err(_) => {
                state.terminal_sent = true;
                let event = Event::default()
                    .event("error")
                    .data(r#"{"error":"unavailable"}"#);
                return Some((Ok(event), state));
            }
        };
        if state.last_event.as_deref() == Some(&encoded) {
            continue;
        }
        state.last_event = Some(encoded.clone());
        state.terminal_sent = terminal;
        return Some((Ok(Event::default().event("placement").data(encoded)), state));
    }
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
            pool_name: record.pool_name,
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
pub(crate) enum ApiError {
    Unauthorized,
    Forbidden,
    Invalid,
    NotFound,
    Conflict,
    Exhausted,
    TooLarge,
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
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
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

    fn worker_pools() -> Arc<WorkerPoolCatalog> {
        let mut catalog: WorkerPoolCatalog =
            serde_json::from_str(include_str!("../../../deploy/k3s/worker-pools.json"))
                .expect("catalog");
        catalog.pools[0].key.runtime_compatibility_cohort = "runsc-v1".to_owned();
        catalog.validate().expect("test catalog");
        Arc::new(catalog)
    }

    #[test]
    fn reviewed_pool_rejects_guest_and_network_tier_mismatch() {
        let catalog = worker_pools();
        let pool = catalog.pool("fixed-standard-warm").expect("pool");
        let topology =
            serde_json::from_str(include_str!("../../../deploy/k3s/fixed-runtime.lock.json"))
                .expect("topology");
        let operation = Operation::Run {
            topology,
            project: "sandbox-a".to_owned(),
            wait_for: "client".to_owned(),
            timeout_ms: 30_000,
        };
        assert!(pool_accepts_request(
            pool,
            "standard-v1",
            "runsc-v1",
            &operation
        ));
        let mut egress_pool = pool.clone();
        egress_pool.key.network_tier = NetworkFeatureTier::UserspaceEgress;
        assert!(!pool_accepts_request(
            &egress_pool,
            "standard-v1",
            "runsc-v1",
            &operation
        ));
        egress_pool.key.network_tier = NetworkFeatureTier::Loopback;
        egress_pool.key.guest_profile =
            runtrue_sandbox_core::GuestProfileIdentity::parse("root-in-sandbox-v1")
                .expect("profile");
        assert!(!pool_accepts_request(
            &egress_pool,
            "standard-v1",
            "runsc-v1",
            &operation
        ));
    }

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
                let store = Arc::new(store);
                let suffix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos();
                let worker_id = format!("gateway-worker-{suffix}");
                let app = router(AppState::new(
                    Arc::clone(&store),
                    Arc::new(AuthPolicy::for_test("a-secure-random-token-with-32-bytes")),
                    Arc::new(WorkerAuthPolicy::for_test(
                        "a-secure-worker-token-with-32-bytes",
                        &worker_id,
                    )),
                    worker_pools(),
                ));
                let stream_store = Arc::new(
                    PostgresPlacementStore::connect_local_insecure(
                        &url,
                        PlacementStoreConfig::default(),
                    )
                    .await
                    .expect("stream replica store"),
                );
                let mut stream_state = AppState::new(
                    stream_store,
                    Arc::new(AuthPolicy::for_test("a-secure-random-token-with-32-bytes")),
                    Arc::new(WorkerAuthPolicy::for_test(
                        "a-secure-worker-token-with-32-bytes",
                        &worker_id,
                    )),
                    worker_pools(),
                );
                stream_state.result_streams = Arc::new(Semaphore::new(1));
                stream_state.result_stream_poll_interval = Duration::from_millis(1);
                let stream_app = router(stream_state);
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
                                "pool_name": "fixed-standard-warm",
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
                            "pool_name": "fixed-standard-warm",
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
                let drain = Request::builder()
                    .method("POST")
                    .uri(format!("/internal/v1/workers/{worker_id}/drain"))
                    .header(
                        "authorization",
                        "Worker worker-key-a.a-secure-worker-token-with-32-bytes",
                    )
                    .body(Body::empty())
                    .expect("drain");
                assert_eq!(
                    app.clone().oneshot(drain).await.expect("drain").status(),
                    StatusCode::NO_CONTENT
                );
                let draining_heartbeat = Request::builder()
                    .method("POST")
                    .uri(format!("/internal/v1/workers/{worker_id}/heartbeat"))
                    .header(
                        "authorization",
                        "Worker worker-key-a.a-secure-worker-token-with-32-bytes",
                    )
                    .body(Body::empty())
                    .expect("draining heartbeat");
                assert_eq!(
                    app.clone()
                        .oneshot(draining_heartbeat)
                        .await
                        .expect("draining heartbeat")
                        .status(),
                    StatusCode::NO_CONTENT
                );
                let quarantine = Request::builder()
                    .method("POST")
                    .uri(format!("/internal/v1/workers/{worker_id}/quarantine"))
                    .header(
                        "authorization",
                        "Worker worker-key-a.a-secure-worker-token-with-32-bytes",
                    )
                    .body(Body::empty())
                    .expect("quarantine");
                assert_eq!(
                    app.clone()
                        .oneshot(quarantine)
                        .await
                        .expect("quarantine")
                        .status(),
                    StatusCode::NO_CONTENT
                );
                let quarantined_heartbeat = Request::builder()
                    .method("POST")
                    .uri(format!("/internal/v1/workers/{worker_id}/heartbeat"))
                    .header(
                        "authorization",
                        "Worker worker-key-a.a-secure-worker-token-with-32-bytes",
                    )
                    .body(Body::empty())
                    .expect("quarantined heartbeat");
                assert_eq!(
                    app.clone()
                        .oneshot(quarantined_heartbeat)
                        .await
                        .expect("quarantined heartbeat")
                        .status(),
                    StatusCode::SERVICE_UNAVAILABLE
                );
                let events = || {
                    Request::builder()
                        .uri(format!("/v1/placements/{idempotency_key}/events"))
                        .header(
                            "authorization",
                            "Bearer key-a.a-secure-random-token-with-32-bytes",
                        )
                        .body(Body::empty())
                        .expect("events")
                };
                let stream_response = stream_app.clone().oneshot(events()).await.expect("stream");
                assert_eq!(stream_response.status(), StatusCode::OK);
                assert_eq!(
                    stream_response
                        .headers()
                        .get("content-type")
                        .and_then(|value| value.to_str().ok()),
                    Some("text/event-stream")
                );
                assert_eq!(
                    stream_app
                        .oneshot(events())
                        .await
                        .expect("bounded streams")
                        .status(),
                    StatusCode::TOO_MANY_REQUESTS
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
                let stream_bytes = to_bytes(stream_response.into_body(), 64 * 1024)
                    .await
                    .expect("stream body");
                let stream_body = std::str::from_utf8(&stream_bytes).expect("UTF-8 stream");
                assert!(stream_body.contains("event: placement"));
                assert!(stream_body.contains(r#""state":"queued""#));
                assert!(stream_body.contains(r#""state":"cancelled""#));
                assert!(!stream_body.contains("queue_position"));
            });
    }
}
