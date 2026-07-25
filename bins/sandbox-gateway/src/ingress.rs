use crate::api::{ApiError, AppState};
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{OriginalUri, Path, Request, State},
    http::{
        header::{AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE},
        HeaderMap, HeaderName, HeaderValue, StatusCode,
    },
    response::Response,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use runtrue_sandbox_protocol::Operation;
use sha2::{Digest as _, Sha256};
use std::{sync::atomic::Ordering, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time::timeout,
};

const MAXIMUM_INGRESS_BODY_BYTES: usize = 1024 * 1024;
const MAXIMUM_RESPONSE_BYTES: usize = 1024 * 1024;
const MAXIMUM_HEADER_BYTES: usize = 16 * 1024;
const INGRESS_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) async fn forward_root(
    state: State<AppState>,
    path: Path<(String, String, u16)>,
    uri: OriginalUri,
    request: Request,
) -> Result<Response, ApiError> {
    forward(state.0, path.0, uri.0, request).await
}

pub(crate) async fn forward_path(
    state: State<AppState>,
    Path((idempotency_key, service, container_port, _path)): Path<(String, String, u16, String)>,
    uri: OriginalUri,
    request: Request,
) -> Result<Response, ApiError> {
    forward(
        state.0,
        (idempotency_key, service, container_port),
        uri.0,
        request,
    )
    .await
}

async fn forward(
    state: AppState,
    (idempotency_key, service, container_port): (String, String, u16),
    uri: axum::http::Uri,
    request: Request,
) -> Result<Response, ApiError> {
    if !valid_token(&idempotency_key, 128) || !valid_token(&service, 63) || container_port == 0 {
        return Err(ApiError::Invalid);
    }
    let principal = state
        .auth
        .authenticate(request.headers())
        .map_err(|()| ApiError::Unauthorized)?;
    let now = now_unix_ms()?;
    let mut assignment = state
        .store
        .active_assignment_by_idempotency(
            &principal.tenant_id,
            &principal.subject_id,
            &idempotency_key,
            now,
        )
        .await?
        .ok_or(ApiError::Unavailable)?;
    principal
        .authorize_workspace(&assignment.identity.workspace_id)
        .map_err(|()| ApiError::Forbidden)?;
    let signer = state.route_signer.as_ref().ok_or(ApiError::Unavailable)?;
    let sequence = state.route_sequence.fetch_add(1, Ordering::Relaxed);
    assignment.request_id = route_request_id(&assignment.request_id, now, sequence);
    assignment.operation = Operation::Inspect {
        sandbox: assignment.identity.sandbox_id.to_string(),
    };
    let work_order = signer
        .sign(&assignment, now)
        .map_err(|_| ApiError::Unavailable)?;
    let work_order = serde_json::to_vec(&work_order).map_err(|_| ApiError::Unavailable)?;
    let work_order = URL_SAFE_NO_PAD.encode(work_order);
    if work_order.len() > MAXIMUM_HEADER_BYTES {
        return Err(ApiError::Unavailable);
    }

    let prefix = format!("/v1/placements/{idempotency_key}/ingress/{service}/{container_port}");
    let path_and_query = uri
        .path_and_query()
        .map(axum::http::uri::PathAndQuery::as_str)
        .ok_or(ApiError::Invalid)?;
    let suffix = path_and_query
        .strip_prefix(&prefix)
        .ok_or(ApiError::Invalid)?;
    let target = if suffix.is_empty() {
        "/"
    } else if suffix.starts_with('?') {
        return forward_exchange(
            assignment.broker_address,
            request,
            &service,
            container_port,
            &format!("/{suffix}"),
            &work_order,
        )
        .await;
    } else {
        suffix
    };
    forward_exchange(
        assignment.broker_address,
        request,
        &service,
        container_port,
        target,
        &work_order,
    )
    .await
}

async fn forward_exchange(
    address: std::net::SocketAddr,
    request: Request,
    service: &str,
    container_port: u16,
    target: &str,
    work_order: &str,
) -> Result<Response, ApiError> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, MAXIMUM_INGRESS_BODY_BYTES)
        .await
        .map_err(|_| ApiError::TooLarge)?;
    timeout(
        INGRESS_TIMEOUT,
        exchange(
            address,
            parts.method.as_str(),
            target,
            &parts.headers,
            &body,
            service,
            container_port,
            work_order,
        ),
    )
    .await
    .map_err(|_| ApiError::Unavailable)?
}

#[allow(clippy::too_many_arguments)]
async fn exchange(
    address: std::net::SocketAddr,
    method: &str,
    target: &str,
    headers: &HeaderMap,
    body: &Bytes,
    service: &str,
    container_port: u16,
    work_order: &str,
) -> Result<Response, ApiError> {
    let original_host = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("sandbox");
    let mut encoded = format!(
        "POST /v1/ingress HTTP/1.1\r\nHost: {address}\r\n\
         X-Runtrue-Work-Order: {work_order}\r\n\
         X-Runtrue-Ingress-Service: {service}\r\n\
         X-Runtrue-Ingress-Port: {container_port}\r\n\
         X-Runtrue-Ingress-Method: {method}\r\n\
         X-Runtrue-Ingress-Target: {}\r\n\
         X-Runtrue-Ingress-Host: {}\r\n",
        URL_SAFE_NO_PAD.encode(target),
        URL_SAFE_NO_PAD.encode(original_host),
    );
    append_forward_headers(&mut encoded, headers)?;
    encoded.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    if encoded.len() > MAXIMUM_HEADER_BYTES {
        return Err(ApiError::TooLarge);
    }
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    stream
        .write_all(encoded.as_bytes())
        .await
        .map_err(|_| ApiError::Unavailable)?;
    stream
        .write_all(body)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    stream.shutdown().await.map_err(|_| ApiError::Unavailable)?;
    let mut response = Vec::new();
    stream
        .take((MAXIMUM_HEADER_BYTES + MAXIMUM_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    parse_response(&response)
}

fn append_forward_headers(encoded: &mut String, headers: &HeaderMap) -> Result<(), ApiError> {
    for (name, value) in headers {
        if name == AUTHORIZATION
            || name == HOST
            || name == CONTENT_LENGTH
            || hop_by_hop(name)
            || name.as_str().starts_with("x-runtrue-")
        {
            continue;
        }
        let value = value.to_str().map_err(|_| ApiError::Invalid)?;
        encoded.push_str(name.as_str());
        encoded.push_str(": ");
        encoded.push_str(value);
        encoded.push_str("\r\n");
    }
    Ok(())
}

fn hop_by_hop(name: &HeaderName) -> bool {
    name == CONNECTION
        || name == TRANSFER_ENCODING
        || name == UPGRADE
        || matches!(
            name.as_str(),
            "keep-alive" | "proxy-connection" | "te" | "trailer"
        )
}

fn parse_response(encoded: &[u8]) -> Result<Response, ApiError> {
    let header_end = encoded
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or(ApiError::Unavailable)?;
    if header_end > MAXIMUM_HEADER_BYTES {
        return Err(ApiError::Unavailable);
    }
    let headers = std::str::from_utf8(&encoded[..header_end]).map_err(|_| ApiError::Unavailable)?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .and_then(|value| StatusCode::from_u16(value).ok())
        .ok_or(ApiError::Unavailable)?;
    let mut response = Response::builder().status(status);
    let mut content_length = None;
    let mut chunked = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(ApiError::Unavailable)?;
        let name = HeaderName::try_from(name).map_err(|_| ApiError::Unavailable)?;
        if name == TRANSFER_ENCODING {
            if chunked || !value.trim().eq_ignore_ascii_case("chunked") {
                return Err(ApiError::Unavailable);
            }
            chunked = true;
            continue;
        }
        if name == CONTENT_LENGTH {
            if content_length.is_some() {
                return Err(ApiError::Unavailable);
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| ApiError::Unavailable)?,
            );
            continue;
        }
        if name != CONNECTION {
            response = response.header(
                name,
                HeaderValue::try_from(value.trim()).map_err(|_| ApiError::Unavailable)?,
            );
        }
    }
    if chunked && content_length.is_some() {
        return Err(ApiError::Unavailable);
    }
    let body = decode_response_body(
        &encoded[header_end..],
        content_length,
        chunked,
        MAXIMUM_RESPONSE_BYTES,
    )?;
    response
        .header(CONTENT_LENGTH, body.len())
        .body(Body::from(body))
        .map_err(|_| ApiError::Unavailable)
}

fn decode_response_body(
    encoded: &[u8],
    content_length: Option<usize>,
    chunked: bool,
    maximum: usize,
) -> Result<Vec<u8>, ApiError> {
    if !chunked {
        if encoded.len() > maximum || content_length.is_some_and(|length| length != encoded.len()) {
            return Err(ApiError::Unavailable);
        }
        return Ok(encoded.to_vec());
    }
    let mut remaining = encoded;
    let mut decoded = Vec::new();
    loop {
        let line_end = remaining
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(ApiError::Unavailable)?;
        if line_end == 0 || line_end > 32 {
            return Err(ApiError::Unavailable);
        }
        let size = std::str::from_utf8(&remaining[..line_end])
            .ok()
            .and_then(|line| line.split(';').next())
            .and_then(|value| usize::from_str_radix(value.trim(), 16).ok())
            .ok_or(ApiError::Unavailable)?;
        remaining = &remaining[line_end + 2..];
        if size == 0 {
            if remaining != b"\r\n" {
                return Err(ApiError::Unavailable);
            }
            return Ok(decoded);
        }
        if size > remaining.len().saturating_sub(2)
            || remaining.get(size..size + 2) != Some(b"\r\n")
            || decoded.len().saturating_add(size) > maximum
        {
            return Err(ApiError::Unavailable);
        }
        decoded.extend_from_slice(&remaining[..size]);
        remaining = &remaining[size + 2..];
    }
}

fn route_request_id(request_id: &str, now: u64, sequence: u64) -> String {
    let mut digest = Sha256::new();
    digest.update(request_id.as_bytes());
    digest.update(now.to_be_bytes());
    digest.update(sequence.to_be_bytes());
    format!("ingress-{}", &hex::encode(digest.finalize())[..48])
}

fn valid_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn now_unix_ms() -> Result<u64, ApiError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ApiError::Unavailable)?
            .as_millis(),
    )
    .map_err(|_| ApiError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{router, AppState},
        auth::AuthPolicy,
        signer::WorkOrderSigner,
        worker_auth::WorkerAuthPolicy,
    };
    use axum::{body::to_bytes, http::Request};
    use hmac::{Hmac, Mac as _};
    use runtrue_sandbox_core::{
        GuestProfile, QueuedWork, ResourceCeilings, SandboxId, SubjectId, TenantId, WorkerId,
        WorkerPoolCatalog, WorkspaceId,
    };
    use runtrue_sandbox_placement::{
        PlacementStoreConfig, PlacementSubmission, PostgresPlacementStore, WorkerRegistration,
    };
    use runtrue_sandbox_protocol::{
        WorkloadAuthorization, WorkloadRequest, WorkloadResponse, PROTOCOL_VERSION,
    };
    use sha2::Sha256;
    use std::{env, sync::Arc, time::SystemTime};
    use tokio::net::TcpListener;
    use tower::ServiceExt as _;

    #[test]
    fn tenant_route_is_signed_and_fails_after_worker_fencing() {
        let Some(url) = env::var_os("SANDBOX_PLACEMENT_POSTGRES_URL") else {
            eprintln!("SANDBOX_PLACEMENT_POSTGRES_URL is unset; skipping ingress integration");
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
                let listener = TcpListener::bind("127.0.0.1:0").await.expect("broker");
                let broker_address = listener.local_addr().expect("broker address");
                let store = Arc::new(
                    PostgresPlacementStore::connect_local_insecure(
                        &url,
                        PlacementStoreConfig {
                            broker_port: broker_address.port(),
                            lease_lifetime: Duration::from_secs(10),
                            ..PlacementStoreConfig::default()
                        },
                    )
                    .await
                    .expect("store"),
                );
                let suffix = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos();
                let worker = WorkerId::parse(format!("ingress-worker-{suffix}")).expect("worker");
                let sandbox =
                    SandboxId::parse(format!("ingress-sandbox-{suffix}")).expect("sandbox");
                let idempotency_key = format!("ingress-placement-{suffix}");
                let now = now_unix_ms().expect("clock");
                let ceilings = ResourceCeilings {
                    allowed_guest_profiles: vec![GuestProfile::strict().identity],
                    maximum_services: 4,
                    maximum_timeout_ms: 30_000,
                    memory_bytes_per_service: 256 * 1024 * 1024,
                    cpu_per_service_millis: 1_000,
                    pids_per_service: 64,
                    tmpfs_bytes: 16 * 1024 * 1024,
                    writable_root_bytes_per_service: 16 * 1024 * 1024,
                    maximum_volumes: 4,
                    maximum_volume_bytes: 64 * 1024 * 1024,
                    maximum_output_bytes: 1024 * 1024,
                };
                let tenant = TenantId::parse("tenant-gateway").expect("tenant");
                let subject = SubjectId::parse("subject-gateway").expect("subject");
                let workspace = WorkspaceId::parse("workspace-a").expect("workspace");
                store
                    .enqueue(
                        &PlacementSubmission {
                            work: QueuedWork {
                                idempotency_key: idempotency_key.clone(),
                                tenant_id: tenant,
                                workspace_id: workspace,
                                sandbox_id: sandbox.clone(),
                                deadline_unix_ms: now + 60_000,
                            },
                            subject_id: subject,
                            pool_name: "fixed-standard-warm".to_owned(),
                            topology: "topology-v1".to_owned(),
                            resource_shape: "standard-v1".to_owned(),
                            compatibility_cohort: "runsc-v1".to_owned(),
                            operation: Operation::Create {
                                topology: serde_json::from_str(include_str!(
                                    "../../../deploy/k3s/fixed-runtime.lock.json"
                                ))
                                .expect("topology"),
                                sandbox: sandbox.to_string(),
                                timeout_ms: 1_000,
                            },
                        },
                        now,
                    )
                    .await
                    .expect("enqueue");
                store
                    .register_worker(
                        &WorkerRegistration {
                            worker_id: worker.clone(),
                            pool_name: "fixed-standard-warm".to_owned(),
                            topology: "topology-v1".to_owned(),
                            resource_shape: "standard-v1".to_owned(),
                            compatibility_cohort: "runsc-v1".to_owned(),
                            broker_address,
                            resource_ceilings: ceilings,
                        },
                        now,
                    )
                    .await
                    .expect("register");
                let assignment = store
                    .assign_next(&worker, now)
                    .await
                    .expect("assign")
                    .expect("assignment");
                store
                    .complete_response(
                        &assignment,
                        &WorkloadResponse {
                            schema_version: PROTOCOL_VERSION,
                            request_id: assignment.request_id.clone(),
                            ok: true,
                            result: Some(serde_json::json!({"state": "running"})),
                            error: None,
                        },
                        now + 1,
                    )
                    .await
                    .expect("publish serving assignment");

                let key = [0x33_u8; 32];
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.expect("gateway connection");
                    let mut encoded = Vec::new();
                    let body_start = loop {
                        let mut chunk = [0_u8; 4096];
                        let read = stream.read(&mut chunk).await.expect("gateway request");
                        assert_ne!(read, 0);
                        encoded.extend_from_slice(&chunk[..read]);
                        if let Some(end) =
                            encoded.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            let body_start = end + 4;
                            let headers =
                                std::str::from_utf8(&encoded[..body_start]).expect("headers");
                            let content_length = headers
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length: ")
                                        .and_then(|value| value.parse::<usize>().ok())
                                })
                                .expect("content length");
                            if encoded.len() >= body_start + content_length {
                                break body_start;
                            }
                        }
                    };
                    let headers =
                        std::str::from_utf8(&encoded[..body_start]).expect("UTF-8 headers");
                    assert!(!headers.contains("a-secure-random-token-with-32-bytes"));
                    assert!(headers.contains("X-Runtrue-Ingress-Service: api\r\n"));
                    assert!(headers.contains("X-Runtrue-Ingress-Port: 8080\r\n"));
                    assert!(headers.contains(&format!(
                        "X-Runtrue-Ingress-Target: {}\r\n",
                        URL_SAFE_NO_PAD.encode("/ready?full=1")
                    )));
                    let encoded_order = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("X-Runtrue-Work-Order: "))
                        .expect("work order");
                    let order: WorkloadRequest = serde_json::from_slice(
                        &URL_SAFE_NO_PAD
                            .decode(encoded_order)
                            .expect("base64 work order"),
                    )
                    .expect("work order JSON");
                    order.validate().expect("work order shape");
                    let WorkloadAuthorization::WorkOrder { work_order } = order.authorization;
                    let claims = serde_json::to_vec(&work_order.claims).expect("claims");
                    let mut verifier = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC");
                    verifier.update(&claims);
                    verifier
                        .verify_slice(&hex::decode(work_order.signature).expect("signature"))
                        .expect("signed route");
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
                        .await
                        .expect("route response");
                });
                let pools: WorkerPoolCatalog =
                    serde_json::from_str(include_str!("../../../deploy/k3s/worker-pools.json"))
                        .expect("worker pools");
                let app = router(
                    AppState::new(
                        Arc::clone(&store),
                        Arc::new(AuthPolicy::for_test("a-secure-random-token-with-32-bytes")),
                        Arc::new(WorkerAuthPolicy::for_test(
                            "a-secure-worker-token-with-32-bytes",
                            worker.as_str(),
                        )),
                        Arc::new(pools),
                    )
                    .with_route_signer(Arc::new(WorkOrderSigner::for_test(
                        key,
                        Duration::from_secs(5),
                    ))),
                );
                let route_request = || {
                    Request::builder()
                        .uri(format!(
                            "/v1/placements/{idempotency_key}/ingress/api/8080/ready?full=1"
                        ))
                        .header(
                            AUTHORIZATION,
                            "Bearer key-a.a-secure-random-token-with-32-bytes",
                        )
                        .body(Body::empty())
                        .expect("route request")
                };
                let response = app
                    .clone()
                    .oneshot(route_request())
                    .await
                    .expect("route response");
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    to_bytes(response.into_body(), 16).await.expect("body"),
                    "pong"
                );
                server.await.expect("broker task");

                store
                    .quarantine_worker(&worker, now + 1)
                    .await
                    .expect("fence worker");
                assert_eq!(
                    app.oneshot(route_request())
                        .await
                        .expect("fenced route response")
                        .status(),
                    StatusCode::SERVICE_UNAVAILABLE
                );
            });
    }
}
