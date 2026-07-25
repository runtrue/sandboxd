use crate::{
    broker::{BrokerError, BrokerState},
    protocol::BrokerRequest,
};
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{Request, State},
    http::{
        header::{AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE},
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    },
    response::Response,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use runtrue_sandbox_protocol::Operation;
use serde::Deserialize;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time::timeout,
};

const MAXIMUM_BODY_BYTES: usize = 1024 * 1024;
const MAXIMUM_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
struct SandboxStatus {
    ingress_endpoints: Vec<IngressEndpoint>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IngressEndpoint {
    service: String,
    container_port: u16,
    host_endpoint: SocketAddr,
    bearer_token: String,
}

pub(crate) async fn route(
    State(state): State<BrokerState>,
    request: Request,
) -> Result<Response, BrokerError> {
    let work_order = required_header(request.headers(), "x-runtrue-work-order")?;
    if work_order.len() > MAXIMUM_HEADER_BYTES {
        return Err(BrokerError::Invalid);
    }
    let work_order = URL_SAFE_NO_PAD
        .decode(work_order)
        .map_err(|_| BrokerError::Invalid)?;
    let work_order: BrokerRequest =
        serde_json::from_slice(&work_order).map_err(|_| BrokerError::Invalid)?;
    work_order.validate().map_err(|_| BrokerError::Invalid)?;
    if !matches!(work_order.operation, Operation::Inspect { .. }) {
        return Err(BrokerError::Invalid);
    }
    let service = required_header(request.headers(), "x-runtrue-ingress-service")?.to_owned();
    if !valid_token(&service, 63) {
        return Err(BrokerError::Invalid);
    }
    let container_port = required_header(request.headers(), "x-runtrue-ingress-port")?
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(BrokerError::Invalid)?;
    let method = required_header(request.headers(), "x-runtrue-ingress-method")?
        .parse::<Method>()
        .map_err(|_| BrokerError::Invalid)?;
    let target = decode_header(request.headers(), "x-runtrue-ingress-target")?;
    let target = target.parse::<Uri>().map_err(|_| BrokerError::Invalid)?;
    if target.scheme().is_some()
        || target.authority().is_some()
        || !target.path().starts_with('/')
        || target.to_string().len() > 8 * 1024
    {
        return Err(BrokerError::Invalid);
    }
    let host = decode_header(request.headers(), "x-runtrue-ingress-host")?;
    let host = HeaderValue::try_from(host).map_err(|_| BrokerError::Invalid)?;
    let headers = request.headers().clone();
    let body = to_bytes(request.into_body(), MAXIMUM_BODY_BYTES)
        .await
        .map_err(|_| BrokerError::TooLarge)?;

    let encoded = serde_json::to_vec(&work_order).map_err(|_| BrokerError::Invalid)?;
    let response = timeout(
        state.io_timeout,
        super::broker::exchange(&state.socket, &encoded),
    )
    .await
    .map_err(|_| BrokerError::Timeout)??;
    response
        .validate_for(&work_order.request_id)
        .map_err(|_| BrokerError::Unavailable)?;
    if !response.ok {
        return Err(BrokerError::Unavailable);
    }
    let status: SandboxStatus =
        serde_json::from_value(response.result.ok_or(BrokerError::Unavailable)?)
            .map_err(|_| BrokerError::Unavailable)?;
    if status.ingress_endpoints.len() > 16 {
        return Err(BrokerError::Unavailable);
    }
    let mut endpoints = status.ingress_endpoints.into_iter().filter(|endpoint| {
        endpoint.service == service && endpoint.container_port == container_port
    });
    let endpoint = endpoints.next().ok_or(BrokerError::Unavailable)?;
    if endpoints.next().is_some()
        || !endpoint.host_endpoint.ip().is_loopback()
        || endpoint.host_endpoint.port() == 0
        || endpoint.bearer_token.len() != 64
        || !endpoint
            .bearer_token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(BrokerError::Unavailable);
    }
    timeout(
        state.io_timeout,
        exchange_ingress(endpoint, &method, &target, &host, &headers, &body),
    )
    .await
    .map_err(|_| BrokerError::Timeout)?
}

async fn exchange_ingress(
    endpoint: IngressEndpoint,
    method: &Method,
    target: &Uri,
    host: &HeaderValue,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<Response, BrokerError> {
    let host = host.to_str().map_err(|_| BrokerError::Invalid)?;
    let mut encoded = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\n",
        endpoint.bearer_token
    );
    append_forward_headers(&mut encoded, headers)?;
    encoded.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    if encoded.len() > MAXIMUM_HEADER_BYTES {
        return Err(BrokerError::TooLarge);
    }
    let mut stream = TcpStream::connect(endpoint.host_endpoint)
        .await
        .map_err(|_| BrokerError::Unavailable)?;
    stream
        .write_all(encoded.as_bytes())
        .await
        .map_err(|_| BrokerError::Unavailable)?;
    stream
        .write_all(body)
        .await
        .map_err(|_| BrokerError::Unavailable)?;
    let mut response = Vec::new();
    stream
        .take((MAXIMUM_HEADER_BYTES + MAXIMUM_BODY_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .await
        .map_err(|_| BrokerError::Unavailable)?;
    parse_response(&response)
}

fn append_forward_headers(encoded: &mut String, headers: &HeaderMap) -> Result<(), BrokerError> {
    for (name, value) in headers {
        if name == AUTHORIZATION
            || name == HOST
            || name == CONTENT_LENGTH
            || hop_by_hop(name)
            || name.as_str().starts_with("x-runtrue-")
        {
            continue;
        }
        let value = value.to_str().map_err(|_| BrokerError::Invalid)?;
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

fn parse_response(encoded: &[u8]) -> Result<Response, BrokerError> {
    let header_end = encoded
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or(BrokerError::Unavailable)?;
    if header_end > MAXIMUM_HEADER_BYTES {
        return Err(BrokerError::Unavailable);
    }
    let headers =
        std::str::from_utf8(&encoded[..header_end]).map_err(|_| BrokerError::Unavailable)?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .and_then(|value| StatusCode::from_u16(value).ok())
        .ok_or(BrokerError::Unavailable)?;
    let mut response = Response::builder().status(status);
    let mut content_length = None;
    let mut chunked = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(BrokerError::Unavailable)?;
        let name = HeaderName::try_from(name).map_err(|_| BrokerError::Unavailable)?;
        if name == TRANSFER_ENCODING {
            if chunked || !value.trim().eq_ignore_ascii_case("chunked") {
                return Err(BrokerError::Unavailable);
            }
            chunked = true;
            continue;
        }
        if name == CONTENT_LENGTH {
            if content_length.is_some() {
                return Err(BrokerError::Unavailable);
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| BrokerError::Unavailable)?,
            );
            continue;
        }
        if name != CONNECTION {
            response = response.header(
                name,
                HeaderValue::try_from(value.trim()).map_err(|_| BrokerError::Unavailable)?,
            );
        }
    }
    if chunked && content_length.is_some() {
        return Err(BrokerError::Unavailable);
    }
    let body = decode_response_body(
        &encoded[header_end..],
        content_length,
        chunked,
        MAXIMUM_BODY_BYTES,
    )?;
    response
        .header(CONTENT_LENGTH, body.len())
        .body(Body::from(body))
        .map_err(|_| BrokerError::Unavailable)
}

fn decode_response_body(
    encoded: &[u8],
    content_length: Option<usize>,
    chunked: bool,
    maximum: usize,
) -> Result<Vec<u8>, BrokerError> {
    if !chunked {
        if encoded.len() > maximum || content_length.is_some_and(|length| length != encoded.len()) {
            return Err(BrokerError::Unavailable);
        }
        return Ok(encoded.to_vec());
    }
    let mut remaining = encoded;
    let mut decoded = Vec::new();
    loop {
        let line_end = remaining
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(BrokerError::Unavailable)?;
        if line_end == 0 || line_end > 32 {
            return Err(BrokerError::Unavailable);
        }
        let size = std::str::from_utf8(&remaining[..line_end])
            .ok()
            .and_then(|line| line.split(';').next())
            .and_then(|value| usize::from_str_radix(value.trim(), 16).ok())
            .ok_or(BrokerError::Unavailable)?;
        remaining = &remaining[line_end + 2..];
        if size == 0 {
            if remaining != b"\r\n" {
                return Err(BrokerError::Unavailable);
            }
            return Ok(decoded);
        }
        if size > remaining.len().saturating_sub(2)
            || remaining.get(size..size + 2) != Some(b"\r\n")
            || decoded.len().saturating_add(size) > maximum
        {
            return Err(BrokerError::Unavailable);
        }
        decoded.extend_from_slice(&remaining[..size]);
        remaining = &remaining[size + 2..];
    }
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, BrokerError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or(BrokerError::Invalid)
}

fn decode_header(headers: &HeaderMap, name: &str) -> Result<String, BrokerError> {
    let encoded = required_header(headers, name)?;
    if encoded.len() > MAXIMUM_HEADER_BYTES {
        return Err(BrokerError::Invalid);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| BrokerError::Invalid)?;
    String::from_utf8(decoded).map_err(|_| BrokerError::Invalid)
}

fn valid_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, http::Request};
    use runtrue_sandbox_core::{
        AssignmentEpoch, GuestProfile, ResourceCeilings, SandboxId, SignedWorkOrder, SubjectId,
        TenantId, WorkOrderClaims, WorkOrderOperation, WorkspaceId, WORK_ORDER_VERSION,
    };
    use runtrue_sandbox_protocol::{
        WorkloadAuthorization, WorkloadRequest, WorkloadResponse, PROTOCOL_VERSION,
    };
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::{
        io::{AsyncBufReadExt as _, BufReader},
        net::{TcpListener, UnixListener},
    };
    use tower::ServiceExt as _;

    fn inspect_request() -> WorkloadRequest {
        WorkloadRequest {
            schema_version: PROTOCOL_VERSION,
            request_id: "ingress-request-a".to_owned(),
            authorization: WorkloadAuthorization::WorkOrder {
                work_order: Box::new(SignedWorkOrder {
                    claims: WorkOrderClaims {
                        schema_version: WORK_ORDER_VERSION,
                        tenant_id: TenantId::parse("tenant-a").expect("tenant"),
                        workspace_id: WorkspaceId::parse("workspace-a").expect("workspace"),
                        subject_id: SubjectId::parse("subject-a").expect("subject"),
                        request_id: "ingress-request-a".to_owned(),
                        operation: WorkOrderOperation::Inspect,
                        sandbox_id: Some(SandboxId::parse("sandbox-a").expect("sandbox")),
                        assignment_epoch: AssignmentEpoch::new(7).expect("epoch"),
                        issued_unix_millis: 1,
                        expires_unix_millis: 2,
                        nonce: "nonce-a".to_owned(),
                        operation_digest: Operation::Inspect {
                            sandbox: "sandbox-a".to_owned(),
                        }
                        .digest()
                        .expect("operation digest"),
                        resource_ceilings: ResourceCeilings {
                            allowed_guest_profiles: vec![GuestProfile::strict().identity],
                            maximum_services: 2,
                            maximum_timeout_ms: 30_000,
                            memory_bytes_per_service: 256 * 1024 * 1024,
                            cpu_per_service_millis: 1_000,
                            pids_per_service: 64,
                            tmpfs_bytes: 16 * 1024 * 1024,
                            writable_root_bytes_per_service: 16 * 1024 * 1024,
                            maximum_volumes: 2,
                            maximum_volume_bytes: 32 * 1024 * 1024,
                            maximum_output_bytes: 1024 * 1024,
                        },
                    },
                    signature: "a".repeat(64),
                }),
            },
            operation: Operation::Inspect {
                sandbox: "sandbox-a".to_owned(),
            },
        }
    }

    #[tokio::test]
    async fn signed_inspect_selects_only_the_declared_loopback_route() {
        let directory = tempdir().expect("temporary directory");
        let socket = directory.path().join("workload.sock");
        let workload = UnixListener::bind(&socket).expect("workload socket");
        let guest = TcpListener::bind("127.0.0.1:0").await.expect("guest");
        let guest_address = guest.local_addr().expect("guest address");
        let worker = tokio::spawn(async move {
            let (stream, _) = workload.accept().await.expect("workload connection");
            let mut reader = BufReader::new(stream);
            let mut encoded = Vec::new();
            reader
                .read_until(b'\n', &mut encoded)
                .await
                .expect("workload request");
            let request: WorkloadRequest =
                serde_json::from_slice(&encoded).expect("inspect request");
            assert!(matches!(request.operation, Operation::Inspect { .. }));
            let response = serde_json::to_vec(&WorkloadResponse {
                schema_version: PROTOCOL_VERSION,
                request_id: request.request_id,
                ok: true,
                result: Some(serde_json::json!({
                    "ingress_endpoints": [{
                        "service": "api",
                        "container_port": 8080,
                        "host_endpoint": guest_address,
                        "bearer_token": "b".repeat(64)
                    }]
                })),
                error: None,
            })
            .expect("workload response");
            reader
                .get_mut()
                .write_all(&response)
                .await
                .expect("response");
            reader.get_mut().write_all(b"\n").await.expect("newline");
        });
        let application = tokio::spawn(async move {
            let (mut stream, _) = guest.accept().await.expect("guest connection");
            let mut request = Vec::new();
            let expected_length = loop {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk).await.expect("guest request");
                assert_ne!(read, 0, "broker half-closed before sending the request");
                request.extend_from_slice(&chunk[..read]);
                let Some(header_end) = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|position| position + 4)
                else {
                    continue;
                };
                let headers = std::str::from_utf8(&request[..header_end]).expect("headers");
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .expect("content length");
                if request.len() >= header_end + content_length {
                    break header_end + content_length;
                }
            };
            assert_eq!(request.len(), expected_length);
            let request = String::from_utf8(request).expect("UTF-8 request");
            let lowercase = request.to_ascii_lowercase();
            assert!(request.starts_with("POST /ready?full=1 HTTP/1.1\r\n"));
            assert!(lowercase.contains(
                &format!("authorization: Bearer {}\r\n", "b".repeat(64)).to_ascii_lowercase()
            ));
            assert!(!request.contains("tenant-secret"));
            assert!(!request.contains("x-runtrue-work-order"));
            assert!(request.ends_with("\r\n\r\nping"));
            let mut extra = [0_u8; 1];
            assert!(
                tokio::time::timeout(Duration::from_millis(100), stream.read(&mut extra))
                    .await
                    .is_err(),
                "broker half-closed before the application response"
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\npong\r\n0\r\n\r\n",
                )
                .await
                .expect("guest response");
        });
        let work_order = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&inspect_request()).expect("encoded inspect"));
        let request = Request::builder()
            .method("POST")
            .uri("/v1/ingress")
            .header("x-runtrue-work-order", work_order)
            .header("x-runtrue-ingress-service", "api")
            .header("x-runtrue-ingress-port", "8080")
            .header("x-runtrue-ingress-method", "POST")
            .header(
                "x-runtrue-ingress-target",
                URL_SAFE_NO_PAD.encode("/ready?full=1"),
            )
            .header(
                "x-runtrue-ingress-host",
                URL_SAFE_NO_PAD.encode("tenant.example"),
            )
            .header(AUTHORIZATION, "Bearer tenant-secret")
            .body(Body::from("ping"))
            .expect("route request");
        let response = crate::broker::router(
            BrokerState::new(socket, Duration::from_secs(2)).expect("broker"),
        )
        .oneshot(request)
        .await
        .expect("route response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 16).await.expect("body"),
            "pong"
        );
        worker.await.expect("worker task");
        application.await.expect("application task");
    }
}
