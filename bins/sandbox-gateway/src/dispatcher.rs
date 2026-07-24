use crate::signer::WorkOrderSigner;
use runtrue_sandbox_placement::{PlacementStoreError, PostgresPlacementStore};
use runtrue_sandbox_protocol::{WorkloadRequest, WorkloadResponse};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time::{sleep, timeout},
};

const MAXIMUM_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_HEADER_BYTES: usize = 16 * 1024;

pub(crate) struct Dispatcher {
    store: Arc<PostgresPlacementStore>,
    signer: Arc<WorkOrderSigner>,
    interval: Duration,
    request_timeout: Duration,
    worker_scan_limit: u16,
}

impl Dispatcher {
    pub(crate) fn new(
        store: Arc<PostgresPlacementStore>,
        signer: Arc<WorkOrderSigner>,
        interval: Duration,
        request_timeout: Duration,
        worker_scan_limit: u16,
    ) -> Result<Self, String> {
        if interval.is_zero()
            || interval > Duration::from_secs(10)
            || request_timeout.is_zero()
            || request_timeout > Duration::from_secs(60)
            || worker_scan_limit == 0
            || worker_scan_limit > 1_024
        {
            return Err("dispatcher timing or worker scan limit is invalid".to_owned());
        }
        Ok(Self {
            store,
            signer,
            interval,
            request_timeout,
            worker_scan_limit,
        })
    }

    pub(crate) async fn run(self) {
        loop {
            if let Err(error) = self.reconcile_once().await {
                eprintln!("placement reconciliation failed: {error}");
            }
            sleep(self.interval).await;
        }
    }

    async fn reconcile_once(&self) -> Result<(), String> {
        let now = now_unix_ms()?;
        self.store
            .fence_expired(now)
            .await
            .map_err(|error| error.to_string())?;
        let workers = self
            .store
            .clean_workers(now, self.worker_scan_limit)
            .await
            .map_err(|error| error.to_string())?;
        for worker in workers {
            let assignment = match self.store.assign_next(&worker, now_unix_ms()?).await {
                Ok(Some(assignment)) => assignment,
                Ok(None) | Err(PlacementStoreError::WorkerUnavailable) => continue,
                Err(error) => return Err(error.to_string()),
            };
            let request = self.signer.sign(&assignment, now_unix_ms()?)?;
            match dispatch(assignment.broker_address, &request, self.request_timeout).await {
                Ok(response) => {
                    match self
                        .store
                        .complete_response(&assignment, &response, now_unix_ms()?)
                        .await
                    {
                        Ok(_) | Err(PlacementStoreError::StaleAssignment) => {}
                        Err(error) => return Err(error.to_string()),
                    }
                }
                Err(error) => {
                    eprintln!(
                        "worker dispatch failed for request {} epoch {}: {error}",
                        assignment.request_id,
                        assignment.epoch.get()
                    );
                }
            }
        }
        Ok(())
    }
}

async fn dispatch(
    address: SocketAddr,
    request: &WorkloadRequest,
    request_timeout: Duration,
) -> Result<WorkloadResponse, String> {
    timeout(request_timeout, exchange(address, request))
        .await
        .map_err(|_| "broker request timed out".to_owned())?
}

async fn exchange(
    address: SocketAddr,
    request: &WorkloadRequest,
) -> Result<WorkloadResponse, String> {
    let body =
        serde_json::to_vec(request).map_err(|error| format!("encode broker request: {error}"))?;
    if body.len() > MAXIMUM_RESPONSE_BYTES {
        return Err("broker request exceeds its size limit".to_owned());
    }
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(|error| format!("connect broker: {error}"))?;
    let headers = format!(
        "POST /v1/dispatch HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .map_err(|error| format!("write broker headers: {error}"))?;
    stream
        .write_all(&body)
        .await
        .map_err(|error| format!("write broker body: {error}"))?;
    let mut encoded = Vec::new();
    stream
        .take((MAXIMUM_HEADER_BYTES + MAXIMUM_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .await
        .map_err(|error| format!("read broker response: {error}"))?;
    parse_response(&encoded, &request.request_id)
}

fn parse_response(encoded: &[u8], request_id: &str) -> Result<WorkloadResponse, String> {
    let header_end = encoded
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or_else(|| "broker response has no header terminator".to_owned())?;
    if header_end > MAXIMUM_HEADER_BYTES {
        return Err("broker response headers exceed their size limit".to_owned());
    }
    let headers = std::str::from_utf8(&encoded[..header_end])
        .map_err(|_| "broker response headers are not UTF-8".to_owned())?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| "broker response has no status".to_owned())?;
    if !(status.starts_with("HTTP/1.1 200 ") || status.starts_with("HTTP/1.0 200 ")) {
        return Err("broker rejected the work order".to_owned());
    }
    let mut content_length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "broker response contains a malformed header".to_owned())?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("chunked broker responses are not accepted".to_owned());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err("broker response repeats content length".to_owned());
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "broker content length is invalid".to_owned())?,
            );
        }
    }
    let body = &encoded[header_end..];
    if content_length != Some(body.len()) || body.len() > MAXIMUM_RESPONSE_BYTES {
        return Err("broker response body length is invalid".to_owned());
    }
    let response: WorkloadResponse =
        serde_json::from_slice(body).map_err(|error| format!("decode broker response: {error}"))?;
    response.validate_for(request_id).map_err(str::to_owned)?;
    Ok(response)
}

fn now_unix_ms() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_owned())?
            .as_millis(),
    )
    .map_err(|_| "system clock does not fit in milliseconds".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac as _};
    use runtrue_sandbox_core::{
        GuestProfile, QueuedWork, ResourceCeilings, SandboxId, SubjectId, TenantId, WorkerId,
        WorkspaceId,
    };
    use runtrue_sandbox_placement::{
        PlacementState, PlacementStoreConfig, PlacementSubmission, WorkerRegistration,
    };
    use runtrue_sandbox_protocol::{Operation, WorkloadAuthorization};
    use sha2::Sha256;
    use std::env;
    use tokio::net::TcpListener;

    #[test]
    fn response_parser_binds_identity_and_rejects_chunking() {
        let body =
            br#"{"schema_version":2,"request_id":"request-a","ok":true,"result":{"done":true}}"#;
        let encoded = [
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
            body,
        ]
        .concat();
        let response = parse_response(&encoded, "request-a").expect("response");
        assert!(response.ok);
        assert!(parse_response(&encoded, "request-b").is_err());
        let chunked = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n";
        assert!(parse_response(chunked, "request-a").is_err());
    }

    #[test]
    fn durable_assignment_is_signed_dispatched_and_completed() {
        let Some(url) = env::var_os("SANDBOX_PLACEMENT_POSTGRES_URL") else {
            eprintln!("SANDBOX_PLACEMENT_POSTGRES_URL is unset; skipping dispatcher integration");
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
                            lease_lifetime: Duration::from_secs(10),
                            broker_port: broker_address.port(),
                            ..PlacementStoreConfig::default()
                        },
                    )
                    .await
                    .expect("store"),
                );
                let suffix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos();
                let tenant = TenantId::parse(format!("dispatch-tenant-{suffix}"))
                    .expect("tenant");
                let workspace = WorkspaceId::parse("workspace-a").expect("workspace");
                let sandbox =
                    SandboxId::parse(format!("dispatch-sandbox-{suffix}")).expect("sandbox");
                let subject = SubjectId::parse("gateway-a").expect("subject");
                let worker =
                    WorkerId::parse(format!("dispatch-worker-{suffix}")).expect("worker");
                let topology = format!("dispatch-topology-{suffix}");
                let key = [0x11; 32];
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.expect("accept");
                    let mut encoded = Vec::new();
                    let body_start = loop {
                        let mut chunk = [0_u8; 1024];
                        let read = stream.read(&mut chunk).await.expect("request");
                        assert_ne!(read, 0, "request closed before its complete body");
                        encoded.extend_from_slice(&chunk[..read]);
                        if let Some(header_end) =
                            encoded.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            let body_start = header_end + 4;
                            let headers =
                                std::str::from_utf8(&encoded[..body_start]).expect("UTF-8 headers");
                            let content_length = headers
                                .lines()
                                .find_map(|line| {
                                    line.strip_prefix("Content-Length: ")
                                        .and_then(|value| value.parse::<usize>().ok())
                                })
                                .expect("content length");
                            if encoded.len() >= body_start + content_length {
                                break body_start;
                            }
                        }
                    };
                    let request: WorkloadRequest =
                        serde_json::from_slice(&encoded[body_start..]).expect("work order");
                    request.validate().expect("valid request");
                    let WorkloadAuthorization::WorkOrder { work_order } = &request.authorization;
                    let claims = serde_json::to_vec(&work_order.claims).expect("claims");
                    let mut verifier = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC");
                    verifier.update(&claims);
                    verifier
                        .verify_slice(&hex::decode(&work_order.signature).expect("signature"))
                        .expect("authentic signature");
                    let response = serde_json::to_vec(&WorkloadResponse {
                        schema_version: 2,
                        request_id: request.request_id,
                        ok: true,
                        result: Some(serde_json::json!({"state": "running"})),
                        error: None,
                    })
                    .expect("response");
                    stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                                response.len()
                            )
                            .as_bytes(),
                        )
                        .await
                        .expect("response headers");
                    stream.write_all(&response).await.expect("response body");
                    stream.shutdown().await.expect("close");
                });
                let ceilings = ResourceCeilings {
                    allowed_guest_profiles: vec![GuestProfile::strict().identity],
                    maximum_services: 4,
                    maximum_timeout_ms: 30_000,
                    memory_bytes_per_service: 256 * 1024 * 1024,
                    cpu_per_service_millis: 1_000,
                    pids_per_service: 64,
                    tmpfs_bytes: 64 * 1024 * 1024,
                    writable_root_bytes_per_service: 64 * 1024 * 1024,
                    maximum_volumes: 8,
                    maximum_volume_bytes: 512 * 1024 * 1024,
                    maximum_output_bytes: 1024 * 1024,
                };
                let now = now_unix_ms().expect("clock");
                store
                    .register_worker(
                        &WorkerRegistration {
                            worker_id: worker,
                            topology: topology.clone(),
                            resource_shape: "standard-v1".to_owned(),
                            compatibility_cohort: "runsc-v1".to_owned(),
                            broker_address,
                            resource_ceilings: ceilings,
                        },
                        now,
                    )
                    .await
                    .expect("worker");
                let idempotency_key = format!("dispatch-{suffix}");
                store
                    .enqueue(
                        &PlacementSubmission {
                            work: QueuedWork {
                                idempotency_key: idempotency_key.clone(),
                                tenant_id: tenant.clone(),
                                workspace_id: workspace,
                                sandbox_id: sandbox.clone(),
                                deadline_unix_ms: now + 60_000,
                            },
                            subject_id: subject.clone(),
                            topology,
                            resource_shape: "standard-v1".to_owned(),
                            compatibility_cohort: "runsc-v1".to_owned(),
                            operation: Operation::Inspect {
                                sandbox: sandbox.to_string(),
                            },
                        },
                        now,
                    )
                    .await
                    .expect("enqueue");
                let dispatcher = Dispatcher::new(
                    Arc::clone(&store),
                    Arc::new(WorkOrderSigner::for_test(key, Duration::from_secs(5))),
                    Duration::from_millis(1),
                    Duration::from_secs(2),
                    1_024,
                )
                .expect("dispatcher");
                dispatcher.reconcile_once().await.expect("dispatch");
                server.await.expect("broker task");
                let record = store
                    .get_by_idempotency(&tenant, &subject, &idempotency_key)
                    .await
                    .expect("lookup")
                    .expect("placement");
                assert_eq!(record.state, PlacementState::Completed);
                assert_eq!(
                    record
                        .response
                        .and_then(|response| response.result)
                        .and_then(|result| result["state"].as_str().map(str::to_owned))
                        .as_deref(),
                    Some("running")
                );
            });
    }
}
