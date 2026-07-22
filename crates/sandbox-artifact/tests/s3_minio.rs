#![cfg(feature = "s3")]

use runtrue_sandbox_artifact::{
    ArtifactError, ArtifactLimits, ArtifactScope, ArtifactStore, LocalArtifactStore,
    S3ArtifactStore, SnapshotPublication, StagedSnapshotObject,
};
use runtrue_sandbox_core::{
    ArtifactRole, AssignmentEpoch, BackendDescriptor, BackendKind, ContainerId, LifecycleState,
    RestoreRequirements, RestoreTarget, SandboxId, SnapshotId, SnapshotManifest, SnapshotMode,
    SnapshotPortability, TenantId, WorkerId, WorkspaceId,
};
use s3_wire::{
    AddressingStyle, ByteStream, CreateMultipartUploadRequest, Credentials, CredentialsProvider,
    DeleteObjectRequest, Endpoint, ListMultipartUploadsRequest, ListObjectsV2Request, ObjectKey,
    PutObjectRequest, RetryPolicy, S3Client, S3Config, StaticCredentialsProvider,
};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Read as _, Write as _},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

const MASTER_KEY: [u8; 32] = [0x6b; 32];

#[test]
#[ignore = "requires an S3-compatible endpoint; run tools/test-s3-artifacts.sh"]
fn publish_on_worker_a_and_materialize_on_worker_b() {
    let client = client_from_environment();
    let administrative_client = client.clone();
    let prefix = format!(
        "runtrue-sandboxd-tests/{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("current time")
            .as_nanos()
    );
    let limits = ArtifactLimits {
        maximum_object_bytes: 8 * 1024 * 1024,
        maximum_snapshot_bytes: 16 * 1024 * 1024,
        maximum_listing_entries: 2_000,
        operation_timeout: Duration::from_secs(5),
        garbage_collection_grace: Duration::from_secs(10),
        ..ArtifactLimits::default()
    };

    let local_fixture = fixture("snapshot-local-baseline");
    let local_root = tempfile::tempdir().expect("local artifact root");
    let local_initialization_started = Instant::now();
    let local = LocalArtifactStore::new(
        local_root.path().join("artifacts"),
        MASTER_KEY,
        limits.clone(),
    )
    .expect("local baseline store");
    let local_initialization_micros = local_initialization_started.elapsed().as_micros();
    let local_published = local
        .publish(local_fixture.publication.clone())
        .expect("local baseline publication");
    let local_destination_root = tempfile::tempdir().expect("local destination root");
    let local_restored = local
        .materialize(
            &local_fixture.publication.scope,
            &local_fixture.publication.manifest.snapshot_id,
            &local_destination_root.path().join("materialized"),
        )
        .expect("local baseline materialization");

    let initialization_started = Instant::now();
    let worker_a =
        S3ArtifactStore::from_client(client.clone(), prefix.clone(), MASTER_KEY, limits.clone())
            .expect("worker A store");
    let worker_b = S3ArtifactStore::from_client(client, prefix.clone(), MASTER_KEY, limits.clone())
        .expect("worker B store");
    let initialization_micros = initialization_started.elapsed().as_micros();
    let remote_fixture = fixture("snapshot-minio");

    let published = worker_a
        .publish(remote_fixture.publication.clone())
        .expect("publish from worker A");
    assert_eq!(published.object_count, 2);
    assert!(published.transferred_bytes > published.logical_bytes);
    let destination_root = tempfile::tempdir().expect("destination root");
    let destination = destination_root.path().join("materialized");
    let restored = worker_b
        .materialize(
            &remote_fixture.publication.scope,
            &remote_fixture.publication.manifest.snapshot_id,
            &destination,
        )
        .expect("materialize on worker B");
    println!(
        "artifact_provider_metrics provider=local initialization_micros={local_initialization_micros} logical_bytes={} publish_transferred_bytes={} publish_millis={} publish_bytes_per_second={} materialize_transferred_bytes={} materialization_millis={} materialize_bytes_per_second={}",
        local_published.logical_bytes,
        local_published.transferred_bytes,
        local_published.publish_millis,
        bytes_per_second(local_published.transferred_bytes, local_published.publish_millis),
        local_restored.transferred_bytes,
        local_restored.materialization_millis,
        bytes_per_second(
            local_restored.transferred_bytes,
            local_restored.materialization_millis
        ),
    );
    println!(
        "artifact_provider_metrics provider=s3-wire-minio initialization_micros={initialization_micros} logical_bytes={} publish_transferred_bytes={} publish_millis={} publish_bytes_per_second={} materialize_transferred_bytes={} materialization_millis={} materialize_bytes_per_second={}",
        published.logical_bytes,
        published.transferred_bytes,
        published.publish_millis,
        bytes_per_second(published.transferred_bytes, published.publish_millis),
        restored.transferred_bytes,
        restored.materialization_millis,
        bytes_per_second(restored.transferred_bytes, restored.materialization_millis),
    );
    assert_eq!(
        restored.manifest.snapshot_id,
        remote_fixture.publication.manifest.snapshot_id
    );
    restored.manifest.validate().expect("restored manifest");
    for (name, expected) in &remote_fixture.expected {
        assert_eq!(
            fs::read(destination.join(name)).expect("materialized object"),
            *expected
        );
    }

    let grant = worker_a
        .publish_transfer_grant(
            &remote_fixture.publication.scope,
            &remote_fixture.publication.manifest.snapshot_id,
        )
        .expect("publish transfer grant");
    let target = RestoreTarget {
        tenant_id: grant.tenant_id.clone(),
        workspace_id: grant.workspace_id.clone(),
        sandbox_id: grant.sandbox_id.clone(),
        worker_id: WorkerId::parse("worker-b").expect("destination worker"),
        assignment_epoch: AssignmentEpoch::new(8).expect("destination epoch"),
        artifact_portability: SnapshotPortability::CrossWorkerSameBackend,
        guest_profile: runtrue_sandbox_core::GuestProfile::strict().identity,
    };
    let claim = worker_b
        .claim_transfer(
            &remote_fixture.publication.scope,
            &remote_fixture.publication.manifest.snapshot_id,
            &target,
        )
        .expect("claim transfer on worker B");
    assert_eq!(claim.destination_worker, target.worker_id);

    let race_fixture = fixture("snapshot-minio-race");
    let (first, second) = thread::scope(|scope| {
        let first_publication = race_fixture.publication.clone();
        let second_publication = race_fixture.publication.clone();
        let first = scope.spawn(|| worker_a.publish(first_publication));
        let second = scope.spawn(|| worker_b.publish(second_publication));
        (
            first.join().expect("first concurrent publisher"),
            second.join().expect("second concurrent publisher"),
        )
    });
    let race_results = [first, second];
    assert_eq!(
        race_results.iter().filter(|result| result.is_ok()).count(),
        1
    );
    assert_eq!(
        race_results
            .iter()
            .filter(|result| matches!(result, Err(ArtifactError::AlreadyExists(_))))
            .count(),
        1
    );

    let runtime_object = restored
        .manifest
        .sandbox_objects
        .iter()
        .find(|object| object.name == "state.img")
        .expect("runtime object descriptor");
    let corrupt_key = remote_object_key(
        &prefix,
        &remote_fixture.publication.scope,
        &runtime_object.artifact.digest,
        &runtime_object.artifact.media_type,
    );
    put_bytes(
        &administrative_client,
        corrupt_key,
        b"truncated-corrupt-envelope",
    );
    let corrupt_destination_root = tempfile::tempdir().expect("corrupt destination root");
    let corrupt_destination = corrupt_destination_root.path().join("materialized");
    let corruption_result = worker_b.materialize(
        &remote_fixture.publication.scope,
        &remote_fixture.publication.manifest.snapshot_id,
        &corrupt_destination,
    );
    assert!(
        matches!(corruption_result, Err(ArtifactError::Integrity(_))),
        "corrupt object returned {corruption_result:?}"
    );
    assert!(!corrupt_destination.exists());

    exercise_minio_pagination(
        &administrative_client,
        &prefix,
        &remote_fixture.publication.scope,
    );
    exercise_minio_transport_interruptions(&administrative_client, &prefix, &limits);

    let abandoned_multipart_key = format!(
        "{}/staging/abandoned-multipart",
        remote_scope_prefix(&prefix, &remote_fixture.publication.scope)
    );
    let runtime = tokio::runtime::Runtime::new().expect("administrative runtime");
    runtime
        .block_on(
            administrative_client.create_multipart_upload(CreateMultipartUploadRequest::new(
                ObjectKey::new(abandoned_multipart_key).expect("multipart key"),
            )),
        )
        .expect("create abandoned multipart upload");

    thread::sleep(Duration::from_millis(10_100));
    let (first_gc, second_gc) = thread::scope(|scope| {
        let first = scope.spawn(|| worker_a.garbage_collect(&remote_fixture.publication.scope));
        let second = scope.spawn(|| worker_b.garbage_collect(&remote_fixture.publication.scope));
        (
            first.join().expect("first concurrent collector"),
            second.join().expect("second concurrent collector"),
        )
    });
    let first_gc = first_gc.expect("first concurrent GC");
    let second_gc = second_gc.expect("second concurrent GC");
    assert!(first_gc.retained_objects >= 3);
    assert!(second_gc.retained_objects >= 3);
    let concurrently_removed_staging = first_gc
        .removed_staging_objects
        .saturating_add(second_gc.removed_staging_objects);

    worker_a
        .remove_reference(
            &remote_fixture.publication.scope,
            &remote_fixture.publication.manifest.snapshot_id,
        )
        .expect("remove snapshot reference");
    worker_a
        .remove_reference(
            &race_fixture.publication.scope,
            &race_fixture.publication.manifest.snapshot_id,
        )
        .expect("remove concurrent snapshot reference");
    let collected = worker_a
        .garbage_collect(&remote_fixture.publication.scope)
        .expect("S3 garbage collection");
    assert!(collected.removed_unreferenced_objects >= 3);
    assert_eq!(collected.removed_transfer_objects, 3);
    assert!(
        collected
            .removed_staging_objects
            .saturating_add(concurrently_removed_staging)
            >= 1
    );
}

fn bytes_per_second(bytes: u64, millis: u128) -> u128 {
    u128::from(bytes).saturating_mul(1_000) / millis.max(1)
}

fn remote_scope_prefix(prefix: &str, scope: &ArtifactScope) -> String {
    format!(
        "{prefix}/tenants/{}/workspaces/{}",
        hex::encode(Sha256::digest(scope.tenant_id().as_str().as_bytes())),
        hex::encode(Sha256::digest(scope.workspace_id().as_str().as_bytes()))
    )
}

fn remote_object_key(
    prefix: &str,
    scope: &ArtifactScope,
    digest: &str,
    media_type: &str,
) -> String {
    let digest = digest.strip_prefix("sha256:").expect("SHA-256 digest");
    let media = Sha256::digest(media_type.as_bytes());
    format!(
        "{}/objects/sha256/{digest}/{}.envelope",
        remote_scope_prefix(prefix, scope),
        hex::encode(&media[..8])
    )
}

fn put_bytes(client: &S3Client, key: String, bytes: &'static [u8]) {
    tokio::runtime::Runtime::new()
        .expect("administrative runtime")
        .block_on(client.put_object(PutObjectRequest::new(
            ObjectKey::new(key).expect("object key"),
            ByteStream::from_bytes(bytes),
        )))
        .expect("put administrative object");
}

fn exercise_minio_pagination(client: &S3Client, prefix: &str, scope: &ArtifactScope) {
    const OBJECTS: usize = 1_001;
    const CONCURRENCY: usize = 32;
    let pagination_prefix = format!("{}/staging/pagination/", remote_scope_prefix(prefix, scope));
    let keys = (0..OBJECTS)
        .map(|index| format!("{pagination_prefix}{index:04}"))
        .collect::<Vec<_>>();
    let runtime = tokio::runtime::Runtime::new().expect("pagination runtime");
    runtime.block_on(async {
        let mut tasks = tokio::task::JoinSet::new();
        for key in &keys {
            let client = client.clone();
            let key = ObjectKey::new(key.clone()).expect("pagination key");
            tasks.spawn(async move {
                client
                    .put_object(PutObjectRequest::new(
                        key,
                        ByteStream::from_bytes(b"page".as_slice()),
                    ))
                    .await
            });
            if tasks.len() >= CONCURRENCY {
                tasks
                    .join_next()
                    .await
                    .expect("pagination upload task")
                    .expect("pagination upload join")
                    .expect("pagination upload");
            }
        }
        while let Some(result) = tasks.join_next().await {
            result
                .expect("pagination upload join")
                .expect("pagination upload");
        }

        let pages = client
            .list_objects_v2_all(
                ListObjectsV2Request {
                    prefix: Some(pagination_prefix),
                    ..ListObjectsV2Request::default()
                },
                3,
            )
            .await
            .expect("paginated MinIO listing");
        assert_eq!(pages.len(), 2);
        assert_eq!(
            pages.iter().map(|page| page.objects.len()).sum::<usize>(),
            OBJECTS
        );

        let mut tasks = tokio::task::JoinSet::new();
        for key in keys {
            let client = client.clone();
            let key = ObjectKey::new(key).expect("pagination key");
            tasks.spawn(async move { client.delete_object(DeleteObjectRequest::new(key)).await });
            if tasks.len() >= CONCURRENCY {
                tasks
                    .join_next()
                    .await
                    .expect("pagination delete task")
                    .expect("pagination delete join")
                    .expect("pagination delete");
            }
        }
        while let Some(result) = tasks.join_next().await {
            result
                .expect("pagination delete join")
                .expect("pagination delete");
        }
    });
}

fn exercise_minio_transport_interruptions(
    administrative_client: &S3Client,
    prefix: &str,
    limits: &ArtifactLimits,
) {
    let upstream = minio_address();

    let upload_proxy = FaultProxy::new(upstream, FaultMode::UploadPart);
    let upload_store = S3ArtifactStore::from_client(
        client_for_endpoint(&format!("http://{}", upload_proxy.address()), 1),
        format!("{prefix}-interrupted-upload"),
        MASTER_KEY,
        limits.clone(),
    )
    .expect("interrupted upload store");
    let upload_fixture = fixture("snapshot-minio-interrupted-upload");
    assert!(upload_store
        .publish(upload_fixture.publication.clone())
        .is_err());
    assert!(upload_proxy.faulted());
    assert!(!upload_store
        .exists(
            &upload_fixture.publication.scope,
            &upload_fixture.publication.manifest.snapshot_id,
        )
        .expect("interrupted snapshot existence"));

    let upload_prefix = remote_scope_prefix(
        &format!("{prefix}-interrupted-upload"),
        &upload_fixture.publication.scope,
    );
    let runtime = tokio::runtime::Runtime::new().expect("fault verification runtime");
    let uploads = runtime
        .block_on(
            administrative_client.list_multipart_uploads(ListMultipartUploadsRequest {
                prefix: Some(upload_prefix),
                ..ListMultipartUploadsRequest::default()
            }),
        )
        .expect("list interrupted multipart uploads");
    assert!(uploads.uploads.is_empty());
    drop(upload_proxy);

    let download_prefix = format!("{prefix}-interrupted-download");
    let direct_store = S3ArtifactStore::from_client(
        administrative_client.clone(),
        download_prefix.clone(),
        MASTER_KEY,
        limits.clone(),
    )
    .expect("download fixture store");
    let download_fixture = fixture("snapshot-minio-interrupted-download");
    direct_store
        .publish(download_fixture.publication.clone())
        .expect("publish interrupted download fixture");

    let download_proxy = FaultProxy::new(upstream, FaultMode::DownloadBody);
    let interrupted_reader = S3ArtifactStore::from_client(
        client_for_endpoint(&format!("http://{}", download_proxy.address()), 1),
        download_prefix,
        MASTER_KEY,
        limits.clone(),
    )
    .expect("interrupted download store");
    let destination_root = tempfile::tempdir().expect("interrupted destination root");
    let destination = destination_root.path().join("materialized");
    assert!(interrupted_reader
        .materialize(
            &download_fixture.publication.scope,
            &download_fixture.publication.manifest.snapshot_id,
            &destination,
        )
        .is_err());
    assert!(download_proxy.faulted());
    assert!(!destination.exists());
}

#[derive(Clone, Copy)]
enum FaultMode {
    UploadPart,
    DownloadBody,
}

struct FaultProxy {
    address: SocketAddr,
    faulted: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl FaultProxy {
    fn new(upstream: SocketAddr, mode: FaultMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind MinIO fault proxy");
        listener
            .set_nonblocking(true)
            .expect("set fault proxy nonblocking");
        let address = listener.local_addr().expect("fault proxy address");
        let faulted = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_faulted = Arc::clone(&faulted);
        let worker_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut connections = Vec::new();
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((downstream, _)) => {
                        let faulted = Arc::clone(&worker_faulted);
                        connections.push(thread::spawn(move || {
                            relay_minio_request(downstream, upstream, mode, &faulted);
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept MinIO fault-proxy connection: {error}"),
                }
            }
            for connection in connections {
                connection.join().expect("MinIO fault-proxy connection");
            }
        });
        Self {
            address,
            faulted,
            stop,
            handle: Some(handle),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn faulted(&self) -> bool {
        self.faulted.load(Ordering::Acquire)
    }
}

impl Drop for FaultProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("stop MinIO fault proxy");
        }
    }
}

fn relay_minio_request(
    mut downstream: TcpStream,
    upstream_address: SocketAddr,
    mode: FaultMode,
    faulted: &AtomicBool,
) {
    downstream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("fault-proxy downstream timeout");
    let mut upstream = TcpStream::connect(upstream_address).expect("connect fault proxy to MinIO");
    upstream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("fault-proxy upstream timeout");
    let request_head = match read_http_head(&mut downstream) {
        Ok(head) => head,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return,
        Err(error) => panic!("read fault-proxy request: {error}"),
    };
    let request_line = first_http_line(&request_head);
    let content_length = http_content_length(&request_head);
    upstream
        .write_all(&connection_close_head(&request_head))
        .expect("forward fault-proxy request head");

    let interrupt_upload = matches!(mode, FaultMode::UploadPart)
        && request_line.starts_with("PUT ")
        && request_line.contains("partNumber=")
        && !faulted.swap(true, Ordering::AcqRel);
    if interrupt_upload {
        let partial = content_length.saturating_sub(1).clamp(1, 64 * 1024);
        io::copy(&mut (&mut downstream).take(partial), &mut upstream)
            .expect("forward partial multipart body");
        let _ = upstream.shutdown(Shutdown::Both);
        let _ = downstream.shutdown(Shutdown::Both);
        return;
    }

    io::copy(&mut (&mut downstream).take(content_length), &mut upstream)
        .expect("forward fault-proxy request body");
    upstream.flush().expect("flush fault-proxy request");

    let interrupt_download = matches!(mode, FaultMode::DownloadBody)
        && request_line.starts_with("GET ")
        && !request_line.contains("?list-type=")
        && !faulted.swap(true, Ordering::AcqRel);
    if interrupt_download {
        let response_head = read_http_head(&mut upstream).expect("read MinIO response head");
        let response_length = http_content_length(&response_head);
        downstream
            .write_all(&response_head)
            .expect("forward MinIO response head");
        let partial = (response_length / 2)
            .max(1)
            .min(response_length.saturating_sub(1));
        io::copy(&mut (&mut upstream).take(partial), &mut downstream)
            .expect("forward partial MinIO response");
        let _ = downstream.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
        return;
    }

    io::copy(&mut upstream, &mut downstream).expect("forward MinIO response");
}

fn read_http_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if stream.read(&mut byte)? == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() > 128 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP headers exceed the fault-proxy limit",
            ));
        }
    }
}

fn first_http_line(head: &[u8]) -> &str {
    let head = std::str::from_utf8(head).expect("ASCII HTTP head");
    head.lines().next().expect("HTTP request line")
}

fn http_content_length(head: &[u8]) -> u64 {
    let head = std::str::from_utf8(head).expect("ASCII HTTP head");
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().expect("HTTP content length"))
        })
        .unwrap_or(0)
}

fn connection_close_head(head: &[u8]) -> Vec<u8> {
    let head = std::str::from_utf8(head).expect("ASCII HTTP head");
    let mut output = head
        .trim_end_matches("\r\n")
        .lines()
        .filter(|line| {
            line.split_once(':')
                .is_none_or(|(name, _)| !name.eq_ignore_ascii_case("connection"))
        })
        .collect::<Vec<_>>()
        .join("\r\n")
        .into_bytes();
    output.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    output
}

fn minio_address() -> SocketAddr {
    env::var("S3_TEST_ENDPOINT")
        .expect("S3_TEST_ENDPOINT")
        .strip_prefix("http://")
        .expect("fault-injected MinIO endpoint must use local HTTP")
        .parse()
        .expect("MinIO socket address")
}

fn client_from_environment() -> S3Client {
    client_for_endpoint(&env::var("S3_TEST_ENDPOINT").expect("S3_TEST_ENDPOINT"), 4)
}

fn client_for_endpoint(endpoint: &str, max_attempts: u32) -> S3Client {
    let endpoint = Endpoint::new(endpoint).expect("S3 endpoint");
    let credentials = Credentials::new(
        env::var("S3_TEST_ACCESS_KEY_ID").expect("S3_TEST_ACCESS_KEY_ID"),
        env::var("S3_TEST_SECRET_ACCESS_KEY").expect("S3_TEST_SECRET_ACCESS_KEY"),
        env::var("S3_TEST_SESSION_TOKEN").ok(),
    )
    .expect("S3 credentials");
    let provider: Arc<dyn CredentialsProvider> =
        Arc::new(StaticCredentialsProvider::new(credentials));
    let mut builder = S3Config::builder()
        .endpoint(endpoint.clone())
        .region(env::var("S3_TEST_REGION").unwrap_or_else(|_| "us-east-1".to_owned()))
        .bucket(env::var("S3_TEST_BUCKET").expect("S3_TEST_BUCKET"))
        .addressing_style(AddressingStyle::Path)
        .connect_timeout(Duration::from_secs(1))
        .attempt_timeout(Duration::from_secs(5))
        .operation_timeout(Duration::from_secs(5))
        .idle_body_timeout(Duration::from_secs(1))
        .multipart_threshold(5 * 1024 * 1024)
        .multipart_part_size(5 * 1024 * 1024)
        .multipart_concurrency(2)
        .max_multipart_in_flight_bytes(10 * 1024 * 1024)
        .retry_policy(
            RetryPolicy::new(
                max_attempts,
                Duration::from_millis(10),
                Duration::from_millis(50),
                Duration::from_secs(2),
            )
            .expect("S3 retry policy"),
        )
        .credentials_provider(provider);
    if !endpoint.is_https() {
        builder = builder.allow_http_for_local_testing();
    }
    S3Client::new(builder.build().expect("S3 configuration")).expect("S3 client")
}

struct Fixture {
    _directory: tempfile::TempDir,
    publication: SnapshotPublication,
    expected: BTreeMap<String, Vec<u8>>,
}

fn fixture(snapshot_id: &str) -> Fixture {
    let directory = tempfile::tempdir().expect("fixture directory");
    let runtime = directory.path().join("state.img");
    let metadata = directory.path().join("service.json");
    let runtime_bytes = vec![0x41; 5 * 1024 * 1024 + 17];
    let metadata_bytes = br#"{"state":"paused"}"#.to_vec();
    fs::write(&runtime, &runtime_bytes).expect("runtime object");
    fs::write(&metadata, &metadata_bytes).expect("metadata object");
    let scope = ArtifactScope::new(
        TenantId::parse("tenant-a").expect("tenant"),
        WorkspaceId::parse("team-a").expect("workspace"),
    );
    let manifest = SnapshotManifest {
        schema_version: runtrue_sandbox_core::SNAPSHOT_MANIFEST_VERSION,
        snapshot_id: SnapshotId::parse(snapshot_id).expect("snapshot"),
        tenant_id: scope.tenant_id().clone(),
        workspace_id: scope.workspace_id().clone(),
        sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox"),
        sandbox_spec_digest: format!("sha256:{}", "a".repeat(64)),
        source_worker: WorkerId::parse("worker-a").expect("worker"),
        source_assignment_epoch: 7,
        created_unix_millis: 1,
        captured_from: LifecycleState::Paused,
        restore_state: LifecycleState::Paused,
        mode: SnapshotMode::StopAndMove,
        backend: BackendDescriptor {
            kind: BackendKind::Gvisor,
            implementation: "runsc".to_owned(),
            implementation_version: "test".to_owned(),
            state_format_version: 1,
            configuration_digest: format!("sha256:{}", "b".repeat(64)),
        },
        restore_requirements: RestoreRequirements {
            architecture: "amd64".to_owned(),
            operating_system: "linux".to_owned(),
            minimum_backend_version: "test".to_owned(),
            portability: SnapshotPortability::CrossWorkerSameBackend,
            required_cpu_features: Vec::new(),
            cpu_features_digest: format!("sha256:{}", "c".repeat(64)),
            preserves_internal_connections: true,
            guest_profile: runtrue_sandbox_core::GuestProfile::strict().identity,
        },
        containers: BTreeMap::new(),
        sandbox_objects: Vec::new(),
        volumes: BTreeMap::new(),
    };
    Fixture {
        _directory: directory,
        publication: SnapshotPublication {
            scope,
            manifest,
            objects: vec![
                StagedSnapshotObject {
                    role: ArtifactRole::RuntimeState,
                    container: None,
                    name: "state.img".to_owned(),
                    path: runtime,
                    media_type: "application/vnd.runtrue.test.runtime".to_owned(),
                    volume: None,
                },
                StagedSnapshotObject {
                    role: ArtifactRole::BackendMetadata,
                    container: Some(ContainerId::parse("server").expect("container")),
                    name: "service.json".to_owned(),
                    path: metadata,
                    media_type: "application/vnd.runtrue.test.metadata+json".to_owned(),
                    volume: None,
                },
            ],
        },
        expected: BTreeMap::from([
            ("state.img".to_owned(), runtime_bytes),
            ("service.json".to_owned(), metadata_bytes),
        ]),
    }
}
