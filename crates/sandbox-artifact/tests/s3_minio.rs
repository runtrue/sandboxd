#![cfg(feature = "s3")]

use runtrue_sandbox_artifact::{
    ArtifactLimits, ArtifactScope, ArtifactStore, S3ArtifactStore, SnapshotPublication,
    StagedSnapshotObject,
};
use runtrue_sandbox_core::{
    ArtifactRole, AssignmentEpoch, BackendDescriptor, BackendKind, ContainerId, LifecycleState,
    RestoreRequirements, RestoreTarget, SandboxId, SnapshotId, SnapshotManifest, SnapshotMode,
    SnapshotPortability, TenantId, WorkerId, WorkspaceId,
};
use s3_wire::{
    AddressingStyle, Credentials, CredentialsProvider, Endpoint, S3Client, S3Config,
    StaticCredentialsProvider,
};
use std::{
    collections::BTreeMap,
    env, fs,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

const MASTER_KEY: [u8; 32] = [0x6b; 32];

#[test]
#[ignore = "requires an S3-compatible endpoint; run tools/test-s3-artifacts.sh"]
fn publish_on_worker_a_and_materialize_on_worker_b() {
    let client = client_from_environment();
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
        operation_timeout: Duration::from_secs(5),
        garbage_collection_grace: Duration::from_secs(10),
        ..ArtifactLimits::default()
    };
    let initialization_started = Instant::now();
    let worker_a =
        S3ArtifactStore::from_client(client.clone(), prefix.clone(), MASTER_KEY, limits.clone())
            .expect("worker A store");
    let worker_b =
        S3ArtifactStore::from_client(client, prefix, MASTER_KEY, limits).expect("worker B store");
    let initialization_millis = initialization_started.elapsed().as_millis();
    let fixture = fixture();

    let published = worker_a
        .publish(fixture.publication.clone())
        .expect("publish from worker A");
    assert_eq!(published.object_count, 2);
    assert!(published.transferred_bytes > published.logical_bytes);
    let destination_root = tempfile::tempdir().expect("destination root");
    let destination = destination_root.path().join("materialized");
    let restored = worker_b
        .materialize(
            &fixture.publication.scope,
            &fixture.publication.manifest.snapshot_id,
            &destination,
        )
        .expect("materialize on worker B");
    println!(
        "s3_minio_metrics initialization_millis={initialization_millis} logical_bytes={} publish_transferred_bytes={} publish_millis={} materialize_transferred_bytes={} materialization_millis={}",
        published.logical_bytes,
        published.transferred_bytes,
        published.publish_millis,
        restored.transferred_bytes,
        restored.materialization_millis,
    );
    assert_eq!(
        restored.manifest.snapshot_id,
        fixture.publication.manifest.snapshot_id
    );
    restored.manifest.validate().expect("restored manifest");
    for (name, expected) in &fixture.expected {
        assert_eq!(
            fs::read(destination.join(name)).expect("materialized object"),
            *expected
        );
    }

    let grant = worker_a
        .publish_transfer_grant(
            &fixture.publication.scope,
            &fixture.publication.manifest.snapshot_id,
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
            &fixture.publication.scope,
            &fixture.publication.manifest.snapshot_id,
            &target,
        )
        .expect("claim transfer on worker B");
    assert_eq!(claim.destination_worker, target.worker_id);

    worker_a
        .remove_reference(
            &fixture.publication.scope,
            &fixture.publication.manifest.snapshot_id,
        )
        .expect("remove snapshot reference");
    thread::sleep(Duration::from_millis(10_100));
    let collected = worker_a
        .garbage_collect(&fixture.publication.scope)
        .expect("S3 garbage collection");
    assert!(collected.removed_unreferenced_objects >= 3);
    assert_eq!(collected.removed_transfer_objects, 3);
}

fn client_from_environment() -> S3Client {
    let endpoint = env::var("S3_TEST_ENDPOINT").expect("S3_TEST_ENDPOINT");
    let endpoint = Endpoint::new(&endpoint).expect("S3 endpoint");
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

fn fixture() -> Fixture {
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
        snapshot_id: SnapshotId::parse("snapshot-minio").expect("snapshot"),
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
