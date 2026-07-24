use runtrue_sandbox_core::{
    GuestProfile, QueuedWork, ResourceCeilings, SandboxId, SubjectId, TenantId, WorkerId,
    WorkspaceId,
};
use runtrue_sandbox_placement::{
    CompletionOutcome, EnqueueOutcome, PlacementStoreConfig, PlacementStoreError,
    PlacementSubmission, PostgresPlacementStore, WorkerRegistration,
};
use runtrue_sandbox_protocol::Operation;
use std::{env, time::Duration};

const TEST_DATABASE_MARKER: &str = "sandboxd_placement_test";

#[test]
fn durable_replicas_bound_queue_and_fence_stale_workers() {
    let Some(url) = env::var_os("SANDBOX_PLACEMENT_POSTGRES_URL") else {
        eprintln!("SANDBOX_PLACEMENT_POSTGRES_URL is unset; skipping PostgreSQL integration");
        return;
    };
    let url = url.to_string_lossy().into_owned();
    assert!(
        url.contains(TEST_DATABASE_MARKER),
        "integration test refuses to reset a database without the test marker"
    );
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Tokio runtime")
        .block_on(exercise(&url));
}

async fn exercise(url: &str) {
    reset(url).await;
    PostgresPlacementStore::migrate_local_insecure(url)
        .await
        .expect("placement migrations");
    let config = PlacementStoreConfig {
        global_queue_limit: 5,
        global_concurrency_limit: 2,
        default_tenant_queue_limit: 3,
        default_tenant_concurrency_limit: 1,
        worker_heartbeat_timeout: Duration::from_secs(30),
        lease_lifetime: Duration::from_millis(50),
        broker_port: 8081,
    };
    let replica_a = PostgresPlacementStore::connect_local_insecure(url, config)
        .await
        .expect("first placement replica");
    let replica_b = PostgresPlacementStore::connect_local_insecure(url, config)
        .await
        .expect("second placement replica");
    let tenant_a = tenant("tenant-a");
    let tenant_b = tenant("tenant-b");
    replica_a
        .set_tenant_policy(&tenant_a, 10, 1, 3)
        .await
        .expect("tenant A policy");
    replica_a
        .set_tenant_policy(&tenant_b, 100, 1, 3)
        .await
        .expect("tenant B policy");

    let first = submission("tenant-a", "idem-a-1", "sandbox-a", 10_000);
    assert!(matches!(
        replica_a.enqueue(&first, 100).await.expect("enqueue"),
        EnqueueOutcome::Queued(_)
    ));
    assert!(matches!(
        replica_b
            .enqueue(&first, 101)
            .await
            .expect("idempotent retry"),
        EnqueueOutcome::Existing(_)
    ));
    let conflicting = submission("tenant-a", "idem-a-other", "sandbox-a", 10_000);
    assert!(matches!(
        replica_b.enqueue(&conflicting, 101).await,
        Err(PlacementStoreError::SandboxConflict)
    ));

    let raced = submission("tenant-b", "idem-b-race", "sandbox-race", 10_000);
    let (raced_a, raced_b) = tokio::join!(
        replica_a.enqueue(&raced, 101),
        replica_b.enqueue(&raced, 101)
    );
    let raced_outcomes = [raced_a.expect("first race"), raced_b.expect("second race")];
    assert_eq!(
        raced_outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EnqueueOutcome::Queued(_)))
            .count(),
        1
    );
    assert_eq!(
        raced_outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EnqueueOutcome::Existing(_)))
            .count(),
        1
    );

    for (tenant_name, key, sandbox) in [
        ("tenant-a", "idem-a-2", "sandbox-b"),
        ("tenant-a", "idem-a-3", "sandbox-c"),
    ] {
        replica_a
            .enqueue(&submission(tenant_name, key, sandbox, 10_000), 102)
            .await
            .expect("bounded enqueue");
    }
    assert!(matches!(
        replica_b
            .enqueue(
                &submission("tenant-a", "tenant-overflow", "sandbox-overflow", 10_000),
                103,
            )
            .await,
        Err(PlacementStoreError::TenantQueueFull)
    ));
    replica_a
        .enqueue(
            &submission("tenant-b", "idem-b-2", "sandbox-d", 10_000),
            103,
        )
        .await
        .expect("fill global queue");
    for sequence in 0..400 {
        let overflow = submission(
            "tenant-b",
            &format!("overflow-{sequence}"),
            &format!("overflow-{sequence}"),
            10_000,
        );
        assert!(matches!(
            replica_b.enqueue(&overflow, 103).await,
            Err(PlacementStoreError::GlobalQueueFull)
        ));
    }

    let worker_a = worker("worker-a");
    let worker_b = worker("worker-b");
    let worker_c = worker("worker-c");
    for (store, registration) in [
        (&replica_a, &worker_a),
        (&replica_b, &worker_b),
        (&replica_b, &worker_c),
    ] {
        store
            .register_worker(registration, 110)
            .await
            .expect("clean worker registration");
    }
    let mut rotated_worker_a = worker_a.clone();
    rotated_worker_a.broker_address = "127.0.0.2:8081".parse().expect("rotated broker address");
    replica_b
        .register_worker(&rotated_worker_a, 111)
        .await
        .expect("clean worker address rotation");
    let source = replica_a
        .assign_next(&worker_a.worker_id, 120)
        .await
        .expect("source assignment")
        .expect("queued work");
    assert_eq!(source.identity.tenant_id, tenant_b);
    assert!(matches!(
        replica_b.register_worker(&worker_a, 121).await,
        Err(PlacementStoreError::WorkerUnavailable)
    ));

    drop(replica_a);
    let published = replica_b
        .complete(&source, &digest('a'), 121)
        .await
        .expect("surviving replica publishes result");
    assert_eq!(published, CompletionOutcome::Published);
    assert_eq!(
        replica_b
            .complete(&source, &digest('a'), 122)
            .await
            .expect("idempotent completion"),
        CompletionOutcome::AlreadyPublished
    );
    assert!(matches!(
        replica_b.complete(&source, &digest('b'), 122).await,
        Err(PlacementStoreError::CompletionConflict)
    ));

    let expired_source = replica_b
        .assign_next(&worker_b.worker_id, 130)
        .await
        .expect("second assignment")
        .expect("queued work");
    let fenced = replica_b
        .fence_expired(181)
        .await
        .expect("fence expired lease");
    assert_eq!(fenced.len(), 1);
    let destination = replica_b
        .assign_next(&worker_c.worker_id, 182)
        .await
        .expect("reassignment")
        .expect("requeued work");
    assert_eq!(destination.identity, expired_source.identity);
    assert!(destination.epoch > expired_source.epoch);
    assert!(matches!(
        replica_b.complete(&expired_source, &digest('c'), 183).await,
        Err(PlacementStoreError::StaleAssignment)
    ));
    replica_b
        .complete(&destination, &digest('d'), 183)
        .await
        .expect("new epoch wins");

    let observed = replica_b
        .get_by_idempotency(&tenant_b, &source.subject_id, &source.idempotency_key)
        .await
        .expect("durable lookup")
        .expect("completed request");
    assert_eq!(
        observed.result_digest.as_deref(),
        Some(digest('a').as_str())
    );
}

async fn reset(url: &str) {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("test database");
    tokio::spawn(async move {
        connection.await.expect("test database connection");
    });
    client
        .batch_execute("DROP SCHEMA IF EXISTS sandboxd_placement CASCADE")
        .await
        .expect("reset placement schema");
}

fn submission(
    tenant_name: &str,
    idempotency_key: &str,
    sandbox_name: &str,
    deadline_unix_ms: u64,
) -> PlacementSubmission {
    PlacementSubmission {
        work: QueuedWork {
            idempotency_key: idempotency_key.to_owned(),
            tenant_id: tenant(tenant_name),
            workspace_id: WorkspaceId::parse("workspace-a").expect("workspace"),
            sandbox_id: SandboxId::parse(sandbox_name).expect("sandbox"),
            deadline_unix_ms,
        },
        subject_id: SubjectId::parse("gateway-a").expect("subject"),
        topology: "topology-v1".to_owned(),
        resource_shape: "standard-v1".to_owned(),
        compatibility_cohort: "runsc-v1".to_owned(),
        operation: Operation::Inspect {
            sandbox: sandbox_name.to_owned(),
        },
    }
}

fn worker(worker_id: &str) -> WorkerRegistration {
    WorkerRegistration {
        worker_id: WorkerId::parse(worker_id).expect("worker"),
        topology: "topology-v1".to_owned(),
        resource_shape: "standard-v1".to_owned(),
        compatibility_cohort: "runsc-v1".to_owned(),
        broker_address: "127.0.0.1:8081".parse().expect("broker address"),
        resource_ceilings: ceilings(),
    }
}

fn ceilings() -> ResourceCeilings {
    ResourceCeilings {
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
    }
}

fn tenant(tenant_id: &str) -> TenantId {
    TenantId::parse(tenant_id).expect("tenant")
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}
