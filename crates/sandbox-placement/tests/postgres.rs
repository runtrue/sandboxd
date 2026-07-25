use runtrue_sandbox_core::{
    GuestProfile, PoolPolicy, QueuedWork, ResourceCeilings, SandboxId, SubjectId, TenantId,
    WorkerId, WorkspaceId,
};
use runtrue_sandbox_placement::{
    Assignment, CompletionOutcome, EnqueueOutcome, PlacementStoreConfig, PlacementStoreError,
    PlacementSubmission, PostgresPlacementStore, RecoveryPolicy, WorkerRegistration,
};
use runtrue_sandbox_protocol::{Operation, WorkloadResponse, PROTOCOL_VERSION};
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
    let mut invalid_recovery = submission(
        "tenant-a",
        "invalid-recovery-operation",
        "sandbox-invalid-recovery",
        10_000,
    );
    invalid_recovery.recovery_policy = Some(RecoveryPolicy {
        snapshot_interval_ms: 1_000,
        maximum_staleness_ms: 5_000,
        maximum_attempts: 2,
    });
    assert!(matches!(
        replica_a.enqueue(&invalid_recovery, 101).await,
        Err(PlacementStoreError::Invalid(_))
    ));
    invalid_recovery.operation = Operation::Restore {
        topology: serde_json::from_str(include_str!("../../../deploy/k3s/fixed-runtime.lock.json"))
            .expect("topology"),
        sandbox: invalid_recovery.work.sandbox_id.to_string(),
        snapshot: "snapshot-a".to_owned(),
        timeout_ms: 1_000,
        fenced_source_epoch: Some(1),
    };
    assert!(matches!(
        replica_a.enqueue(&invalid_recovery, 101).await,
        Err(PlacementStoreError::Invalid(_))
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
    for sequence in 0..500 {
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
    let active_route = replica_b
        .active_assignment_by_idempotency(
            &expired_source.identity.tenant_id,
            &expired_source.subject_id,
            &expired_source.idempotency_key,
            130,
        )
        .await
        .expect("active route lookup")
        .expect("active route");
    assert_eq!(active_route.worker_id, expired_source.worker_id);
    assert_eq!(active_route.epoch, expired_source.epoch);
    assert!(replica_b
        .active_assignment_by_idempotency(
            &expired_source.identity.tenant_id,
            &expired_source.subject_id,
            &expired_source.idempotency_key,
            181,
        )
        .await
        .expect("expired route lookup")
        .is_none());
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
    assert_terminal_audit(url, &source, &digest('a')).await;

    let worker_d = worker("worker-d");
    replica_b
        .register_worker(&worker_d, 200)
        .await
        .expect("worker to drain");
    replica_b
        .drain_worker(&worker_d.worker_id)
        .await
        .expect("drain worker");
    replica_b
        .heartbeat_worker(&worker_d.worker_id, 201)
        .await
        .expect("draining worker heartbeat");
    assert!(!replica_b
        .clean_workers(201, 16)
        .await
        .expect("clean workers")
        .contains(&worker_d.worker_id));
    replica_b
        .quarantine_worker(&worker_d.worker_id, 202)
        .await
        .expect("quarantine worker");
    assert!(matches!(
        replica_b.heartbeat_worker(&worker_d.worker_id, 202).await,
        Err(PlacementStoreError::WorkerUnavailable)
    ));

    let mut service = submission(
        "tenant-service",
        "service-create",
        "sandbox-service",
        10_000,
    );
    service.operation = Operation::Create {
        topology: serde_json::from_str(include_str!("../../../deploy/k3s/fixed-runtime.lock.json"))
            .expect("topology"),
        sandbox: service.work.sandbox_id.to_string(),
        timeout_ms: 1_000,
    };
    service.topology = "service-topology".to_owned();
    replica_b
        .enqueue(&service, 400)
        .await
        .expect("enqueue service");
    let mut service_worker = worker("worker-service");
    service_worker.topology = service.topology.clone();
    replica_b
        .register_worker(&service_worker, 400)
        .await
        .expect("register service worker");
    let service_assignment = replica_b
        .assign_next(&service_worker.worker_id, 401)
        .await
        .expect("assign service")
        .expect("service assignment");
    replica_b
        .complete_response(
            &service_assignment,
            &WorkloadResponse {
                schema_version: PROTOCOL_VERSION,
                request_id: service_assignment.request_id.clone(),
                ok: true,
                result: Some(serde_json::json!({"state": "running"})),
                error: None,
            },
            402,
        )
        .await
        .expect("publish serving state");
    let serving = replica_b
        .get_by_idempotency(
            &service.work.tenant_id,
            &service.subject_id,
            &service.work.idempotency_key,
        )
        .await
        .expect("serving lookup")
        .expect("serving placement");
    assert_eq!(
        serving.state,
        runtrue_sandbox_placement::PlacementState::Serving
    );
    replica_b
        .heartbeat_worker(&service_worker.worker_id, 440)
        .await
        .expect("renew serving lease");
    assert!(replica_b
        .active_assignment_by_idempotency(
            &service.work.tenant_id,
            &service.subject_id,
            &service.work.idempotency_key,
            452,
        )
        .await
        .expect("renewed route lookup")
        .is_some());
    let fenced = replica_b
        .fence_expired(452)
        .await
        .expect("fence unrelated leases");
    assert!(fenced
        .iter()
        .all(|record| record.request_id != service_assignment.request_id));
    let cancelled = replica_b
        .cancel(
            &service.work.tenant_id,
            &service.subject_id,
            &service.work.idempotency_key,
            453,
        )
        .await
        .expect("cancel service")
        .expect("cancelled service");
    assert_eq!(
        cancelled.state,
        runtrue_sandbox_placement::PlacementState::Cancelled
    );

    let expiring = submission(
        "tenant-expiry",
        "deadline-expiry",
        "sandbox-deadline-expiry",
        300,
    );
    replica_b
        .enqueue(&expiring, 200)
        .await
        .expect("enqueue deadline test");
    replica_b
        .fence_expired(301)
        .await
        .expect("periodic deadline reconciliation");
    let expired = replica_b
        .get_by_idempotency(
            &expiring.work.tenant_id,
            &expiring.subject_id,
            &expiring.work.idempotency_key,
        )
        .await
        .expect("lookup expired request")
        .expect("expired request");
    assert_eq!(
        expired.state,
        runtrue_sandbox_placement::PlacementState::Expired
    );
    replica_b
        .enqueue(
            &submission(
                "tenant-expiry",
                "after-expiry",
                "sandbox-after-expiry",
                10_000,
            ),
            302,
        )
        .await
        .expect("expired queue entry releases capacity");

    let mut quarantined_submission = submission(
        "tenant-quarantine",
        "quarantine-assignment",
        "sandbox-quarantine",
        10_000,
    );
    quarantined_submission.topology = "quarantine-topology".to_owned();
    replica_b
        .enqueue(&quarantined_submission, 303)
        .await
        .expect("enqueue quarantine test");
    let mut worker_e = worker("worker-e");
    worker_e.topology = "quarantine-topology".to_owned();
    replica_b
        .register_worker(&worker_e, 303)
        .await
        .expect("quarantine source worker");
    let quarantined_assignment = replica_b
        .assign_next(&worker_e.worker_id, 304)
        .await
        .expect("assign quarantine source")
        .expect("quarantine assignment");
    replica_b
        .quarantine_worker(&worker_e.worker_id, 305)
        .await
        .expect("fence quarantined worker");
    assert!(matches!(
        replica_b
            .complete(&quarantined_assignment, &digest('e'), 306)
            .await,
        Err(PlacementStoreError::StaleAssignment)
    ));
    let mut worker_f = worker("worker-f");
    worker_f.topology = "quarantine-topology".to_owned();
    replica_b
        .register_worker(&worker_f, 306)
        .await
        .expect("quarantine destination worker");
    let replacement = replica_b
        .assign_next(&worker_f.worker_id, 307)
        .await
        .expect("assign quarantine replacement")
        .expect("replacement assignment");
    assert!(replacement.epoch > quarantined_assignment.epoch);
    replica_b
        .complete(&replacement, &digest('f'), 308)
        .await
        .expect("replacement wins");

    let policy = PoolPolicy {
        minimum_workers: 0,
        maximum_workers: 100,
        warm_headroom: 2,
        maximum_scale_up_per_reconcile: 10,
        maximum_scale_down_per_reconcile: 4,
        idle_before_scale_down_ms: 10,
    };
    let first_scale = replica_b
        .reconcile_pool("fixed-standard-warm", 0, 100, policy, 309)
        .await
        .expect("durable demand");
    assert!(first_scale.decision.create_workers > 0);
    let duplicate_scale = replica_b
        .reconcile_pool("fixed-standard-warm", 0, 100, policy, 309)
        .await
        .expect("duplicate reconcile");
    assert_eq!(duplicate_scale, first_scale);
    let quota = replica_b
        .reconcile_pool("fixed-standard-warm", 0, 0, policy, 310)
        .await
        .expect("quota backpressure");
    assert_eq!(quota.decision.desired_workers, 0);
    assert!(quota.decision.backpressured_assignments > 0);

    let mut idle_a = worker("worker-idle-a");
    idle_a.pool_name = "idle-pool".to_owned();
    let mut idle_b = worker("worker-idle-b");
    idle_b.pool_name = "idle-pool".to_owned();
    replica_b
        .register_worker(&idle_a, 400)
        .await
        .expect("first idle worker");
    replica_b
        .register_worker(&idle_b, 400)
        .await
        .expect("second idle worker");
    let cold_policy = PoolPolicy {
        warm_headroom: 0,
        ..policy
    };
    assert_eq!(
        replica_b
            .reconcile_pool("idle-pool", 2, 2, cold_policy, 400)
            .await
            .expect("start idle clock")
            .decision
            .drain_clean_workers,
        0
    );
    assert_eq!(
        replica_b
            .reconcile_pool("idle-pool", 2, 2, cold_policy, 410)
            .await
            .expect("restart-safe idle scale down")
            .decision
            .drain_clean_workers,
        2
    );
    assert!(replica_b
        .drain_workers_if_clean(&[idle_a.worker_id.clone(), idle_b.worker_id.clone()])
        .await
        .expect("atomic clean drain"));
    assert!(replica_b
        .worker_states(&[idle_a.worker_id.clone(), idle_b.worker_id.clone()])
        .await
        .expect("draining state")
        .iter()
        .all(|(_, state)| *state == runtrue_sandbox_placement::PlacementWorkerState::Draining));

    let mut pool_bound = submission(
        "tenant-pool-bound",
        "pool-bound",
        "sandbox-pool-bound",
        10_000,
    );
    pool_bound.pool_name = "other-reviewed-pool".to_owned();
    pool_bound.topology = "pool-bound-topology".to_owned();
    replica_b
        .enqueue(&pool_bound, 420)
        .await
        .expect("pool-bound demand");
    let mut wrong_pool = worker("worker-wrong-pool");
    wrong_pool.topology = "pool-bound-topology".to_owned();
    replica_b
        .register_worker(&wrong_pool, 420)
        .await
        .expect("wrong-pool worker");
    assert!(replica_b
        .assign_next(&wrong_pool.worker_id, 421)
        .await
        .expect("pool fence")
        .is_none());
    let mut matching_pool = worker("worker-matching-pool");
    matching_pool.pool_name = "other-reviewed-pool".to_owned();
    matching_pool.topology = "pool-bound-topology".to_owned();
    replica_b
        .register_worker(&matching_pool, 421)
        .await
        .expect("matching-pool worker");
    let pool_assignment = replica_b
        .assign_next(&matching_pool.worker_id, 422)
        .await
        .expect("pool assignment")
        .expect("matching pool demand");
    assert!(!replica_b
        .drain_workers_if_clean(&[matching_pool.worker_id])
        .await
        .expect("active worker is not drainable"));
    assert_eq!(
        pool_assignment.identity.tenant_id,
        pool_bound.work.tenant_id
    );
    assert_eq!(
        pool_assignment.identity.sandbox_id,
        pool_bound.work.sandbox_id
    );

    let mut recovery = submission(
        "tenant-recovery",
        "recover-active",
        "sandbox-recovery",
        10_000,
    );
    recovery.topology = "recovery-topology".to_owned();
    recovery.operation = Operation::Create {
        topology: serde_json::from_str(include_str!("../../../deploy/k3s/fixed-runtime.lock.json"))
            .expect("topology"),
        sandbox: recovery.work.sandbox_id.to_string(),
        timeout_ms: 1_000,
    };
    recovery.recovery_policy = Some(RecoveryPolicy {
        snapshot_interval_ms: 1_000,
        maximum_staleness_ms: 5_000,
        maximum_attempts: 2,
    });
    replica_b
        .enqueue(&recovery, 1_000)
        .await
        .expect("enqueue recoverable service");
    let mut recovery_source = worker("worker-recovery-source");
    recovery_source.topology = recovery.topology.clone();
    replica_b
        .register_worker(&recovery_source, 1_000)
        .await
        .expect("register recovery source");
    let source_assignment = replica_b
        .assign_next(&recovery_source.worker_id, 1_001)
        .await
        .expect("assign recovery source")
        .expect("recovery source assignment");
    replica_b
        .complete_response(
            &source_assignment,
            &WorkloadResponse {
                schema_version: PROTOCOL_VERSION,
                request_id: source_assignment.request_id.clone(),
                ok: true,
                result: Some(serde_json::json!({"state": "running"})),
                error: None,
            },
            1_002,
        )
        .await
        .expect("source serving");
    for heartbeat in (1_040..=2_000).step_by(40) {
        replica_b
            .heartbeat_worker(&recovery_source.worker_id, heartbeat)
            .await
            .expect("renew before checkpoint");
    }
    let checkpoints = replica_b
        .claim_due_checkpoints(2_002, 8)
        .await
        .expect("claim checkpoint");
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].assignment.epoch, source_assignment.epoch);
    assert!(replica_b
        .claim_due_checkpoints(2_002, 8)
        .await
        .expect("checkpoint claim is leased")
        .is_empty());
    replica_b
        .publish_checkpoint(&checkpoints[0], 2_003)
        .await
        .expect("publish durable checkpoint reference");
    let fenced = replica_b
        .fence_expired(2_052)
        .await
        .expect("fence lost recovery source");
    let fenced_recovery = fenced
        .iter()
        .find(|record| record.request_id == source_assignment.request_id)
        .expect("recovery source was fenced");
    assert_eq!(
        fenced_recovery.state,
        runtrue_sandbox_placement::PlacementState::Recovering
    );
    let mut recovery_destination = worker("worker-recovery-destination");
    recovery_destination.topology = recovery.topology.clone();
    replica_b
        .register_worker(&recovery_destination, 2_052)
        .await
        .expect("register recovery destination");
    assert!(replica_b
        .assign_next(&recovery_destination.worker_id, 2_053)
        .await
        .expect("unconfirmed fence blocks recovery")
        .is_none());
    assert_eq!(
        replica_b
            .confirm_recovery_fence(&recovery_source.worker_id, 2_053)
            .await
            .expect("confirm source Pod fence"),
        1
    );
    let restored = replica_b
        .assign_next(&recovery_destination.worker_id, 2_054)
        .await
        .expect("assign recovery destination")
        .expect("recovery assignment");
    assert!(restored.epoch > source_assignment.epoch);
    assert!(matches!(
        restored.operation,
        Operation::Restore { ref snapshot, .. }
            if snapshot == checkpoints[0].snapshot_id.as_str()
    ));
    assert!(matches!(
        replica_b
            .complete_response(
                &source_assignment,
                &WorkloadResponse {
                    schema_version: PROTOCOL_VERSION,
                    request_id: source_assignment.request_id.clone(),
                    ok: true,
                    result: Some(serde_json::json!({"stale": true})),
                    error: None,
                },
                2_055,
            )
            .await,
        Err(PlacementStoreError::StaleAssignment)
    ));
    replica_b
        .complete_response(
            &restored,
            &WorkloadResponse {
                schema_version: PROTOCOL_VERSION,
                request_id: restored.request_id.clone(),
                ok: true,
                result: Some(serde_json::json!({"state": "running"})),
                error: None,
            },
            2_056,
        )
        .await
        .expect("destination serving");
    let recovered = replica_b
        .get_by_idempotency(
            &recovery.work.tenant_id,
            &recovery.subject_id,
            &recovery.work.idempotency_key,
        )
        .await
        .expect("recovery lookup")
        .expect("recovered placement");
    assert_eq!(
        recovered.state,
        runtrue_sandbox_placement::PlacementState::Serving
    );
    let recovery_status = recovered.recovery.expect("recovery status");
    assert_eq!(recovery_status.source_epoch, Some(source_assignment.epoch));
    assert_eq!(recovery_status.attempts, 1);
    assert_eq!(recovery_status.recovered_unix_ms, Some(2_056));
    assert_recovery_audit(
        url,
        &source_assignment,
        &restored,
        checkpoints[0].snapshot_id.as_str(),
    )
    .await;

    replica_b
        .record_scale_up("fixed-standard-warm", 3, 423)
        .await
        .expect("record activation");
    replica_b
        .record_scale_up("fixed-standard-warm", 3, 424)
        .await
        .expect("duplicate activation");
    replica_b
        .observe_pool_activation("fixed-standard-warm", 3, 2, 425)
        .await
        .expect("activation is still pending");
    replica_b
        .observe_pool_activation("fixed-standard-warm", 3, 3, 430)
        .await
        .expect("activation becomes ready");
    let metrics = replica_b
        .autoscale_metrics(
            &[
                "fixed-standard-warm".to_owned(),
                "other-reviewed-pool".to_owned(),
            ],
            2_100,
            Duration::from_secs(3),
        )
        .await
        .expect("durable autoscale metrics");
    assert_eq!(metrics.pools.len(), 2);
    assert!(metrics
        .latencies
        .iter()
        .any(|metric| metric.phase == "queue_residence"));
    let activation = metrics
        .latencies
        .iter()
        .find(|metric| {
            metric.pool_name == "fixed-standard-warm" && metric.phase == "create_to_ready"
        })
        .expect("activation quantiles");
    assert_eq!(activation.samples, 1);
    assert_eq!(activation.p99_milliseconds, 7);
    let recovery_rpo = metrics
        .latencies
        .iter()
        .find(|metric| metric.phase == "recovery_rpo/standard-v1")
        .expect("recovery RPO quantiles");
    assert_eq!(recovery_rpo.p99_milliseconds, 49);
    let recovery_rto = metrics
        .latencies
        .iter()
        .find(|metric| metric.phase == "recovery_rto/standard-v1")
        .expect("recovery RTO quantiles");
    assert_eq!(recovery_rto.p99_milliseconds, 4);
}

async fn assert_recovery_audit(
    url: &str,
    source: &Assignment,
    destination: &Assignment,
    snapshot: &str,
) {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("recovery audit database");
    tokio::spawn(async move {
        connection
            .await
            .expect("recovery audit database connection");
    });
    let rows = client
        .query(
            "SELECT worker_id, assignment_epoch, event, snapshot_id
             FROM sandboxd_placement.audit WHERE request_id = $1
             AND event IN (
                'checkpoint_published', 'source_fenced', 'recovery_queued',
                'source_fence_confirmed',
                'recovery_assigned', 'recovery_completed'
             ) ORDER BY sequence",
            &[&source.request_id],
        )
        .await
        .expect("recovery audit chain");
    assert_eq!(
        rows.iter()
            .map(|row| row.get::<_, String>("event"))
            .collect::<Vec<_>>(),
        vec![
            "checkpoint_published",
            "source_fenced",
            "recovery_queued",
            "source_fence_confirmed",
            "recovery_assigned",
            "recovery_completed"
        ]
    );
    assert_eq!(
        rows[1].get::<_, Option<String>>("worker_id").as_deref(),
        Some(source.worker_id.as_str())
    );
    assert_eq!(
        rows[1].get::<_, Option<i64>>("assignment_epoch"),
        Some(i64::try_from(source.epoch.get()).expect("source epoch"))
    );
    assert_eq!(
        rows[4].get::<_, Option<String>>("worker_id").as_deref(),
        Some(destination.worker_id.as_str())
    );
    assert_eq!(
        rows[4].get::<_, Option<i64>>("assignment_epoch"),
        Some(i64::try_from(destination.epoch.get()).expect("destination epoch"))
    );
    assert!(rows
        .iter()
        .all(|row| row.get::<_, Option<String>>("snapshot_id").as_deref() == Some(snapshot)));
}

async fn assert_terminal_audit(url: &str, assignment: &Assignment, result_digest: &str) {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("audit database");
    tokio::spawn(async move {
        connection.await.expect("audit database connection");
    });
    let row = client
        .query_one(
            "SELECT request_id, tenant_id, workspace_id, sandbox_id, subject_id,
                    worker_id, assignment_epoch, event, result_digest
             FROM sandboxd_placement.audit
             WHERE request_id = $1 AND event = 'completed'",
            &[&assignment.request_id],
        )
        .await
        .expect("terminal audit row");
    assert_eq!(row.get::<_, String>("request_id"), assignment.request_id);
    assert_eq!(
        row.get::<_, String>("tenant_id"),
        assignment.identity.tenant_id.as_str()
    );
    assert_eq!(
        row.get::<_, String>("workspace_id"),
        assignment.identity.workspace_id.as_str()
    );
    assert_eq!(
        row.get::<_, String>("sandbox_id"),
        assignment.identity.sandbox_id.as_str()
    );
    assert_eq!(
        row.get::<_, String>("subject_id"),
        assignment.subject_id.as_str()
    );
    assert_eq!(
        row.get::<_, Option<String>>("worker_id").as_deref(),
        Some(assignment.worker_id.as_str())
    );
    assert_eq!(
        row.get::<_, Option<i64>>("assignment_epoch"),
        Some(i64::try_from(assignment.epoch.get()).expect("epoch"))
    );
    assert_eq!(row.get::<_, String>("event"), "completed");
    assert_eq!(
        row.get::<_, Option<String>>("result_digest").as_deref(),
        Some(result_digest)
    );

    let columns = client
        .query(
            "SELECT column_name FROM information_schema.columns
             WHERE table_schema = 'sandboxd_placement' AND table_name = 'audit'",
            &[],
        )
        .await
        .expect("audit columns");
    assert!(columns.into_iter().all(|row| {
        let column = row.get::<_, String>(0);
        !["secret", "token", "credential", "operation", "response"]
            .iter()
            .any(|forbidden| column.contains(forbidden))
    }));
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
        pool_name: "fixed-standard-warm".to_owned(),
        topology: "topology-v1".to_owned(),
        resource_shape: "standard-v1".to_owned(),
        compatibility_cohort: "runsc-v1".to_owned(),
        operation: Operation::Inspect {
            sandbox: sandbox_name.to_owned(),
        },
        recovery_policy: None,
    }
}

fn worker(worker_id: &str) -> WorkerRegistration {
    WorkerRegistration {
        worker_id: WorkerId::parse(worker_id).expect("worker"),
        pool_name: "fixed-standard-warm".to_owned(),
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
