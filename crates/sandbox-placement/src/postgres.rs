use runtrue_sandbox_core::{
    reconcile_worker_pool, AssignmentEpoch, AutoscaleDecision, PlacementIdentity, PoolObservation,
    PoolPolicy, QueuedWork, ResourceCeilings, SandboxId, SubjectId, TenantId, WorkerId,
    WorkspaceId,
};
use runtrue_sandbox_protocol::{Operation, WorkloadResponse};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read as _,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio_postgres::{
    config::{ChannelBinding, Host, SslMode},
    Client, Config, NoTls, Row,
};
use tokio_postgres_rustls::MakeRustlsConnect;

const MIGRATION_LOCK: i64 = 7_223_510_449_421;
const QUEUE_LOCK: i64 = 7_223_510_449_422;
const AUTOSCALE_LOCK: i64 = 7_223_510_449_423;
const SCHEMA_VERSION: i32 = 5;
const MAXIMUM_PEM_BYTES: u64 = 1024 * 1024;
const MAXIMUM_OPERATION_BYTES: usize = 512 * 1024;
const MAXIMUM_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

const MIGRATION: &str = r#"
CREATE SCHEMA IF NOT EXISTS sandboxd_placement;

CREATE TABLE IF NOT EXISTS sandboxd_placement.schema_version (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version INTEGER NOT NULL CHECK (version > 0)
);
INSERT INTO sandboxd_placement.schema_version (singleton, version)
VALUES (TRUE, 1) ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS sandboxd_placement.tenant_policy (
    tenant_id TEXT PRIMARY KEY,
    weight SMALLINT NOT NULL CHECK (weight BETWEEN 1 AND 100),
    concurrency_limit INTEGER NOT NULL CHECK (concurrency_limit > 0),
    queue_limit INTEGER NOT NULL CHECK (queue_limit > 0),
    virtual_finish BIGINT NOT NULL DEFAULT 0 CHECK (virtual_finish >= 0)
);

CREATE TABLE IF NOT EXISTS sandboxd_placement.queue_clock (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    virtual_time BIGINT NOT NULL DEFAULT 0 CHECK (virtual_time >= 0)
);
INSERT INTO sandboxd_placement.queue_clock (singleton, virtual_time)
VALUES (TRUE, 0) ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS sandboxd_placement.workers (
    worker_id TEXT PRIMARY KEY,
    topology TEXT NOT NULL,
    resource_shape TEXT NOT NULL,
    compatibility_cohort TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('clean', 'leased', 'draining', 'quarantined', 'consumed')),
    heartbeat_unix_ms BIGINT NOT NULL CHECK (heartbeat_unix_ms > 0),
    registered_unix_ms BIGINT NOT NULL CHECK (registered_unix_ms > 0)
);

CREATE TABLE IF NOT EXISTS sandboxd_placement.requests (
    request_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES sandboxd_placement.tenant_policy(tenant_id),
    workspace_id TEXT NOT NULL,
    sandbox_id TEXT NOT NULL,
    topology TEXT NOT NULL,
    resource_shape TEXT NOT NULL,
    compatibility_cohort TEXT NOT NULL,
    deadline_unix_ms BIGINT NOT NULL,
    created_unix_ms BIGINT NOT NULL,
    fair_finish BIGINT NOT NULL CHECK (fair_finish > 0),
    state TEXT NOT NULL CHECK (state IN ('queued', 'assigned', 'completed', 'cancelled', 'expired')),
    worker_id TEXT REFERENCES sandboxd_placement.workers(worker_id),
    assignment_epoch BIGINT,
    lease_expires_unix_ms BIGINT,
    result_digest TEXT,
    terminal_unix_ms BIGINT,
    UNIQUE (tenant_id, idempotency_key)
);

CREATE UNIQUE INDEX IF NOT EXISTS requests_live_sandbox
ON sandboxd_placement.requests (tenant_id, workspace_id, sandbox_id)
WHERE state IN ('queued', 'assigned', 'completed');

CREATE INDEX IF NOT EXISTS requests_queue_order
ON sandboxd_placement.requests (fair_finish, created_unix_ms, request_id)
WHERE state = 'queued';

CREATE TABLE IF NOT EXISTS sandboxd_placement.assignment_epochs (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    sandbox_id TEXT NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    PRIMARY KEY (tenant_id, workspace_id, sandbox_id)
);

CREATE TABLE IF NOT EXISTS sandboxd_placement.audit (
    sequence BIGSERIAL PRIMARY KEY,
    event_unix_ms BIGINT NOT NULL,
    request_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    sandbox_id TEXT NOT NULL,
    worker_id TEXT,
    assignment_epoch BIGINT,
    event TEXT NOT NULL,
    result_digest TEXT
);
"#;

const MIGRATION_V2: &str = r#"
ALTER TABLE sandboxd_placement.requests ADD COLUMN IF NOT EXISTS subject_id TEXT;
UPDATE sandboxd_placement.requests SET subject_id = 'legacy-unknown' WHERE subject_id IS NULL;
ALTER TABLE sandboxd_placement.requests ALTER COLUMN subject_id SET NOT NULL;

ALTER TABLE sandboxd_placement.audit ADD COLUMN IF NOT EXISTS subject_id TEXT;
UPDATE sandboxd_placement.audit SET subject_id = 'legacy-unknown' WHERE subject_id IS NULL;
ALTER TABLE sandboxd_placement.audit ALTER COLUMN subject_id SET NOT NULL;

UPDATE sandboxd_placement.schema_version SET version = 2 WHERE singleton = TRUE;
"#;

const MIGRATION_V3: &str = r#"
ALTER TABLE sandboxd_placement.workers
    ADD COLUMN IF NOT EXISTS broker_address TEXT,
    ADD COLUMN IF NOT EXISTS resource_ceilings TEXT;
UPDATE sandboxd_placement.workers
SET state = 'quarantined'
WHERE broker_address IS NULL OR resource_ceilings IS NULL;

ALTER TABLE sandboxd_placement.requests ADD COLUMN IF NOT EXISTS operation TEXT;
ALTER TABLE sandboxd_placement.requests ADD COLUMN IF NOT EXISTS terminal_response TEXT;
UPDATE sandboxd_placement.requests
SET state = 'expired',
    terminal_unix_ms = COALESCE(
        terminal_unix_ms,
        (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT
    )
WHERE operation IS NULL AND state IN ('queued', 'assigned');
UPDATE sandboxd_placement.requests
SET operation = '{"kind":"ping"}'
WHERE operation IS NULL;
ALTER TABLE sandboxd_placement.requests ALTER COLUMN operation SET NOT NULL;

UPDATE sandboxd_placement.schema_version SET version = 3 WHERE singleton = TRUE;
"#;

const MIGRATION_V4: &str = r#"
ALTER TABLE sandboxd_placement.workers ADD COLUMN IF NOT EXISTS pool_name TEXT;
UPDATE sandboxd_placement.workers
SET pool_name = 'legacy-unpooled'
WHERE pool_name IS NULL;
ALTER TABLE sandboxd_placement.workers ALTER COLUMN pool_name SET NOT NULL;

ALTER TABLE sandboxd_placement.requests ADD COLUMN IF NOT EXISTS pool_name TEXT;
UPDATE sandboxd_placement.requests
SET pool_name = 'legacy-unpooled'
WHERE pool_name IS NULL;
ALTER TABLE sandboxd_placement.requests ALTER COLUMN pool_name SET NOT NULL;

CREATE INDEX IF NOT EXISTS workers_pool_state
ON sandboxd_placement.workers (pool_name, state, heartbeat_unix_ms);
CREATE INDEX IF NOT EXISTS requests_pool_state
ON sandboxd_placement.requests (pool_name, state, created_unix_ms);

CREATE TABLE IF NOT EXISTS sandboxd_placement.autoscale_state (
    pool_name TEXT PRIMARY KEY,
    idle_since_unix_ms BIGINT,
    desired_workers INTEGER NOT NULL CHECK (desired_workers >= 0),
    updated_unix_ms BIGINT NOT NULL CHECK (updated_unix_ms > 0)
);

UPDATE sandboxd_placement.schema_version SET version = 4 WHERE singleton = TRUE;
"#;

const MIGRATION_V5: &str = r#"
ALTER TABLE sandboxd_placement.requests
    ADD COLUMN IF NOT EXISTS assigned_unix_ms BIGINT,
    ADD COLUMN IF NOT EXISTS first_output_unix_ms BIGINT,
    ADD COLUMN IF NOT EXISTS capacity_class TEXT;
UPDATE sandboxd_placement.requests
SET capacity_class = 'unknown'
WHERE capacity_class IS NULL;
ALTER TABLE sandboxd_placement.requests
    ALTER COLUMN capacity_class SET NOT NULL;
DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'requests_capacity_class'
          AND conrelid = 'sandboxd_placement.requests'::regclass
    ) THEN
        ALTER TABLE sandboxd_placement.requests
            ADD CONSTRAINT requests_capacity_class
            CHECK (capacity_class IN ('warm', 'cold', 'unknown'));
    END IF;
END
$migration$;

CREATE TABLE IF NOT EXISTS sandboxd_placement.pool_activations (
    sequence BIGSERIAL PRIMARY KEY,
    pool_name TEXT NOT NULL,
    requested_unix_ms BIGINT NOT NULL CHECK (requested_unix_ms > 0),
    target_workers INTEGER NOT NULL CHECK (target_workers > 0),
    ready_unix_ms BIGINT,
    cancelled_unix_ms BIGINT,
    CHECK (ready_unix_ms IS NULL OR cancelled_unix_ms IS NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS pool_activations_one_pending
ON sandboxd_placement.pool_activations (pool_name)
WHERE ready_unix_ms IS NULL AND cancelled_unix_ms IS NULL;
CREATE INDEX IF NOT EXISTS pool_activations_history
ON sandboxd_placement.pool_activations (pool_name, requested_unix_ms);
CREATE INDEX IF NOT EXISTS requests_metrics_assigned
ON sandboxd_placement.requests (pool_name, assigned_unix_ms)
WHERE assigned_unix_ms IS NOT NULL;
CREATE INDEX IF NOT EXISTS requests_metrics_terminal
ON sandboxd_placement.requests (pool_name, terminal_unix_ms)
WHERE terminal_unix_ms IS NOT NULL;

UPDATE sandboxd_placement.schema_version SET version = 5 WHERE singleton = TRUE;
"#;

#[derive(Debug, Clone, Copy)]
pub struct PlacementStoreConfig {
    pub global_queue_limit: i64,
    pub global_concurrency_limit: i64,
    pub default_tenant_queue_limit: i32,
    pub default_tenant_concurrency_limit: i32,
    pub worker_heartbeat_timeout: Duration,
    pub lease_lifetime: Duration,
    pub broker_port: u16,
}

impl PlacementStoreConfig {
    fn validate(self) -> Result<Self, PlacementStoreError> {
        if self.global_queue_limit <= 0
            || self.global_queue_limit > 1_000_000
            || self.global_concurrency_limit <= 0
            || self.global_concurrency_limit > 1_000_000
            || self.default_tenant_queue_limit <= 0
            || i64::from(self.default_tenant_queue_limit) > self.global_queue_limit
            || self.default_tenant_concurrency_limit <= 0
            || self.worker_heartbeat_timeout.is_zero()
            || self.worker_heartbeat_timeout > Duration::from_secs(300)
            || self.lease_lifetime.is_zero()
            || self.lease_lifetime > Duration::from_secs(300)
            || self.broker_port == 0
        {
            return Err(PlacementStoreError::Invalid(
                "placement store configuration is invalid".to_owned(),
            ));
        }
        Ok(self)
    }
}

impl Default for PlacementStoreConfig {
    fn default() -> Self {
        Self {
            global_queue_limit: 10_000,
            global_concurrency_limit: 1_000,
            default_tenant_queue_limit: 100,
            default_tenant_concurrency_limit: 10,
            worker_heartbeat_timeout: Duration::from_secs(30),
            lease_lifetime: Duration::from_secs(30),
            broker_port: 8081,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementDatabaseTls {
    pub ca_certificate: PathBuf,
    pub client_certificate: Option<PathBuf>,
    pub client_private_key: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementSubmission {
    pub work: QueuedWork,
    pub subject_id: SubjectId,
    pub pool_name: String,
    pub topology: String,
    pub resource_shape: String,
    pub compatibility_cohort: String,
    pub operation: Operation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerRegistration {
    pub worker_id: WorkerId,
    pub pool_name: String,
    pub topology: String,
    pub resource_shape: String,
    pub compatibility_cohort: String,
    pub broker_address: SocketAddr,
    pub resource_ceilings: ResourceCeilings,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementState {
    Queued,
    Assigned,
    Completed,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementWorkerState {
    Clean,
    Leased,
    Draining,
    Quarantined,
    Consumed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementRecord {
    pub request_id: String,
    pub idempotency_key: String,
    pub identity: PlacementIdentity,
    pub subject_id: SubjectId,
    pub pool_name: String,
    pub state: PlacementState,
    pub worker_id: Option<WorkerId>,
    pub assignment_epoch: Option<AssignmentEpoch>,
    pub lease_expires_unix_ms: Option<u64>,
    pub result_digest: Option<String>,
    pub response: Option<WorkloadResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurablePoolDecision {
    pub observation: PoolObservation,
    pub decision: AutoscaleDecision,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PoolAutoscaleMetrics {
    pub pool_name: String,
    pub queued_assignments: u64,
    pub active_leases: u64,
    pub clean_warm_slots: u64,
    pub draining_workers: u64,
    pub desired_workers: u64,
    pub utilization_ratio: f64,
    pub saturated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolLatencyMetrics {
    pub pool_name: String,
    pub phase: String,
    pub samples: u64,
    pub p50_milliseconds: u64,
    pub p95_milliseconds: u64,
    pub p99_milliseconds: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AutoscaleMetrics {
    pub pools: Vec<PoolAutoscaleMetrics>,
    pub latencies: Vec<PoolLatencyMetrics>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Queued(PlacementRecord),
    Existing(PlacementRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub request_id: String,
    pub idempotency_key: String,
    pub identity: PlacementIdentity,
    pub subject_id: SubjectId,
    pub worker_id: WorkerId,
    pub epoch: AssignmentEpoch,
    pub lease_expires_unix_ms: u64,
    pub broker_address: SocketAddr,
    pub resource_ceilings: ResourceCeilings,
    pub operation: Operation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionOutcome {
    Published,
    AlreadyPublished,
}

#[derive(Debug, Error)]
pub enum PlacementStoreError {
    #[error("placement database: {0}")]
    Database(#[from] tokio_postgres::Error),
    #[error("placement database TLS: {0}")]
    Tls(String),
    #[error("{0}")]
    Invalid(String),
    #[error("global placement queue is full")]
    GlobalQueueFull,
    #[error("tenant placement queue is full")]
    TenantQueueFull,
    #[error("sandbox identity is already in use")]
    SandboxConflict,
    #[error("worker is unavailable or incompatible")]
    WorkerUnavailable,
    #[error("assignment is stale, expired, or fenced")]
    StaleAssignment,
    #[error("completion conflicts with the winning result")]
    CompletionConflict,
}

pub struct PostgresPlacementStore {
    client: Arc<Mutex<Client>>,
    config: PlacementStoreConfig,
}

impl PostgresPlacementStore {
    pub async fn migrate(
        connection_string: &str,
        tls: &PlacementDatabaseTls,
    ) -> Result<(), PlacementStoreError> {
        let database = secure_database_config(connection_string)?;
        let connector = rustls_connector(tls)?;
        let (mut client, connection) = database.connect(connector).await?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("placement migration database connection ended: {error}");
            }
        });
        apply_session_limits(&client).await?;
        Self::apply_migrations(&mut client).await
    }

    /// Apply migrations without TLS only to a loopback or Unix-socket test database.
    pub async fn migrate_local_insecure(
        connection_string: &str,
    ) -> Result<(), PlacementStoreError> {
        let database = local_database_config(connection_string)?;
        let (mut client, connection) = database.connect(NoTls).await?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("local placement migration connection ended: {error}");
            }
        });
        apply_session_limits(&client).await?;
        Self::apply_migrations(&mut client).await
    }

    pub async fn connect(
        connection_string: &str,
        tls: &PlacementDatabaseTls,
        config: PlacementStoreConfig,
    ) -> Result<Self, PlacementStoreError> {
        let config = config.validate()?;
        let database = secure_database_config(connection_string)?;
        let connector = rustls_connector(tls)?;
        let (client, connection) = database.connect(connector).await?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("placement database connection ended: {error}");
            }
        });
        Self::initialize(client, config).await
    }

    /// Connect without TLS only to a loopback or Unix-socket test database.
    ///
    /// Production callers must use [`Self::connect`].
    pub async fn connect_local_insecure(
        connection_string: &str,
        config: PlacementStoreConfig,
    ) -> Result<Self, PlacementStoreError> {
        let config = config.validate()?;
        let database = local_database_config(connection_string)?;
        let (client, connection) = database.connect(NoTls).await?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("local placement database connection ended: {error}");
            }
        });
        Self::initialize(client, config).await
    }

    async fn initialize(
        client: Client,
        config: PlacementStoreConfig,
    ) -> Result<Self, PlacementStoreError> {
        apply_session_limits(&client).await?;
        let store = Self {
            client: Arc::new(Mutex::new(client)),
            config,
        };
        store.verify_schema().await?;
        Ok(store)
    }

    async fn apply_migrations(client: &mut Client) -> Result<(), PlacementStoreError> {
        let transaction = client.transaction().await?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK])
            .await?;
        transaction.batch_execute(MIGRATION).await?;
        let mut version: i32 = transaction
            .query_one(
                "SELECT version FROM sandboxd_placement.schema_version
                 WHERE singleton = TRUE",
                &[],
            )
            .await?
            .get("version");
        if version == 1 {
            transaction.batch_execute(MIGRATION_V2).await?;
            version = 2;
        }
        if version == 2 {
            transaction.batch_execute(MIGRATION_V3).await?;
            version = 3;
        }
        if version == 3 {
            transaction.batch_execute(MIGRATION_V4).await?;
            version = 4;
        }
        if version == 4 {
            transaction.batch_execute(MIGRATION_V5).await?;
            version = 5;
        }
        if version != SCHEMA_VERSION {
            return Err(PlacementStoreError::Invalid(format!(
                "placement database schema version {version} is not supported"
            )));
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn verify_schema(&self) -> Result<(), PlacementStoreError> {
        let version: i32 = self
            .client
            .lock()
            .await
            .query_one(
                "SELECT version FROM sandboxd_placement.schema_version
                 WHERE singleton = TRUE",
                &[],
            )
            .await?
            .get("version");
        if version != SCHEMA_VERSION {
            return Err(PlacementStoreError::Invalid(format!(
                "placement database schema version {version} is not supported"
            )));
        }
        Ok(())
    }

    pub async fn set_tenant_policy(
        &self,
        tenant_id: &TenantId,
        weight: i16,
        concurrency_limit: i32,
        queue_limit: i32,
    ) -> Result<(), PlacementStoreError> {
        if !(1..=100).contains(&weight)
            || concurrency_limit <= 0
            || queue_limit <= 0
            || i64::from(queue_limit) > self.config.global_queue_limit
        {
            return Err(PlacementStoreError::Invalid(
                "tenant placement policy is invalid".to_owned(),
            ));
        }
        self.client
            .lock()
            .await
            .execute(
                "INSERT INTO sandboxd_placement.tenant_policy
                 (tenant_id, weight, concurrency_limit, queue_limit)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (tenant_id) DO UPDATE SET
                 weight = EXCLUDED.weight,
                 concurrency_limit = EXCLUDED.concurrency_limit,
                 queue_limit = EXCLUDED.queue_limit",
                &[
                    &tenant_id.as_str(),
                    &weight,
                    &concurrency_limit,
                    &queue_limit,
                ],
            )
            .await?;
        Ok(())
    }

    pub async fn ping(&self) -> Result<(), PlacementStoreError> {
        self.client.lock().await.query_one("SELECT 1", &[]).await?;
        Ok(())
    }

    pub async fn enqueue(
        &self,
        submission: &PlacementSubmission,
        now_unix_ms: u64,
    ) -> Result<EnqueueOutcome, PlacementStoreError> {
        validate_submission(submission, now_unix_ms)?;
        let operation = serde_json::to_string(&submission.operation)
            .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?;
        let now = to_i64(now_unix_ms)?;
        let deadline = to_i64(submission.work.deadline_unix_ms)?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&QUEUE_LOCK])
            .await?;
        ensure_tenant(&transaction, &submission.work.tenant_id, self.config).await?;
        if let Some(row) = transaction
            .query_opt(
                "SELECT * FROM sandboxd_placement.requests
                 WHERE tenant_id = $1 AND idempotency_key = $2",
                &[
                    &submission.work.tenant_id.as_str(),
                    &submission.work.idempotency_key,
                ],
            )
            .await?
        {
            let record = record_from_row(&row)?;
            transaction.commit().await?;
            return Ok(EnqueueOutcome::Existing(record));
        }
        expire_queued(&transaction, now).await?;
        let global: i64 = transaction
            .query_one(
                "SELECT count(*) FROM sandboxd_placement.requests
                 WHERE state = 'queued'",
                &[],
            )
            .await?
            .get(0);
        if global >= self.config.global_queue_limit {
            return Err(PlacementStoreError::GlobalQueueFull);
        }
        let tenant_count: i64 = transaction
            .query_one(
                "SELECT count(*) FROM sandboxd_placement.requests
                 WHERE tenant_id = $1 AND state = 'queued'",
                &[&submission.work.tenant_id.as_str()],
            )
            .await?
            .get(0);
        let policy = transaction
            .query_one(
                "SELECT weight, queue_limit, virtual_finish
                 FROM sandboxd_placement.tenant_policy WHERE tenant_id = $1 FOR UPDATE",
                &[&submission.work.tenant_id.as_str()],
            )
            .await?;
        let tenant_limit: i32 = policy.get("queue_limit");
        if tenant_count >= i64::from(tenant_limit) {
            return Err(PlacementStoreError::TenantQueueFull);
        }
        let conflict = transaction
            .query_opt(
                "SELECT 1 FROM sandboxd_placement.requests
                 WHERE tenant_id = $1 AND workspace_id = $2 AND sandbox_id = $3
                 AND state IN ('queued', 'assigned', 'completed')",
                &[
                    &submission.work.tenant_id.as_str(),
                    &submission.work.workspace_id.as_str(),
                    &submission.work.sandbox_id.as_str(),
                ],
            )
            .await?
            .is_some();
        if conflict {
            return Err(PlacementStoreError::SandboxConflict);
        }
        let weight = i64::from(policy.get::<_, i16>("weight"));
        let previous_finish: i64 = policy.get("virtual_finish");
        let virtual_time: i64 = transaction
            .query_one(
                "SELECT virtual_time FROM sandboxd_placement.queue_clock
                 WHERE singleton = TRUE FOR UPDATE",
                &[],
            )
            .await?
            .get("virtual_time");
        let fair_finish = previous_finish
            .max(virtual_time)
            .checked_add(10_000 / weight)
            .ok_or_else(|| PlacementStoreError::Invalid("fair queue score overflow".to_owned()))?;
        transaction
            .execute(
                "UPDATE sandboxd_placement.tenant_policy SET virtual_finish = $2
                 WHERE tenant_id = $1",
                &[&submission.work.tenant_id.as_str(), &fair_finish],
            )
            .await?;
        let heartbeat_cutoff = now
            .checked_sub(duration_millis(self.config.worker_heartbeat_timeout)?)
            .ok_or_else(|| PlacementStoreError::Invalid("invalid heartbeat time".to_owned()))?;
        let warm_capacity: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1 FROM sandboxd_placement.workers
                    WHERE pool_name = $1 AND topology = $2 AND resource_shape = $3
                    AND compatibility_cohort = $4 AND state = 'clean'
                    AND heartbeat_unix_ms > $5
                 )",
                &[
                    &submission.pool_name,
                    &submission.topology,
                    &submission.resource_shape,
                    &submission.compatibility_cohort,
                    &heartbeat_cutoff,
                ],
            )
            .await?
            .get(0);
        let capacity_class = if warm_capacity { "warm" } else { "cold" };
        transaction
            .execute(
                "INSERT INTO sandboxd_placement.requests
                 (request_id, idempotency_key, tenant_id, workspace_id, sandbox_id, subject_id,
                  pool_name, topology, resource_shape, compatibility_cohort, deadline_unix_ms,
                  created_unix_ms, fair_finish, operation, state, capacity_class)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'queued',$15)",
                &[
                    &request_id(&submission.work),
                    &submission.work.idempotency_key,
                    &submission.work.tenant_id.as_str(),
                    &submission.work.workspace_id.as_str(),
                    &submission.work.sandbox_id.as_str(),
                    &submission.subject_id.as_str(),
                    &submission.pool_name,
                    &submission.topology,
                    &submission.resource_shape,
                    &submission.compatibility_cohort,
                    &deadline,
                    &now,
                    &fair_finish,
                    &operation,
                    &capacity_class,
                ],
            )
            .await?;
        let row = transaction
            .query_one(
                "SELECT * FROM sandboxd_placement.requests WHERE request_id = $1",
                &[&request_id(&submission.work)],
            )
            .await?;
        let record = record_from_row(&row)?;
        append_audit(&transaction, &record, now, "queued").await?;
        transaction.commit().await?;
        Ok(EnqueueOutcome::Queued(record))
    }

    pub async fn register_worker(
        &self,
        registration: &WorkerRegistration,
        now_unix_ms: u64,
    ) -> Result<(), PlacementStoreError> {
        validate_worker(registration, self.config.broker_port)?;
        let now = to_i64(now_unix_ms)?;
        let broker_address = registration.broker_address.to_string();
        let resource_ceilings = serde_json::to_string(&registration.resource_ceilings)
            .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?;
        let updated = self
            .client
            .lock()
            .await
            .execute(
                "INSERT INTO sandboxd_placement.workers
                 (worker_id, topology, resource_shape, compatibility_cohort, state,
                  heartbeat_unix_ms, registered_unix_ms, broker_address, resource_ceilings,
                  pool_name)
                 VALUES ($1,$2,$3,$4,'clean',$5,$5,$6,$7,$8)
                 ON CONFLICT (worker_id) DO UPDATE SET
                 heartbeat_unix_ms = EXCLUDED.heartbeat_unix_ms,
                 broker_address = EXCLUDED.broker_address,
                 resource_ceilings = EXCLUDED.resource_ceilings
                 WHERE sandboxd_placement.workers.state = 'clean'
                 AND sandboxd_placement.workers.pool_name = EXCLUDED.pool_name
                 AND sandboxd_placement.workers.topology = EXCLUDED.topology
                 AND sandboxd_placement.workers.resource_shape = EXCLUDED.resource_shape
                 AND sandboxd_placement.workers.compatibility_cohort = EXCLUDED.compatibility_cohort",
                &[
                    &registration.worker_id.as_str(),
                    &registration.topology,
                    &registration.resource_shape,
                    &registration.compatibility_cohort,
                    &now,
                    &broker_address,
                    &resource_ceilings,
                    &registration.pool_name,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(PlacementStoreError::WorkerUnavailable);
        }
        Ok(())
    }

    pub async fn heartbeat_worker(
        &self,
        worker_id: &WorkerId,
        now_unix_ms: u64,
    ) -> Result<(), PlacementStoreError> {
        let updated = self
            .client
            .lock()
            .await
            .execute(
                "UPDATE sandboxd_placement.workers SET heartbeat_unix_ms = $2
                 WHERE worker_id = $1 AND state IN ('clean', 'leased', 'draining')",
                &[&worker_id.as_str(), &to_i64(now_unix_ms)?],
            )
            .await?;
        if updated != 1 {
            return Err(PlacementStoreError::WorkerUnavailable);
        }
        Ok(())
    }

    pub async fn drain_worker(&self, worker_id: &WorkerId) -> Result<(), PlacementStoreError> {
        let updated = self
            .client
            .lock()
            .await
            .execute(
                "UPDATE sandboxd_placement.workers SET state = 'draining'
                 WHERE worker_id = $1 AND state IN ('clean', 'leased', 'draining')",
                &[&worker_id.as_str()],
            )
            .await?;
        if updated != 1 {
            return Err(PlacementStoreError::WorkerUnavailable);
        }
        Ok(())
    }

    pub async fn drain_workers_if_clean(
        &self,
        worker_ids: &[WorkerId],
    ) -> Result<bool, PlacementStoreError> {
        if worker_ids.is_empty() || worker_ids.len() > 1_024 {
            return Err(PlacementStoreError::Invalid(
                "worker drain set is invalid".to_owned(),
            ));
        }
        let mut identities = worker_ids
            .iter()
            .map(|worker| worker.as_str().to_owned())
            .collect::<Vec<_>>();
        identities.sort();
        identities.dedup();
        if identities.len() != worker_ids.len() {
            return Err(PlacementStoreError::Invalid(
                "worker drain set contains duplicates".to_owned(),
            ));
        }
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&QUEUE_LOCK])
            .await?;
        let rows = transaction
            .query(
                "SELECT worker_id, state FROM sandboxd_placement.workers
                 WHERE worker_id = ANY($1) FOR UPDATE",
                &[&identities],
            )
            .await?;
        if rows.len() != identities.len()
            || rows
                .iter()
                .any(|row| row.get::<_, &str>("state") != "clean")
        {
            transaction.commit().await?;
            return Ok(false);
        }
        let updated = transaction
            .execute(
                "UPDATE sandboxd_placement.workers SET state = 'draining'
                 WHERE worker_id = ANY($1) AND state = 'clean'",
                &[&identities],
            )
            .await?;
        if usize::try_from(updated).ok() != Some(identities.len()) {
            return Err(PlacementStoreError::Invalid(
                "worker drain set changed concurrently".to_owned(),
            ));
        }
        transaction.commit().await?;
        Ok(true)
    }

    pub async fn worker_states(
        &self,
        worker_ids: &[WorkerId],
    ) -> Result<Vec<(WorkerId, PlacementWorkerState)>, PlacementStoreError> {
        if worker_ids.is_empty() || worker_ids.len() > 1_024 {
            return Err(PlacementStoreError::Invalid(
                "worker state query is invalid".to_owned(),
            ));
        }
        let identities = worker_ids
            .iter()
            .map(|worker| worker.as_str().to_owned())
            .collect::<Vec<_>>();
        self.client
            .lock()
            .await
            .query(
                "SELECT worker_id, state FROM sandboxd_placement.workers
                 WHERE worker_id = ANY($1) ORDER BY worker_id",
                &[&identities],
            )
            .await?
            .into_iter()
            .map(|row| {
                let worker = WorkerId::parse(row.get::<_, String>("worker_id"))
                    .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?;
                let state = match row.get::<_, &str>("state") {
                    "clean" => PlacementWorkerState::Clean,
                    "leased" => PlacementWorkerState::Leased,
                    "draining" => PlacementWorkerState::Draining,
                    "quarantined" => PlacementWorkerState::Quarantined,
                    "consumed" => PlacementWorkerState::Consumed,
                    value => {
                        return Err(PlacementStoreError::Invalid(format!(
                            "unknown worker state `{value}`"
                        )))
                    }
                };
                Ok((worker, state))
            })
            .collect()
    }

    pub async fn quarantine_worker(
        &self,
        worker_id: &WorkerId,
        now_unix_ms: u64,
    ) -> Result<(), PlacementStoreError> {
        let now = to_i64(now_unix_ms)?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&QUEUE_LOCK])
            .await?;
        let updated = transaction
            .execute(
                "UPDATE sandboxd_placement.workers SET state = 'quarantined'
                 WHERE worker_id = $1
                 AND state IN ('clean', 'leased', 'draining', 'quarantined')",
                &[&worker_id.as_str()],
            )
            .await?;
        if updated != 1 {
            return Err(PlacementStoreError::WorkerUnavailable);
        }
        let rows = transaction
            .query(
                "SELECT * FROM sandboxd_placement.requests
                 WHERE worker_id = $1 AND state = 'assigned' FOR UPDATE",
                &[&worker_id.as_str()],
            )
            .await?;
        for row in rows {
            let record = record_from_row(&row)?;
            let deadline: i64 = row.get("deadline_unix_ms");
            if deadline <= now {
                transaction
                    .execute(
                        "UPDATE sandboxd_placement.requests SET state = 'expired',
                         terminal_unix_ms = $2 WHERE request_id = $1",
                        &[&record.request_id, &now],
                    )
                    .await?;
            } else {
                transaction
                    .execute(
                        "UPDATE sandboxd_placement.requests SET state = 'queued',
                         worker_id = NULL, assignment_epoch = NULL,
                         lease_expires_unix_ms = NULL, assigned_unix_ms = NULL,
                         first_output_unix_ms = NULL WHERE request_id = $1",
                        &[&record.request_id],
                    )
                    .await?;
            }
            append_audit(&transaction, &record, now, "worker_quarantined").await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn clean_workers(
        &self,
        now_unix_ms: u64,
        limit: u16,
    ) -> Result<Vec<WorkerId>, PlacementStoreError> {
        if limit == 0 || limit > 1_024 {
            return Err(PlacementStoreError::Invalid(
                "worker scan limit is invalid".to_owned(),
            ));
        }
        let heartbeat_cutoff = to_i64(now_unix_ms)?
            .checked_sub(duration_millis(self.config.worker_heartbeat_timeout)?)
            .ok_or_else(|| PlacementStoreError::Invalid("invalid heartbeat time".to_owned()))?;
        self.client
            .lock()
            .await
            .query(
                "SELECT worker_id FROM sandboxd_placement.workers
                 WHERE state = 'clean' AND heartbeat_unix_ms > $1
                 AND broker_address IS NOT NULL AND resource_ceilings IS NOT NULL
                 ORDER BY registered_unix_ms, worker_id LIMIT $2",
                &[&heartbeat_cutoff, &i64::from(limit)],
            )
            .await?
            .into_iter()
            .map(|row| {
                WorkerId::parse(row.get::<_, String>("worker_id"))
                    .map_err(|error| PlacementStoreError::Invalid(error.to_string()))
            })
            .collect()
    }

    pub async fn reconcile_pool(
        &self,
        pool_name: &str,
        current_workers: u32,
        quota_workers: u32,
        policy: PoolPolicy,
        now_unix_ms: u64,
    ) -> Result<DurablePoolDecision, PlacementStoreError> {
        if !valid_pool_name(pool_name) || now_unix_ms == 0 {
            return Err(PlacementStoreError::Invalid(
                "autoscale pool identity or time is invalid".to_owned(),
            ));
        }
        policy
            .validate()
            .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?;
        let now = to_i64(now_unix_ms)?;
        let heartbeat_cutoff = now
            .checked_sub(duration_millis(self.config.worker_heartbeat_timeout)?)
            .ok_or_else(|| PlacementStoreError::Invalid("invalid heartbeat time".to_owned()))?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&AUTOSCALE_LOCK])
            .await?;
        expire_queued(&transaction, now).await?;
        let workers = transaction
            .query_one(
                "SELECT
                    count(*) FILTER (WHERE state = 'clean') AS clean,
                    count(*) FILTER (WHERE state = 'leased') AS leased,
                    count(*) FILTER (WHERE state = 'draining') AS draining
                 FROM sandboxd_placement.workers
                 WHERE pool_name = $1 AND heartbeat_unix_ms > $2
                 AND state IN ('clean', 'leased', 'draining')",
                &[&pool_name, &heartbeat_cutoff],
            )
            .await?;
        let demand = transaction
            .query_one(
                "SELECT
                    count(*) FILTER (WHERE state = 'queued') AS queued,
                    count(*) FILTER (WHERE state = 'assigned') AS assigned
                 FROM sandboxd_placement.requests
                 WHERE pool_name = $1 AND state IN ('queued', 'assigned')",
                &[&pool_name],
            )
            .await?;
        let clean_workers = count_u32(workers.get("clean"))?;
        let leased_workers = count_u32(workers.get("leased"))?;
        let draining_workers = count_u32(workers.get("draining"))?;
        let assigned = count_u32(demand.get("assigned"))?;
        if assigned > leased_workers {
            return Err(PlacementStoreError::Invalid(
                "assigned demand exceeds live leased workers".to_owned(),
            ));
        }
        let queued_assignments = count_u32(demand.get("queued"))?;
        let previous_idle = transaction
            .query_opt(
                "SELECT idle_since_unix_ms
                 FROM sandboxd_placement.autoscale_state
                 WHERE pool_name = $1 FOR UPDATE",
                &[&pool_name],
            )
            .await?
            .and_then(|row| row.get::<_, Option<i64>>("idle_since_unix_ms"))
            .map(to_u64)
            .transpose()?;
        let idle_since_unix_ms = if queued_assignments == 0 && assigned == 0 {
            previous_idle.or(Some(now_unix_ms))
        } else {
            None
        };
        let observation = PoolObservation {
            current_workers,
            clean_workers,
            leased_or_active_workers: leased_workers,
            draining_workers,
            queued_assignments,
            quota_workers,
            idle_since_unix_ms,
        };
        let decision = reconcile_worker_pool(policy, observation, now_unix_ms)
            .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?;
        let desired_workers = i32::try_from(decision.desired_workers).map_err(|_| {
            PlacementStoreError::Invalid(
                "desired worker count exceeds PostgreSQL integer".to_owned(),
            )
        })?;
        let idle_since = idle_since_unix_ms.map(to_i64).transpose()?;
        transaction
            .execute(
                "INSERT INTO sandboxd_placement.autoscale_state
                 (pool_name, idle_since_unix_ms, desired_workers, updated_unix_ms)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (pool_name) DO UPDATE SET
                 idle_since_unix_ms = EXCLUDED.idle_since_unix_ms,
                 desired_workers = EXCLUDED.desired_workers,
                 updated_unix_ms = EXCLUDED.updated_unix_ms",
                &[&pool_name, &idle_since, &desired_workers, &now],
            )
            .await?;
        transaction.commit().await?;
        Ok(DurablePoolDecision {
            observation,
            decision,
        })
    }

    pub async fn record_scale_up(
        &self,
        pool_name: &str,
        target_workers: u32,
        now_unix_ms: u64,
    ) -> Result<(), PlacementStoreError> {
        if !valid_pool_name(pool_name) || target_workers == 0 || now_unix_ms == 0 {
            return Err(PlacementStoreError::Invalid(
                "scale-up activation is invalid".to_owned(),
            ));
        }
        let target = i32::try_from(target_workers).map_err(|_| {
            PlacementStoreError::Invalid("activation target exceeds PostgreSQL integer".to_owned())
        })?;
        let now = to_i64(now_unix_ms)?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&AUTOSCALE_LOCK])
            .await?;
        let updated = transaction
            .execute(
                "UPDATE sandboxd_placement.pool_activations
                 SET target_workers = GREATEST(target_workers, $2)
                 WHERE pool_name = $1 AND ready_unix_ms IS NULL
                 AND cancelled_unix_ms IS NULL",
                &[&pool_name, &target],
            )
            .await?;
        if updated == 0 {
            transaction
                .execute(
                    "INSERT INTO sandboxd_placement.pool_activations
                     (pool_name, requested_unix_ms, target_workers)
                     VALUES ($1, $2, $3)",
                    &[&pool_name, &now, &target],
                )
                .await?;
        }
        transaction
            .execute(
                "DELETE FROM sandboxd_placement.pool_activations
                 WHERE sequence IN (
                    SELECT sequence FROM sandboxd_placement.pool_activations
                    WHERE pool_name = $1
                    AND (ready_unix_ms IS NOT NULL OR cancelled_unix_ms IS NOT NULL)
                    ORDER BY sequence DESC OFFSET 10000
                 )",
                &[&pool_name],
            )
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn observe_pool_activation(
        &self,
        pool_name: &str,
        desired_workers: u32,
        ready_workers: u32,
        now_unix_ms: u64,
    ) -> Result<(), PlacementStoreError> {
        if !valid_pool_name(pool_name) || now_unix_ms == 0 {
            return Err(PlacementStoreError::Invalid(
                "activation observation is invalid".to_owned(),
            ));
        }
        let desired = i32::try_from(desired_workers).map_err(|_| {
            PlacementStoreError::Invalid("desired workers exceed PostgreSQL integer".to_owned())
        })?;
        let ready = i32::try_from(ready_workers).map_err(|_| {
            PlacementStoreError::Invalid("ready workers exceed PostgreSQL integer".to_owned())
        })?;
        let now = to_i64(now_unix_ms)?;
        self.client
            .lock()
            .await
            .execute(
                "UPDATE sandboxd_placement.pool_activations
                 SET ready_unix_ms = CASE
                        WHEN target_workers <= $2 THEN $4::BIGINT ELSE NULL
                     END,
                     cancelled_unix_ms = CASE
                        WHEN target_workers > $1 AND target_workers > $2 THEN $4::BIGINT
                        ELSE NULL
                     END
                 WHERE pool_name = $3 AND ready_unix_ms IS NULL
                 AND cancelled_unix_ms IS NULL
                 AND (target_workers <= $2 OR (target_workers > $1 AND target_workers > $2))",
                &[&desired, &ready, &pool_name, &now],
            )
            .await?;
        Ok(())
    }

    pub async fn autoscale_metrics(
        &self,
        pool_names: &[String],
        now_unix_ms: u64,
        lookback: Duration,
    ) -> Result<AutoscaleMetrics, PlacementStoreError> {
        if pool_names.is_empty()
            || pool_names.len() > 1_024
            || lookback.is_zero()
            || lookback > Duration::from_secs(90 * 24 * 60 * 60)
            || now_unix_ms == 0
            || pool_names.iter().any(|pool| !valid_pool_name(pool))
        {
            return Err(PlacementStoreError::Invalid(
                "autoscale metrics query is invalid".to_owned(),
            ));
        }
        let mut unique = pool_names.to_vec();
        unique.sort();
        unique.dedup();
        if unique.len() != pool_names.len() {
            return Err(PlacementStoreError::Invalid(
                "autoscale metrics pools contain duplicates".to_owned(),
            ));
        }
        let now = to_i64(now_unix_ms)?;
        let cutoff = now
            .checked_sub(duration_millis(lookback)?)
            .ok_or_else(|| PlacementStoreError::Invalid("metrics cutoff is invalid".to_owned()))?;
        let heartbeat_cutoff = now
            .checked_sub(duration_millis(self.config.worker_heartbeat_timeout)?)
            .ok_or_else(|| PlacementStoreError::Invalid("invalid heartbeat time".to_owned()))?;
        let client = self.client.lock().await;
        let pool_rows = client
            .query(
                "WITH selected(pool_name) AS (SELECT unnest($1::text[])),
                 workers AS (
                    SELECT pool_name,
                        count(*) FILTER (WHERE state = 'clean') AS clean,
                        count(*) FILTER (WHERE state = 'leased') AS leased,
                        count(*) FILTER (WHERE state = 'draining') AS draining
                    FROM sandboxd_placement.workers
                    WHERE pool_name = ANY($1) AND heartbeat_unix_ms > $2
                    AND state IN ('clean', 'leased', 'draining')
                    GROUP BY pool_name
                 ),
                 demand AS (
                    SELECT pool_name,
                        count(*) FILTER (WHERE state = 'queued') AS queued,
                        count(*) FILTER (WHERE state = 'assigned') AS active
                    FROM sandboxd_placement.requests
                    WHERE pool_name = ANY($1) AND state IN ('queued', 'assigned')
                    GROUP BY pool_name
                 )
                 SELECT selected.pool_name,
                    COALESCE(demand.queued, 0)::BIGINT AS queued,
                    COALESCE(demand.active, 0)::BIGINT AS active,
                    COALESCE(workers.clean, 0)::BIGINT AS clean,
                    COALESCE(workers.leased, 0)::BIGINT AS leased,
                    COALESCE(workers.draining, 0)::BIGINT AS draining,
                    COALESCE(autoscale_state.desired_workers, 0)::BIGINT AS desired
                 FROM selected
                 LEFT JOIN workers USING (pool_name)
                 LEFT JOIN demand USING (pool_name)
                 LEFT JOIN sandboxd_placement.autoscale_state USING (pool_name)
                 ORDER BY selected.pool_name",
                &[&unique, &heartbeat_cutoff],
            )
            .await?;
        let mut pools = Vec::with_capacity(pool_rows.len());
        for row in pool_rows {
            let clean = metric_u64(row.get("clean"))?;
            let leased = metric_u64(row.get("leased"))?;
            let queued = metric_u64(row.get("queued"))?;
            let routable = clean.saturating_add(leased);
            pools.push(PoolAutoscaleMetrics {
                pool_name: row.get("pool_name"),
                queued_assignments: queued,
                active_leases: metric_u64(row.get("active"))?,
                clean_warm_slots: clean,
                draining_workers: metric_u64(row.get("draining"))?,
                desired_workers: metric_u64(row.get("desired"))?,
                utilization_ratio: if routable == 0 {
                    0.0
                } else {
                    leased as f64 / routable as f64
                },
                saturated: queued > 0 && clean == 0,
            });
        }
        let latency_rows = client
            .query(
                "WITH samples AS (
                    SELECT pool_name, 'queue_residence'::TEXT AS phase,
                        assigned_unix_ms - created_unix_ms AS duration_ms,
                        assigned_unix_ms AS sampled_unix_ms
                    FROM sandboxd_placement.requests
                    WHERE pool_name = ANY($1) AND assigned_unix_ms >= $2
                    UNION ALL
                    SELECT pool_name, capacity_class || '_wait',
                        assigned_unix_ms - created_unix_ms, assigned_unix_ms
                    FROM sandboxd_placement.requests
                    WHERE pool_name = ANY($1) AND assigned_unix_ms >= $2
                    AND capacity_class IN ('warm', 'cold')
                    UNION ALL
                    SELECT pool_name, 'first_output',
                        first_output_unix_ms - created_unix_ms, first_output_unix_ms
                    FROM sandboxd_placement.requests
                    WHERE pool_name = ANY($1) AND first_output_unix_ms >= $2
                    AND state = 'completed'
                    UNION ALL
                    SELECT pool_name, 'execution',
                        terminal_unix_ms - assigned_unix_ms, terminal_unix_ms
                    FROM sandboxd_placement.requests
                    WHERE pool_name = ANY($1) AND terminal_unix_ms >= $2
                    AND state = 'completed' AND assigned_unix_ms IS NOT NULL
                    UNION ALL
                    SELECT pool_name, 'create_to_ready',
                        ready_unix_ms - requested_unix_ms, ready_unix_ms
                    FROM sandboxd_placement.pool_activations
                    WHERE pool_name = ANY($1) AND ready_unix_ms >= $2
                 )
                 SELECT pool_name, phase, count(*)::BIGINT AS samples,
                    percentile_disc(0.50) WITHIN GROUP (ORDER BY duration_ms)::BIGINT AS p50,
                    percentile_disc(0.95) WITHIN GROUP (ORDER BY duration_ms)::BIGINT AS p95,
                    percentile_disc(0.99) WITHIN GROUP (ORDER BY duration_ms)::BIGINT AS p99
                 FROM samples
                 WHERE sampled_unix_ms >= $2 AND duration_ms >= 0
                 GROUP BY pool_name, phase ORDER BY pool_name, phase",
                &[&unique, &cutoff],
            )
            .await?;
        let latencies = latency_rows
            .into_iter()
            .map(|row| {
                Ok(PoolLatencyMetrics {
                    pool_name: row.get("pool_name"),
                    phase: row.get("phase"),
                    samples: metric_u64(row.get("samples"))?,
                    p50_milliseconds: metric_u64(row.get("p50"))?,
                    p95_milliseconds: metric_u64(row.get("p95"))?,
                    p99_milliseconds: metric_u64(row.get("p99"))?,
                })
            })
            .collect::<Result<Vec<_>, PlacementStoreError>>()?;
        Ok(AutoscaleMetrics { pools, latencies })
    }

    pub async fn assign_next(
        &self,
        worker_id: &WorkerId,
        now_unix_ms: u64,
    ) -> Result<Option<Assignment>, PlacementStoreError> {
        let now = to_i64(now_unix_ms)?;
        let heartbeat_cutoff = now
            .checked_sub(duration_millis(self.config.worker_heartbeat_timeout)?)
            .ok_or_else(|| PlacementStoreError::Invalid("invalid heartbeat time".to_owned()))?;
        let lease_expires = now
            .checked_add(duration_millis(self.config.lease_lifetime)?)
            .ok_or_else(|| PlacementStoreError::Invalid("lease expiration overflow".to_owned()))?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&QUEUE_LOCK])
            .await?;
        let worker = transaction
            .query_opt(
                "SELECT pool_name, topology, resource_shape, compatibility_cohort,
                        broker_address, resource_ceilings
                 FROM sandboxd_placement.workers
                 WHERE worker_id = $1 AND state = 'clean' AND heartbeat_unix_ms > $2
                 AND broker_address IS NOT NULL AND resource_ceilings IS NOT NULL
                 FOR UPDATE",
                &[&worker_id.as_str(), &heartbeat_cutoff],
            )
            .await?;
        let Some(worker) = worker else {
            return Err(PlacementStoreError::WorkerUnavailable);
        };
        let pool_name: String = worker.get("pool_name");
        let topology: String = worker.get("topology");
        let resource_shape: String = worker.get("resource_shape");
        let cohort: String = worker.get("compatibility_cohort");
        let broker_address = worker
            .get::<_, String>("broker_address")
            .parse::<SocketAddr>()
            .map_err(|_| PlacementStoreError::Invalid("invalid broker address".to_owned()))?;
        let resource_ceilings: ResourceCeilings =
            serde_json::from_str(worker.get::<_, &str>("resource_ceilings"))
                .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?;
        resource_ceilings
            .validate()
            .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?;
        expire_queued(&transaction, now).await?;
        let active: i64 = transaction
            .query_one(
                "SELECT count(*) FROM sandboxd_placement.requests WHERE state = 'assigned'",
                &[],
            )
            .await?
            .get(0);
        if active >= self.config.global_concurrency_limit {
            transaction.commit().await?;
            return Ok(None);
        }
        let candidate = transaction
            .query_opt(
                "SELECT r.* FROM sandboxd_placement.requests r
                 JOIN sandboxd_placement.tenant_policy p ON p.tenant_id = r.tenant_id
                 WHERE r.state = 'queued' AND r.deadline_unix_ms > $1
                 AND r.pool_name = $4
                 AND r.topology = $2 AND r.resource_shape = $3
                 AND r.compatibility_cohort = $5
                 AND (
                    SELECT count(*) FROM sandboxd_placement.requests active
                    WHERE active.tenant_id = r.tenant_id AND active.state = 'assigned'
                 ) < p.concurrency_limit
                 ORDER BY r.fair_finish, r.created_unix_ms, r.request_id
                 LIMIT 1 FOR UPDATE OF r SKIP LOCKED",
                &[&now, &topology, &resource_shape, &pool_name, &cohort],
            )
            .await?;
        let Some(candidate) = candidate else {
            transaction.commit().await?;
            return Ok(None);
        };
        let operation: Operation = serde_json::from_str(candidate.get::<_, &str>("operation"))
            .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?;
        let tenant: String = candidate.get("tenant_id");
        let workspace: String = candidate.get("workspace_id");
        let sandbox: String = candidate.get("sandbox_id");
        let epoch: i64 = transaction
            .query_one(
                "INSERT INTO sandboxd_placement.assignment_epochs
                 (tenant_id, workspace_id, sandbox_id, epoch) VALUES ($1,$2,$3,1)
                 ON CONFLICT (tenant_id, workspace_id, sandbox_id)
                 DO UPDATE SET epoch = sandboxd_placement.assignment_epochs.epoch + 1
                 RETURNING epoch",
                &[&tenant, &workspace, &sandbox],
            )
            .await?
            .get("epoch");
        let request_id: String = candidate.get("request_id");
        transaction
            .execute(
                "UPDATE sandboxd_placement.requests SET
                 state = 'assigned', worker_id = $2, assignment_epoch = $3,
                 lease_expires_unix_ms = $4, assigned_unix_ms = $5,
                 first_output_unix_ms = NULL
                 WHERE request_id = $1 AND state = 'queued'",
                &[
                    &request_id,
                    &worker_id.as_str(),
                    &epoch,
                    &lease_expires,
                    &now,
                ],
            )
            .await?;
        let candidate_finish: i64 = candidate.get("fair_finish");
        transaction
            .execute(
                "UPDATE sandboxd_placement.queue_clock
                 SET virtual_time = GREATEST(virtual_time, $1) WHERE singleton = TRUE",
                &[&candidate_finish],
            )
            .await?;
        transaction
            .execute(
                "UPDATE sandboxd_placement.workers SET state = 'leased' WHERE worker_id = $1",
                &[&worker_id.as_str()],
            )
            .await?;
        let row = transaction
            .query_one(
                "SELECT * FROM sandboxd_placement.requests WHERE request_id = $1",
                &[&request_id],
            )
            .await?;
        let record = record_from_row(&row)?;
        append_audit(&transaction, &record, now, "assigned").await?;
        let assignment =
            assignment_from_record(record, broker_address, resource_ceilings, operation)?;
        transaction.commit().await?;
        Ok(Some(assignment))
    }

    pub async fn renew(
        &self,
        assignment: &Assignment,
        now_unix_ms: u64,
    ) -> Result<u64, PlacementStoreError> {
        let now = to_i64(now_unix_ms)?;
        let expires = now
            .checked_add(duration_millis(self.config.lease_lifetime)?)
            .ok_or_else(|| PlacementStoreError::Invalid("lease expiration overflow".to_owned()))?;
        let updated = self
            .client
            .lock()
            .await
            .execute(
                "UPDATE sandboxd_placement.requests SET lease_expires_unix_ms = $4
                 WHERE request_id = $1 AND worker_id = $2 AND assignment_epoch = $3
                 AND state = 'assigned' AND lease_expires_unix_ms > $5",
                &[
                    &assignment.request_id,
                    &assignment.worker_id.as_str(),
                    &to_i64(assignment.epoch.get())?,
                    &expires,
                    &now,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(PlacementStoreError::StaleAssignment);
        }
        u64::try_from(expires)
            .map_err(|_| PlacementStoreError::Invalid("lease expiration is negative".to_owned()))
    }

    pub async fn complete(
        &self,
        assignment: &Assignment,
        result_digest: &str,
        now_unix_ms: u64,
    ) -> Result<CompletionOutcome, PlacementStoreError> {
        self.complete_inner(assignment, result_digest, None, now_unix_ms)
            .await
    }

    pub async fn complete_response(
        &self,
        assignment: &Assignment,
        response: &WorkloadResponse,
        now_unix_ms: u64,
    ) -> Result<CompletionOutcome, PlacementStoreError> {
        response
            .validate_for(&assignment.request_id)
            .map_err(|error| PlacementStoreError::Invalid(error.to_owned()))?;
        let encoded = serde_json::to_string(response)
            .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?;
        if encoded.len() > MAXIMUM_RESPONSE_BYTES {
            return Err(PlacementStoreError::Invalid(
                "worker response exceeds its size limit".to_owned(),
            ));
        }
        let result_digest = format!("sha256:{}", hex::encode(Sha256::digest(encoded.as_bytes())));
        self.complete_inner(
            assignment,
            &result_digest,
            Some((encoded, response.clone())),
            now_unix_ms,
        )
        .await
    }

    async fn complete_inner(
        &self,
        assignment: &Assignment,
        result_digest: &str,
        response: Option<(String, WorkloadResponse)>,
        now_unix_ms: u64,
    ) -> Result<CompletionOutcome, PlacementStoreError> {
        if !valid_digest(result_digest) {
            return Err(PlacementStoreError::Invalid(
                "result digest is invalid".to_owned(),
            ));
        }
        let now = to_i64(now_unix_ms)?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT * FROM sandboxd_placement.requests WHERE request_id = $1 FOR UPDATE",
                &[&assignment.request_id],
            )
            .await?
            .ok_or(PlacementStoreError::StaleAssignment)?;
        let record = record_from_row(&row)?;
        if record.state == PlacementState::Completed {
            return if record.result_digest.as_deref() == Some(result_digest) {
                Ok(CompletionOutcome::AlreadyPublished)
            } else {
                Err(PlacementStoreError::CompletionConflict)
            };
        }
        if record.state != PlacementState::Assigned
            || record.worker_id.as_ref() != Some(&assignment.worker_id)
            || record.assignment_epoch != Some(assignment.epoch)
            || record
                .lease_expires_unix_ms
                .is_none_or(|expiry| expiry <= now_unix_ms)
        {
            return Err(PlacementStoreError::StaleAssignment);
        }
        let first_output = response.as_ref().map(|_| now);
        transaction
            .execute(
                "UPDATE sandboxd_placement.requests SET state = 'completed',
                 result_digest = $2, terminal_response = $3, terminal_unix_ms = $4,
                 first_output_unix_ms = $5
                 WHERE request_id = $1",
                &[
                    &assignment.request_id,
                    &result_digest,
                    &response.as_ref().map(|(encoded, _)| encoded),
                    &now,
                    &first_output,
                ],
            )
            .await?;
        transaction
            .execute(
                "UPDATE sandboxd_placement.workers SET state = 'consumed' WHERE worker_id = $1",
                &[&assignment.worker_id.as_str()],
            )
            .await?;
        let mut completed = record;
        completed.state = PlacementState::Completed;
        completed.result_digest = Some(result_digest.to_owned());
        completed.response = response.map(|(_, response)| response);
        append_audit(&transaction, &completed, now, "completed").await?;
        transaction.commit().await?;
        Ok(CompletionOutcome::Published)
    }

    pub async fn cancel(
        &self,
        tenant_id: &TenantId,
        subject_id: &SubjectId,
        idempotency_key: &str,
        now_unix_ms: u64,
    ) -> Result<Option<PlacementRecord>, PlacementStoreError> {
        let now = to_i64(now_unix_ms)?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT * FROM sandboxd_placement.requests
                 WHERE tenant_id = $1 AND subject_id = $2 AND idempotency_key = $3 FOR UPDATE",
                &[&tenant_id.as_str(), &subject_id.as_str(), &idempotency_key],
            )
            .await?;
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(None);
        };
        let mut record = record_from_row(&row)?;
        if matches!(
            record.state,
            PlacementState::Completed | PlacementState::Cancelled | PlacementState::Expired
        ) {
            transaction.commit().await?;
            return Ok(Some(record));
        }
        transaction
            .execute(
                "UPDATE sandboxd_placement.requests SET state = 'cancelled',
                 terminal_unix_ms = $2 WHERE request_id = $1",
                &[&record.request_id, &now],
            )
            .await?;
        if let Some(worker_id) = &record.worker_id {
            transaction
                .execute(
                    "UPDATE sandboxd_placement.workers SET state = 'quarantined'
                     WHERE worker_id = $1 AND state = 'leased'",
                    &[&worker_id.as_str()],
                )
                .await?;
        }
        record.state = PlacementState::Cancelled;
        append_audit(&transaction, &record, now, "cancelled").await?;
        transaction.commit().await?;
        Ok(Some(record))
    }

    pub async fn fence_expired(
        &self,
        now_unix_ms: u64,
    ) -> Result<Vec<PlacementRecord>, PlacementStoreError> {
        let now = to_i64(now_unix_ms)?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&QUEUE_LOCK])
            .await?;
        expire_queued(&transaction, now).await?;
        let rows = transaction
            .query(
                "SELECT * FROM sandboxd_placement.requests
                 WHERE state = 'assigned' AND lease_expires_unix_ms <= $1
                 FOR UPDATE",
                &[&now],
            )
            .await?;
        let mut fenced = Vec::with_capacity(rows.len());
        for row in rows {
            let previous = record_from_row(&row)?;
            if let Some(worker) = &previous.worker_id {
                transaction
                    .execute(
                        "UPDATE sandboxd_placement.workers SET state = 'quarantined'
                         WHERE worker_id = $1",
                        &[&worker.as_str()],
                    )
                    .await?;
            }
            let deadline: i64 = row.get("deadline_unix_ms");
            if deadline <= now {
                transaction
                    .execute(
                        "UPDATE sandboxd_placement.requests SET state = 'expired',
                         terminal_unix_ms = $2 WHERE request_id = $1",
                        &[&previous.request_id, &now],
                    )
                    .await?;
                append_audit(&transaction, &previous, now, "deadline_expired").await?;
                let mut expired = previous;
                expired.state = PlacementState::Expired;
                fenced.push(expired);
            } else {
                transaction
                    .execute(
                        "UPDATE sandboxd_placement.requests SET state = 'queued',
                         worker_id = NULL, assignment_epoch = NULL, lease_expires_unix_ms = NULL,
                         assigned_unix_ms = NULL, first_output_unix_ms = NULL
                         WHERE request_id = $1",
                        &[&previous.request_id],
                    )
                    .await?;
                append_audit(&transaction, &previous, now, "lease_expired").await?;
                let mut requeued = previous;
                requeued.state = PlacementState::Queued;
                requeued.worker_id = None;
                requeued.assignment_epoch = None;
                requeued.lease_expires_unix_ms = None;
                fenced.push(requeued);
            }
        }
        transaction.commit().await?;
        Ok(fenced)
    }

    pub async fn get_by_idempotency(
        &self,
        tenant_id: &TenantId,
        subject_id: &SubjectId,
        idempotency_key: &str,
    ) -> Result<Option<PlacementRecord>, PlacementStoreError> {
        self.client
            .lock()
            .await
            .query_opt(
                "SELECT * FROM sandboxd_placement.requests
                 WHERE tenant_id = $1 AND subject_id = $2 AND idempotency_key = $3",
                &[&tenant_id.as_str(), &subject_id.as_str(), &idempotency_key],
            )
            .await?
            .as_ref()
            .map(record_from_row)
            .transpose()
    }
}

async fn ensure_tenant(
    transaction: &tokio_postgres::Transaction<'_>,
    tenant_id: &TenantId,
    config: PlacementStoreConfig,
) -> Result<(), PlacementStoreError> {
    transaction
        .execute(
            "INSERT INTO sandboxd_placement.tenant_policy
             (tenant_id, weight, concurrency_limit, queue_limit)
             VALUES ($1,1,$2,$3) ON CONFLICT (tenant_id) DO NOTHING",
            &[
                &tenant_id.as_str(),
                &config.default_tenant_concurrency_limit,
                &config.default_tenant_queue_limit,
            ],
        )
        .await?;
    Ok(())
}

async fn expire_queued(
    transaction: &tokio_postgres::Transaction<'_>,
    now: i64,
) -> Result<(), PlacementStoreError> {
    let rows = transaction
        .query(
            "UPDATE sandboxd_placement.requests SET state = 'expired', terminal_unix_ms = $1
             WHERE state = 'queued' AND deadline_unix_ms <= $1 RETURNING *",
            &[&now],
        )
        .await?;
    for row in rows {
        let record = record_from_row(&row)?;
        append_audit(transaction, &record, now, "deadline_expired").await?;
    }
    Ok(())
}

async fn append_audit(
    transaction: &tokio_postgres::Transaction<'_>,
    record: &PlacementRecord,
    now: i64,
    event: &str,
) -> Result<(), PlacementStoreError> {
    let worker = record.worker_id.as_ref().map(WorkerId::as_str);
    let epoch = record
        .assignment_epoch
        .map(AssignmentEpoch::get)
        .map(to_i64)
        .transpose()?;
    transaction
        .execute(
            "INSERT INTO sandboxd_placement.audit
             (event_unix_ms, request_id, tenant_id, workspace_id, sandbox_id,
              subject_id, worker_id, assignment_epoch, event, result_digest)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[
                &now,
                &record.request_id,
                &record.identity.tenant_id.as_str(),
                &record.identity.workspace_id.as_str(),
                &record.identity.sandbox_id.as_str(),
                &record.subject_id.as_str(),
                &worker,
                &epoch,
                &event,
                &record.result_digest,
            ],
        )
        .await?;
    Ok(())
}

fn record_from_row(row: &Row) -> Result<PlacementRecord, PlacementStoreError> {
    let worker = row
        .get::<_, Option<String>>("worker_id")
        .map(WorkerId::parse)
        .transpose()
        .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?;
    let epoch = row
        .get::<_, Option<i64>>("assignment_epoch")
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| PlacementStoreError::Invalid("negative assignment epoch".to_owned()))
                .and_then(|value| {
                    AssignmentEpoch::new(value)
                        .map_err(|error| PlacementStoreError::Invalid(error.to_string()))
                })
        })
        .transpose()?;
    let expiry = row
        .get::<_, Option<i64>>("lease_expires_unix_ms")
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| PlacementStoreError::Invalid("negative lease expiration".to_owned()))
        })
        .transpose()?;
    Ok(PlacementRecord {
        request_id: row.get("request_id"),
        idempotency_key: row.get("idempotency_key"),
        identity: PlacementIdentity {
            tenant_id: TenantId::parse(row.get::<_, String>("tenant_id"))
                .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?,
            workspace_id: WorkspaceId::parse(row.get::<_, String>("workspace_id"))
                .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?,
            sandbox_id: SandboxId::parse(row.get::<_, String>("sandbox_id"))
                .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?,
        },
        subject_id: SubjectId::parse(row.get::<_, String>("subject_id"))
            .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?,
        pool_name: row.get("pool_name"),
        state: match row.get::<_, &str>("state") {
            "queued" => PlacementState::Queued,
            "assigned" => PlacementState::Assigned,
            "completed" => PlacementState::Completed,
            "cancelled" => PlacementState::Cancelled,
            "expired" => PlacementState::Expired,
            state => {
                return Err(PlacementStoreError::Invalid(format!(
                    "unknown placement state `{state}`"
                )))
            }
        },
        worker_id: worker,
        assignment_epoch: epoch,
        lease_expires_unix_ms: expiry,
        result_digest: row.get("result_digest"),
        response: row
            .get::<_, Option<String>>("terminal_response")
            .map(|encoded| serde_json::from_str(&encoded))
            .transpose()
            .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?,
    })
}

fn assignment_from_record(
    record: PlacementRecord,
    broker_address: SocketAddr,
    resource_ceilings: ResourceCeilings,
    operation: Operation,
) -> Result<Assignment, PlacementStoreError> {
    Ok(Assignment {
        request_id: record.request_id,
        idempotency_key: record.idempotency_key,
        identity: record.identity,
        subject_id: record.subject_id,
        worker_id: record
            .worker_id
            .ok_or_else(|| PlacementStoreError::Invalid("assignment has no worker".to_owned()))?,
        epoch: record
            .assignment_epoch
            .ok_or_else(|| PlacementStoreError::Invalid("assignment has no epoch".to_owned()))?,
        lease_expires_unix_ms: record.lease_expires_unix_ms.ok_or_else(|| {
            PlacementStoreError::Invalid("assignment has no lease expiration".to_owned())
        })?,
        broker_address,
        resource_ceilings,
        operation,
    })
}

fn validate_submission(
    submission: &PlacementSubmission,
    now_unix_ms: u64,
) -> Result<(), PlacementStoreError> {
    let operation_bytes = serde_json::to_vec(&submission.operation)
        .map_err(|error| PlacementStoreError::Invalid(error.to_string()))?;
    let workload_operation = submission.operation.work_order_operation();
    if submission.work.idempotency_key.is_empty()
        || submission.work.idempotency_key.len() > 128
        || !submission
            .work
            .idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || submission.work.deadline_unix_ms <= now_unix_ms
        || !valid_pool_name(&submission.pool_name)
        || !bounded_label(&submission.topology)
        || !bounded_label(&submission.resource_shape)
        || !bounded_label(&submission.compatibility_cohort)
        || operation_bytes.len() > MAXIMUM_OPERATION_BYTES
        || workload_operation.is_none_or(|operation| !operation.requires_sandbox())
        || submission.operation.sandbox() != Some(submission.work.sandbox_id.as_str())
    {
        return Err(PlacementStoreError::Invalid(
            "placement submission is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn request_id(work: &QueuedWork) -> String {
    let mut digest = Sha256::new();
    digest.update(work.tenant_id.as_str().as_bytes());
    digest.update([0]);
    digest.update(work.idempotency_key.as_bytes());
    hex::encode(digest.finalize())
}

fn validate_worker(
    registration: &WorkerRegistration,
    broker_port: u16,
) -> Result<(), PlacementStoreError> {
    if !valid_pool_name(&registration.pool_name)
        || !bounded_label(&registration.topology)
        || !bounded_label(&registration.resource_shape)
        || !bounded_label(&registration.compatibility_cohort)
        || registration.broker_address.port() != broker_port
        || registration.broker_address.ip().is_unspecified()
        || registration.broker_address.ip().is_multicast()
        || registration.resource_ceilings.validate().is_err()
    {
        return Err(PlacementStoreError::Invalid(
            "worker registration is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn valid_pool_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn bounded_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn duration_millis(duration: Duration) -> Result<i64, PlacementStoreError> {
    i64::try_from(duration.as_millis())
        .map_err(|_| PlacementStoreError::Invalid("duration is too large".to_owned()))
}

fn to_i64(value: u64) -> Result<i64, PlacementStoreError> {
    i64::try_from(value)
        .map_err(|_| PlacementStoreError::Invalid("timestamp is too large".to_owned()))
}

fn to_u64(value: i64) -> Result<u64, PlacementStoreError> {
    u64::try_from(value)
        .map_err(|_| PlacementStoreError::Invalid("timestamp is negative".to_owned()))
}

fn count_u32(value: i64) -> Result<u32, PlacementStoreError> {
    u32::try_from(value)
        .map_err(|_| PlacementStoreError::Invalid("database count exceeds u32".to_owned()))
}

fn metric_u64(value: i64) -> Result<u64, PlacementStoreError> {
    u64::try_from(value)
        .map_err(|_| PlacementStoreError::Invalid("database metric is negative".to_owned()))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn rustls_connector(tls: &PlacementDatabaseTls) -> Result<MakeRustlsConnect, PlacementStoreError> {
    use rustls::pki_types::{pem::PemObject as _, CertificateDer, PrivateKeyDer};

    if tls.client_certificate.is_some() != tls.client_private_key.is_some() {
        return Err(PlacementStoreError::Tls(
            "client certificate and private key must be configured together".to_owned(),
        ));
    }
    let ca_pem = read_bounded_pem(&tls.ca_certificate, false)?;
    let certificates = CertificateDer::pem_slice_iter(&ca_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| PlacementStoreError::Tls(format!("read CA certificate: {error}")))?;
    let mut roots = rustls::RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(certificates);
    if accepted == 0 || rejected != 0 {
        return Err(PlacementStoreError::Tls(
            "CA bundle is empty or contains an invalid certificate".to_owned(),
        ));
    }
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let client = match (&tls.client_certificate, &tls.client_private_key) {
        (Some(certificate), Some(private_key)) => {
            let certificate_pem = read_bounded_pem(certificate, false)?;
            let certificates = CertificateDer::pem_slice_iter(&certificate_pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    PlacementStoreError::Tls(format!("read client certificate: {error}"))
                })?;
            if certificates.is_empty() {
                return Err(PlacementStoreError::Tls(
                    "client certificate bundle is empty".to_owned(),
                ));
            }
            let key_pem = read_bounded_pem(private_key, true)?;
            let private_key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|error| {
                PlacementStoreError::Tls(format!("read client private key: {error}"))
            })?;
            builder
                .with_client_auth_cert(certificates, private_key)
                .map_err(|error| {
                    PlacementStoreError::Tls(format!("configure client identity: {error}"))
                })?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => unreachable!("paired TLS identity checked above"),
    };
    Ok(MakeRustlsConnect::new(client))
}

fn open_regular_file(path: &Path, private: bool) -> Result<File, PlacementStoreError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| PlacementStoreError::Tls(format!("open `{}`: {error}", path.display())))?;
    let metadata = file.metadata().map_err(|error| {
        PlacementStoreError::Tls(format!("inspect `{}`: {error}", path.display()))
    })?;
    let process_owned =
        metadata.uid() == nix::unistd::geteuid().as_raw() && metadata.mode() & 0o077 == 0;
    let root_group_mounted = metadata.uid() == 0
        && metadata.gid() == nix::unistd::getegid().as_raw()
        && metadata.mode() & 0o037 == 0
        && metadata.mode() & 0o040 != 0;
    if !metadata.is_file() || (private && !process_owned && !root_group_mounted) {
        return Err(PlacementStoreError::Tls(format!(
            "`{}` must be a regular non-symlink{}",
            path.display(),
            if private {
                " owned by the process with mode 0600, or root-owned and process-group-readable with mode 0640 or stricter"
            } else {
                ""
            }
        )));
    }
    Ok(file)
}

fn read_bounded_pem(path: &Path, private: bool) -> Result<Vec<u8>, PlacementStoreError> {
    let mut bytes = Vec::new();
    open_regular_file(path, private)?
        .take(MAXIMUM_PEM_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| PlacementStoreError::Tls(format!("read `{}`: {error}", path.display())))?;
    if bytes.is_empty() || bytes.len() as u64 > MAXIMUM_PEM_BYTES {
        return Err(PlacementStoreError::Tls(format!(
            "`{}` is empty or exceeds the PEM size limit",
            path.display()
        )));
    }
    Ok(bytes)
}

fn loopback_address(host: &str) -> bool {
    host.parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn secure_database_config(connection_string: &str) -> Result<Config, PlacementStoreError> {
    let mut database = Config::from_str(connection_string)?;
    database
        .ssl_mode(SslMode::Require)
        .channel_binding(ChannelBinding::Prefer)
        .connect_timeout(Duration::from_secs(10));
    Ok(database)
}

fn local_database_config(connection_string: &str) -> Result<Config, PlacementStoreError> {
    let mut database = Config::from_str(connection_string)?;
    if database.get_hosts().iter().any(|host| match host {
        Host::Tcp(host) => host != "localhost" && !loopback_address(host),
        #[cfg(unix)]
        Host::Unix(_) => false,
    }) {
        return Err(PlacementStoreError::Invalid(
            "insecure placement database must use loopback or a Unix socket".to_owned(),
        ));
    }
    database
        .ssl_mode(SslMode::Disable)
        .connect_timeout(Duration::from_secs(10));
    Ok(database)
}

async fn apply_session_limits(client: &Client) -> Result<(), PlacementStoreError> {
    client
        .batch_execute(
            "SET statement_timeout = '10s';
             SET lock_timeout = '5s';
             SET idle_in_transaction_session_timeout = '15s';",
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_database_connections_are_strictly_local() {
        assert!(local_database_config("host=127.0.0.1 user=test").is_ok());
        assert!(local_database_config("host=::1 user=test").is_ok());
        assert!(local_database_config("host=localhost user=test").is_ok());
        assert!(local_database_config("host=198.51.100.10 user=test").is_err());
        assert!(local_database_config("host=database.internal user=test").is_err());
    }

    #[test]
    fn mtls_identity_must_be_configured_as_a_pair() {
        let tls = PlacementDatabaseTls {
            ca_certificate: PathBuf::from("/does-not-matter"),
            client_certificate: Some(PathBuf::from("/client.crt")),
            client_private_key: None,
        };
        assert!(matches!(
            rustls_connector(&tls),
            Err(PlacementStoreError::Tls(message))
                if message.contains("must be configured together")
        ));
    }
}
