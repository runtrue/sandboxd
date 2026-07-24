use runtrue_sandbox_core::{
    AssignmentEpoch, PlacementIdentity, QueuedWork, SandboxId, TenantId, WorkerId, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::BufReader,
    net::IpAddr,
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
const SCHEMA_VERSION: i32 = 1;

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

#[derive(Debug, Clone, Copy)]
pub struct PlacementStoreConfig {
    pub global_queue_limit: i64,
    pub global_concurrency_limit: i64,
    pub default_tenant_queue_limit: i32,
    pub default_tenant_concurrency_limit: i32,
    pub worker_heartbeat_timeout: Duration,
    pub lease_lifetime: Duration,
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
    pub topology: String,
    pub resource_shape: String,
    pub compatibility_cohort: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerRegistration {
    pub worker_id: WorkerId,
    pub topology: String,
    pub resource_shape: String,
    pub compatibility_cohort: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementRecord {
    pub request_id: String,
    pub idempotency_key: String,
    pub identity: PlacementIdentity,
    pub state: PlacementState,
    pub worker_id: Option<WorkerId>,
    pub assignment_epoch: Option<AssignmentEpoch>,
    pub lease_expires_unix_ms: Option<u64>,
    pub result_digest: Option<String>,
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
    pub worker_id: WorkerId,
    pub epoch: AssignmentEpoch,
    pub lease_expires_unix_ms: u64,
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
        let version: i32 = transaction
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

    pub async fn enqueue(
        &self,
        submission: &PlacementSubmission,
        now_unix_ms: u64,
    ) -> Result<EnqueueOutcome, PlacementStoreError> {
        validate_submission(submission, now_unix_ms)?;
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
        transaction
            .execute(
                "INSERT INTO sandboxd_placement.requests
                 (request_id, idempotency_key, tenant_id, workspace_id, sandbox_id,
                  topology, resource_shape, compatibility_cohort, deadline_unix_ms,
                  created_unix_ms, fair_finish, state)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'queued')",
                &[
                    &request_id(&submission.work),
                    &submission.work.idempotency_key,
                    &submission.work.tenant_id.as_str(),
                    &submission.work.workspace_id.as_str(),
                    &submission.work.sandbox_id.as_str(),
                    &submission.topology,
                    &submission.resource_shape,
                    &submission.compatibility_cohort,
                    &deadline,
                    &now,
                    &fair_finish,
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
        validate_worker(registration)?;
        let now = to_i64(now_unix_ms)?;
        let updated = self
            .client
            .lock()
            .await
            .execute(
                "INSERT INTO sandboxd_placement.workers
                 (worker_id, topology, resource_shape, compatibility_cohort, state,
                  heartbeat_unix_ms, registered_unix_ms)
                 VALUES ($1,$2,$3,$4,'clean',$5,$5)
                 ON CONFLICT (worker_id) DO UPDATE SET
                 heartbeat_unix_ms = EXCLUDED.heartbeat_unix_ms
                 WHERE sandboxd_placement.workers.state = 'clean'
                 AND sandboxd_placement.workers.topology = EXCLUDED.topology
                 AND sandboxd_placement.workers.resource_shape = EXCLUDED.resource_shape
                 AND sandboxd_placement.workers.compatibility_cohort = EXCLUDED.compatibility_cohort",
                &[
                    &registration.worker_id.as_str(),
                    &registration.topology,
                    &registration.resource_shape,
                    &registration.compatibility_cohort,
                    &now,
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
                "SELECT topology, resource_shape, compatibility_cohort
                 FROM sandboxd_placement.workers
                 WHERE worker_id = $1 AND state = 'clean' AND heartbeat_unix_ms > $2
                 FOR UPDATE",
                &[&worker_id.as_str(), &heartbeat_cutoff],
            )
            .await?;
        let Some(worker) = worker else {
            return Err(PlacementStoreError::WorkerUnavailable);
        };
        let topology: String = worker.get("topology");
        let resource_shape: String = worker.get("resource_shape");
        let cohort: String = worker.get("compatibility_cohort");
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
                 AND r.topology = $2 AND r.resource_shape = $3
                 AND r.compatibility_cohort = $4
                 AND (
                    SELECT count(*) FROM sandboxd_placement.requests active
                    WHERE active.tenant_id = r.tenant_id AND active.state = 'assigned'
                 ) < p.concurrency_limit
                 ORDER BY r.fair_finish, r.created_unix_ms, r.request_id
                 LIMIT 1 FOR UPDATE OF r SKIP LOCKED",
                &[&now, &topology, &resource_shape, &cohort],
            )
            .await?;
        let Some(candidate) = candidate else {
            transaction.commit().await?;
            return Ok(None);
        };
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
                 lease_expires_unix_ms = $4
                 WHERE request_id = $1 AND state = 'queued'",
                &[&request_id, &worker_id.as_str(), &epoch, &lease_expires],
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
        let assignment = assignment_from_record(record)?;
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
        transaction
            .execute(
                "UPDATE sandboxd_placement.requests SET state = 'completed',
                 result_digest = $2, terminal_unix_ms = $3 WHERE request_id = $1",
                &[&assignment.request_id, &result_digest, &now],
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
        append_audit(&transaction, &completed, now, "completed").await?;
        transaction.commit().await?;
        Ok(CompletionOutcome::Published)
    }

    pub async fn cancel(
        &self,
        tenant_id: &TenantId,
        idempotency_key: &str,
        now_unix_ms: u64,
    ) -> Result<Option<PlacementRecord>, PlacementStoreError> {
        let now = to_i64(now_unix_ms)?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT * FROM sandboxd_placement.requests
                 WHERE tenant_id = $1 AND idempotency_key = $2 FOR UPDATE",
                &[&tenant_id.as_str(), &idempotency_key],
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
                         worker_id = NULL, assignment_epoch = NULL, lease_expires_unix_ms = NULL
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
        idempotency_key: &str,
    ) -> Result<Option<PlacementRecord>, PlacementStoreError> {
        self.client
            .lock()
            .await
            .query_opt(
                "SELECT * FROM sandboxd_placement.requests
                 WHERE tenant_id = $1 AND idempotency_key = $2",
                &[&tenant_id.as_str(), &idempotency_key],
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
              worker_id, assignment_epoch, event, result_digest)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[
                &now,
                &record.request_id,
                &record.identity.tenant_id.as_str(),
                &record.identity.workspace_id.as_str(),
                &record.identity.sandbox_id.as_str(),
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
    })
}

fn assignment_from_record(record: PlacementRecord) -> Result<Assignment, PlacementStoreError> {
    Ok(Assignment {
        request_id: record.request_id,
        idempotency_key: record.idempotency_key,
        identity: record.identity,
        worker_id: record
            .worker_id
            .ok_or_else(|| PlacementStoreError::Invalid("assignment has no worker".to_owned()))?,
        epoch: record
            .assignment_epoch
            .ok_or_else(|| PlacementStoreError::Invalid("assignment has no epoch".to_owned()))?,
        lease_expires_unix_ms: record.lease_expires_unix_ms.ok_or_else(|| {
            PlacementStoreError::Invalid("assignment has no lease expiration".to_owned())
        })?,
    })
}

fn validate_submission(
    submission: &PlacementSubmission,
    now_unix_ms: u64,
) -> Result<(), PlacementStoreError> {
    if submission.work.idempotency_key.is_empty()
        || submission.work.idempotency_key.len() > 128
        || !submission
            .work
            .idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || submission.work.deadline_unix_ms <= now_unix_ms
        || !bounded_label(&submission.topology)
        || !bounded_label(&submission.resource_shape)
        || !bounded_label(&submission.compatibility_cohort)
    {
        return Err(PlacementStoreError::Invalid(
            "placement submission is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn request_id(work: &QueuedWork) -> String {
    format!("{}/{}", work.tenant_id, work.idempotency_key)
}

fn validate_worker(registration: &WorkerRegistration) -> Result<(), PlacementStoreError> {
    if !bounded_label(&registration.topology)
        || !bounded_label(&registration.resource_shape)
        || !bounded_label(&registration.compatibility_cohort)
    {
        return Err(PlacementStoreError::Invalid(
            "worker registration is invalid".to_owned(),
        ));
    }
    Ok(())
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

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn rustls_connector(tls: &PlacementDatabaseTls) -> Result<MakeRustlsConnect, PlacementStoreError> {
    if tls.client_certificate.is_some() != tls.client_private_key.is_some() {
        return Err(PlacementStoreError::Tls(
            "client certificate and private key must be configured together".to_owned(),
        ));
    }
    let mut ca_reader = BufReader::new(open_regular_file(&tls.ca_certificate, false)?);
    let certificates = rustls_pemfile::certs(&mut ca_reader)
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
            let mut certificate_reader = BufReader::new(open_regular_file(certificate, false)?);
            let certificates = rustls_pemfile::certs(&mut certificate_reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    PlacementStoreError::Tls(format!("read client certificate: {error}"))
                })?;
            if certificates.is_empty() {
                return Err(PlacementStoreError::Tls(
                    "client certificate bundle is empty".to_owned(),
                ));
            }
            let mut key_reader = BufReader::new(open_regular_file(private_key, true)?);
            let private_key = rustls_pemfile::private_key(&mut key_reader)
                .map_err(|error| {
                    PlacementStoreError::Tls(format!("read client private key: {error}"))
                })?
                .ok_or_else(|| {
                    PlacementStoreError::Tls("client private key is empty".to_owned())
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
    if !metadata.is_file()
        || (private
            && (metadata.mode() & 0o077 != 0 || metadata.uid() != nix::unistd::geteuid().as_raw()))
    {
        return Err(PlacementStoreError::Tls(format!(
            "`{}` must be a regular non-symlink{}",
            path.display(),
            if private {
                " owned by the process identity with mode 0600 or stricter"
            } else {
                ""
            }
        )));
    }
    Ok(file)
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
