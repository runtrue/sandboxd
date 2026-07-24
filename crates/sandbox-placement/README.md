# Durable placement repository

`runtrue-sandbox-placement` is the shared correctness boundary for placement
replicas. PostgreSQL, rather than process memory, owns accepted queue entries,
idempotency, worker state, assignment epochs, leases, winning results, and the
audit chain.

The repository enforces:

- bounded global and per-tenant queues;
- separate global and per-tenant concurrency limits;
- durable weighted-fair ordering;
- exact worker topology, resource-shape, and compatibility-cohort matching;
- one clean worker token per assignment;
- monotonically increasing epochs after lease expiry;
- idempotent request replay and result publication;
- stale-worker rejection and quarantine; and
- bounded database connection, statement, lock, and idle-transaction waits.

## Deployment boundary

Production connections require a trusted CA and may require an owner-only mTLS
client key. The non-TLS API rejects non-loopback TCP destinations and exists
only for local tests. Put the database behind a default-deny network policy and
allow only placement replicas and the migration job.

Run `PostgresPlacementStore::migrate` from a dedicated deployment job. Runtime
replicas call `PostgresPlacementStore::connect`; they verify the schema version
and do not create or alter database objects. The migration role needs `CREATE`
on its dedicated database. The runtime role needs:

```sql
GRANT USAGE ON SCHEMA sandboxd_placement TO sandboxd_placement_runtime;
GRANT SELECT, INSERT, UPDATE
ON ALL TABLES IN SCHEMA sandboxd_placement
TO sandboxd_placement_runtime;
GRANT USAGE, SELECT
ON ALL SEQUENCES IN SCHEMA sandboxd_placement
TO sandboxd_placement_runtime;
```

Do not grant the runtime role database ownership, schema creation, table
deletion, role administration, replication, or superuser privileges.

The repository is intentionally not a tenant-facing API.

`runtrue-sandbox-gateway` is the stateless tenant-facing HTTP boundary. Tenant,
subject, workspace, deadline, topology, shape, and cohort authorization come
from an owner-only hashed-token policy; tenant identity is never accepted from
the request body. The gateway can submit, inspect, and cancel placement records
only. It has no Kubernetes client, service-account token, worker address input,
or sandboxd operator operation.

The deployment in `deploy/k3s/sandbox-gateway.yaml` runs as UID/GID 65532 with
no Linux capabilities, no privilege escalation, a read-only root, RuntimeDefault
seccomp/AppArmor, no service-account token, and explicit network policy. It is
ClusterIP-only. Its cleartext Pod listener must sit behind trusted TLS
termination; non-loopback binding requires an explicit acknowledgement flag.

Create `sandbox-gateway-database` with `url`, `ca.crt`, `tls.crt`, and
`tls.key`; create `sandbox-gateway-migration-database` with a separate
DDL-capable identity and the same key names. Create `sandbox-gateway-auth` with
`policy.json` in this form:

```json
{
  "schema_version": 1,
  "credentials": {
    "key-id": {
      "token_sha256": "64-lowercase-hex-characters",
      "tenant_id": "tenant-a",
      "subject_id": "service-a",
      "workspaces": ["workspace-a"],
      "maximum_deadline_ms": 300000,
      "topologies": ["topology-v1"],
      "resource_shapes": ["standard-v1"],
      "compatibility_cohorts": ["runsc-v1"]
    }
  }
}
```

Clients send `Authorization: Bearer key-id.<high-entropy-secret>` and
`Idempotency-Key: <bounded-key>`. Store only the SHA-256 digest of a randomly
generated secret with at least 32 bytes of entropy. The migration Job and
runtime Deployment use different Kubernetes Secrets and database roles.

The remaining #50 work is the narrow worker broker, signed work-order dispatch,
result streaming, worker registration endpoints, and fault-injected gateway
rollout tests.
