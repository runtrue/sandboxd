# Durable placement repository

`runtrue-sandbox-placement` is the shared correctness boundary for placement
replicas. PostgreSQL, rather than process memory, owns accepted queue entries,
idempotency, typed operations, worker state, assignment epochs, leases,
terminal responses, and the audit chain.

The repository enforces:

- bounded global and per-tenant queues;
- separate global and per-tenant concurrency limits;
- durable weighted-fair ordering;
- exact reviewed pool, worker topology, resource-shape, and
  compatibility-cohort matching;
- exact authenticated worker registration, broker address, and signed ceiling
  advertisement;
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
GRANT DELETE
ON sandboxd_placement.pool_activations
TO sandboxd_placement_runtime;
```

The narrow row-delete grant only bounds completed activation measurements; no
request, worker, assignment, audit, or tenant-policy row is deletable by this
role. Do not grant database ownership, schema creation, table DDL, role
administration, replication, or superuser privileges.

The repository is intentionally not a tenant-facing API.

`runtrue-sandbox-gateway` is the stateless tenant-facing HTTP boundary. Tenant,
subject, workspace, deadline, topology, shape, and cohort authorization come
from an owner-only hashed-token policy. Pool selection is restricted by that
policy and resolved against the bounded operator catalog; tenant identity is
never accepted from the request body. The gateway can submit, inspect, cancel,
stream placement records, and forward bounded HTTP to a declared ingress
service on an active assignment. It has no Kubernetes client, service-account
token, tenant-selected worker address, or sandboxd operator operation. Every
replica also runs the same bounded reconciliation loop: it claims durable work,
signs the typed operation, delivers it to the assigned broker, and publishes a
terminal response only while that lease epoch still wins.

Ingress forwarding uses
`/v1/placements/{idempotency_key}/ingress/{service}/{container_port}/{path}`.
The tenant selects only a service identity and declared guest port. For each
request the gateway reloads the active durable assignment and signs a fresh
`inspect` operation. The broker obtains the current loopback endpoint and
bearer from sandboxd, strips tenant/internal authorization, and relays through
the authenticated reverse tunnel. The route disappears when the lease is
expired, fenced, quarantined, or reassigned. Headers are capped at 16 KiB,
bodies in each adapter hop at 1 MiB, and the normal concurrency/deadline bounds
remain in force. Successful create/restore placements remain in `serving`
until cancellation or fencing.

`GET /v1/placements/{idempotency_key}/events` returns authenticated
`text/event-stream` placement snapshots. It emits only when the durable record
changes, remains open for `serving`, and closes after completed, cancelled, or
expired. Each replica admits
at most 64 concurrent streams, retains one bounded last snapshot plus the
bounded outgoing event per stream, and polls PostgreSQL at a fixed interval. A
client may reconnect to any replica because the stream owns no correctness
state. Events contain the same tenant-scoped fields as inspection and never
expose queue position or another tenant's identity. Database failures produce a
generic terminal error event without internal details.

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
  "schema_version": 2,
  "credentials": {
    "key-id": {
      "token_sha256": "64-lowercase-hex-characters",
      "tenant_id": "tenant-a",
      "subject_id": "service-a",
      "workspaces": ["workspace-a"],
      "maximum_deadline_ms": 300000,
      "pools": ["fixed-standard-warm"],
      "topologies": ["topology-v1"],
      "resource_shapes": ["standard-v1"],
      "compatibility_cohorts": ["runsc-v1"],
      "service_levels": {
        "fixed-standard-warm": {
          "mode": "retained_warm",
          "clean_workers": 2
        }
      }
    }
  }
}
```

Every authorized pool must have exactly one service-level entry. A
`scale_to_zero` entry is accepted only for a reviewed pool whose minimum and
warm headroom are both zero. `retained_warm` is accepted only when the reviewed
pool retains at least the requested clean slots. The client cannot override
this credential-bound choice in a placement body.

Clients send `Authorization: Bearer key-id.<high-entropy-secret>` and
`Idempotency-Key: <bounded-key>`. Store only the SHA-256 digest of a randomly
generated secret with at least 32 bytes of entropy. The migration Job and
runtime Deployment use different Kubernetes Secrets and database roles.

The runtime `sandbox-gateway-auth` Secret also contains:

- `worker-policy.json`, which maps each worker credential to one exact worker
  ID, pool, topology, resource shape, and compatibility cohort; and
- `work-order.key`, the same 64-lowercase-hex HMAC key mounted read-only into
  sandboxd, but never into the broker.

`worker-policy.json` has this form:

```json
{
  "schema_version": 1,
  "credentials": {
    "worker-key-a": {
      "token_sha256": "64-lowercase-hex-characters",
      "worker_id": "worker-a",
      "pool_name": "fixed-standard-warm",
      "topology": "topology-v1",
      "resource_shape": "standard-v1",
      "compatibility_cohort": "runsc-v1"
    }
  }
}
```

A worker sends `Authorization: Worker key-id.<high-entropy-secret>` to
`POST /internal/v1/workers/register` and its exact worker ID heartbeat path.
The registration body contains its broker socket address and typed resource
ceilings. A credential cannot register or heartbeat a different worker
identity. NetworkPolicy admits these routes only from labeled worker
registration clients.

Pool demand, fresh clean/leased/draining workers, the idle clock, desired
capacity, and quota backpressure are reconciled transactionally in PostgreSQL.
Duplicate controllers serialize their decision and a restart resumes from the
same idle clock. Kubernetes replica count is an explicit observation rather
than inferred from registrations, so stale worker rows cannot manufacture
capacity.

The same exact worker credential may request a fail-closed state transition at
`POST /internal/v1/workers/{worker_id}/drain` or
`POST /internal/v1/workers/{worker_id}/quarantine`. Draining workers continue
heartbeating but receive no new assignment. Quarantined workers neither
heartbeat nor re-register; quarantine atomically fences and requeues (or
deadline-expires) any active assignment before a higher epoch can be issued.
They require operator reconciliation or replacement. Consumed workers cannot
return to service through either endpoint.

The dispatcher uses bounded worker scans and request timeouts. An ambiguous
network failure leaves the assignment leased; lease reconciliation quarantines
that worker before a higher epoch is requeued. The same periodic transaction
terminalizes queued requests whose client deadlines elapsed, even when no
worker is available, so they cannot retain queue quota indefinitely.
PostgreSQL stores the complete typed operation and bounded response, while
audit rows contain only identity, epoch, worker, event, and result digest.
Successful `create` and `restore` responses enter `serving`: the worker stays
leased, authenticated heartbeats extend only an unexpired serving lease, and
ingress remains routable. Cancel, quarantine, or lease expiry fences the worker
and removes the route. Batch operations and failed service starts enter
terminal `completed`.
