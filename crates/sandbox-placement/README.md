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

The repository is intentionally not a tenant-facing API. The remaining #50
work is the stateless authenticated gateway, the narrow worker broker, and
streaming/cancellation wiring around this store.
