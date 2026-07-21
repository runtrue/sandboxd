# Authenticated control plane

## Deployment boundary

`sandboxd` is a privileged worker component, not a tenant-facing API server.
The supported request path is:

```text
tenant client -> identity/policy service -> work-order signer -> local broker
              -> workload Unix socket -> sandboxd -> gVisor sandbox

root operator -------------------------------------> operator Unix socket
```

The identity and policy service authenticates the tenant and decides whether a
request is allowed. A trusted signer turns that decision into a narrowly scoped
work order. A single configured broker UID may deliver it over the local
workload socket. The broker may receive already-signed orders and does not need
access to the signing key.

Network permissions are part of that decision. The signed operation digest
covers the complete topology lock, including its sandbox-wide network profile,
domain/CIDR rules, limits, and ingress declarations. In particular,
`restricted_tcp` is an operator grant rather than a tenant-controlled Compose
escape hatch. The worker returns server-allocated ingress endpoints only after
the assignment is active; the tenant-facing control plane is responsible for
delivering those endpoint credentials to the owning principal without logging
or cross-tenant caching them.

The root-only operator socket is a separate recovery and development path. It
is not an authorization boundary between tenants: the operator is trusted to
select any local tenant/workspace scope.

## Worker configuration

The workload endpoint is disabled unless its socket, broker UID, and verifier
key are all configured:

```bash
sudo runtrue-sandboxd serve \
  --socket /run/runtrue-sandboxd/operator.sock \
  --workload-socket /run/runtrue-sandboxd/workload.sock \
  --broker-uid 991 \
  --work-order-key /etc/runtrue-sandboxd/work-order.key \
  --guest-profile root-in-sandbox-v1 \
  --maximum-connections 64 \
  --io-timeout-seconds 5
```

`strict-v1` is always installed. Repeat `--guest-profile` to enable the
reviewed `root-in-sandbox-v1` and/or `oci-compat-v1` profiles. The flag accepts
only those versioned built-ins; it does not accept raw UIDs or capabilities.
The selected set is worker policy and is returned, with exact restrictions, by
the ping capability response.

The key file contains exactly 32 bytes encoded as 64 lowercase or uppercase
hexadecimal characters, optionally followed by one newline. It must be a
root-owned regular file, must not be group-writable, and must have no world
permissions. A symlink is rejected. The daemon supports one active HMAC key;
rotation requires replacing the file and restarting the worker.

The operator socket is mode `0600` and accepts UID 0. The workload socket is
mode `0600`, is owned by the configured non-root broker UID, and accepts that
UID only. Configuring UID 0 as the broker is rejected. Both checks use Unix
peer credentials rather than caller-supplied fields.

## Protocol v2

Requests and responses are newline-delimited JSON. A message is limited to four
MiB, request identifiers are limited to 64 ASCII letters, digits, hyphens, or
underscores, and unknown fields are rejected.

A workload request has this outer form:

```json
{
  "schema_version": 2,
  "request_id": "request-42",
  "authorization": {
    "kind": "work_order",
    "work_order": {
      "claims": {
        "schema_version": 4,
        "tenant_id": "tenant-a",
        "workspace_id": "team-a",
        "subject_id": "agent-service",
        "request_id": "request-42",
        "operation": "inspect",
        "sandbox_id": "sandbox-a",
        "assignment_epoch": 7,
        "issued_unix_millis": 1784500000000,
        "expires_unix_millis": 1784500060000,
        "nonce": "nonce-42",
        "operation_digest": "sha256:<64 lowercase hex characters>",
        "resource_ceilings": {
          "allowed_guest_profiles": [{"name": "strict", "version": 1}],
          "maximum_services": 4,
          "maximum_timeout_ms": 30000,
          "memory_bytes_per_service": 268435456,
          "cpu_per_service_millis": 1000,
          "pids_per_service": 64,
          "tmpfs_bytes": 67108864,
          "writable_root_bytes_per_service": 67108864,
          "maximum_volumes": 8,
          "maximum_volume_bytes": 536870912,
          "maximum_output_bytes": 1048576
        }
      },
      "signature": "<64 lowercase hex characters>"
    }
  },
  "operation": {
    "kind": "inspect",
    "parameters": { "sandbox": "sandbox-a" }
  }
}
```

The supported workload operations are `ping`, `stats`, `admit`, `run`,
`create`, `restore`, `inspect`, `pause`, `resume`, `stop`, `logs`, and
`snapshot`. `shutdown` is operator-only and cannot be represented by a work
order.

## Signing contract

The operation digest is SHA-256 over the compact UTF-8 JSON encoding of the
`operation` object, including its `kind` and, where present, `parameters`. It is
encoded as `sha256:` followed by lowercase hexadecimal.

The signature is HMAC-SHA-256 over the compact UTF-8 JSON encoding of the
`claims` object. The fields must appear in the order shown above, including the
fields inside `resource_ceilings`; no whitespace is inserted. The signature is
encoded as 64 hexadecimal characters. Identifiers are validated before use, and
the signed request ID, operation type, sandbox ID, and operation digest must
match the outer request exactly.

Work orders must have a nonzero assignment epoch, cannot live longer than five
minutes, and are accepted with at most 30 seconds of future clock skew. An
expired order is rejected. Each tenant/workspace/nonce combination is consumed
at most once. Only the nonce digest is persisted, and replay rejection survives
a daemon restart. The nonce record reaches durable storage before its operation
may execute.

For operations containing a topology, the worker verifies the signed guest
profile allowlist plus service, memory, CPU, PID, tmpfs, writable-root, and
captured-output ceilings before image admission or execution. Run, create, and
restore deadlines must not exceed the signed maximum. The topology compiler
and runtime also apply their
stricter absolute limits; a work order cannot widen them.

## Ownership and recovery

The internal key for live handles, operation reservations, assignment records,
logs, snapshots, and workload metrics contains the verified tenant and
workspace identity. A caller-supplied sandbox string is never used as a global
lookup key. The gVisor project name is an opaque digest of tenant, workspace,
sandbox, and assignment epoch.

Create, run, and restore consume a monotonically increasing assignment epoch.
Follow-up lifecycle operations must carry the current active epoch, and the
worker rechecks it after acquiring the sandbox lock so an operation queued
before a fence cannot run afterward. Stop-and-move persists `fencing` before
checkpoint work and `transferable` only after the source is no longer
executable. Restore persists `restoring` and must advance the source epoch when
it preserves the sandbox identity. Consumed epochs cannot be reused. If the
daemon restarts while an assignment is provisioning, restoring, active, or
fencing, recovery marks it failed; a completed transferable assignment remains
fenced and bound to its snapshot.

The private control directory contains:

- `assignments.wal`, the ownership and assignment-epoch journal;
- `replay.wal`, the live nonce-digest journal; and
- `audit.jsonl`, the operation audit journal.

These files are append-only during normal operation. A bounded writer queue
preserves journal order and groups concurrent appends into one durable commit.
Assignment transitions and nonce consumption return only after their records
are durable. Periodic ordered replacement compacts the assignment and replay
journals without losing appends that were already acknowledged. Startup
discards only a torn final record, validates strict file and record bounds, and
fails closed on complete malformed records. Audit records use the same bounded
group-commit path; each record has a bounded size, while retention and rotation
remain an operator responsibility.

Audit records contain the verified tenant/workspace/subject only after
successful authorization. They omit operation parameters, topology content,
environment values, work orders, signatures, and keys. Operator stats may
enumerate worker state; workload stats contain only the verified scope and do
not expose shared image-cache contents or global counters.

## Compatibility

Protocol v2 is used by current local commands and is required on the workload
socket. Signed requests use work-order schema 4, which adds `maximum_volumes`
and `maximum_volume_bytes` to the canonical HMAC payload. The daemon sums each
top-level volume quota once, even when several containers attach the same named
volume. The same schema adds the versioned `allowed_guest_profiles` ceiling.
Protocol v1 requests without an authorization object remain accepted only from
UID 0 on the operator socket. This is an explicit migration path, not a
workload compatibility mode.
