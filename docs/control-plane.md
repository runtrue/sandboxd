# Control-plane integration

`sandboxd` exposes local Unix sockets for operator and workload traffic. A
control plane authenticates users, applies policy, signs authorized operations,
and delivers them through a local broker.

```text
client -> identity and policy -> work-order signer -> local broker
       -> workload socket -> sandboxd -> gVisor sandbox

operator ---------------------> operator socket

HTTP ingress follows the same authority chain:

```text
tenant HTTP -> authenticated gateway -> assigned worker broker
            -> signed current-epoch inspect -> sandboxd loopback endpoint
            -> authenticated reverse tunnel -> declared guest service
```
```

## Request path

The control plane owns tenant authentication, policy, placement, and work-order
issuance. The signed operation digest covers the complete topology lock,
including guest profile, resource ceilings, network policy, and ingress
declarations.

One configured broker UID may submit signed requests without holding the
signing key. `sandboxd` verifies the broker's Unix peer credentials and the work
order independently.

`runtrue-sandbox-broker` is the network-to-Unix bridge. It accepts only
protocol-v2 `work_order` authorization and the workload operation set listed
below. It has no operator authorization variant and cannot forward readiness,
shutdown, artifact publication, or artifact garbage-collection operations.
The broker performs structural checks and identity matching; sandboxd remains
the final authority for the HMAC signature, expiry, nonce replay, assignment
epoch, operation digest, and resource ceilings.

The root-only operator socket provides administration and recovery access. It
may select any local tenant and workspace scope.

## Worker configuration

The workload socket is enabled only when its path, broker UID, and verifier key
are configured together:

```bash
sudo runtrue-sandboxd serve \
  --socket /run/runtrue-sandboxd/operator.sock \
  --workload-socket /run/runtrue-sandboxd/workload.sock \
  --broker-uid 991 \
  --broker-gid 991 \
  --work-order-key /etc/runtrue-sandboxd/work-order.key \
  --guest-profile root-in-sandbox-v1 \
  --maximum-connections 64 \
  --io-timeout-seconds 5
```

The operator socket is mode `0600` and accepts UID 0. By default the workload
socket is mode `0600`, is owned by the configured non-root broker UID, and
accepts that UID only. `--broker-gid` instead requires the socket directory to
be pre-provisioned with that non-root GID, preserves it as a setgid directory,
and creates the socket mode `0660` in that group. This avoids `CAP_CHOWN` in a
Kubernetes user namespace. Unix peer credentials still require the exact
configured broker UID, so group membership grants filesystem access but not
workload authorization.

The key file contains exactly 32 bytes encoded as 64 hexadecimal characters,
with an optional trailing newline. It must be a root-owned regular file, must
not be group-writable, and must have no world permissions. Symlinks are
rejected. Replace the file and restart the worker to rotate the active key.

`strict-v1` is always installed. Repeat `--guest-profile` to enable the reviewed
`root-in-sandbox-v1` or `oci-compat-v1` profiles. The worker returns the enabled
profiles and their restrictions in its capability response.

Run the broker as the exact configured non-root UID and mount only the workload
socket directory:

```bash
runtrue-sandbox-broker \
  --listen 127.0.0.1:8081 \
  --workload-socket /run/runtrue-sandboxd/workload.sock \
  --io-timeout-seconds 30
```

The listener defaults to loopback. A non-loopback listener is rejected unless
`--allow-non-loopback-http` explicitly acknowledges that a trusted mTLS
service mesh terminates and authenticates the connection. The broker itself
does not terminate TLS, hold the signing key, mount the operator socket, use a
service-account token, or require Linux capabilities. Its request body,
response, concurrency, and I/O time are bounded. Kubernetes must additionally
apply default-deny policy and allow the broker port only from the placement
dispatcher identity.

With `--registration-config`, `--gateway-address`, and `--advertise-ip`, the
broker waits for the workload socket, registers one exact worker
advertisement, and sends bounded heartbeats. The owner-only registration file
contains a worker credential, identity, topology/shape/cohort, and resource
ceilings; it contains no work-order signing key. Broker readiness stays false
until both the Unix socket and registration are live. Kubernetes injects the
Pod IP through `POD_IP` and the gateway host through
`SANDBOX_GATEWAY_ADDRESS`.

## Reverse HTTP ingress

An authenticated tenant may send HTTP to:

```text
/v1/placements/{idempotency_key}/ingress/{service}/{container_port}/{path}
```

`container_port` is the declared guest port, never a host port. The gateway
resolves only an assigned, unexpired placement belonging to the authenticated
tenant and subject. It creates a fresh short-lived `inspect` work order for
each HTTP request. The worker broker submits that order over the workload Unix
socket, accepts only one exact matching loopback endpoint returned by
sandboxd, and injects its epoch-scoped bearer locally. Tenant authorization and
all internal routing headers are removed before the request reaches the guest.

The gateway cannot supply an endpoint address, bearer, worker identity, or
assignment epoch. Pause, fencing, quarantine, lease expiration, and
reassignment therefore fail closed in sandboxd or the durable placement
lookup. Gateway and broker each cap headers at 16 KiB and request/response
bodies at 1 MiB; their existing concurrency and I/O deadlines also apply.
Chunked and connection-close responses are decoded within that bound.

A successful `create` or `restore` response transitions the placement to
`serving` rather than terminal `completed`. Authenticated worker heartbeats
renew only a still-live serving lease; they cannot revive an expired lease.
The route remains available while that worker and epoch own the serving
record. Cancel, quarantine, missed heartbeat/lease expiry, and reassignment
remove it immediately. Batch `run` and failed create/restore operations still
become terminal `completed`.

## Protocol

Requests and responses are newline-delimited JSON. Messages are limited to four
MiB. Request IDs may contain up to 64 ASCII letters, digits, hyphens, or
underscores. Unknown fields are rejected.

Current workload operations are:

```text
ping stats admit run create restore inspect pause resume stop logs snapshot
```

`shutdown`, artifact publication, and artifact garbage collection are
operator-only.

### Signed request

The workload socket uses protocol v2 and work-order schema 4:

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

### Signing contract

The operation digest is SHA-256 over the compact UTF-8 JSON encoding of the
complete `operation` object. Encode it as `sha256:` followed by lowercase
hexadecimal.

The signature is HMAC-SHA-256 over the compact UTF-8 JSON encoding of `claims`.
Fields must appear in the order shown above, including fields inside
`resource_ceilings`, with no inserted whitespace. Encode the signature as 64
hexadecimal characters.

The worker verifies that the signed request ID, operation, sandbox ID, and
operation digest match the outer request.

Work orders:

- use a nonzero assignment epoch;
- expire within five minutes;
- allow at most 30 seconds of future clock skew; and
- use each tenant, workspace, and nonce combination once.

The nonce digest is persisted before the operation runs, so replay protection
survives restart.

For topology-bearing operations, the worker checks the signed guest-profile,
service, memory, CPU, PID, tmpfs, writable-root, volume, timeout, and output
ceilings before admission. Runtime limits may be stricter than the signed
ceiling; a work order cannot widen them.

## Ownership and fencing

All live handles, reservations, assignments, logs, snapshots, and workload
metrics are keyed by verified tenant and workspace identity. Runtime project IDs
are opaque digests of tenant, workspace, sandbox, and assignment epoch.

Create, run, and restore consume monotonically increasing assignment epochs.
Lifecycle operations must present the active epoch, which is rechecked after
the sandbox lock is acquired.

Stop-and-move records `fencing` before checkpoint work and `transferable` only
after the source can no longer execute. Restore records `restoring` and advances
the epoch when preserving the sandbox identity. Consumed epochs cannot be
reused.

## Durable state and recovery

The private control directory contains:

- `assignments.wal` for ownership and assignment transitions;
- `replay.wal` for live nonce digests; and
- `audit.jsonl` for authorized operation events.

Assignment transitions and nonce consumption are acknowledged only after a
durable commit. Bounded queues preserve order and group concurrent appends.
Compaction retains acknowledged state.

Startup discards a torn final record and rejects complete malformed records. An
assignment interrupted during provisioning, restore, active execution, or
fencing is marked failed. A completed transferable assignment remains fenced
and bound to its snapshot.

Audit records contain verified tenant, workspace, and subject identities. They
exclude operation parameters, topology content, environment values, work
orders, signatures, and keys. Operators manage audit retention and rotation.

### Automatic worker-loss recovery

Create and restore submissions may opt into a bounded recovery policy:

```json
{
  "recovery_policy": {
    "snapshot_interval_ms": 30000,
    "maximum_staleness_ms": 90000,
    "maximum_attempts": 3
  }
}
```

The interval controls checkpoint cadence and storage cost. Maximum staleness is
the declared RPO ceiling: an expired lease with no checkpoint inside that
window terminates as `recovery_failed` instead of starting an empty sandbox.
The attempt limit bounds controller, network, artifact-backend, and restore
retries. Recovery is opt-in.

A gateway replica transactionally claims each due checkpoint, signs a live
snapshot operation for the current worker and epoch, and records the snapshot
only after successful manifest-last publication. Multiple replicas cannot
claim the same checkpoint. A failed or ambiguous attempt publishes no
control-plane reference and becomes eligible again at the next interval.

On lease expiry or explicit quarantine, PostgreSQL quarantines the source,
validates the latest snapshot and attempt limit, replaces the stored operation
with a restore bound to that snapshot and source epoch, and exposes
`recovering`. Only an exactly compatible worker can receive the new,
higher-epoch assignment. `serving` is restored only after restore succeeds.
Autoscaler heartbeats require a bounded direct response from the worker broker;
stale Kubernetes `Running` or `Ready` status cannot renew a partitioned node.

The signed recovery operation contains a controller-only
`fenced_source_epoch`. A live snapshot cannot move workers without that exact
proof, and the destination epoch must be newer. Tenant submissions cannot
supply the field. Restore also validates tenant scope, topology, attested
roots, guest profile, runsc configuration and version, architecture, CPU
features, artifact and volume portability, storage caps, and network policy
before guest execution. Fresh route and tunnel credentials are created after
restore.

Responses include policy, latest snapshot, source epoch, attempts, timestamps,
and terminal error. Recovery assignment remains blocked until the namespaced
controller confirms that the exact old Pod UID is absent. Audit rows reconstruct
`checkpoint_published -> source_fenced -> recovery_queued ->
source_fence_confirmed -> recovery_assigned -> recovery_completed`.
Metrics publish `recovery_rpo/<resource-shape>` and
`recovery_rto/<resource-shape>` P50/P95/P99 series.

Recovery preserves checkpointed process, memory, tmpfs, internal sockets,
supported writable roots, and portable provider volumes. The checked-in
multi-node k3s conformance proves this path for forced worker-Pod deletion and
complete source-agent loss. It requires the declared 120-second RPO ceiling,
a 10-second per-recovery RTO ceiling, a newer epoch, confirmed source fencing,
and the complete audit chain. The reference Level B run resumed process
memory, a pre-opened internal TCP socket, tmpfs, and the writable OCI root with
four capabilities and no privileged worker Pod or host integration.

Directory provider archives preserve numeric ownership. A named directory
volume is portable only when the destination storage provider supplies the
same ownership mapping, such as a qualified idmapped or CSI implementation.
Independent Kubernetes Pod user namespaces do not guarantee that mapping.

The guest may observe the read-only gVisor restore notification at
`/proc/gvisor/checkpoint`; the worker does not enable the guest checkpoint
trigger. Recovery does not make external effects exactly once. Work after the
recovery point can repeat; clients need idempotency keys or transactional
sinks at external side-effect boundaries.

## Compatibility

Protocol v2 and work-order schema 4 are required on the workload socket.
Protocol v1 remains available to UID 0 on the operator socket for local
migration. It is not accepted as workload authorization.
