# Architecture

## Trust boundary

The supported deployment is one trusted Linux worker with a root-owned
`sandboxd` process. Its operator Unix socket accepts UID 0 only. An optional,
separate workload Unix socket accepts one configured local broker UID, and each
request on that socket must carry a short-lived signed work order. Tenant
clients authenticate to an external control plane and never connect directly
to the privileged worker.

Topology documents, guest arguments, environment values, OCI image contents,
workload requests, and guest execution are treated as untrusted. The worker
operator, daemon configuration, work-order signer, local broker process,
containerd daemon and snapshotter, `ctr` client, runsc binary, iproute2 binary,
image store, state store, artifact store, and artifact master key are trusted.

The security boundary for guest code is gVisor plus host namespaces and cgroup
containment. The daemon itself is privileged and is not a tenant-facing network
service. Possession of the operator socket is equivalent to control of the
worker. Possession of the workload socket is insufficient without a valid
signed work order, but compromise of the configured broker or signer remains
inside the trusted control-plane boundary.

## Sandbox ownership

A sandbox—not an individual container—is the unit of create, placement, pause,
resume, snapshot, restore, recovery, and destruction. It owns:

```text
sandbox
  |-- one gVisor Sentry
  |-- root OCI container
  |-- zero or more child OCI containers
  |-- one host network namespace and veth pair
  |-- service cgroup materializations
  |-- runsc state and process handles
  `-- portable immutable snapshot references
```

Host paths, network interface names, process IDs, cgroup paths, and runtime
handles are worker materializations. They do not enter topology locks or the
backend-neutral snapshot data types.

## Workspace ownership

```text
bins/
  sandboxctl/               restricted Compose and image tooling
  sandboxd/                 privileged worker daemon and local client

crates/
  sandbox-core/             identities, capabilities, lifecycle, snapshot types
  sandbox-runtime/          backend and live-instance interfaces
  sandbox-artifact/         encrypted artifacts, providers, references, GC
  sandbox-oci/              Compose validation and OCI provider implementations
  sandbox-gvisor/           gVisor execution, snapshots, recovery, cleanup

examples/
  containerd-compose/       minimal public-image provider and network fixture
  python-compose/           local multi-container lifecycle and snapshot checks
```

The backend-neutral `BackendKind` has stable wire identities for `gvisor` and
`marcovm`. A stable identity does not imply that an executor is installed. The
daemon capability response contains gVisor only because this repository ships
only the gVisor executor.

## Control plane

`sandboxd` always listens on a mode `0600`, UID-0 operator Unix socket. When
configured, it also listens on a mode `0600` Unix socket owned by the broker
UID. Requests and responses are newline-delimited JSON with a four-MiB message
limit, a schema version, a bounded request identifier, and read/write
deadlines. A fixed connection limiter rejects excess clients instead of
creating an unbounded queue or thread set. The listener loop waits for socket
readiness and drains each ready accept backlog; it does not impose a periodic
accept-sleep latency floor.

The operator endpoint verifies `SO_PEERCRED` UID 0 and retains shutdown and
recovery access. Protocol v2 operator requests carry an explicit local scope;
protocol v1 remains accepted only on this endpoint for migration. The workload
endpoint verifies the configured broker UID and protocol-v2 HMAC work orders
bound to the exact operation, request ID, tenant, workspace, subject, sandbox,
resource ceilings, nonce, expiration, and assignment epoch. Shutdown has no
workload work-order representation.

The daemon owns image admission handles, tenant-scoped active sandbox handles,
worker metrics, state paths, and artifact scopes. Tenant-facing sandbox IDs are
mapped to opaque epoch-scoped runtime project IDs. Assignments, consumed nonce
digests, and bounded audit events are persisted under the private control state
directory. Their bounded append queues preserve ordering and group concurrent
writes into durable commits. Assignment and replay acknowledgements are issued
only after persistence; ordered compaction bounds recovery work. A restart
repairs an incomplete final journal record, rejects complete malformed state,
and fences provisioning, restoring, active, and in-progress source assignments
before accepting new work. Completed transferable records remain fenced across
restart.

Each tenant/workspace/sandbox identity is reserved while create, run, or restore
materializes host resources. Persistent instances are stored behind a
sandbox-specific mutex. Artifact keys include the verified tenant and workspace,
logs require a scoped live-sandbox lookup, and workload metrics
contain only the verified scope. The immutable image cache may be shared; its
contents and global cache metrics are not exposed through workload stats.
Graceful shutdown refuses to proceed while a sandbox remains active.

The exact request and signing contract is documented in
[control-plane.md](control-plane.md).

## Topology admission

`sandboxctl` accepts a restricted Compose subset. Unknown fields
are rejected. The compiler bounds service, network, argument, environment, and
value counts; rejects privileged and ambient host features; requires internal
networks; validates dependency order; resolves images to repository and image
digests; and writes a canonical topology digest.

The daemon re-verifies the topology digest before execution. The containerd
provider resolves metadata through containerd and verifies the locked index,
platform manifest, configuration, and every layer by digest and byte count. It
also revalidates the descriptor graph and exact OS, architecture, and variant
before a runtime is created. Layers are fetched without unpacking and pass a
bounded streaming archive scan before containerd's configured snapshotter may
extract them. The scan applies compressed, decoded, logical-size, entry-count,
path-length, and deadline limits and rejects traversal, absolute paths, unsafe
hardlinks, duplicate entries, special files, extended attributes, and sparse
metadata. A second bounded scan of the materialized rootfs rejects residual
special files and extended attributes before immutable publication.

Activation adds only empty runtime-owned `/etc/hosts` and `/etc/resolv.conf`
mount targets when an image omits them, then remounts the snapshotter view
read-only. The daemon caches opaque immutable handles and releases every
activation on graceful shutdown. Registry credentials are scoped to one tenant
and registry, live only in mode-`0700` temporary provider state, and never enter
topology locks or snapshot manifests. Docker export and GNU tar remain available
only through an explicitly named diagnostic command; neither is part of the
production admission or execution path.

## gVisor execution

The first service in dependency order is written as a CRI sandbox container.
The remaining services are CRI child containers that reference the root
sandbox ID. This creates one Sentry and one checkpoint boundary for the whole
sandbox, consistent with gVisor's
[sandbox-scoped checkpoint model](https://gvisor.dev/docs/user_guide/checkpoint_restore/).

Generated OCI specifications provide:

- numeric unprivileged guest users;
- no capabilities and `noNewPrivileges`;
- read-only OCI roots;
- bounded tmpfs mounts for `/dev`, `/tmp`, and `/work`;
- read-only `/etc/hosts` and `/etc/resolv.conf` materializations;
- isolated PID, network, IPC, UTS, and mount namespaces;
- masked sensitive proc/sys paths; and
- no raw networking, host Unix sockets, host FIFOs, or directfs.

Every runsc control command has a subprocess deadline. A wedged state, pause,
resume, checkpoint, kill, or delete command cannot hold a daemon request
indefinitely. Failed cleanup preserves its recovery journal so a daemon restart
can retry deletion of runsc, network, and cgroup materializations.

## Networking

Each sandbox receives one host network namespace and one private bridge/veth
attachment. No default route, NAT rule, nameserver, or host address is
installed. Service names resolve to shared loopback.

The containers share the Sentry network stack and port namespace. This is
pod-style networking, not independent Docker Compose network namespaces. Two
services that bind the same address and port conflict. Port publishing and
external networking are not part of the accepted topology.

## Resource containment

The worker creates cgroup-v2 paths for the sandbox services and configures host
memory, swap, CPU, and PID bounds before launching runsc. Output capture shares
a fixed byte budget between stdout and stderr. Guest tmpfs mounts have explicit
size bounds.

The shared Sentry performs guest work for every container. Host cgroup metrics
therefore establish a sandbox containment boundary, but they do not establish
independent per-container guest CPU or memory accounting. Policy fields that
contain `per_service` retain their wire format but must be interpreted as an
experimental host-process configuration rather than a tenant accounting
guarantee.

## Lifecycle

The persistent gVisor instance implements:

```text
create -> running -> paused -> running -> stopped
                   |          |
                   + snapshot +

portable snapshot -> restore under a new sandbox identity -> running
```

Pause and resume target the root sandbox once, which affects every child in the
shared Sentry. Stop kills and deletes children before the root sandbox, tears
down networking and cgroups, verifies that runsc state is empty, and removes
the recovery journal only after successful cleanup.

The core crate also contains a broader lifecycle data type for backend-neutral
orchestration. Its additional states are contracts, not daemon capability
claims.

## Snapshot artifacts

Both snapshot modes operate on the complete gVisor sandbox:

- `live` checkpoints and immediately resumes the source;
- `stop_and_move` checkpoints and removes the source instance.

runsc writes one sandbox-scoped checkpoint into a private staging directory.
The artifact layer hashes each file while streaming, encrypts it with a random
data key, wraps that key with a tenant/workspace-derived key, and publishes the
object by content digest. A versioned encrypted manifest records tenant,
sandbox, source worker, assignment epoch, topology, service states, backend
cohort, CPU profile, architecture, operating system, and object roles. The
small immutable snapshot pointer is published only after every referenced
object and the manifest are durable.

The default provider uses root-owned local files and conditional rename. Its
garbage-collection grace cannot be shorter than the maximum operation duration,
so it cannot reclaim an active staging publication. The S3-compatible provider
uses `s3-wire` for bounded streaming, retries, deadlines, conditional PUT,
verified GET, HEAD, listing, and deletion. It hashes tenant and workspace names
before deriving remote keys and publishes the snapshot pointer last. Large
objects use bounded managed multipart uploads. A durable conditional lock gives
one publisher ownership of a multipart destination, losing publishers wait for
the completed object, and failed uploads are aborted. Garbage collection removes
abandoned locks and stale multipart uploads after the configured grace period.
The S3 provider requires that grace to be at least twice the operation timeout,
leaving one full timeout window for client-owned abort cleanup after a caller
deadline expires.
The production endpoint must use TLS. The runtime principal is restricted to
its configured bucket and prefix; bucket versioning must either be disabled or
paired with a lifecycle policy because ordinary deletion cannot remove older
versions. Environment credentials support session tokens. An optional
owner-only credential file is re-read for every request so short-lived values
can be rotated atomically without entering manifests, logs, or command lines.

For stop-and-move, the assignment journal records `fencing` before runsc starts
the checkpoint. The source remains inaccessible to later lifecycle operations
until the attempt either returns to `active` with intact runtime resources or
advances to `transferable` after checkpoint publication and source cleanup. An
encrypted transfer grant is published only after cleanup. A destination claim
is immutable, idempotent for the same worker and epoch, and rejects a competing
worker. The S3 provider implements the claim with a strong conditional create
before advertising cross-worker portability.

Restore bounds the pointer, encrypted object, object count, individual object,
and total snapshot sizes before publication into an empty read-only directory.
It authenticates every encrypted chunk, re-hashes every plaintext file, and
checks tenant scope, sandbox identity, source and destination workers,
monotonically increasing assignment epoch, stop-and-move mode, provider
portability, topology, runsc state format and version, runtime configuration,
CPU features, architecture, and operating system. These checks finish before
destination cgroups, namespaces, or runsc state are allocated. The root restore
starts first; active child
containers then restore against the same checkpoint. A child that had already
exited is represented as stopped and is not passed to runsc restore.

The checkpoint contains process state, memory, sockets, and writable tmpfs
contents. The read-only OCI roots are re-admitted from the destination image
store. The manifest declares `cross_worker_same_backend`, but the daemon reports
the lower portability of its configured artifact provider. The current local
provider therefore reports `same_worker` and rejects cross-worker restore before
runtime allocation. A remote provider must preserve the same conditional grant
and claim semantics and pass the migration fault gates before that capability
can be enabled.

## Backend-neutral snapshot types

`sandbox-core` defines portable snapshot descriptors with tenant scope, worker
identity, assignment epoch, backend version and configuration, compatibility
requirements, and content-addressed object roles. Manifests contain no host
paths, process IDs, sockets, runtime handles, credentials, or encryption keys.

MarcoVM has a reserved backend identity and can use the same outer contracts.
There is no MarcoVM executor, VM snapshot format, or cross-backend conversion
in this repository.
