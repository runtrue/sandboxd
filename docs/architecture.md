# Architecture

This document describes the worker's security-relevant design. Operational
instructions live in [install.md](install.md); the wire contract lives in
[control-plane.md](control-plane.md).

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
  |-- zero or more private quota-backed writable roots
  |-- runsc state and process handles
  `-- portable immutable snapshot references
```

Host paths, network interface names, process IDs, cgroup paths, and runtime
handles are worker materializations. They do not enter topology locks or the
backend-neutral snapshot data types.

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

`sandboxctl` accepts a restricted Compose subset. Unknown fields are rejected.
The compiler bounds service, network, argument, environment, and
value counts; rejects privileged and ambient host features; requires internal
networks; validates dependency order; resolves images to repository and image
digests; and writes a canonical topology digest.

The topology contains one versioned guest-profile identity for the complete
sandbox. `strict-v1` is the default. Tenants can request another reviewed name
through the top-level `x-runtrue-guest-profile` extension, but cannot provide a
UID, capability list, device, namespace, or runtime annotation. Admission
fails unless that exact profile is installed by the operator, and its identity
is covered by the topology digest.

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

Read-only roots remain the default. For an explicitly writable service, the
provider creates a sparse ext4 image at the authorized size, attaches it to a
private loop device, and mounts an overlay above the immutable image root. The
ext4 filesystem enforces the bound at write time; post-hoc byte accounting is
not the quota. Project, service, and image identity determine a provider key,
and callers never supply host paths, loop devices, upper directories, work
directories, or mount options. Provider metadata and the immutable lower layer
remain outside the guest root.

## Volume providers

`sandbox-core` defines versioned volume specifications containing a tenant-owned
volume ID, normalized guest destination, read-only flag, persistence class,
snapshot policy, quota, and optional artifact digest. The restricted Compose
compiler accepts only typed references to top-level volume definitions. Strings
such as `/host/path:/guest/path`, protected guest destinations, unknown IDs,
writable artifact/secret mounts, and secrets included in snapshots fail before
image admission.

`sandbox-volume` defines create, attach, mount, freeze/thaw, snapshot, restore,
unmount, detach, delete, capability, and recovery operations over opaque
provider handles. This is also the boundary for an operator-installed CSI or
customer-hosted integration; no CSI plugin is loaded by the privileged daemon
in this repository. The local provider derives a SHA-256 key from tenant,
workspace, and volume ID. Ephemeral and persistent volumes use sparse ext4
images, private loop devices, and hard block quotas. Persistent storage remains
after the final detach; ephemeral storage is destroyed. Attachment ownership is
atomically persisted before a mount is issued, and startup recovery clears
stale ownership, mounts, and loop devices after daemon or worker failure.

Artifact volumes resolve a provider-owned regular file by its SHA-256 digest,
verify it is immutable, and expose it only through a read-only bind mount.
The root-only operator control path ingests a host file by expected digest. It
streams and verifies SHA-256 before an fsynced no-clobber rename, making
publication atomic and idempotent without recording the source path in tenant
topology, handles, or metadata. Operator-triggered garbage collection removes
only objects older than its grace period that have no live artifact-volume
record; publication, handle creation, and collection use the same provider
operation lock. The provider store is a cache, so operators retain the external
source of truth and can safely republish an object by digest.
Secret volumes resolve bounded owner-only files under
`secret-source/tenants/<tenant>/workspaces/<workspace>/<volume>`, reject
symlinks and special files, copy the bytes into a size-bounded tmpfs, and expose
that tmpfs read-only. Secret bytes, source paths, and tmpfs handles do not enter
topology locks or snapshot manifests.

Snapshotting pauses the complete sandbox, freezes each named ext4 volume,
copies the quota image, thaws it on success or failure, and publishes the image
as a typed encrypted artifact. Manifest v3 binds each volume ID to exactly one
object plus provider, persistence, and portability metadata. Restore verifies
the topology, digest, size, quota, provider, and portability before attaching
storage. Excluded named volumes reject snapshot creation explicitly; artifacts
are reconstructed from their digest and secrets are freshly materialized.

## gVisor execution

The first service in dependency order is written as a CRI sandbox container.
The remaining services are CRI child containers that reference the root
sandbox ID. This creates one Sentry and one checkpoint boundary for the whole
sandbox, consistent with gVisor's
[sandbox-scoped checkpoint model](https://gvisor.dev/docs/user_guide/checkpoint_restore/).

Generated OCI specifications provide:

- the selected profile's fixed numeric guest UID/GID;
- `noNewPrivileges` and an empty ambient and inheritable capability set;
- read-only OCI roots unless the topology explicitly requests an authorized
  quota-backed writable root;
- bounded tmpfs mounts for `/dev`, `/tmp`, and `/work`;
- read-only `/etc/hosts` and `/etc/resolv.conf` materializations;
- isolated PID, network, IPC, UTS, and mount namespaces;
- masked sensitive proc/sys paths; and
- no raw networking, host Unix sockets, host FIFOs, or directfs.

The worker always installs `strict-v1` (UID/GID 65534, no capabilities).
Operators may additionally install `root-in-sandbox-v1` (guest UID/GID 0, no
capabilities) and `oci-compat-v1`. The compatibility profile grants only
`CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_FSETID`, `CAP_SETGID`, and
`CAP_SETUID` inside gVisor. It never grants `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`,
`CAP_NET_RAW`, module loading, process tracing, host mount administration, or
host namespace access. Every CRI child uses the same sandbox-wide profile, so
a child cannot exceed its parent sandbox. Ping capability responses report the
installed identities and these exact restrictions.

Every runsc control command has a subprocess deadline. A wedged state, pause,
resume, checkpoint, kill, or delete command cannot hold a daemon request
indefinitely. Failed cleanup preserves its recovery journal so a daemon restart
can retry deletion of runsc, network, and cgroup materializations.

## Networking

Each sandbox receives one host network namespace, one private bridge/veth
attachment, and one nftables table whose name is derived from the assignment's
runtime identity. The `none` profile is the default: it installs no default
route, host address, NAT rule, or nameserver and retains the original no-egress
behavior.

An explicit top-level `x-runtrue-network` policy is canonicalized into the
topology digest. `http_connect` installs a sandbox-local policy resolver and an
HTTP/CONNECT proxy. The OCI environment points HTTP clients at that proxy, and
nftables drops every direct guest input or forwarded packet. The proxy matches
complete lower-case DNS labels, schemes, and ports, rejects IP literals, pins a
filtered public resolution for each connection, and reapplies policy when a
redirect causes a new request. Loopback, link-local, private, carrier-grade NAT,
metadata, multicast, reserved, and documentation destinations are never valid
HTTP proxy targets.

`restricted_tcp` is intended only for a signer-approved topology. Its canonical
destination CIDR and port rules are rendered into the sandbox nftables table;
all unmatched forwarding is dropped. DNS and DNS-over-TLS ports cannot be added
to raw TCP rules. The per-sandbox policy resolver filters every synthesized
answer against the authorized CIDRs. nftables connection-count, byte-quota, and
rate rules are applied before destination accepts. HTTP proxy traffic uses the
same limits in its relay. gVisor TBF was not selected because one Sentry owns the
whole network stack and the required accounting boundary is the complete
sandbox; enforcing the ceiling in the host policy path also covers traffic after
it leaves the Sentry.

Ingress declarations contain only a guest service identity and container port.
The worker allocates loopback host endpoints and 256-bit bearer credentials;
caller-selected host addresses and ports are not represented in the lock.
Authorization is removed before forwarding. Pause and fencing deactivate new
and existing relays, resume reactivates the current assignment, and stop or
move drops the listeners. Restore allocates a new endpoint and credential under
the destination assignment epoch, so a stale source mapping cannot become the
new route. A deployment may place its own authenticated edge in front of the
worker-loopback endpoint.

The containers share the Sentry network stack and port namespace. This is
pod-style networking, not independent Docker Compose network namespaces. Two
services that bind the same address and port conflict, and every network policy
therefore applies to the complete sandbox rather than an individual service.

For example, an HTTPS-only profile with one published guest port is:

```yaml
x-runtrue-network:
  profile: http_connect
  http_rules:
    - domains: [api.example.com, "*.services.example"]
      schemes: [https]
      ports: [443]
  dns:
    maximum_queries: 256
    maximum_response_bytes: 4096
    maximum_total_bytes: 1048576
  limits:
    maximum_connections: 32
    maximum_bytes: 67108864
    bandwidth_bytes_per_second: 8388608
  ingress:
    - service: api
      container_port: 8080
```

## Resource containment

The worker creates cgroup-v2 paths for the sandbox services and configures host
memory, swap, CPU, and PID bounds before launching runsc. Output capture shares
a fixed byte budget between stdout and stderr. Guest tmpfs mounts have explicit
size bounds. Each writable OCI root has its own ext4 block quota and overlay
upper directory; writable roots are never shared even when services or tenants
use the same immutable image.

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
shared Sentry. Stop terminates child process trees, tears down the root Sentry,
removes stopped child state, releases writable mounts and loop devices, tears
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
When any OCI root is writable, the daemon pauses the complete sandbox before
checkpoint and diff export so publication cannot observe a changing upper
layer. Each upper layer is encoded as an uncompressed OCI diff tar, including
overlay whiteouts and basic ownership, mode, timestamp, file, directory, and
symlink metadata. Hard links and non-overlay extended attributes fail closed
until their portable representation is supported. A live snapshot resumes the
source before artifact publication; failure also attempts to resume it.
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
contents. Immutable OCI roots are re-admitted from the destination image store.
For each writable service, the manifest carries exactly one
`writable_filesystem` object and its authorized quota. Restore rejects missing,
extra, corrupt, oversized, or topology-mismatched diffs, reconstructs the
private overlay, and only then starts guest code. Failed reconstruction releases
its mounts, loop device, and provider state. The manifest declares
`cross_worker_same_backend`, but the daemon reports the lower portability of
its configured artifact provider. The local provider reports `same_worker` and
rejects cross-worker restore before runtime allocation. The S3-compatible
provider reports `cross_worker_same_backend`.

## Backend-neutral snapshot types

`sandbox-core` defines portable snapshot descriptors with tenant scope, worker
identity, assignment epoch, backend version and configuration, compatibility
requirements, and content-addressed object roles. Manifests contain no host
paths, process IDs, sockets, runtime handles, credentials, or encryption keys.

MarcoVM has a reserved backend identity and can use the same outer contracts.
There is no MarcoVM executor, VM snapshot format, or cross-backend conversion
in this repository.
