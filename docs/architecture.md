# Architecture

This document describes the worker's security-relevant design. Operational
instructions live in [install.md](install.md); the wire contract lives in
[control-plane.md](control-plane.md).

## Trust boundary

`sandboxd` runs as a root-owned process in a dedicated worker container. The
worker runs in a standard Linux pod; a runtime-provided VM boundary is optional.
Its private containerd daemon shares the worker's mount namespace; Kubernetes
node runtime sockets and storage are not part of the worker. The operator Unix
socket accepts UID 0 only. An optional workload socket accepts one configured
local broker UID and requires a short-lived signed work order for each request.
Tenant traffic reaches the worker through the surrounding control plane and
broker.

Topology documents, guest arguments, environment values, OCI image contents,
workload requests, and guest execution are treated as untrusted. The worker
operator, daemon configuration, work-order signer, local broker process,
containerd daemon and snapshotter, `ctr` client, runsc binary, iproute2 binary,
image store, state store, artifact store, and artifact master key are trusted.

The security boundary for guest code is gVisor plus host namespaces and cgroup
containment. Access to the operator socket grants worker administration. The
workload socket additionally requires a valid signed work order; the configured
broker and signer are part of the trusted control-plane boundary.

## Sandbox ownership

The durable placement state distinguishes batch completion from a live
service. Successful create and restore responses enter `serving`; the worker
remains leased and its authenticated heartbeats extend only the current,
unexpired assignment epoch. Batch runs and failed starts enter terminal
`completed`. Cancellation, quarantine, lease expiry, and reassignment fence a
serving route before another epoch may own the sandbox.

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
creating an unbounded queue or thread set.

The operator endpoint verifies `SO_PEERCRED` UID 0 and retains shutdown and
recovery access. Protocol v2 operator requests carry an explicit local scope;
protocol v1 remains accepted only on this endpoint for migration. The workload
endpoint verifies the configured broker UID and protocol-v2 HMAC work orders
bound to the exact operation, request ID, tenant, workspace, subject, sandbox,
resource ceilings, nonce, expiration, and assignment epoch.

The daemon owns image admission handles, tenant-scoped active sandbox handles,
worker metrics, state paths, and artifact scopes. Tenant-facing sandbox IDs are
mapped to opaque epoch-scoped runtime project IDs. Assignments, consumed nonce
digests, and bounded audit events are persisted under the private control state
directory. Bounded append queues preserve ordering and group concurrent writes
into durable commits. Assignment and replay acknowledgements are issued only
after persistence. Recovery repairs an incomplete final record, validates
complete state, and fences in-progress assignments. Completed transferable
records remain fenced across restart.

Each tenant/workspace/sandbox identity is reserved while create, run, or restore
materializes host resources. Persistent instances are stored behind a
sandbox-specific mutex. Artifact keys include the verified tenant and workspace,
logs require a scoped live-sandbox lookup, and workload metrics contain only
the verified scope. The immutable image cache may be shared; its
contents and global cache metrics are not exposed through workload stats.
Graceful shutdown refuses to proceed while a sandbox remains active.

The exact request and signing contract is documented in
[control-plane.md](control-plane.md).

## Topology admission

`sandboxctl` accepts a restricted Compose subset. Unknown fields are rejected.
The compiler bounds service, network, argument, environment, and value counts;
rejects privileged and ambient host features; requires internal
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
topology locks or snapshot manifests.

Read-only roots remain the default. For an explicitly writable service, runsc
creates a private directory-backed root overlay above the immutable image root
and enforces the authorized upper-layer size. No loop device, filesystem image,
host overlay mount, mount propagation, or formatting helper is involved.
Project, service, and image identity determine a provider record, and callers
never supply worker paths or runtime overlay options. Provider metadata and the
immutable lower layer remain outside the guest root.

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
provider handles. Operator-installed storage integrations connect at this
boundary. The reduced directory provider derives a SHA-256 key from tenant,
workspace, and volume ID beneath an operator-mounted PVC. It exposes only the
canonical data leaf to runsc; tenant input never contains a claim, host path,
or mount source. Persistent storage remains after the final detach; ephemeral
storage is destroyed. Attachment ownership is atomically persisted before a
mount is issued, and startup recovery clears stale ownership and reconciles an
interrupted directory replacement after daemon or worker failure. Plain
directory volumes use the worker Pod/PVC as their aggregate physical boundary;
the declared per-volume quota additionally bounds portable export but is not
misrepresented as a hard write-time directory quota.

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

Snapshotting pauses the complete sandbox, marks each named directory frozen,
exports one bounded portable tar, thaws on success or failure, and publishes
the result as a typed encrypted artifact. Export and restore enforce path
length/depth/count, logical bytes, special-file, hard-link, sparse-file,
symlink, and extended-metadata policy. Restore validates the topology, digest,
size, quota, provider, and portability before an atomic directory swap, with
rollback and startup reconciliation for interrupted swaps. Manifest v3 binds
each volume ID to exactly one object plus provider, persistence, and
portability metadata. Excluded named volumes reject snapshot creation
explicitly; artifacts are reconstructed from their digest and secrets are
freshly materialized.

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
route, host address, NAT rule, or nameserver.

An explicit top-level `x-runtrue-network` policy is canonicalized into the
topology digest. `http_connect` installs a sandbox-local policy resolver and an
HTTP/CONNECT proxy. The OCI environment points HTTP clients at that proxy, and
nftables drops every direct guest input or forwarded packet. The proxy matches
complete lower-case DNS labels, schemes, and ports, rejects IP literals, pins a
filtered public resolution for each connection, and reapplies policy when a
redirect causes a new request. Loopback, link-local, private, carrier-grade NAT,
metadata, multicast, reserved, and documentation destinations are never valid
HTTP proxy targets.

The reduced userspace-network deployment keeps gVisor networking disabled and
mounts only a read-only Unix-socket transport directory into the guest. One
unprivileged `runtrue-sandbox-net-agent` service exposes an HTTP proxy on shared
guest loopback and registers reverse tunnels for explicitly selected ingress
services. It re-reads the read-only route configuration before each tunnel so
pause, resume, restore, and reassignment use only the current epoch credential.
The agent is a static executable baked into the measured application image; it
needs no capability, device, host path, cluster network, or shared library.
This mode intentionally cannot provide transparent TCP, guest DNS, UDP, or
QUIC.

`restricted_tcp` is intended only for a signer-approved topology. Its canonical
destination CIDR and port rules are rendered into the sandbox nftables table;
all unmatched forwarding is dropped. DNS and DNS-over-TLS ports cannot be added
to raw TCP rules. The per-sandbox policy resolver filters every synthesized
answer against the authorized CIDRs. nftables connection-count, byte-quota, and
rate rules are applied before destination accepts. HTTP proxy traffic uses the
same limits in its relay.

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
size bounds. Each writable OCI root has a gVisor-enforced upper-layer size and
private runtime directory; writable roots are never shared even when services
or tenants use the same immutable image. The worker Pod's bounded state volume
is the aggregate sandbox storage ceiling.

The shared Sentry performs guest work for every container. Host cgroup metrics
therefore establish the sandbox containment boundary. Policy fields named
`per_service` configure host process materializations; they do not provide
independent guest-container CPU or memory accounting.

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
removes stopped child state, releases writable-root provider records, tears
down networking and cgroups, verifies that runsc state is empty, and removes
the recovery journal only after successful cleanup.

## Snapshot artifacts

Both snapshot modes operate on the complete gVisor sandbox:

- `live` checkpoints and immediately resumes the source;
- `stop_and_move` checkpoints and removes the source instance.

runsc writes one sandbox-scoped checkpoint into a private staging directory.
When any OCI root is writable, the daemon pauses the complete sandbox before
checkpoint and diff export so publication cannot observe a changing upper
layer. Each upper layer is exported with runsc's rootfs-upper interface,
canonicalized to normalized relative paths, and then passed through the same
bounded special-file, sparse-file, xattr, traversal, duplicate, entry-count,
logical-size, archive-size, and deadline checks used for untrusted OCI diffs.
Restore validates and materializes the provider-backed writable root, then
lets runsc restore its checkpointed overlay against the unchanged OCI spec.
Injecting the exported diff through the rootfs-upper annotation would change
that spec and is rejected by runsc checkpoint restore. A live snapshot resumes
the source before artifact publication; failure also attempts to resume it.
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
one publisher ownership of a multipart destination while other publishers wait
for the completed object. Failed uploads are aborted. Garbage collection removes
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

For failure recovery, the controller periodically requests manifest-last live
checkpoints while the source lease is current. PostgreSQL stores only a
successfully published pointer. After lease expiry it quarantines the source
before creating a restore operation with the exact source epoch and a higher
destination epoch. This signed fence proof is the only path that permits a live
checkpoint to cross workers; ordinary live snapshots remain same-worker. A
returning quarantined Pod receives no route, heartbeat, or signed command and
the namespaced autoscaler deletes it with exact Pod UID and resource-version
preconditions.

Restore bounds the pointer, encrypted object, object count, individual object,
and total snapshot sizes before publication into an empty read-only directory.
It authenticates every encrypted chunk, re-hashes every plaintext file, and
checks tenant scope, sandbox identity, source and destination workers,
monotonically increasing assignment epoch, stop-and-move grant or signed live
recovery fence, provider
portability, topology, runsc state format and version, runtime configuration,
CPU features, architecture, and operating system. These checks finish before
destination cgroups, namespaces, or runsc state are allocated. The root restore
starts first; every child container then supplies its replacement OCI spec and
filesystem handles before runsc completes the restore. This includes children
whose init process had already exited because they remain part of the gVisor
checkpoint's container set; their stopped state remains stopped afterward.

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

The contracts reserve a MarcoVM backend identity for future implementations.
This release includes the gVisor executor and same-backend snapshot formats.
