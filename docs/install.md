# Installation and operation

Run `sandboxd` in a dedicated worker container that matches the
[validated platform](../README.md#requirements). It runs in a standard Linux
pod; runtimes that place the pod inside a VM are also compatible. Connect
tenant-facing services through the signed broker interface described in
[control-plane.md](control-plane.md).

## Install a release

Download the archive and `SHA256SUMS` from the matching GitHub release when
assembling the worker image:

```bash
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf sandboxd-v0.1.0-alpha.1-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 \
  sandboxd-v0.1.0-alpha.1-x86_64-unknown-linux-gnu/runtrue-sandboxd \
  sandboxd-v0.1.0-alpha.1-x86_64-unknown-linux-gnu/runtrue-sandboxctl \
  /usr/local/bin/
```

The archive also contains a static x86-64 musl
`runtrue-sandbox-net-agent`. Copy that binary into application images that use
`--network-mode userspace`; it has no guest shared-library dependency. It is
guest software, not a worker daemon, and must be part of the application's
measured, digest-pinned OCI root.

Install compatible `runsc`, containerd, and system dependencies in the worker
image. Run containerd privately in the same container and mount namespace as
`sandboxd`; do not mount the Kubernetes node's containerd socket or snapshotter
storage. The README lists the known-good versions used by project CI and
integration testing; they are not global pins. Validate other versions with
both worker integration suites before operating them. Snapshot migration
requires matching `runsc` versions and runtime configuration across the source
and destination workers.

## Build from source

```bash
git clone https://github.com/runtrue/sandboxd.git
cd sandboxd
cargo build --workspace --release --locked
sudo install -m 0755 \
  target/release/runtrue-sandboxd \
  target/release/runtrue-sandboxctl \
  /usr/local/bin/
```

Run the checks in [CONTRIBUTING.md](../CONTRIBUTING.md) before operating a local
build.

## Run the worker container

Run the container as UID 0 with `privileged: false`. The worker needs a bounded
set of kernel capabilities selected by feature. The recommended fixed and
userspace-network profiles use only `SETGID`, `SETUID`, `SYS_CHROOT`, and
`SYS_ADMIN` inside a Kubernetes-created user namespace:

```yaml
securityContext:
  runAsUser: 0
  privileged: false
  capabilities:
    drop: ["ALL"]
    add: [SETGID, SETUID, SYS_ADMIN, SYS_CHROOT]
```

The userspace-network profile adds no Linux capability and no host networking
setting. It uses `--network-mode userspace`, runsc `network=none`, and a single
read-only Unix-socket directory. It supports policy-approved HTTP CONNECT;
declared reverse HTTP ingress uses separate epoch-scoped tunnel credentials.
Direct guest DNS, raw TCP/UDP, and transparent networking remain disabled.

Run exactly one `runtrue-sandbox-net-agent` service in a userspace-network
sandbox. It binds a conventional HTTP proxy only on shared guest loopback,
relays it to `/run/lock/egress.sock`, and registers only ingress services named
with repeated `--ingress-service` arguments. Configure application services
with `HTTP_PROXY=http://127.0.0.1:3128` and
`HTTPS_PROXY=http://127.0.0.1:3128`. The agent runs as the same unprivileged
guest identity as application code and needs no capability, device, host
mount, Kubernetes API access, or cluster-network access.

The agent does not make transparent sockets work. Software that ignores proxy
environment variables needs explicit proxy configuration or application
changes. UDP, QUIC, arbitrary TCP, inbound UDP, caller-selected host ports, and
protocols other than HTTP proxy egress and reverse TCP transport for declared
HTTP routes remain unsupported.

The following larger set is only for the host-integrated compatibility profile
that exercises kernel networking and the legacy loop-backed named volume
provider:

```yaml
securityContext:
  runAsUser: 0
  privileged: false
  capabilities:
    drop: ["ALL"]
    add:
      - CHOWN
      - DAC_OVERRIDE
      - FOWNER
      - KILL
      - SETGID
      - SETUID
      - SETPCAP
      - NET_ADMIN
      - NET_RAW
      - SYS_CHROOT
      - SYS_ADMIN
      - MKNOD
```

`SYS_ADMIN` is required for the current normal runsc namespace/mount setup.
`NET_ADMIN` and `NET_RAW` are required only by `--network-mode private`.
Directory-backed writable roots and their snapshot/restore path add no
capability to the fixed profile. `MKNOD`, loop devices, filesystem formatting,
and host overlay mounts are not used by writable roots. Do not grant the
compatibility set to fixed or userspace-network workers.

The container also needs:

- a private containerd daemon in the same mount namespace, with its Unix socket
  at the configured `--containerd-address`;
- a writable cgroup v2 subtree with the `cpu`, `memory`, and `pids` controllers
  delegated by the container runtime at
  `/sys/fs/cgroup/runtrue-sandboxd`;
- pod volumes for persistent worker state and image storage; and
- loop-control and allocated loop devices only when the legacy local named
  volume provider is explicitly enabled.

Do not mount the Kubernetes node's containerd socket, snapshotter storage,
cgroup tree, or other system paths. The container runtime must supply the
delegated cgroup namespace and any selected devices directly. Allow the
required namespace, mount, networking, and runsc syscalls in the pod's seccomp,
AppArmor, or SELinux policy.

The worker uses runsc's systrap platform, so it does not need `/dev/kvm`.
The worker does not require a VM-backed runtime. A deployment may choose one as
an additional outer boundary without changing the worker image; gVisor remains
the workload isolation layer inside the worker. Validate the final pod policy
with both example suites because cgroup delegation, device assignment, and
mandatory-access-control behavior vary by Kubernetes runtime.

For the optional broker socket and signed work orders, see
[control-plane.md](control-plane.md). Keep artifact keys, work-order keys, and
S3 credentials in Kubernetes Secrets or the deployment's secret manager.

## Configure S3-compatible artifact storage

The default artifact provider stores snapshots on one worker. Configure the
S3-compatible provider for cross-worker restore:

```bash
sudo --preserve-env=AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN \
  runtrue-sandboxd serve \
  --worker-id worker-a \
  --artifact-master-key /etc/runtrue-sandboxd/artifact-master.key \
  --artifact-s3-bucket sandbox-artifacts \
  --artifact-s3-region us-east-1
```

Workers in one migration pool need:

- the same owner-only 32-byte artifact master key;
- the same bucket and prefix;
- compatible runtime and host cohorts; and
- distinct worker IDs and local state roots.

Automatic worker-loss recovery additionally requires:

- a shared, durable S3-compatible backend; the local provider remains
  same-worker only;
- the same credential authority and artifact master key on every eligible
  worker;
- durable, highly available gateway PostgreSQL;
- more than one schedulable node and a compatible clean destination worker;
- namespaced autoscaler permission to delete only an owned Pod whose durable
  worker state is already `quarantined` or `consumed`; and
- outer network policy allowing only required artifact and control-plane
  endpoints.

Do not use node-local object storage for this feature. Configure replication,
encryption, retention, and availability for the declared RPO. The controller
never falls back to a stale checkpoint or an empty create when recovery was
requested.

The provider uses HTTPS by default. Set `--artifact-s3-endpoint` for a compatible
service. `--artifact-s3-allow-http-for-local-testing` is only for a trusted
local test endpoint.

Credentials may come from the standard AWS environment variables. For rotating
temporary credentials, pass an absolute owner-only JSON file through
`--artifact-s3-credentials-file`; the daemon reads it for every signed request.
The file contains `access_key_id`, `secret_access_key`, and an optional
`session_token`.

Restrict the runtime principal to the configured bucket and prefix. If bucket
versioning is enabled, add a lifecycle policy for old object versions.

Local-only builds can omit S3 dependencies:

```bash
cargo build -p runtrue-sandboxd --no-default-features
```

## Manage artifact volumes

Publish a file through the root-only operator socket:

```bash
digest="sha256:$(sha256sum ./dataset.bin | cut -d' ' -f1)"
sudo runtrue-sandboxd publish-artifact \
  --source ./dataset.bin \
  --digest "$digest"
```

The daemon verifies the digest and publishes content atomically. Repeating the
same command is safe.

Remove unreferenced objects older than the default 24-hour grace period:

```bash
sudo runtrue-sandboxd garbage-collect-artifacts
```

Use `--minimum-age-seconds` to change the grace period. Keep an external durable
copy of artifact-volume inputs; republishing by digest is the recovery path
after collection.
