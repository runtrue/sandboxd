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

The following larger set is only for the host-integrated compatibility
profile that exercises lifecycle, kernel networking, and writable-root
snapshot suites:

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
`MKNOD` is required only when writable-root snapshot restore recreates OCI
whiteouts. Do not grant the compatibility set to fixed or userspace-network
workers.

The container also needs:

- a private containerd daemon in the same mount namespace, with its Unix socket
  at the configured `--containerd-address`;
- a writable cgroup v2 subtree with the `cpu`, `memory`, and `pids` controllers
  delegated by the container runtime at
  `/sys/fs/cgroup/runtrue-sandboxd`;
- pod volumes for persistent worker state and image storage; and
- loop-control and allocated loop devices when writable roots or local named
  volumes are enabled.

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
