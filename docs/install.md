# Installation and operation

Install `sandboxd` in a dedicated Linux worker environment that matches the
[validated platform](../README.md#requirements). The worker may be a host
service or a capability-scoped Kubernetes pod, including a pod on a
microVM-backed node. Connect tenant-facing services through the signed broker
interface described in [control-plane.md](control-plane.md).

## Install a release

Download the archive and `SHA256SUMS` from the matching GitHub release:

```bash
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf sandboxd-v0.1.0-alpha.1-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 \
  sandboxd-v0.1.0-alpha.1-x86_64-unknown-linux-gnu/runtrue-sandboxd \
  sandboxd-v0.1.0-alpha.1-x86_64-unknown-linux-gnu/runtrue-sandboxctl \
  /usr/local/bin/
```

Install compatible `runsc`, containerd, and host dependencies. The README lists
the known-good versions used by project CI and integration testing; they are not
global pins. Validate other versions with both worker integration suites before
operating them. Snapshot migration requires matching `runsc` versions and
runtime configuration across the source and destination workers.

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

## Run with systemd

This minimal unit enables only the root-owned operator socket:

```ini
[Unit]
Description=Runtrue OCI sandbox worker
Documentation=https://github.com/runtrue/sandboxd
After=containerd.service network-online.target
Requires=containerd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/runtrue-sandboxd serve
ExecStop=/usr/local/bin/runtrue-sandboxd shutdown
Restart=on-failure
RestartSec=5s
RuntimeDirectory=runtrue-sandboxd
RuntimeDirectoryMode=0700
StateDirectory=runtrue-sandboxd
StateDirectoryMode=0700
UMask=0077
LimitNOFILE=1048576
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
```

Save the unit as `/etc/systemd/system/runtrue-sandboxd.service`, then verify and
start it:

```bash
sudo systemd-analyze verify /etc/systemd/system/runtrue-sandboxd.service
sudo systemctl daemon-reload
sudo systemctl enable --now runtrue-sandboxd.service
sudo runtrue-sandboxd ping
```

The worker runs as root to manage cgroups, namespaces, nftables, loop devices,
ext4 mounts, containerd, and gVisor. Validate any additional systemd sandboxing
directives with the complete lifecycle and recovery suites.

For the optional broker socket and signed work orders, see
[control-plane.md](control-plane.md). Keep artifact keys, work-order keys, and
S3 credentials out of the unit file.

## Run in Kubernetes

Run the container as UID 0 with `privileged: false`. The worker needs a bounded
set of kernel capabilities because it creates mount and network namespaces,
bridges, veth pairs, routes, nftables rules, and filesystem mounts. The
following reduced set passes the lifecycle and writable-root snapshot suites:

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

This is a validated deployment set, not a claim that every capability is
required by every configuration. `SYS_ADMIN` is required for namespaces and
mounts, `NET_ADMIN` for worker networking, and `NET_RAW` by the current runsc
network setup. `MKNOD` is needed when writable-root snapshot restore recreates
OCI whiteouts and may be omitted when that feature is disabled.

The pod also needs narrowly scoped access to:

- a writable cgroup v2 subtree with the `cpu`, `memory`, and `pids`
  controllers delegated at `/sys/fs/cgroup/runtrue-sandboxd`;
- containerd's Unix socket and the snapshotter paths returned by `ctr`, or a
  containerd instance inside the same pod or microVM;
- persistent worker state and image storage; and
- loop-control and allocated loop devices when writable roots or local named
  volumes are enabled.

Allow the required namespace, mount, networking, and runsc syscalls in the
pod's seccomp, AppArmor, or SELinux policy. Do not mount the complete host
cgroup tree or all host devices when a delegated subtree and selected devices
are sufficient.

The worker uses runsc's systrap platform, so it does not need `/dev/kvm`.
A microVM-backed Kubernetes runtime can provide the outer worker boundary while
gVisor continues to isolate workloads inside that VM. Validate the final pod
policy with both example suites because device and mandatory-access-control
behavior varies by Kubernetes runtime.

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
