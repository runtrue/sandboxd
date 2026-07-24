# Installation and operation

`sandboxd` is an experimental privileged worker. Install it only on a dedicated
Linux host that matches the [validated cohort](../README.md#requirements). Do
not expose either Unix socket directly to tenant clients.

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

Install the exact `runsc`, containerd, and host dependencies listed in the
README. They are not included in the release archive.

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

The worker requires root to manage cgroups, namespaces, nftables, loop devices,
ext4 mounts, containerd, and gVisor. Test the complete lifecycle and recovery
suites before adding systemd sandboxing directives.

For the optional broker socket and signed work orders, see
[control-plane.md](control-plane.md). Keep artifact keys, work-order keys, and
S3 credentials out of the unit file.

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
