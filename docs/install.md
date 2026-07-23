# Installation and service operation

## Status

The published binaries are an experimental x86-64 Linux alpha for the validated
host cohort in the project README. They are not a stable support commitment.
The daemon is a privileged worker and must not be exposed directly to tenants.

## Install a release archive

Download the archive and `SHA256SUMS` from the matching GitHub release, then
verify and install it:

```bash
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf sandboxd-v0.1.0-alpha.1-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 \
  sandboxd-v0.1.0-alpha.1-x86_64-unknown-linux-gnu/runtrue-sandboxd \
  sandboxd-v0.1.0-alpha.1-x86_64-unknown-linux-gnu/runtrue-sandboxctl \
  /usr/local/bin/
```

Install the exact `runsc`, containerd, and host dependencies listed in the
README before starting the daemon. The release archive does not bundle those
trusted host components.

## Build from source

Use the pinned Rust toolchain and the locked dependency graph:

```bash
git clone https://github.com/runtrue/sandboxd.git
cd sandboxd
cargo build --workspace --release --locked
sudo install -m 0755 \
  target/release/runtrue-sandboxd \
  target/release/runtrue-sandboxctl \
  /usr/local/bin/
```

Run the local validation commands in the README before operating that build.

## Example systemd service

The following unit exposes only the root-owned operator socket and uses the
daemon defaults. It deliberately does not enable the optional workload socket
or broader guest profiles:

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

Save it as `/etc/systemd/system/runtrue-sandboxd.service`, then validate the
host and start the service:

```bash
sudo systemd-analyze verify /etc/systemd/system/runtrue-sandboxd.service
sudo systemctl daemon-reload
sudo systemctl enable --now runtrue-sandboxd.service
sudo runtrue-sandboxd ping
```

The worker must run as root because it manages cgroups, network namespaces,
nftables, loop devices, ext4 mounts, containerd content, and gVisor processes.
Do not add generic systemd sandboxing directives without testing the complete
lifecycle and recovery suites; many otherwise useful restrictions would block
those required host operations.

For S3-backed artifacts, guest-profile enablement, or a local broker socket,
create an owner-only environment/configuration strategy appropriate to the
operator and add the documented command-line flags explicitly. Never put
artifact master keys, work-order keys, or S3 credentials directly in the unit
file.
