# sandboxd

[![CI](https://github.com/runtrue/sandboxd/actions/workflows/ci.yml/badge.svg)](https://github.com/runtrue/sandboxd/actions/workflows/ci.yml)
[![K3s integration](https://github.com/runtrue/sandboxd/actions/workflows/k3s-integration.yml/badge.svg)](https://github.com/runtrue/sandboxd/actions/workflows/k3s-integration.yml)

`sandboxd` is a containerized Linux execution worker for running restricted OCI
workloads inside [gVisor](https://gvisor.dev/). The worker runs in a standard
Kubernetes pod with a scoped security context. A sandbox may contain multiple
containers, but it has one lifecycle, network stack, resource boundary, and
checkpoint.

> [!IMPORTANT]
> `sandboxd` is currently in alpha. Production deployments should integrate it
> with a trusted control plane and follow [SECURITY.md](SECURITY.md).

## What it provides

- Restricted Docker Compose admission with digest-pinned OCI images.
- One gVisor Sentry per sandbox, with sandbox-wide pause, resume, and stop.
- Read-only image roots by default; opt-in quota-backed writable roots.
- Ephemeral, persistent, artifact, and secret volume types.
- Default-deny networking with explicit DNS, egress, and ingress policies.
- Host containment through cgroup v2, namespaces, nftables, and bounded output.
- Signed local work orders, replay protection, ownership checks, and audit logs.
- Encrypted live and stop-and-move snapshots, stored locally or in S3-compatible
  storage.

The operator socket is root-only. An optional workload socket accepts one local
broker UID and requires a short-lived signed work order for every request.
Tenant identity and policy integrate through the signed broker interface.

## Requirements

The worker container targets Linux x86-64. Its runtime environment provides
cgroup v2 with the `cpu`, `memory`, and `pids` controllers, plus outbound HTTPS
access for OCI image preparation. The worker image contains:

- gVisor `runsc` using systrap (tested with 20260714.0);
- containerd 2.x with the overlayfs snapshotter and `ctr` (tested with 2.2.2);
  and
- iproute2, nftables, util-linux, and e2fsprogs.

Building from source uses Rust 1.97.1. Directory-backed writable roots require
no block device or host mount. The legacy local named-volume provider still
requires explicitly assigned loop devices.

The worker process and its private containerd run in the same container and
mount namespace. They do not use the Kubernetes node's containerd socket,
snapshotter storage, or other runtime paths. The container runs as UID 0 with a
bounded capability set; it does not require `privileged: true`. See
[Installation and operation](docs/install.md#run-the-worker-container).

The listed runtime versions are a known-good reference rather than global pins.
Qualify other versions with the lifecycle and snapshot integration suites in
the target environment. Snapshot restore requires source and destination
workers to report the same `runsc` version and runtime configuration.

## Kubernetes deployment

Production-oriented k3s manifests are provided for fixed-rootfs,
private-containerd, and host-integrated feature levels. The fixed-rootfs
profile is the recommended minimum-authority starting point; the complete
capability and feature contract is documented in
[`deploy/k3s/SECURITY-PROFILES.md`](deploy/k3s/SECURITY-PROFILES.md).

## Get started

Build with the pinned toolchain and locked dependency graph:

```bash
git clone https://github.com/runtrue/sandboxd.git
cd sandboxd
cargo build --workspace --release --locked
```

Run the lifecycle and snapshot integration fixtures on a compatible test
worker:

```bash
sudo ./examples/python-compose/run-local.sh
sudo ./examples/python-compose/run-snapshot-local.sh
```

For container configuration, S3 storage, and artifact maintenance,
see [Installation and operation](docs/install.md).

## Documentation

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Isolation, admission, networking, storage, lifecycle, and snapshots |
| [Control plane](docs/control-plane.md) | Broker boundary, protocol, work orders, ownership, and recovery |
| [Installation and operation](docs/install.md) | Worker container, Kubernetes, S3, and maintenance |
| [Performance](docs/performance.md) | Pull-request benchmarks and local measurements |
| [Release process](docs/releasing.md) | Public release gates and signed tags |
| [Security policy](SECURITY.md) | Supported boundary and vulnerability reporting |
| [Contributing](CONTRIBUTING.md) | Development checks and design rules |

## Supported scope

- The validated platform is Linux x86-64. Additional runtime versions can be
  qualified with the integration suites.
- The worker is self-contained and does not mount the Kubernetes node's
  containerd socket or snapshotter storage.
- A sandbox uses one shared network and port namespace.
- Host CPU and memory limits apply to the complete sandbox.
- Local artifact storage supports same-worker restore; S3-compatible storage
  supports cross-worker restore within a compatible backend cohort.
- The admission model excludes raw host bind mounts, arbitrary runtime
  annotations, privileged containers, host namespaces, and ambient
  capabilities.
- Registry trust, credentials, signing, audit retention, and artifact-key
  management integrate with operator-controlled services.

## License

Licensed under the [Apache License 2.0](LICENSE).
