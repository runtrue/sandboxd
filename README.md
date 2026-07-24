# sandboxd

[![CI](https://github.com/runtrue/sandboxd/actions/workflows/ci.yml/badge.svg)](https://github.com/runtrue/sandboxd/actions/workflows/ci.yml)

`sandboxd` is a Linux execution worker for running restricted OCI workloads
inside [gVisor](https://gvisor.dev/). It can run directly on a worker host or in
a capability-scoped Kubernetes pod, including on a microVM-backed node. A
sandbox may contain multiple containers, but it has one lifecycle, network
stack, resource boundary, and checkpoint.

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

The validated worker environment is Linux x86-64 with:

- cgroup v2 with the `cpu`, `memory`, and `pids` controllers;
- Rust 1.97.1;
- gVisor `runsc` using systrap (tested with 20260714.0);
- containerd 2.x with the overlayfs snapshotter and `ctr` (tested with 2.2.2);
- iproute2, nftables, util-linux, e2fsprogs, and available loop devices; and
- outbound HTTPS access for OCI image preparation.

The worker process runs as UID 0 because it manages isolation and runtime
resources. A Kubernetes deployment does not require `privileged: true`; grant
only the capabilities, devices, mounts, and cgroup delegation described in
[Installation and operation](docs/install.md#run-in-kubernetes). Install the
runtime dependencies separately from the release archive. The listed versions
are a known-good reference rather than global pins. Qualify other versions with
the lifecycle and snapshot integration suites in the target environment.
Snapshot restore requires source and destination workers to report the same
`runsc` version and runtime configuration.

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

For installation, systemd configuration, S3 storage, and artifact maintenance,
see [Installation and operation](docs/install.md).

## Documentation

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Isolation, admission, networking, storage, lifecycle, and snapshots |
| [Control plane](docs/control-plane.md) | Broker boundary, protocol, work orders, ownership, and recovery |
| [Installation and operation](docs/install.md) | Binaries, host or Kubernetes setup, S3, and maintenance |
| [Performance](docs/performance.md) | Pull-request benchmarks and local measurements |
| [Release process](docs/releasing.md) | Public release gates and signed tags |
| [Security policy](SECURITY.md) | Supported boundary and vulnerability reporting |
| [Contributing](CONTRIBUTING.md) | Development checks and design rules |

## Supported scope

- The validated platform is Linux x86-64. Additional runtime versions can be
  qualified with the integration suites.
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
