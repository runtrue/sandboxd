# sandboxd

[![CI](https://github.com/runtrue/sandboxd/actions/workflows/ci.yml/badge.svg)](https://github.com/runtrue/sandboxd/actions/workflows/ci.yml)

`sandboxd` is a privileged Linux worker for running restricted OCI workloads
inside [gVisor](https://gvisor.dev/). A sandbox may contain multiple containers,
but it has one lifecycle, network stack, resource boundary, and checkpoint.

> [!WARNING]
> `sandboxd` is experimental security software. It is not a tenant-facing API
> or a complete multi-tenant control plane. The project has not completed an
> independent security review. Read [SECURITY.md](SECURITY.md) before use.

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
Tenant identity and policy services are outside this repository.

## Requirements

The validated host is Linux x86-64 with:

- cgroup v2 with the `cpu`, `memory`, and `pids` controllers;
- Rust 1.97.1;
- gVisor `runsc` using systrap (tested with 20260714.0);
- containerd 2.x with the overlayfs snapshotter and `ctr` (tested with 2.2.2);
- iproute2, nftables, util-linux, e2fsprogs, and available loop devices; and
- outbound HTTPS access for OCI image preparation.

The worker runs as root because it manages host isolation and runtime
resources. Release archives do not bundle these host dependencies. The listed
runtime versions are a known-good reference, not global pins. Other versions
must pass the privileged lifecycle and snapshot suites on the target host.
Snapshot restore additionally requires source and destination workers to report
the same `runsc` version and runtime configuration.

## Get started

Build with the pinned toolchain and locked dependency graph:

```bash
git clone https://github.com/runtrue/sandboxd.git
cd sandboxd
cargo build --workspace --release --locked
```

Run the privileged lifecycle and snapshot fixtures on a compatible test worker:

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
| [Installation and operation](docs/install.md) | Binaries, host setup, systemd, S3, and maintenance |
| [Performance](docs/performance.md) | Pull-request benchmarks and local measurements |
| [Release process](docs/releasing.md) | Public release gates and signed tags |
| [Security policy](SECURITY.md) | Supported boundary and vulnerability reporting |
| [Contributing](CONTRIBUTING.md) | Development checks and design rules |

## Current limitations

- Only Linux x86-64 is regularly tested. Runtime versions outside the reference
  cohort require operator validation.
- Containers in a sandbox share one network and port namespace.
- Host CPU and memory accounting applies to the complete sandbox, not
  independently to each guest container.
- The local artifact provider restores on the same worker only. Cross-worker
  restore requires the S3-compatible provider and a shared backend cohort.
- Raw host bind mounts, arbitrary runtime annotations, privileged containers,
  host namespaces, and ambient capabilities are rejected.
- The operator remains responsible for OCI registry trust, credentials, signing
  services, audit retention, and artifact keys.

## License

Licensed under the [Apache License 2.0](LICENSE).
