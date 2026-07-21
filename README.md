# sandboxd

[![CI](https://github.com/runtrue/sandboxd/actions/workflows/ci.yml/badge.svg)](https://github.com/runtrue/sandboxd/actions/workflows/ci.yml)

`sandboxd` is an experimental local OCI sandbox worker. It runs restricted
multi-container topologies inside gVisor, treats the complete sandbox as the
lifecycle boundary, and supports sandbox-scoped pause, resume, snapshot, and
restore.

> **Security status:** the daemon is a privileged local worker. Its operator
> socket is root-only. An optional workload socket accepts one configured local
> broker UID and requires a short-lived signed work order for every request;
> tenant clients do not connect to either socket. The control path has not
> completed an independent adversarial review. See [SECURITY.md](SECURITY.md).

## Capabilities

- restricted Docker Compose compilation into an immutable topology lock;
- digest-pinned OCI image admission with immutable shared image roots;
- opt-in, quota-backed writable OCI roots with portable snapshot deltas;
- one gVisor Sentry containing a root sandbox and child containers;
- private sandbox networking with service-name resolution;
- create, inspect, logs, pause, resume, stop, and crash recovery;
- cgroup-backed host resource containment and bounded output capture;
- tenant/workspace-scoped ownership with durable assignment fencing;
- bounded local control transport with peer credentials, signed work orders,
  replay protection, and structured audit records;
- live and stop-and-move gVisor checkpoints;
- tenant-scoped, encrypted, content-addressed snapshot artifacts with fenced
  transfer grants and one-winner destination claims; and
- local restore under a new sandbox identity.

The daemon derives snapshot portability from the configured artifact provider;
the current local provider reports `same_worker`. The backend-neutral contracts
reserve stable identities for both `gvisor` and `marcovm`; this repository
contains a gVisor executor only.

## Execution model

A sandbox is the unit of placement and isolation. Its containers share one
gVisor Sentry, one network stack, and one checkpoint boundary. Service names
resolve over the shared loopback interface, so containers also share one port
namespace. Two services cannot bind the same address and port.

OCI roots are read-only by default. An explicit Compose `read_only: false`
request gives that service a private ext4-backed overlay with a hard block
quota; immutable image layers remain shared and read-only. Each container also
receives writable `/tmp` and `/work` tmpfs mounts. A snapshot captures guest
processes, memory, internal sockets, tmpfs contents, and an OCI-compatible diff
for each writable root. Restore requires an exact topology, writable-root
policy, runsc version, runtime configuration, CPU feature, architecture, and
operating-system match.

Host cgroups contain the Sentry, gofers, and runsc processes. Because guest work
is executed by a shared Sentry, the host accounting boundary is the
complete sandbox; policy fields named per-service must not be interpreted as
independent guest CPU or memory guarantees.

## Explicit limitations

- the tenant-facing identity, policy, and work-order signing service is not part
  of this worker; the optional local broker boundary supports one configured UID
  and one active HMAC key;
- the local artifact provider restricts snapshot restore to the same worker;
- bind mounts and external volumes are unsupported;
- writable-root snapshots reject hard links and non-overlay extended
  attributes until those representations have a portable contract;
- outbound networking and external DNS are disabled;
- Compose port publishing, privileged containers, ambient capabilities, and
  host namespace access are rejected;
- OCI registry trust, availability, and credential distribution remain operator
  responsibilities; and
- only the pinned x86-64 Linux cohort described below is exercised regularly.

## Workspace

- `runtrue-sandboxd` owns worker state and exposes a bounded, versioned protocol
  over a Unix socket.
- `runtrue-sandboxctl` compiles restricted Compose files, prepares OCI images,
  and provides local diagnostics.
- `sandbox-core` contains backend-neutral identities, lifecycle states,
  capability records, and snapshot contracts.
- `sandbox-runtime` defines backend and live-instance interfaces.
- `sandbox-artifact` owns encrypted content-addressed publication, verified
  materialization, references, garbage collection, and the local storage
  provider.
- `sandbox-oci` owns Compose validation, topology locks, the backend-neutral
  image-provider contract, and the containerd provider.
- `sandbox-gvisor` owns runsc execution, OCI bundles, host resources, portable
  snapshot mapping, recovery, and cleanup.

Detailed documentation covers [architecture and isolation](docs/architecture.md),
[authenticated control](docs/control-plane.md), and
[performance feedback](docs/performance.md).

## Validated host cohort

- Linux x86-64 with cgroup v2 and the `cpu`, `memory`, and `pids` controllers;
- Rust 1.94;
- gVisor `runsc` release `20260714.0` using the systrap platform;
- containerd 2.2.2 with the overlayfs snapshotter and `ctr` client;
- util-linux `losetup`, e2fsprogs `mkfs.ext4`, and available loop devices;
- iproute2; and
- outbound HTTPS access to the OCI registries used during preparation.

The worker requires root for cgroup and network namespace management.

## Run locally

Run the networking, lifecycle, and resource-limit scenario:

```bash
sudo ./examples/python-compose/run-local.sh
```

Run live snapshot, live-copy restore, stop-and-move restore, connection
continuity, quota-backed writable-root continuity, pause/resume, and cleanup
checks:

```bash
sudo ./examples/python-compose/run-snapshot-local.sh
```

The scripts build the Rust binaries locally and resolve the official Python
image directly through the OCI provider. They do not require Docker Engine,
GNU tar, hosted workers, or a project-specific artifact registry.

## Local validation

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo audit
cargo deny check advisories licenses bans sources
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools/performance/tests
shellcheck tools/performance/run-control-plane.sh
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for the local development workflow. Send
security-sensitive reports through GitHub's private vulnerability reporting;
do not open a public issue containing exploit details.

## License

Licensed under the [Apache License 2.0](LICENSE).
