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
- digest-pinned OCI image admission and verified read-only root filesystems;
- one gVisor Sentry containing a root sandbox and child containers;
- private sandbox networking with service-name resolution;
- create, inspect, logs, pause, resume, stop, and crash recovery;
- cgroup-backed host resource containment and bounded output capture;
- tenant/workspace-scoped ownership with durable assignment fencing;
- bounded local control transport with peer credentials, signed work orders,
  replay protection, and structured audit records;
- live and stop-and-move gVisor checkpoints;
- immutable local snapshot publication with SHA-256 verification; and
- same-worker restore under a new sandbox identity.

The daemon reports only installed backend implementations. The backend-neutral
contracts reserve stable identities for both `gvisor` and `marcovm`; this
repository contains a gVisor executor only.

## Execution model

A sandbox is the unit of placement and isolation. Its containers share one
gVisor Sentry, one network stack, and one checkpoint boundary. Service names
resolve over the shared loopback interface, so containers also share one port
namespace. Two services cannot bind the same address and port.

OCI roots are read-only. Each container receives writable `/tmp` and `/work`
tmpfs mounts. The local snapshot captures guest processes, memory, internal
sockets, and tmpfs contents. Restore requires an exact topology, runsc version,
runtime configuration, CPU feature, architecture, and operating-system match.

Host cgroups contain the Sentry, gofers, and runsc processes. Because guest work
is executed by a shared Sentry, the host accounting boundary is the
complete sandbox; policy fields named per-service must not be interpreted as
independent guest CPU or memory guarantees.

## Explicit limitations

- the tenant-facing identity, policy, and work-order signing service is not part
  of this worker; the optional local broker boundary supports one configured UID
  and one active HMAC key;
- snapshots are stored on the same worker and are not transferable artifacts;
- writable OCI layers, bind mounts, and external volumes are unsupported;
- outbound networking and external DNS are disabled;
- Compose port publishing, privileged containers, ambient capabilities, and
  host namespace access are rejected;
- image preparation uses local Docker Engine and GNU tar tooling; and
- only the pinned x86-64 Linux cohort described below is exercised regularly.

## Workspace

- `runtrue-sandboxd` owns worker state and exposes a bounded, versioned protocol
  over a Unix socket.
- `runtrue-sandboxctl` compiles restricted Compose files, prepares OCI images,
  and provides local diagnostics.
- `sandbox-core` contains backend-neutral identities, lifecycle states,
  capability records, and snapshot contracts.
- `sandbox-runtime` defines backend and live-instance interfaces.
- `sandbox-oci` owns Compose validation, topology locks, and image preparation.
- `sandbox-gvisor` owns runsc execution, OCI bundles, host resources, local
  snapshots, recovery, and cleanup.

See [docs/architecture.md](docs/architecture.md) for the ownership and isolation
model and [docs/control-plane.md](docs/control-plane.md) for the authenticated
control contract.

## Validated host cohort

- Linux x86-64 with cgroup v2 and the `cpu`, `memory`, and `pids` controllers;
- Rust 1.94;
- gVisor `runsc` release `20260714.0` using the systrap platform;
- iproute2; and
- Docker Engine plus GNU tar for local image preparation.

The worker requires root for cgroup and network namespace management.

## Run locally

Build the pinned example image:

```bash
./examples/python-compose/build-local.sh
```

Run the networking, lifecycle, and resource-limit scenario:

```bash
sudo ./examples/python-compose/run-local.sh
```

Run live snapshot, live-copy restore, stop-and-move restore, connection
continuity, tmpfs continuity, pause/resume, and cleanup checks:

```bash
sudo ./examples/python-compose/run-snapshot-local.sh
```

The scripts build the Rust binaries locally and do not use hosted workers or an
artifact registry.

## Local validation

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo audit
cargo deny check advisories licenses bans sources
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for the local development workflow. Send
security-sensitive reports through GitHub's private vulnerability reporting;
do not open a public issue containing exploit details.

## License

Licensed under the [Apache License 2.0](LICENSE).
