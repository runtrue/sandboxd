# Contributing

## Development environment

Use the pinned Rust toolchain from `rust-toolchain.toml`. Runtime integration
checks require Linux x86-64, cgroup v2, root access, iproute2, containerd with
the overlayfs snapshotter, the `ctr` client, and the runsc release listed in the
README.

Keep backend-neutral contracts in `sandbox-core` and `sandbox-runtime`. OCI
topology and image handling belong in `sandbox-oci`. gVisor-specific execution,
host resources, checkpoint state, and cleanup belong in `sandbox-gvisor`.

Repository ownership:

| Path | Responsibility |
| --- | --- |
| `bins/sandboxctl` | Restricted Compose and image tooling |
| `bins/sandboxd` | Privileged worker and local client |
| `crates/sandbox-core` | Identities, capabilities, lifecycle, and snapshot types |
| `crates/sandbox-runtime` | Backend and live-instance interfaces |
| `crates/sandbox-artifact` | Encrypted artifacts, providers, references, and GC |
| `crates/sandbox-volume` | Local volumes, artifacts, secrets, and snapshots |
| `crates/sandbox-oci` | Compose validation and OCI providers |
| `crates/sandbox-gvisor` | gVisor execution, recovery, and cleanup |

## Local checks

Run these commands before submitting a change:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo audit
cargo deny check advisories licenses bans sources
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools/performance/tests
shellcheck tools/performance/run-control-plane.sh
git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
```

Changes to lifecycle, networking, resource limits, snapshots, recovery, or
cleanup should also run both root-required example scripts on a clean worker.

The `CI` workflow runs portable quality, dependency-policy, and same-run
reproducibility checks on GitHub-hosted workers. The manually dispatched
`gVisor integration` workflow runs only on a dedicated, ephemeral, root-owned
self-hosted worker labeled `sandboxd-gvisor`. Do not register a long-lived or
general-purpose privileged runner with this public repository. The privileged
workflow has no pull-request trigger.

Releases follow the additional gates in [docs/releasing.md](docs/releasing.md).
All project interactions must follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Change design

- Treat the complete sandbox as the lifecycle and checkpoint boundary.
- Do not serialize host paths, process IDs, sockets, namespace names, or runtime
  handles into portable contracts.
- Reject unsupported input rather than silently widening capabilities.
- Preserve hard deadlines around external processes and cleanup operations.
- Add a failure-path test for every new host resource.
- Keep capability responses limited to behavior implemented by the running
  daemon.

Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md).
