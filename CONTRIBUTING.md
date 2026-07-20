# Contributing

## Development environment

Use the pinned Rust toolchain from `rust-toolchain.toml`. Runtime integration
checks require Linux x86-64, cgroup v2, root access, iproute2, Docker Engine,
GNU tar, and the runsc release listed in the README.

Keep backend-neutral contracts in `sandbox-core` and `sandbox-runtime`. OCI
topology and image handling belongs in `sandbox-oci`. gVisor-specific execution,
host resources, checkpoint state, and cleanup belongs in `sandbox-gvisor`.

## Local checks

Run these commands before submitting a change:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo audit
cargo deny check advisories licenses bans sources
bash -n examples/python-compose/build-local.sh
bash -n examples/python-compose/run-local.sh
bash -n examples/python-compose/run-snapshot-local.sh
```

Changes to lifecycle, networking, resource limits, snapshots, recovery, or
cleanup should also run both root-required example scripts on a clean worker.

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
