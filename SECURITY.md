# Security policy

## Project status

`sandboxd` is experimental security software. There are no supported stable
releases. The `main` branch is the only maintained source state.

Do not expose the daemon socket to untrusted users or use the repository as a
completed multi-tenant security boundary without an independent review.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for security-sensitive reports. Do
not open a public issue containing exploit details, tenant data, credentials,
or a working escape technique.

A useful report includes:

- the commit and runsc versions;
- host kernel, architecture, and cgroup configuration;
- the smallest reproducing topology or artifact;
- the security boundary that was crossed;
- observed cleanup and host-resource state; and
- whether the behavior reproduces after a clean worker restart.

## Security model

The supported model has a trusted worker operator, root-owned daemon, root-only
Unix socket, trusted local toolchain, and untrusted guest code inside gVisor.
Guest inputs include topology values, OCI image contents, arguments,
environment variables, filesystem activity, network traffic inside the
sandbox, and checkpoint-time process state.

The daemon does not authenticate tenants. Access to its socket grants control
over the worker API. Local Docker Engine and GNU tar participate in image
preparation and belong to the trusted operator boundary.

The implemented snapshot portability is `same_worker`. Writable OCI layers,
bind mounts, external volumes, artifact import, worker assignment fencing,
cross-worker restore, and cross-backend restore are outside the supported
boundary.

## Security-relevant local checks

```bash
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo audit
cargo deny check advisories licenses bans sources
sudo ./examples/python-compose/run-local.sh
sudo ./examples/python-compose/run-snapshot-local.sh
```
