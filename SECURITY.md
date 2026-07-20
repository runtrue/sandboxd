# Security policy

## Project status

`sandboxd` is experimental security software. There are no supported stable
releases. The `main` branch is the only maintained source state.

Do not expose either daemon socket to tenant clients or use the repository as a
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
operator Unix socket, trusted local toolchain, and untrusted guest code inside
gVisor. An optional workload socket accepts one configured broker UID and
requires a signed, short-lived, operation-bound work order. Tenant clients
authenticate to a separate control-plane service and never connect directly to
the daemon. Guest inputs include topology values, OCI image contents,
arguments, environment variables, filesystem activity, network traffic inside
the sandbox, and checkpoint-time process state.

The worker verifies local peer credentials, work-order integrity and expiry,
durable nonce replay state, resource ceilings, tenant/workspace ownership, and
assignment epochs. Tenant-visible state is scoped before lookup. The signer and
configured broker are trusted; this repository does not implement their
tenant-facing identity or policy layer. Local Docker Engine and GNU tar
participate in image preparation and belong to the trusted operator boundary.

The implemented snapshot portability is `same_worker`. Writable OCI layers,
bind mounts, external volumes, artifact import, transferable snapshot fencing,
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
