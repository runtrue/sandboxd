# Security policy

## Status

`sandboxd` is experimental security software. There are no supported stable
releases, and `main` is the only maintained source state.

Do not expose the daemon sockets to tenant clients or describe the project as a
complete multi-tenant security boundary before an independent review.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/runtrue/sandboxd/security/advisories/new).
Do not open a public issue containing exploit details, tenant data, credentials,
or a working escape technique.

Include:

- the sandboxd commit and runsc version;
- host kernel, architecture, and cgroup configuration;
- the smallest reproducing topology or artifact;
- the boundary that was crossed;
- remaining host resources after cleanup; and
- whether the issue reproduces after a clean worker restart.

## Supported boundary

The trusted boundary includes the worker operator, root-owned daemon,
configuration and signing services, local broker, containerd, runsc, host
isolation tools, state and artifact stores, and artifact master key.

Untrusted input includes topology documents, OCI images, guest arguments and
environment, workload requests, network traffic, filesystem activity, and
checkpoint-time guest state.

The operator socket accepts UID 0 only. The optional workload socket accepts one
configured non-root broker UID and requires a short-lived signed work order.
Tenant clients authenticate to an external identity and policy service; they do
not connect directly to the worker.

The worker enforces:

- gVisor isolation plus host namespaces and cgroup v2 containment;
- digest-pinned image admission and bounded archive extraction;
- default-deny networking with signed sandbox-wide policy;
- tenant and workspace scoping before state lookup;
- signed resource ceilings, durable replay protection, and assignment fencing;
- quota-backed writable roots and named volumes without tenant-supplied host
  paths; and
- encrypted, authenticated snapshot objects with conditional publication and
  restore-time compatibility checks.

See [docs/architecture.md](docs/architecture.md) for the detailed design and
[docs/control-plane.md](docs/control-plane.md) for the authorization contract.

## Operator responsibilities

- Protect the operator socket, signer, broker, work-order key, and artifact key.
- Restrict OCI registry credentials and S3 principals to their required scope.
- Keep the validated kernel, runsc, containerd, and host-tool cohort patched.
- Retain and rotate `audit.jsonl`; the daemon bounds records but does not manage
  long-term retention.
- Treat ingress credentials and credential files as secrets.
- Review `restricted_tcp` policy independently of tenant input.

The local artifact provider supports same-worker restore only. Cross-worker
restore requires the S3-compatible provider, shared backend configuration, and
compatible workers. Neither provider replaces distributed placement or
ownership policy.

Unsupported input fails closed. Raw bind mounts, arbitrary CSI plugins,
privileged containers, tenant-selected capabilities, host namespaces,
cross-backend restore, and artifact-key rotation are outside the supported
boundary.

## Security checks

```bash
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo audit --deny warnings
cargo deny check advisories licenses bans sources
./tools/test-s3-artifacts.sh
sudo ./examples/python-compose/run-local.sh
sudo ./examples/python-compose/run-snapshot-local.sh
```
