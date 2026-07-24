# Security

`sandboxd` is designed as a hardened execution worker for untrusted OCI
workloads. It combines gVisor isolation with host namespaces, cgroup v2,
default-deny networking, signed workload authorization, and encrypted snapshot
storage.

The current release channel is alpha. Security fixes are maintained on `main`.

## Deployment model

Run `sandboxd` in a dedicated Linux worker environment behind a trusted control
plane. The worker may run as a host service or a capability-scoped Kubernetes
pod, including on a microVM-backed node. Tenant clients authenticate to the
surrounding identity and policy service, which issues narrowly scoped work
orders through a local broker.

The operator socket accepts UID 0 only. The optional workload socket accepts one
configured non-root broker UID and requires a short-lived signed work order for
every request.

The trusted computing base includes:

- the worker operator and host kernel;
- `sandboxd`, its configuration, signer, and local broker;
- containerd, runsc, and the required host isolation tools;
- the worker state and artifact stores; and
- work-order and artifact master keys.

Topology documents, OCI images, guest arguments and environment, workload
requests, guest network traffic, filesystem activity, and checkpoint-time
process state are treated as untrusted.

## Enforced controls

The worker enforces:

- one gVisor isolation boundary per sandbox;
- host namespace and cgroup v2 containment;
- digest-pinned image admission with bounded archive extraction;
- read-only image roots unless a quota-backed writable root is authorized;
- typed volumes without tenant-supplied host paths;
- default-deny networking with signed DNS, egress, and ingress policy;
- tenant and workspace scoping before state lookup;
- signed resource ceilings and operation digests;
- durable replay protection and assignment fencing;
- bounded subprocess, transport, output, and cleanup operations; and
- encrypted, authenticated snapshots with conditional publication and
  restore-time compatibility checks.

Unsupported topology and runtime input is rejected rather than silently
downgraded.

See [docs/architecture.md](docs/architecture.md) for the detailed isolation
design and [docs/control-plane.md](docs/control-plane.md) for the authorization
contract.

## Operational requirements

- Protect the operator socket, signer, broker, work-order key, and artifact key.
- Restrict OCI registry credentials and S3 principals to the required tenant,
  bucket, and prefix scope.
- Keep the kernel, runsc, containerd, and worker tools patched and validate
  runtime updates with the worker integration suites.
- For Kubernetes, keep `privileged: false` and grant only the capabilities,
  delegated cgroup subtree, runtime paths, and optional devices required by the
  enabled features.
- Retain and rotate `audit.jsonl` according to the deployment's audit policy.
- Keep ingress credentials and credential files out of logs and tenant-visible
  state.
- Issue `restricted_tcp` policy only after an independent authorization
  decision.

The local artifact provider supports same-worker restore. Cross-worker restore
uses the S3-compatible provider with shared backend configuration, compatible
workers, and matching runsc versions and runtime configuration.

Tenant-facing identity, placement, and policy remain responsibilities of the
surrounding control plane. Raw bind mounts, arbitrary CSI plugins, privileged
containers, tenant-selected capabilities, host namespaces, cross-backend
restore, and artifact-key rotation are not enabled by this release.

## Security validation

Every pull request runs Rust tests, dependency policy checks, CodeQL analysis,
and a reproducible release build. The release process adds S3 conformance and
gVisor lifecycle and snapshot runs on the validated worker cohort.

Run the local security checks with:

```bash
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo audit --deny warnings
cargo deny check advisories licenses bans sources
./tools/test-s3-artifacts.sh
sudo ./examples/python-compose/run-local.sh
sudo ./examples/python-compose/run-snapshot-local.sh
```

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
