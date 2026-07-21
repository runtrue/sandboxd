# Security policy

## Project status

`sandboxd` is experimental security software. There are no supported stable
releases. The `main` branch is the only maintained source state.

Do not expose either daemon socket to tenant clients or treat the repository as
a complete multi-tenant security boundary without an independent review.

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
tenant-facing identity or policy layer. The local containerd daemon,
snapshotter, and `ctr` client participate in image preparation and belong to
the trusted operator boundary. The loop driver, ext4 implementation, overlayfs,
`losetup`, `fsfreeze`, `mkfs.ext4`, and the local volume provider join that
trusted host boundary when writable roots or named volumes are enabled. OCI
registries and their transport remain outside the worker
boundary, so every admitted descriptor and blob is verified against the locked
digest and size.

Snapshot objects are tenant/workspace-scoped, content-addressed, encrypted with
tenant-derived envelope keys, and published before their immutable manifest
reference. Stop-and-move records a durable local fence before checkpointing,
publishes a transfer grant only after source cleanup, and binds a destination
claim to one worker and a newer assignment epoch. The current local provider
still supports one worker only, so these records do not establish a distributed
lease. The artifact master key remains an operator-managed secret.

Writable roots are private, quota-backed overlays created only from
provider-issued identities. Named-volume keys bind tenant, workspace, and
volume ID; customer input contains only the guest destination and never a host
path, loop device, mount option, or provider handle. Attachment ownership is
written durably before guest mounting, and startup recovery clears stale
attachments, removes ephemeral and secret state, and retains unattached
persistent data. Read-only artifacts are verified against their digest from the
provider-owned artifact root. Secret source files must be owner-only regular
files, are copied into a dedicated tmpfs, and neither their bytes nor source
paths enter topology locks or snapshot manifests.

Portable named-volume snapshots freeze the ext4 filesystem and publish the raw
quota image as a typed encrypted artifact. A manifest declares the volume
provider and portability; a nonportable or explicitly excluded named volume
causes snapshot rejection. Writable-root snapshots currently reject hard links
and non-overlay extended attributes. Raw bind mounts, arbitrary CSI plugins,
key rotation, a remote conditional artifact provider, and cross-backend restore
remain outside the supported boundary. An artifact being portable does not by
itself prove that a distributed control plane transferred ownership safely.

## Security-relevant local checks

```bash
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo audit
cargo deny check advisories licenses bans sources
sudo ./examples/python-compose/run-local.sh
sudo ./examples/python-compose/run-snapshot-local.sh
```
