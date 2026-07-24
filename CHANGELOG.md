# Changelog

All notable changes to sandboxd will be recorded here. The project uses
[Semantic Versioning](https://semver.org/) for release identifiers. During
alpha, interfaces may evolve between `0.x` releases.

## Unreleased

## 0.1.0-alpha.1

Initial public alpha of the local OCI sandbox worker:

- restricted multi-container topology compilation and digest-pinned OCI image
  admission;
- gVisor lifecycle management, crash recovery, pause, resume, checkpoint, and
  restore;
- tenant/workspace ownership, assignment fencing, signed local work orders, and
  bounded control transport;
- default-deny networking with reviewed DNS, egress, and ingress profiles;
- quota-backed writable roots and tenant-scoped named, artifact, and secret
  volumes;
- encrypted content-addressed snapshot artifacts with local and S3-compatible
  providers; and
- portable live-copy and stop-and-move snapshot workflows for compatible
  workers.

This release is intended for deployment as a worker behind a trusted identity,
policy, and placement control plane.
