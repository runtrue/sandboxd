# Kubernetes security profiles and feature authority

This document is the deployment authority contract for sandboxd. It records
the minimum configuration observed for each feature and separates validated
behavior from required release work.

Validation environment on 2026-07-24:

- Ubuntu 26.04, Linux 7.0;
- k3s `v1.36.1+k3s1`;
- gVisor `release-20260714.0`; and
- a single local-only Kubernetes node.

## Recommended baseline

The fixed-runtime profile is the least-authority normal daemon configuration
that completed multi-container create:

- Kubernetes user namespace (`hostUsers: false`);
- `SETGID`, `SETUID`, `SYS_CHROOT`, and `SYS_ADMIN`, scoped to that user
  namespace;
- fixed, pre-expanded, read-only guest root bound to one verified OCI image
  identity from an operator-supplied lock;
- loopback gVisor networking;
- external cgroup mode, with Kubernetes enforcing aggregate pod limits;
- no host path, socket, device, namespace, port, Service, Ingress, or
  service-account token; and
- read-only worker image plus bounded writable `emptyDir` mounts.

It completed admission, create, separate server/client child processes in one
gVisor Sentry, dependency health checks, logs, inspect, pause/resume, and local
live snapshot/restore of a read-only topology.

## Authority ladder

| Level | Authority | Enabled features | Unavailable features | Required production work |
| --- | --- | --- | --- | --- |
| A. Rootless direct run | Non-root UID; all capabilities dropped; `allowPrivilegeEscalation: false` | One direct `runsc --rootless=true --network=none run` | Normal daemon create, save/restore, Netstack, managed cgroups | The node's AppArmor user-namespace restriction had to be disabled for this test. gVisor rootless documents the remaining runtime limits. This is not a viable full daemon profile. |
| B. Fixed runtime | User namespace plus `SETGID`, `SETUID`, `SYS_CHROOT`, `SYS_ADMIN` | Fixed read-only images, multi-container Sentry, loopback, lifecycle APIs, local read-only snapshot/restore | Dynamic images, ingress/egress, writable roots/volumes, managed cgroups | Signed rootfs attestation, custom AppArmor/seccomp, durable-state qualification, cleanup-race fix |
| B-N. Userspace policy network | Level B; no networking capability or host-network setting; `network-mode=userspace`; gVisor `network=none` and `host-uds=open` | Policy-approved HTTP CONNECT and declared reverse HTTP ingress over one read-only mounted Unix-socket directory; static unprivileged guest agent; current-lease gateway/broker adapter; connection, byte, bandwidth, and deadline ceilings | Raw TCP/UDP, guest DNS, transparent proxying, software without explicit HTTP proxy support, durable ingress after placement completion | Add a persistent service-assignment lifecycle and combined live-k3s adapter conformance, bake the released agent into each measured application image, restrict outer Pod egress with an FQDN-aware CNI or egress gateway, qualify custom MAC/seccomp profiles |
| B+ measured runtime | Level B plus `DAC_READ_SEARCH` | Recomputes full root digest, entry count, and byte count at admission | Same feature limits as B | Use only when runtime measurement is worth pod-wide read/search bypass authority |
| C. Dynamic runtime | One user-namespaced worker container with `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`, `SYS_ADMIN`, `SYS_CHROOT` and a private containerd process | Arbitrary pinned OCI pull, validation, unpack, and loopback execution | Kernel policy networking, current loop/ext4 storage, managed cgroups | Registry trust, credential delivery/rotation, image GC, egress policy, supervisor qualification, and a future safe privilege split |
| D. Kernel networking | Level B or C plus `NET_ADMIN`, `NET_RAW`; `network-mode=private`; namespaced `net.ipv4.ip_forward=1` | Bridge/veth network, nftables policy, policy proxies, HTTP/TCP egress, ingress plumbing | Still no current writable storage or managed cgroups | Kubelet unsafe-sysctl allowlist, pod sysctl, dedicated nodes, custom network security profiles |
| E. Brokered storage/cgroups | Trusted node brokers, CSI/device integration, or redesigned userspace providers | Quota-backed writable roots, named writable volumes, per-sandbox resources | Depends on broker implementation | Narrow authenticated APIs, tenant/path binding, transactional cleanup, quotas, recovery, dedicated threat model |
| F. Host integrated | Privileged pod, host containerd paths/socket, bidirectional mount propagation, host-backed state | Full current image, networking, loop/ext4 storage, and cgroup implementation | No meaningful worker/host kernel boundary | Dedicated tainted nodes or VMs, strict scheduling/admission, host hardening; compatibility profile only |

Dynamic images, networking, storage, cgroups, and durable state are independent
authority axes. Do not enable a higher level wholesale when only one axis is
needed.

## Linux capability contract

### Normal gVisor create path

| Capability | Feature requiring it | Failure when independently removed |
| --- | --- | --- |
| `SETGID` | Drop the gVisor sandbox process to the configured guest group | runsc could not switch the child group to `nobody` |
| `SETUID` | Drop the gVisor sandbox process to the configured guest user | runsc could not switch the child user to `nobody` |
| `SYS_CHROOT` | gVisor gofer filesystem isolation | gofer could not chroot to `/root` |
| `SYS_ADMIN` | User/mount namespace and gofer re-exec setup | gofer mount-namespace setup failed |

These capabilities are effective only in the Kubernetes-created user
namespace; they are not equivalent to the same capabilities in the initial
host user namespace. `SYS_ADMIN` remains high-risk because it exposes a broad
kernel namespace and mount surface. User namespaces reduce host-object access,
but they do not eliminate kernel exploit risk.

Putting the four capabilities only on the `runsc` file was tested and failed:
gVisor's internal gofer re-exec did not retain the required capability state.
A future split must use a dedicated launcher with a narrow authenticated
protocol rather than file capabilities.

### Image preparation

Private containerd extraction additionally required:

| Capability | Current purpose |
| --- | --- |
| `CHOWN` | Apply OCI layer ownership |
| `DAC_OVERRIDE` | Create and replace layer paths regardless of mode bits |
| `FOWNER` | Apply file metadata when the effective UID is not the owner |

The complete dynamic-image run passed with seven namespaced capabilities.
containerd 2.2 materializes image mounts in its own mount namespace. A
separate Kubernetes sidecar would require bidirectional mount propagation,
which Kubernetes permits only for privileged containers. The non-privileged
profile therefore keeps both processes in one container and sandboxd inherits
all seven capabilities. Splitting image preparation safely requires a
different provider/broker contract, not a sidecar-only manifest change.

### Kernel networking

| Capability or setting | Current purpose |
| --- | --- |
| `NET_ADMIN` | bridge, veth, addresses, routes, namespaces, nftables |
| `NET_RAW` | networking setup/runtime operations required by the tested path |
| namespaced `net.ipv4.ip_forward=1` | forward traffic between guest veth and policy gateway |

The six-capability fixed-image network profile reached forwarding setup but
the node rejected the unsafe sysctl. The fully privileged compatibility
profile passed HTTPS access through the policy network. Therefore Level D is
specified but not release-qualified under the no-host-change constraint.

### Userspace policy networking

The B-N profile keeps runsc at `--network=none`, so the guest has loopback but
no route or DNS server. sandboxd owns an `AF_UNIX` CONNECT endpoint and mounts
only its dedicated read-only directory at `/run/lock` in the guest. The proxy
checks the signed domain, scheme, and port policy before host resolution and
rejects any resolved loopback, link-local, private, multicast, unspecified, or
otherwise protected address. The guest cannot request an IP literal.

The signed limits independently bound concurrent connections, sandbox-wide
bytes, per-connection guest-to-upstream bytes, per-connection
upstream-to-guest bytes, bandwidth, connect/header time, and idle time. Because
HTTPS payloads are opaque after CONNECT, the directional limits bound encrypted
tunnel bytes; they are not semantic HTTP body-size enforcement.

For each declared ingress rule, sandboxd creates a caller-inaccessible
loopback endpoint with a random gateway bearer credential and a separate
reverse-tunnel Unix socket with a random guest credential. The guest
configuration is mounted from runtime state and is not part of the guest
rootfs or runsc checkpoint. Route activation happens only after all services
start and the durable assignment becomes active. Pause, stop, transfer, and
reassignment fence the route; a generation change rejects pre-fence queued
tunnels. Restore constructs a new policy service and fresh credentials.

The checked-in conformance agent demonstrates the narrow protocol. A production
guest-agent binary and the broker/gateway route adapter remain required before
tenant-facing ingress deployment. No Kubernetes Service, Ingress, `hostPort`,
or caller-selected listener is created for the worker.

`--host-uds=open` is broader than one socket at the runsc flag level. The
boundary therefore also depends on rootfs and volume admission rejecting Unix
sockets and other special files, and on mounting no host directory except the
dedicated transport directory. Adding another host socket to a guest-visible
mount changes this security contract and requires review.

The portable NetworkPolicy permits worker-Pod DNS and TCP/443 so the
sandboxd-owned proxy can resolve and connect. It cannot express FQDN targets.
Production clusters must constrain this outer path with an FQDN-aware CNI,
service mesh, or egress gateway. That outer control is defense in depth; the
signed per-topology policy remains mandatory.

## Feature matrix

| Feature | Minimum level | Validation result | Missing or required addition |
| --- | --- | --- | --- |
| Fixed immutable image | B | Passed | Sign worker digest and rootfs measurement; verify provenance at admission |
| Multiple services in one Sentry | B | Passed | Reject port collisions; select a durable sandbox anchor independent of startup order |
| Health, inspect, logs, pause/resume | B | Passed | Continuous conformance and crash recovery |
| Local live snapshot/restore, read-only root | B | Passed, with one cleanup race observed | Fix idempotent stop/reconcile race; repeated fault injection |
| Dynamic pinned OCI images | C | Passed with private containerd | Registry credentials, trust policy, controlled registry egress, GC |
| Policy-approved HTTPS CONNECT egress | B-N | Passed in local k3s without host network mutation; released static agent translates standard HTTP proxy traffic | FQDN-aware outer Pod egress; no transparent compatibility |
| Declared reverse HTTP ingress | B-N | Worker path passed in local k3s; released agent refreshes epoch credentials; gateway/broker adapter is tenant-scoped, signed per request, and unit-integration tested through fencing | Persistent service leases and combined adapter/worker live-k3s conformance |
| Restricted raw TCP/UDP egress | D | Passed only in host-integrated profile | Keep disabled or qualify the kernel-network profile |
| Kernel-network ingress | D | Plumbing exists; public exposure intentionally not tested | Prefer B-N reverse ingress; otherwise authenticated local/ClusterIP endpoint and policy tests, never host networking |
| Writable OCI root | E or F | Failed at B; passed at F | Replace loop/ext4/overlay provider or add a storage broker |
| Persistent named writable volume | E or F | Failed at B; passed at F | Broker/userspace provider and explicit ownership/idmapping |
| Artifact read-only volume | B expected | Not release-qualified | Integrity, mount-permission, quota, and recovery conformance |
| Secret volume | B expected | Not release-qualified | Non-persistent delivery, zeroization, access audit, snapshot exclusion |
| Per-sandbox cgroup limits | E or F | External aggregate pod limit passed; managed subtree unavailable at B/C | Writable delegated cgroup subtree, one pod per sandbox, or resource broker |
| Durable local recovery | B plus PVC | Not release-qualified | Compatible encrypted RWO PVC, fencing, restart and eviction tests |
| Cross-worker restore | B plus shared artifact backend and egress | Not exercised | S3 backend, common key, identity fencing, compatibility cohort, credential rotation |
| Root/OCI-compatible guest profiles | B | Root profile enabled only for host-integrated volume test | Treat as operator policy; design non-root volume ownership |
| Signed workload socket | Any daemon level | Implemented, not exercised here | Non-root broker, key delivery/rotation, replay and NetworkPolicy tests |

## Non-capability Kubernetes requirements

The current pinned runsc release needs:

- `allowPrivilegeEscalation: true`;
- an AppArmor profile that permits the gofer `/proc/self/exe` re-exec and its
  exact mount-namespace operations; and
- a seccomp profile that permits the observed gVisor syscall set, including
  `pivot_root`.

The supplied manifests use unconfined profiles so behavior is explicit and
repeatable. This violates Kubernetes Restricted and Baseline policies. Before
untrusted production release, capture the pinned runsc syscall and AppArmor
denials, build allowlist profiles, install them on every eligible node, and
run both positive and negative conformance suites.

Also require:

- dedicated node labels, taints/tolerations, and admission enforcement;
- worker images pinned by digest with signature, SBOM, provenance, and
  vulnerability policy;
- default-deny pod networking and explicit registry/artifact egress only where
  required;
- no service-account token unless a separately reviewed control integration
  needs one;
- explicit CPU, memory, PID, and ephemeral-storage ceilings;
- encrypted state storage and tenant-safe audit export; and
- alerts for stuck assignments, cleanup failures, restart loops, capacity,
  image-GC failure, and runtime version drift.

## Product issues blocking general production release

1. A stop immediately following one successful live restore exposed a gofer
   cleanup race, leaving an active assignment without live runtime resources.
   Cleanup and reconciliation must become idempotent and fault-tested.
2. Image measurement cache identity mixes manifest digest with source registry
   identity. Registry aliases for the same manifest can cause a hard mismatch;
   define and enforce one canonical cache key.
3. A named-volume mountpoint absent from a read-only root fails at runtime.
   Validate required mountpoints during compilation/admission.
4. Strict guest UID/GID 65534 cannot write a new root-owned named volume.
   Add explicit ownership or idmapping policy.
5. The first Compose service currently becomes the Sentry anchor. If it exits
   before dependents join, `service_completed_successfully` topologies fail.
   Select and manage an independent durable anchor.
6. Durable PVC recovery, artifact/secret volumes, workload-socket deployment,
   cross-worker restore, and the private-containerd supervisor lifecycle still
   require release conformance.
7. Custom AppArmor and seccomp profiles are mandatory before mutually
   untrusted workloads.

Until these are closed, the fixed-runtime manifest is a hardened deployment
candidate for controlled fixed workloads, not a blanket claim that every
sandboxd feature is production-qualified.

Relevant upstream constraints:

- [gVisor rootless mode](https://gvisor.dev/docs/user_guide/rootless/)
- [Kubernetes pod user namespaces](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)
- [Kubernetes AppArmor](https://kubernetes.io/docs/tutorials/security/apparmor/)
