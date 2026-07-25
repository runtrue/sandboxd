# Kubernetes security profiles and feature authority

This document is the deployment authority contract for sandboxd. It records
the minimum configuration observed for each feature and separates validated
behavior from required release work.

Validation environment on 2026-07-25:

- Ubuntu 26.04, Linux 7.0;
- k3s `v1.36.1+k3s1`;
- gVisor `release-20260714.0`; and
- one local-only k3s server plus a disposable real k3s agent.

The disposable agent runs inside a privileged Docker container only to provide
CI node infrastructure. The sandboxd worker Pods on both nodes are not
privileged and receive no host path, host namespace, host runtime socket,
device, service-account token, Service, Ingress, or host port.

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
| B. Fixed runtime | User namespace plus `SETGID`, `SETUID`, `SYS_CHROOT`, `SYS_ADMIN` | Fixed or signed pre-expanded images, multi-container Sentry, loopback, lifecycle APIs, directory-backed writable roots, local live snapshot, cross-worker recovery through shared S3-compatible artifacts | In-worker pulls, ingress/egress, named writable volumes, managed cgroups, recovery without a durable shared artifact backend | Custom AppArmor/seccomp and qualification against the selected production object store |
| B-V. PVC directory volumes | Level B plus `CHOWN`, `DAC_OVERRIDE`, and one operator-selected bounded RWO PVC | Strict, root, and OCI-compatible named-volume writes; tenant-scoped persistent reopen after Pod loss; portable directory snapshot/restore between workers with compatible ownership mapping | Hard per-volume write quota on a shared directory, CSI-native snapshots, portable cross-worker restore between independently mapped Pod user namespaces | Encrypted CSI class, retention/backup policy, per-slot claims, idmapped or equivalent portable ownership, custom AppArmor/seccomp |
| B-N. Userspace policy network | Level B; no networking capability or host-network setting; `network-mode=userspace`; gVisor `network=none` and `host-uds=open` | Policy-approved HTTP CONNECT and declared reverse HTTP ingress over one read-only mounted Unix-socket directory; static unprivileged guest agent; heartbeat-renewed serving leases; gateway/broker adapter; connection, byte, bandwidth, and deadline ceilings | Raw TCP/UDP, guest DNS, transparent proxying, software without explicit HTTP proxy support | Bake the released agent into each measured application image, restrict outer Pod egress with an FQDN-aware CNI or egress gateway, qualify custom MAC/seccomp profiles |
| B+ measured runtime | Level B plus `DAC_READ_SEARCH` | Recomputes full root digest, entry count, and byte count at admission | Same feature limits as B | Use only when runtime measurement is worth pod-wide read/search bypass authority |
| P. Isolated image preparation | Separate user-namespaced Job with `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SYS_ADMIN`; no privilege escalation; default seccomp; private containerd | Resolve a mutable reference once, verify and unpack OCI content, attach evidence, sign, atomically publish an immutable root, audit revocation/pool impact, and lock-aware GC | Sandbox execution, host-runtime access, worker credential access | FQDN-aware registry egress, external key service or short-lived signing key, CSI physical quota, custom AppArmor profile permitting only required mounts/signals |
| C. Dynamic runtime | One user-namespaced worker container with `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`, `SYS_ADMIN`, `SYS_CHROOT` and a private containerd process | Arbitrary pinned OCI pull, validation, unpack, and loopback execution | Kernel policy networking, current loop/ext4 storage, managed cgroups | Registry trust, credential delivery/rotation, image GC, egress policy, supervisor qualification, and a future safe privilege split |
| D. Kernel networking | Level B or C plus `NET_ADMIN`, `NET_RAW`; `network-mode=private`; namespaced `net.ipv4.ip_forward=1` | Bridge/veth network, nftables policy, policy proxies, HTTP/TCP egress, ingress plumbing | Still no current writable storage or managed cgroups | Kubelet unsafe-sysctl allowlist, pod sysctl, dedicated nodes, custom network security profiles |
| E. Delegated cgroups or advanced CSI | Level B or B-V plus a reviewed CSI integration or trusted resource broker | CSI-native snapshots, backend-specific hard quota, delegated per-sandbox resources | Depends on the selected provider | Provider-specific fencing, recovery, quota, and threat model |
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

### PVC-backed directory volumes

The directory-volume tier adds exactly:

| Capability | Current purpose | Independent removal result |
| --- | --- | --- |
| `DAC_OVERRIDE` | Let gVisor's capability-reduced gofer create and traverse the exact provider-resolved bind source across the nested user-namespace boundary | Strict UID 65534 create failed with `EACCES` |
| `CHOWN` | Assign the guest UID/GID to a newly created inode and preserve portable snapshot ownership | Create reached the bind but failed with `EPERM` |

Both together passed strict-profile write/read, live snapshot, forced worker
replacement, persistent reopen, and portable tar restore. An exact-capability
restore test passed with only these two storage capabilities plus the normal
runsc set; `FOWNER` was not required. `directfs=true` was also tested and
failed during the gofer re-exec under the reduced outer capability set, so the
profile retains the stricter `directfs=false`.

These capabilities apply to the whole sandboxd process in its Kubernetes user
namespace. Their reachable filesystem is constrained by the read-only image,
dedicated runtime tmpfs, and the single operator-mounted state PVC; the profile
has no host path, runtime socket, device, host namespace, or mount
propagation. `DAC_OVERRIDE` still weakens Unix mode enforcement inside that
mounted PVC, so tenant separation must continue to rely on opaque provider
handles, canonical source validation, one-sandbox worker assignment, and
storage encryption/fencing.

Portable directory archives retain numeric guest ownership. Distinct
`hostUsers: false` Pods can receive different outer UID/GID mappings, so a
directory created in one Pod may be inaccessible after restore in another.
`CHOWN` and `DAC_OVERRIDE` do not translate independent user-namespace
mappings. Cross-worker B-V recovery therefore requires a CSI or idmapped
provider that defines a portable ownership mapping; without one, keep named
directory volumes on the same mapped worker cohort. Level B recovery of
process memory, sockets, tmpfs, and writable OCI roots does not require the
B-V capabilities.

### Image preparation

The isolated private-containerd preparer requires:

| Capability | Current purpose |
| --- | --- |
| `CHOWN` | Apply OCI layer ownership |
| `DAC_OVERRIDE` | Create and replace layer paths regardless of mode bits |
| `FOWNER` | Apply file metadata when the effective UID is not the owner |
| `SYS_ADMIN` | Bind-mount native-snapshotter roots inside the Pod user namespace |

`SETUID`, `SETGID`, and `SYS_CHROOT` were independently removed from the
preparer and the complete pull, unpack, measure, sign, and cache-hit path still
passed. Removing `CHOWN` failed on layer ownership; removing `FOWNER` failed
while restoring modes; removing `DAC_OVERRIDE` failed while walking
non-readable layer paths; removing `SYS_ADMIN` failed the native-snapshotter
bind mount. The four remaining capabilities are scoped to the Kubernetes Pod
user namespace. The Job is not privileged, forbids privilege escalation, uses
the runtime-default seccomp profile, mounts no host path or host runtime
socket, and disables containerd's CRI and opt plugins.

The preparer and its private containerd remain in one container; a containerd
sidecar would need mount propagation that Kubernetes only exposes through a
privileged boundary. Reduced workers never inherit the preparation
capabilities. They receive the published root read-only and verify the
operator key, preparation and vulnerability policies, toolchain, age,
revocation state, complete OCI descriptor graph, platform, expanded-root
digest/count/bytes, and deployment-selected worker artifact digest before
readiness. Publication uses a crash-released advisory lock, temporary
same-filesystem staging, fsync, and one atomic rename, so interruption cannot
make a partial directory trusted.

The stock AppArmor runtime-default profile denied the preparer's
user-namespaced bind mount and denied its supervisor signal to containerd.
Until the required narrow mount and signal rules are installed as a versioned
localhost profile, the preparer explicitly uses AppArmor `Unconfined`. This is
isolated to preparation; it is not a reason to grant extra worker authority.

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

The checked-in Python conformance agent demonstrates the narrow protocol
without changing the independently measured fixture root. Production images
must include the released static `runtrue-sandbox-net-agent`; the live k3s
suite exercises the same transport through the broker/gateway route adapter.
No Kubernetes Service, Ingress, `hostPort`, or caller-selected listener is
created for the worker.

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
| Fixed immutable image | B | Signed descriptor/root/worker binding passed before readiness | Key rotation and custom MAC qualification |
| Approved OCI image through isolated preparation | P then B | Cold publish, duplicate cache hit, reduced-worker activation, cache pressure, lock-aware GC, revocation-to-pool inventory, and gVisor child execution passed | CSI physical quota, placement quarantine integration, FQDN-aware registry egress |
| Multiple services in one Sentry | B | Passed | Reject port collisions; select a durable sandbox anchor independent of startup order |
| Health, inspect, logs, pause/resume | B | Passed | Continuous conformance and crash recovery |
| Local live snapshot/restore, read-only root | B | Passed; restored gofers are reaped by exact recorded PID during root teardown | Repeated fault injection in each released runtime cohort |
| Dynamic pinned OCI images inside worker | C | Passed with private containerd | Prefer P+B; otherwise registry credentials, trust policy, controlled registry egress, and GC remain worker concerns |
| Policy-approved HTTPS CONNECT egress | B-N | Passed in local k3s without host network mutation; released static agent translates standard HTTP proxy traffic | FQDN-aware outer Pod egress; no transparent compatibility |
| Declared reverse HTTP ingress | B-N | Full local-k3s path passed: scale-from-zero, signed dispatch, guest reverse tunnel, exact declared route, bounded bulk response, heartbeat renewal, and immediate withdrawal on cancel | Bake the released static agent into every measured application root; qualify outer FQDN egress and custom MAC/seccomp profiles |
| Restricted raw TCP/UDP egress | D | Passed only in host-integrated profile | Keep disabled or qualify the kernel-network profile |
| Kernel-network ingress | D | Plumbing exists; public exposure intentionally not tested | Prefer B-N reverse ingress; otherwise authenticated local/ClusterIP endpoint and policy tests, never host networking |
| Writable OCI root | B | Strict UID write, bounded live snapshot, and cross-worker replacement restore passed through the directory-backed gVisor upper layer | Qualify the selected production object store and runtime cohort |
| Persistent named writable volume | B-V | Strict, root, and OCI-compatible writes plus reopen after forced Pod replacement passed on a PVC-backed worker | Encrypted production CSI qualification; use separate claims/project quota when hard per-volume enforcement is required |
| Attested root on read-only RWO content volume | P+B | Integrity, signature, mount permission, and nested execution passed | CSI-specific recovery, multi-node delivery, quota, and GC conformance |
| Secret volume | B expected | Not release-qualified | Non-persistent delivery, zeroization, access audit, snapshot exclusion |
| Per-sandbox cgroup limits | E or F | External aggregate pod limit passed; managed subtree unavailable at B/C | Writable delegated cgroup subtree, one pod per sandbox, or resource broker |
| Durable local recovery | B-V | Forced Pod loss cleared stale attachments and reopened retained content from the same RWO PVC | Repeated eviction/node-loss fault injection and storage-class-specific fencing |
| Cross-worker restore | B plus shared artifact backend and egress | Real two-node k3s Pod-loss and complete agent-loss recovery passed with process, memory, pre-opened internal socket, tmpfs, and writable-root continuity; epochs, fencing, audit chain, RPO, RTO, and metric series were verified | Qualify every enabled resource shape, production object store, and target failure domain; add portable ownership before including named directory volumes |
| Root/OCI-compatible guest profiles | B-V | Strict UID/GID 65534, root-in-sandbox, and OCI-compatible volume paths passed | Treat profile enablement as explicit operator policy |
| Signed workload socket | Any daemon level | Non-root, capability-free broker passed local-k3s dispatch and reverse-ingress conformance | Production key delivery/rotation and continuous replay/NetworkPolicy tests |

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

## Durable recovery qualification

The multi-node conformance runs the source and destination on different real
k3s nodes and exercises two independent failures: immediate deletion of the
source worker Pod and stopping the complete disposable k3s agent. Both use the
Level B four-capability profile and an S3-compatible shared artifact backend.
The destination must resume the checkpointed process, memory token, counter,
tmpfs file, writable OCI-root file, and an already-open internal TCP socket.
The test also requires a newer assignment epoch, confirmed source fencing, the
complete six-event audit chain, RPO no greater than the declared 120-second
maximum staleness, RTO no greater than 10 seconds, and emitted P50/P95/P99
metric series.

The 2026-07-25 reference run observed:

| Failure | RPO | RTO |
| --- | ---: | ---: |
| Forced source Pod deletion | 60.529 s | 0.815 s |
| Complete source k3s-agent stop | 62.319 s | 2.336 s |

These are qualification observations, not universal service guarantees.
Production SLOs must be set per resource shape, object store, cluster, and
failure domain. The CI recovery limit is 10 seconds and can be tightened with
`MULTINODE_RECOVERY_MAX_RTO_MS`.

On restore, gVisor exposes its read-only checkpoint notification at
`/proc/gvisor/checkpoint`. The guest can observe `restore` and continue over
pre-opened internal sockets, but the worker does not enable the guest
checkpoint trigger. Snapshot authority remains exclusively on the signed
operator/control-plane path.

## Product issues blocking general production release

1. Image measurement cache identity mixes manifest digest with source registry
   identity. Registry aliases for the same manifest can cause a hard mismatch;
   define and enforce one canonical cache key.
2. The first Compose service currently becomes the Sentry anchor. If it exits
   before dependents join, `service_completed_successfully` topologies fail.
   Select and manage an independent durable anchor.
3. Secret-volume lifecycle and CSI-specific snapshot delivery still require
   release conformance. Cross-worker directory-volume recovery additionally
   needs a portable ownership mapping across Pod user namespaces.
4. Custom AppArmor and seccomp profiles are mandatory before mutually
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
