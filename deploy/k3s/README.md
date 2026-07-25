# Kubernetes deployment

This directory contains production-oriented deployment profiles for running
sandboxd as a nested gVisor worker. Start with the fixed-runtime profile and
enable additional authority only for features that require it.

The detailed capability, host-integration, feature, and release-readiness
matrix is in [`SECURITY-PROFILES.md`](SECURITY-PROFILES.md).

## Deployment profiles

| Profile | Manifest | Image build | Intended use |
| --- | --- | --- | --- |
| Isolated image preparation | `image-preparer.yaml` | `Dockerfile.preparer` | Resolve, verify, unpack, measure, attach evidence, sign, and atomically publish approved OCI roots without a host runtime socket. Runs separately from reduced workers. |
| Fixed runtime | `sandboxd-fixed-runtime.yaml` | `Dockerfile.fixed-runtime` | Recommended minimum-authority profile. One attested, pre-expanded rootfs; internal loopback only; pod-level resource limits. |
| Userspace network runtime | `sandboxd-userspace-runtime.yaml` | `Dockerfile.fixed-runtime` | Fixed runtime plus policy-approved HTTPS CONNECT and declared reverse HTTP ingress over guest-visible Unix sockets. No `NET_ADMIN`, `NET_RAW`, veth, bridge, nftables, forwarding sysctl, host path, host namespace, Kubernetes Service/Ingress, or `hostPort`. |
| Brokered fixed runtime | `sandboxd-fixed-runtime-brokered.yaml` | `Dockerfile.fixed-runtime` + `Dockerfile.broker` | Fixed worker plus a capability-free native broker sidecar, signed workload socket, authenticated registration, and default-deny control-plane routing. |
| Dynamic runtime | `sandboxd-dynamic-runtime.yaml` | `Dockerfile.host-integrated` | Private containerd in the worker container for arbitrary pinned OCI images. No host socket, path, device, or namespace. |
| Host integrated | `sandboxd-host-integrated.yaml` | `Dockerfile.host-integrated` | Compatibility profile for features implemented with host containerd, loop devices, mounts, networking, and cgroups. Requires dedicated trusted nodes. |

The optional `sandbox-gateway.yaml` control-plane manifest is separate from
the worker profiles. It runs two stateless, non-root, capability-free gateway
replicas plus a one-shot schema migration Job. Build it with
`Dockerfile.gateway`. It requires:

- an HA PostgreSQL service with TLS and network policy;
- separate runtime and migration database identities;
- `sandbox-gateway-database`, `sandbox-gateway-migration-database`, and
  `sandbox-gateway-auth` Secrets as documented in
  `crates/sandbox-placement/README.md`;
- a `sandbox-worker-pools` ConfigMap whose `catalog.json` key is created from
  the reviewed [`worker-pools.json`](worker-pools.json);
- a trusted TLS ingress or service mesh selected by the gateway-client network
  policy labels; and
- an admission policy replacing the local image tag with an immutable digest.

The checked-in Service is ClusterIP-only. Do not create a public LoadBalancer
or permit cleartext ingress directly to the Pod listener.

Create or update the catalog before rolling the gateway:

```bash
kubectl create configmap sandbox-worker-pools \
  --namespace sandboxd-system \
  --from-file=catalog.json=deploy/k3s/worker-pools.json \
  --dry-run=client -o yaml | kubectl apply -f -
```

`Dockerfile.broker` packages the per-worker network broker as UID/GID 65533 in
a scratch image. The broker runs with a read-only root filesystem, no
capabilities, no privilege escalation, no service-account token, and only the
shared workload-socket directory. It does not receive the work-order signing
key or the separate operator-socket `emptyDir`. The workload directory is
pre-provisioned with broker GID 65533, so sandboxd creates a group-accessible
socket without `CAP_CHOWN`; Unix peer credentials still require broker UID
65533. Non-loopback use requires authenticated mTLS
termination plus NetworkPolicy restricting ingress to the placement
dispatcher. The broker waits for sandboxd's workload socket before registering,
then sends authenticated heartbeats. It is a Kubernetes native sidecar
(`initContainers[*].restartPolicy: Always`), so kubelet terminates it when the
single-use sandboxd container exits and the ReplicaSet can replace the whole
Pod.

The brokered manifest requires `sandbox-work-order` with key `key` and
`sandbox-worker-auth` with key `registration.json`. The HMAC key is mounted
only into sandboxd and the gateway. The registration credential is mounted only
into the broker. Both mounts use `subPath` so the strict regular-file readers
never follow Kubernetes Secret symlinks.

The checked-in worker identity represents one statically provisioned slot.
Production pools issue a unique worker identity and registration credential per
Pod, then remove or rotate it when the slot is consumed. Do not share one
credential across replicas. The warm-pool controller owns that lifecycle.

The fixed and dynamic profiles use a Kubernetes user namespace
(`hostUsers: false`), disable service-account token mounting, expose no Service
or Ingress, use no host namespace or `hostPath`, and apply a default-deny
NetworkPolicy. The dynamic profile additionally permits DNS and TCP/443 egress
for OCI registries; constrain those destinations with a CNI or egress gateway
that supports FQDN policy. Their control socket exists only inside the pod.

## Cluster prerequisites

- Linux node with Kubernetes user namespaces enabled.
- A container runtime and filesystem that support user-namespaced pods.
- Kubernetes API and kubelet bound to private or loopback addresses.
- A dedicated sandbox node pool for any profile that grants `SYS_ADMIN`.
- Fixed and dynamic nodes labeled `runtrue.io/sandbox-node=true`; optionally
  taint them `runtrue.io/sandbox=true:NoSchedule`.
- A node pool per reviewed worker resource shape. Kubernetes has no portable
  per-Pod PID-limit field, so the fixed `standard-v1` pool must configure
  kubelet `pod-max-pids=256`. Do not mix shapes with different PID ceilings on
  that pool.
- Host-integrated compatibility nodes use the separate
  `runtrue.io/sandbox-host-integrated=true` label.
- An admission policy that pins worker images by digest in release
  environments.
- A bounded RWO CSI StorageClass for the preparation cache. The local
  conformance harness creates one static local PV only because the local-only
  k3s profile deliberately disables its host-path provisioner.
- An operator signing identity delivered only to the isolated preparer. Use an
  external signing service or a short-lived projected Secret in production;
  never mount it into a worker.
- FQDN-aware egress enforcement for approved OCI registries. Portable
  NetworkPolicy can restrict the preparer to DNS and TCP/443 but cannot express
  registry hostnames.
- Node-installed, versioned AppArmor and seccomp profiles before untrusted
  production use. The supplied manifests remain `Unconfined` because the stock
  profiles blocked the pinned gVisor release; this is a tracked release
  requirement, not a recommended steady state.

The validated local k3s node used:

```yaml
# /etc/rancher/k3s/config.yaml
bind-address: 127.0.0.1
advertise-address: 127.0.0.1
node-ip: <node-ip>
tls-san:
  - 127.0.0.1
write-kubeconfig-mode: "0600"
disable:
  - traefik
  - servicelb
  - metrics-server
  - local-storage
kubelet-arg:
  - pod-max-pids=256
kube-controller-manager-arg:
  - terminated-pod-gc-threshold=32
disable-network-policy: false
```

Install the reviewed k3s release through your normal package and artifact
verification pipeline. The conformance run documented here used
`v1.36.1+k3s1`; do not make an installer fetched at deployment time part of a
production bootstrap.

Verify that the node is local-only:

```bash
ss -lntp | grep -E ':(6443|10250)'
KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl wait \
  --for=condition=Ready node --all --timeout=120s
```

Both listeners must resolve to loopback or an explicitly approved management
address.

## Automated conformance

[`k3s-integration.yml`](../../.github/workflows/k3s-integration.yml) runs the
fixed-runtime profile on an ephemeral GitHub-hosted Ubuntu VM for relevant pull
requests, `main` pushes, a weekly schedule, and manual dispatch. It downloads a
checksum-pinned k3s binary, starts a local-only cluster, builds and imports the
worker image, validates all manifests, and runs
[`tools/test-k3s-fixed-runtime.sh`](../../tools/test-k3s-fixed-runtime.sh).

The harness verifies the successful nested server/client path, one-assignment
admission, fresh-Pod replacement after success and injected failures, the
actual Pod-cgroup PID ceiling, the exact host-side capability mask,
user-namespace mapping, read-only worker root, default-deny NetworkPolicy, and
absence of host integration. It also verifies rejection of external
networking, writable roots, and a mismatched OCI image. Pod, k3s, firewall, and
image diagnostics are retained for every workflow run.

[`tools/test-k3s-userspace-egress.sh`](../../tools/test-k3s-userspace-egress.sh)
proves the reduced network profile in the same real cluster. It requires
approved TLS to traverse the policy socket; denies guest DNS, direct IP, raw
socket, metadata/private, unapproved-domain, and over-limit connection paths;
routes authenticated ingress only to the declared service; rejects a stale
pre-pause tunnel after resume; measures warm ingress latency and 128 KiB
throughput; checks runsc uses `network=none` and `host-uds=open`; and compares
host links, network namespaces, nftables, and forwarding sysctls before and
after the nested run.

[`tools/test-k3s-image-preparation.sh`](../../tools/test-k3s-image-preparation.sh)
drives the isolated preparation and reduced-runtime boundary in the same real
cluster. It resolves a mutable Python tag to one immutable manifest, publishes
the expanded root through a private containerd with no host socket, repeats the
request and requires the same cache object, verifies the signed descriptor,
platform, root, evidence, and worker-artifact binding, and confirms the private
key is absent from retained content. It then starts a worker with no
containerd, registry Secret, pull egress, host path, host namespace, or
service-account token; requires revocation and artifact mismatch to fail before
readiness; and creates two nested containers under gVisor. CI retains cold
preparation time, root size, cache-hit status, and signed-root activation time.

The preparer needs only `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, and `SYS_ADMIN`
inside its Kubernetes user namespace. `allowPrivilegeEscalation` is false and
the seccomp profile is `RuntimeDefault`. The stock AppArmor default denied the
private native-snapshotter bind mount and its supervisor signal, so the
checked-in Job explicitly uses AppArmor `Unconfined` until a node-installed
localhost profile grants exactly those operations. The reduced worker does not
inherit any preparation capability.

Production application images for this profile include the released
`runtrue-sandbox-net-agent` in their measured OCI root and declare one ordinary
guest service that runs it. The agent requires no capability: it presents a
loopback HTTP proxy to applications, consumes only the read-only policy
transports under `/run/lock`, and opens reverse tunnels only for services
selected with `--ingress-service`. The conformance image retains its compact
Python protocol fixture so the fixed upstream rootfs measurement remains
independently reproducible; the Rust agent has unit-level end-to-end tests for
both transport directions and is included in release reproducibility checks.

The gateway exposes active routes at
`/v1/placements/{idempotency_key}/ingress/{service}/{container_port}`. Every
request revalidates the durable lease and carries a fresh signed inspect order
to the selected worker broker. The broker resolves only sandboxd's current
loopback endpoint and injects its bearer locally; the tenant cannot choose a
worker address or host port. The adapter is bounded to 16 KiB headers and
1 MiB request/response bodies. The combined autoscaling suite retains gateway
latency and 128 KiB transfer measurements alongside the direct-worker
measurements above. Successful create/restore placements enter `serving`;
authenticated worker heartbeats renew only their current unexpired lease.
Cancel, quarantine, lease expiry, and reassignment withdraw the route.

[`tools/test-k3s-resource-limits.sh`](../../tools/test-k3s-resource-limits.sh)
separately drives CPU saturation, fork exhaustion, bounded temporary-storage
exhaustion, and memory pressure through real nested gVisor workloads. It
requires CPU throttling in the Pod cgroup, guest process creation to stop below
the Pod PID ceiling, `/tmp` to return `ENOSPC` at its declared 16 MiB limit, and
the Pod cgroup to record an OOM kill while the node remains ready. A local
`standard-v1` run recorded:

```json
{"cpu_nr_throttled_delta":2,"pid_children_before_ceiling":95,"tmpfs_bytes_before_enospc":16777216,"pod_oom_kill_delta":4}
```

These are conformance observations, not benchmark baselines; CI retains fresh
measurements on each run. The fixed tier exposes no writable disk-backed guest
path, so disk amplification is rejected by construction and bounded `/tmp`
exhaustion is the relevant guest-write test. Writable disk conformance belongs
to the directory/PVC storage tier.

## Build and deploy isolated image preparation

Build and publish `Dockerfile.preparer` by immutable digest. It contains the
release `runtrue-sandboxctl`, checksum-verified containerd 2.2.3 binaries, a
private containerd configuration with workload/CRI plugins disabled, and the
bounded supervisor. It never connects to the node container runtime.

Before applying `image-preparer.yaml`, create:

- `sandbox-image-preparer-signing`, with the 32-byte Ed25519 seed at
  `private-key`;
- `sandbox-image-preparer-evidence`, with bounded `sbom.json` and
  `provenance.json` keys; and
- optionally `sandbox-image-preparer-registry`, with `credential.json`.

Generate an offline keypair when an external signer is not yet integrated:

```bash
runtrue-sandboxctl generate-image-attestation-key \
  --private-key ./preparer.private \
  --public-key ./preparer.public

kubectl create secret generic sandbox-image-preparer-signing \
  --namespace sandboxd-system \
  --from-file=private-key=./preparer.private
```

The optional registry credential is accepted only by the preparer:

```json
{
  "kind": "basic",
  "tenant": "preparation-service",
  "registry": "registry.example",
  "username": "short-lived-identity",
  "password": "short-lived-secret"
}
```

Bearer form replaces `username`/`password` with `token` and sets
`"kind": "bearer"`. The credential is registry-scoped by the provider, is read
from a bounded projected file, and is not copied to the cache. Do not put a
credential in an environment variable, topology lock, Job argument, or
ConfigMap.

Set these reviewed values in the Job template or render them through the
release deployment pipeline:

- `RUNTRUE_PREPARATION_REFERENCE`: the approved OCI reference; a mutable tag is
  resolved once and only the resulting digest-pinned identity is attested;
- `RUNTRUE_PREPARATION_KEY_ID`: the key identifier present in worker trust
  policy;
- `RUNTRUE_PREPARATION_POLICY`: normalization/validation policy version;
- `RUNTRUE_PREPARATION_TOOLCHAIN_DIGEST`: digest of the reviewed preparer
  toolchain; and
- `RUNTRUE_VULNERABILITY_POLICY`: the vulnerability gate that produced the
  mounted evidence.

Each successful cache directory is named by
`worker_artifact_digest` and contains only `rootfs/`, `attestation.json`,
`sbom.json`, and `provenance.json`. A same-filesystem temporary directory is
fsynced and renamed once while an advisory lock is held. The lock is released
by the kernel on process or Pod death, concurrent publishers re-check the
winner, and a failed copy has no trusted final directory. `latest-result.json`
is an atomic operational pointer, not a trust root.

Workers mount one digest directory read-only and supply all of:

```text
--fixed-rootfs /artifact/rootfs
--fixed-topology-lock /config/topology.json
--fixed-rootfs-digest <expanded-root digest>
--fixed-rootfs-entries <expanded-root entries>
--fixed-rootfs-bytes <expanded-root bytes>
--image-attestation /artifact/attestation.json
--image-attestation-trust-policy /trust/policy.json
--worker-artifact-digest <selected artifact digest>
```

The trust policy must contain the signer public key, allowlisted preparation,
toolchain, and vulnerability policies, a maximum age, and both root and worker
artifact revocation sets. Any mismatch or revocation exits before the worker
becomes Ready. A deployment controller must select only a prepared artifact;
unseen `cold-build` requests remain queued until publication completes, while
`preapproved` requests bind directly to an existing digest directory. Cache
quota/GC and the revocation-to-pool inventory require a preparation-cache
controller; do not enable unbounded tenant-triggered preparation without it.

## Build and deploy the fixed-runtime profile

The build context contains the release binary, pinned gVisor binary, verified
topology lock, and expanded guest root. In a release pipeline, replace the
local tag with a registry digest, sign it, attach SBOM/provenance, and update
the manifest to that digest.

```bash
cargo test --workspace --all-targets --locked
cargo build --workspace --release --locked

build_id=$(sha256sum target/release/runtrue-sandboxd | cut -d' ' -f1)
docker build \
  --build-arg "SANDBOXD_BUILD_ID=$build_id" \
  -t sandboxd-fixed-runtime:local \
  -f deploy/k3s/Dockerfile.fixed-runtime .
docker save sandboxd-fixed-runtime:local | k3s ctr images import -

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl apply -f deploy/k3s/sandboxd-fixed-runtime.yaml
kubectl wait -n sandboxd-system \
  --for=condition=Ready pod \
  -l app.kubernetes.io/name=sandboxd-fixed-runtime \
  --timeout=180s
```

Run the nested-container conformance check:

```bash
pod=$(kubectl get pod -n sandboxd-system \
  -l app.kubernetes.io/name=sandboxd-fixed-runtime \
  -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n sandboxd-system "$pod" -- \
  runtrue-sandboxd admit \
  --socket /run/runtrue-sandboxd/control.sock \
  --lock /opt/runtrue-sandboxd/fixed-runtime.lock.json

kubectl exec -n sandboxd-system "$pod" -- \
  runtrue-sandboxd create \
  --socket /run/runtrue-sandboxd/control.sock \
  --lock /opt/runtrue-sandboxd/fixed-runtime.lock.json \
  --sandbox release-conformance \
  --timeout-seconds 30

kubectl exec -n sandboxd-system "$pod" -- \
  runtrue-sandboxd logs \
  --socket /run/runtrue-sandboxd/control.sock \
  --sandbox release-conformance \
  --container client
```

The result must have exit code zero, contain
`"marker": "nested-container-passed"`, report kernel `4.19.0-gvisor`, and run
as UID 65534.

`tools/test-k3s-brokered-runtime.sh` exercises the network-facing path through
an integration-only loopback PostgreSQL sidecar:

```text
tenant HTTP -> gateway -> durable assignment -> signed work order
            -> broker UID 65533 -> workload Unix socket -> sandboxd -> gVisor
```

It requires a terminal result containing the nested gVisor kernel, UID 65534,
and the fixture marker; requires the authenticated SSE stream to publish and
close on that completed result without exposing queue position; repeats the
tenant idempotency key; rejects an operator request at the broker; and inspects
the live Pod to confirm the broker has no capabilities, signing key, operator
socket, or service-account token.

## Runtime configuration

Production behavior is selected by typed command-line options:

- `--fixed-rootfs` and `--fixed-topology-lock` enable a pre-expanded image
  provider bound to the lock's single verified OCI image identity, without
  containerd.
- `--fixed-rootfs-digest`, `--fixed-rootfs-entries`, and
  `--fixed-rootfs-bytes` install build-time measurements as one atomic set.
- `--image-attestation`, `--image-attestation-trust-policy`, and
  `--worker-artifact-digest` make a fixed-root worker fail before readiness
  unless an Ed25519-signed preparation record exactly matches the locked OCI
  descriptor graph, platform, expanded-root measurement, and deployment-
  selected worker artifact. The trust policy bounds signer keys, preparation
  policy, toolchain, age, and revoked root/worker digests.
- `--network-mode loopback` creates no bridge, veth, network namespace, or
  nftables state and rejects any topology requesting egress or ingress.
- `--network-mode userspace` accepts HTTP CONNECT egress and declared reverse
  HTTP ingress policies, keeps gVisor networking disabled, exposes egress at
  `RUNTRUE_EGRESS_SOCKET`, and writes epoch-scoped ingress registration data to
  `/run/lock/ingress.json`. The unprivileged `runtrue-sandbox-net-agent`
  translates conventional loopback `HTTP_PROXY` and `HTTPS_PROXY` traffic and
  declared ingress services to those narrow protocols. Transparent sockets,
  UDP, QUIC, and arbitrary TCP are not enabled in this tier.
- `--network-mode private` enables the kernel networking provider.
- `--cgroup-mode external` delegates aggregate enforcement to the enclosing
  Kubernetes pod.
- `--cgroup-mode managed` creates sandboxd-owned cgroup-v2 subtrees.
- `--resource-shape` and the accompanying CPU, memory, PID, ephemeral-storage,
  and service ceilings define the guest admission budget. The Pod limit is a
  larger enforcement envelope that includes runsc, Sentry, gofers, sandboxd,
  and cleanup overhead.

The daemon validates these options at startup. There are no deployment-only
environment-variable shortcuts.

## State, availability, and rollout

The checked-in fixed and dynamic manifests run single-use worker Deployments
with bounded `emptyDir` volumes. The Pod-level policy remains `Always`, as
required by a Deployment, while Kubernetes 1.36's per-container restart policy
sets sandboxd to `Never`. Exit code 75 therefore makes the Pod terminal and the
ReplicaSet creates a fresh Pod with fresh storage instead of restarting
sandboxd in the contaminated Pod. This requires the `ContainerRestartRules`
feature available in the pinned Kubernetes cohort. Terminal Pod objects do not
retain running processes or `emptyDir` data, but the control plane keeps them
for diagnostics until garbage collection; the dedicated cohort therefore uses
a bounded `terminated-pod-gc-threshold`. These manifests provide one static
clean slot; they are not the warm-pool controller specified by the
placement/autoscaling phases and do not claim restart-durable sandboxes. Before
enabling durable operation:

1. use an encrypted, user-namespace-compatible, single-writer PVC for state and
   local artifacts;
2. verify idmapped-mount behavior with the selected CSI driver;
3. add worker fencing and repeated crash/recovery tests;
4. deploy the fenced placement and warm-pool controller before exposing tenant
   submission; and
5. monitor failed cleanup, assignment reconciliation, storage capacity,
   sandbox count, and pod eviction.

Do not put the operator socket behind a Service. Tenant traffic must use the
separate workload socket with signed work orders and a non-root broker identity.

## Reviewed worker-pool catalog

[`worker-pools.json`](worker-pools.json) is the operator-owned autoscaling
catalog. A pool key binds the attested root cohort, resource shape, reviewed
guest profile, runsc/snapshot compatibility cohort, and networking and storage
feature tiers to one named StatefulSet and a bounded scaling policy. The
catalog accepts at most 128 unique pools and exactly one cold fallback. Unknown
request combinations route to that existing fallback; tenant input never
becomes a StatefulSet name, image pull, or new pool.

The service-level override has only two forms: scale to zero or retain a
positive number of clean workers within the pool maximum. It cannot raise the
operator-reviewed maximum. The controller integration and drain-first
StatefulSet reconciliation consume this catalog; the static Deployment below
remains the single-worker conformance fixture.

`sandboxd-worker-pools.yaml` pre-creates three reviewed StatefulSets at zero
replicas: retained-warm loopback, scale-to-zero userspace ingress, and reviewed
cold fallback. Worker Pods still have `automountServiceAccountToken: false`;
they carry neither a Kubernetes credential nor a shared worker-registration
secret. The autoscaler registers only Ready Pods owned by the exact reviewed
StatefulSet, derives `worker-<pod-uid>`, and records the catalog-fixed topology,
shape, cohort, broker address, and resource ceilings in PostgreSQL.
It continues heartbeat renewal for an already registered worker while
sandboxd's container is Running; readiness intentionally becomes false while
that worker is occupied.
Only the userspace pool receives DNS and TCP/443 Pod egress; none of the pools
has a Kubernetes Service, Ingress, host port, or host-network access.

`sandbox-autoscaler.yaml` is the only component in this path with a Kubernetes
service-account token. Its namespaced Role permits exactly:

- `get` and `patch` on StatefulSets; and
- `list` on Pods.

It cannot read Secrets, create workloads, delete Pods, mutate Deployments, or
access cluster-scoped resources. Database access uses a separate runtime
identity. Apply a site-specific egress policy allowing only the Kubernetes API
and PostgreSQL endpoints; those addresses cannot be expressed portably in the
checked-in manifest.

`--maximum-total-workers` is required and must equal the smaller worker budget
allocated by cluster capacity policy and the namespace quota. The controller
uses that reviewed number for immediate backpressure instead of creating
permanently Pending Pods. It deliberately has no permission to read
ResourceQuota or node capacity. Sites that require automatic reaction to quota
changes must add read-only `get/list/watch` access for ResourceQuota and a
separate reviewed capacity source; the least-privilege profile keeps the budget
explicit and grants neither permission.

The autoscaler exposes Prometheus text metrics on port `9090`. The checked-in
NetworkPolicy admits only same-namespace Pods labeled
`runtrue.io/metrics-scraper=true`; adapt the peer selector when the monitoring
stack runs in a dedicated namespace. Gauges come directly from durable
placement state. P50/P95/P99 samples cover cold wait, warm wait,
create-to-ready, queue residence, execution, and first output over a bounded
lookback. The current work protocol returns output only with its terminal
response, so `first_output` records that first observable response; a future
streaming worker protocol can persist an earlier timestamp without changing
the metric contract.

Scale-down is StatefulSet-ordinal-safe. The controller examines the exact
highest ordinals Kubernetes will remove, atomically changes only clean workers
to `draining`, and then patches the replica count with the observed resource
version. A leased, missing, starting, quarantined, or consumed trailing worker
blocks ordinary scale-down. A failed patch leaves workers draining and
unroutable for a safe retry. Duplicate controllers serialize their durable
decision in PostgreSQL.

Build and pin `Dockerfile.autoscaler`, create
`sandbox-autoscaler-database` with `url`, `ca.crt`, `tls.crt`, and `tls.key`
for a DML-only placement identity, and install the brokered control-plane
prerequisites (`sandboxd-system`, `sandboxd-brokered`, `sandbox-work-order`,
the gateway, and PostgreSQL). Then apply in this order:

```bash
kubectl apply -f deploy/k3s/sandboxd-worker-pools.yaml
kubectl apply -f deploy/k3s/sandbox-autoscaler.yaml
```

The local k3s conformance script runs the same release binary outside the
cluster against a loopback PostgreSQL port-forward. Production must not enable
plaintext non-loopback database access.

## Dynamic-runtime profile

Build `Dockerfile.host-integrated` under the dynamic image name, import its
digest-pinned release artifact, and apply the dynamic manifest:

```bash
docker build \
  --build-arg "SANDBOXD_BUILD_ID=$build_id" \
  -t sandboxd-dynamic-runtime:local \
  -f deploy/k3s/Dockerfile.host-integrated .
docker save sandboxd-dynamic-runtime:local | k3s ctr images import -
kubectl apply -f deploy/k3s/sandboxd-dynamic-runtime.yaml
kubectl wait -n sandboxd-system \
  --for=condition=Ready pod \
  -l app.kubernetes.io/name=sandboxd-dynamic-runtime \
  --timeout=180s
```

The private containerd content store is empty on every new pod. Prepare each
approved image through the worker's containerd before admission. Registry
credentials must be delivered by an owner-only mechanism and must never be
placed in the topology lock.

The current containerd image-mount API requires sandboxd and private containerd
to share one mount namespace, so this profile uses one supervised container
with seven capabilities. A Kubernetes sidecar would require privileged
bidirectional mount propagation and is intentionally not used.

## Host-integrated compatibility profile

`sandboxd-host-integrated.yaml` is retained to qualify the complete current
storage, networking, and cgroup implementation. It is privileged and mounts
host containerd and state paths. Run it only on dedicated tainted sandbox nodes
or in disposable VMs. It is not an escalation path for the fixed or dynamic
profiles and should remain scaled down unless a compatibility test is active.
