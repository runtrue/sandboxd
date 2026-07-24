# Kubernetes deployment

This directory contains production-oriented deployment profiles for running
sandboxd as a nested gVisor worker. Start with the fixed-runtime profile and
enable additional authority only for features that require it.

The detailed capability, host-integration, feature, and release-readiness
matrix is in [`SECURITY-PROFILES.md`](SECURITY-PROFILES.md).

## Deployment profiles

| Profile | Manifest | Image build | Intended use |
| --- | --- | --- | --- |
| Fixed runtime | `sandboxd-fixed-runtime.yaml` | `Dockerfile.fixed-runtime` | Recommended minimum-authority profile. One attested, pre-expanded rootfs; internal loopback only; pod-level resource limits. |
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
- a trusted TLS ingress or service mesh selected by the gateway-client network
  policy labels; and
- an admission policy replacing the local image tag with an immutable digest.

The checked-in Service is ClusterIP-only. Do not create a public LoadBalancer
or permit cleartext ingress directly to the Pod listener.

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
  - coredns
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

## Runtime configuration

Production behavior is selected by typed command-line options:

- `--fixed-rootfs` and `--fixed-topology-lock` enable a pre-expanded image
  provider bound to the lock's single verified OCI image identity, without
  containerd.
- `--fixed-rootfs-digest`, `--fixed-rootfs-entries`, and
  `--fixed-rootfs-bytes` install build-time measurements as one atomic set.
- `--network-mode loopback` creates no bridge, veth, network namespace, or
  nftables state and rejects any topology requesting egress or ingress.
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
