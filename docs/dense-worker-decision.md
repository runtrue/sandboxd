# Dense multi-sandbox worker decision

Status: rejected on 2026-07-25. The one-sandbox-per-worker-Pod boundary remains
the production design.

## Decision gates

The dense mode had to pass both gates before implementation:

1. reduce measured active worker memory by at least 25% and improve
   brokered node packing by at least 20%, even after adding the enforcement
   mechanism; and
2. preserve hard per-sandbox CPU, memory, PID, storage, ownership, epoch,
   cleanup, and failure boundaries without a privileged Pod, host path, host
   namespace, host runtime socket, or general-purpose node agent.

The thresholds reflect the minimum material gain required to offset a larger
trusted computing base, multi-tenant worker lifecycle, more complex
reconciliation, and an increased failure blast radius. They were fixed before
the retained measurement.

## Reproducible measurement

Run the gate on a labeled k3s node after importing
`sandboxd-fixed-runtime:local`:

```bash
tools/performance/run-density-gate.sh \
  --slots 16 \
  --output /tmp/sandboxd-density-gate.json
```

The retained raw result is
[`benchmarks/dense-worker-2026-07-25.json`](benchmarks/dense-worker-2026-07-25.json).
It ran commit `abaf313000f70b6d42aa6b41598acf1583dcd669` with k3s
`v1.36.1+k3s1`, Linux `7.0.0-1009-ibm`, and runsc
`release-20260714.0`.

Sixteen real Level B workers were scheduled. Each held one independent active
gVisor sandbox while the script read its complete Pod cgroup. The dense result
is deliberately more favorable than an implementation could be: it charges
one median clean-worker footprint, adds only each measured active-minus-idle
sandbox increment, shares the entire declared broker request, and assigns zero
cost to slot state, cgroup enforcement, monitoring, cleanup, contention, and
the broker itself.

| Measurement | P50 | P95 | P99 |
| --- | ---: | ---: | ---: |
| Clean worker memory | 1.72 MB | 1.88 MB | 1.88 MB |
| Active worker memory | 41.18 MB | 41.78 MB | 41.78 MB |
| Sequential activation | 786 ms | 843 ms | 843 ms |
| Stop to clean replacement | 6.578 s | 6.614 s | 6.614 s |

All 16 workers became ready in 4.213 seconds. Activating all slots
sequentially took 13.024 seconds; replacing them after concurrent stop took
6.618 seconds.

The optimistic dense bound saved only 3.94% of measured worker memory and
improved brokered scheduler packing from 58 to 64 slots, or 10.34%. It also
changed one worker failure from one lost sandbox to 16. Both economic results
missed their thresholds before any dense-mode overhead was charged.

Exploratory 32-slot burst runs strengthened the rejection: one successful run
had 18.460-second P99 activation and 11.022-second P99 replacement, while
subsequent high-pressure runs exercised fail-closed worker quarantine and a
resource kill. Those stress runs are operational evidence, not inputs to the
retained sequential economics result.

## Security and operational cost

Kubernetes applies CPU, memory, PID, and ephemeral-storage enforcement to a
Pod, not to tenant-selected process groups inside one Pod. A hard dense mode
would therefore need one of:

- a writable cgroup-v2 subtree delegated by the host runtime;
- a privileged or host-integrated node agent; or
- a narrow host cgroup broker that can identify and move every runsc, Sentry,
  gofer, and helper process before guest execution.

The first is not a portable Kubernetes Pod contract. The second violates the
reduced deployment boundary. The third adds a host authority that must
authenticate tenant, sandbox, worker, resource shape, and lease epoch; reject
paths, PIDs, and controller values from tenant input; reconcile restarts; and
quarantine every ambiguous cleanup. It still does not provide per-sandbox
storage quota without a separate CSI or storage broker.

Sharing one gVisor Sentry would not solve this problem because it would merge
the process, memory, socket, lifecycle, and checkpoint boundary. A compliant
dense mode still needs one Sentry and gofer set per sandbox, which is why the
measured shareable worker overhead is small.

## Consequences

- Dense mode is not implemented and cannot be enabled accidentally.
- One worker Pod continues to admit exactly one tenant sandbox and is replaced
  after terminal use.
- Kubernetes remains the hard aggregate CPU, memory, PID, and storage
  enforcement boundary without host integration.
- Warm pools remain the supported way to reduce activation latency.
- A node or worker failure affects one active tenant sandbox per worker Pod.

Reconsider this decision only if Kubernetes or the selected runtime exposes a
standard, non-privileged hard sub-Pod resource boundary and a new retained
benchmark passes both gates on representative small, standard, and large
resource shapes.

Relevant upstream contracts:

- [Kubernetes resource management for Pods and containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
- [Kubernetes cgroup v2 architecture](https://kubernetes.io/docs/concepts/architecture/cgroups/)
- [Kubernetes delegated cgroup-tree requirement for rootless node components](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-in-userns/#creating-a-delegated-cgroup-tree)
