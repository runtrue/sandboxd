# Workload and suspension model

The production scheduling unit is one sandbox on one clean worker Pod. A
worker accepts exactly one assignment and is replaced after terminal use.
Warm capacity is a pool of clean worker Pods, not a pool of mutable tenant
containers.

## Task assignments

Every independent task receives a fresh sandbox. The worker starts the locked
topology against an already prepared image root, returns the bounded result,
and becomes consumed. `sandboxd` deliberately provides no general command
injection or `exec` operation against an existing sandbox. Reusing a mutable
tenant process across unrelated assignments would weaken image attestation,
idempotency, resource accounting, cleanup, and tenant isolation.

A long-lived application may expose its own authenticated task protocol through
a declared ingress service. That is application traffic inside one leased
sandbox, not a new sandboxd assignment, and the worker remains unavailable to
other tenants until the application is cancelled or fenced.

## Multi-container applications

One sandbox may contain up to the operator-reviewed service ceiling. The
checked-in standard pool permits eight services. The first service owns the
gVisor sandbox container and later services are CRI child containers in the
same Sentry. This is appropriate for tightly coupled components such as a
server, sidecar, and task client.

The complete topology shares one lifecycle, network boundary, checkpoint, and
aggregate Pod resource envelope. Child containers cannot be independently
paused, restored, reassigned, or given a separate hard Kubernetes resource
boundary.

## Pause and capacity release

Pause is a short control-plane operation. It freezes every child in the
sandbox, deactivates ingress, and retains the worker Pod and all reserved
memory, CPU, PID, and storage capacity. A paused sandbox never becomes a clean
worker slot and cannot accept another assignment.

When suspension must return capacity, use a `stop_and_move` snapshot. It
checkpoints the complete sandbox, fences and removes the source, and allows a
later restore under a new assignment. Operators choose the maximum economical
pause duration from workload cost and restore latency; sandboxd does not
silently convert pause into a destructive or storage-bearing operation.

The reviewed policy is recorded in
[`deploy/k3s/warm-pool-slo.json`](../deploy/k3s/warm-pool-slo.json):

- fresh sandbox per independent assignment;
- short pause retains its worker;
- capacity-releasing suspension uses `stop_and_move`; and
- individual child pause is unsupported.

## Warm-pool objective

The checked-in reference objective requires concurrent activation P99 at or
below one second for two simultaneous starts per sandbox node. A separate
nine-second P99 budget covers clean-worker replacement, including the
one-second post-initialization stabilization window. The gate requires at least
100 measured activations so a P99 result is never inferred from a tiny sample.

At a peak of one new assignment per second, a nine-second replacement window
consumes nine clean slots. Applying the declared 25 percent safety margin
requires twelve warm slots:

```text
ceil(max(2-task burst, 1 task/s * 9 s) * 1.25) = 12
```

The calculation is enforced against the worker-pool catalog by
`tools/performance/warm_pool.py`. The end-to-end runner performs an unscored
priming cohort followed by a measured concurrent cohort:

```bash
tools/performance/run-warm-pool-slo.sh \
  --output /tmp/sandboxd-warm-pool-slo.json
```

The result fails closed when activation or replacement exceeds its budget,
the test is not concurrent, the measured concurrency differs from policy, or
the configured headroom is insufficient. The report distinguishes the minimum
node count for the declared burst from the conservative node count required if
the entire warm reserve starts simultaneously. Worker StatefulSets use a
hostname spread constraint so available nodes receive a balanced share of
warm workers.

Traffic above the reference rate or burst requires a site-specific policy,
more headroom, and enough labeled nodes. It must be remeasured on the exact
production CPU, kernel, Kubernetes, runsc, image, and resource cohort.
