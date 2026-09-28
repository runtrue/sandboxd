# Independent security review package

This package defines the release gate for an independent adversarial review of
sandboxd. It prepares reproducible evidence; it does not replace an independent
reviewer or assert that a review has happened.

## Independence and candidate identity

The reviewer must not have implemented the reviewed changes and must control
their test plan, findings, and final disposition. Project maintainers may
explain architecture and provide infrastructure, but may not downgrade or close
a finding on the reviewer's behalf.

The release operator creates a signed, annotated, non-release tag at the exact
`main` commit:

```bash
git switch main
git pull --ff-only
git tag -s security-review-candidate-20260725.1 \
  -m "sandboxd security review candidate 20260725.1"
git push origin security-review-candidate-20260725.1
```

Candidate tags use the `security-review-candidate-YYYYMMDD.N` namespace and do
not trigger artifact publication. Do not move or reuse a candidate tag. Any
code change after review starts requires a new candidate tag and explicit
reviewer confirmation of the delta.

The reviewer checks out the tag in a clean clone, builds all in-scope images
from that checkout, and runs:

```bash
./tools/security-review/verify-target.sh \
  --tag security-review-candidate-20260725.1 \
  --repository runtrue/sandboxd \
  --image fixed=sandboxd-fixed-runtime:review \
  --image host-integrated=sandboxd-host-integrated:review \
  --image preparer=sandbox-image-preparer:review \
  --image broker=sandbox-broker:review \
  --image gateway=sandbox-gateway:review \
  | tee review-target.json
```

The verifier fails unless GitHub reports a valid signature on the annotated
tag, the tag targets the checked-out current `main` commit, the machine matches
the exact [`cohort.json`](cohort.json), all required images exist, and the
checked-in runtime pins match the cohort. Retain `review-target.json`, the
candidate image export or registry digests, and its SHA-256 checksum with the
review evidence.

## Minimum adversarial scope

Passing existing tests is a starting point, not the review result. The reviewer
must attempt bypasses and failure cases in every row.

| Boundary | Required implementation areas | Existing evidence to reproduce | Required adversarial emphasis |
| --- | --- | --- | --- |
| Worker and broker authority | Kubernetes profiles, operator/workload sockets, peer credentials, broker registration | `test-k3s-fixed-runtime.sh`, `test-k3s-brokered-runtime.sh`, `test-k3s-autoscaling.sh` | Capability and user-namespace escape, confused deputy, forged/stale registration, socket substitution |
| OCI and filesystem inputs | Image provider, archive extraction, writable root, typed volumes, artifact and secret paths | `test-k3s-image-preparation.sh`, `test-k3s-directory-volumes.sh`, `test-s3-artifacts.sh` | Traversal, links, device/special files, decompression limits, digest races, quota bypass, cross-tenant reads |
| gVisor construction | OCI bundle generation, runsc command line, gofers, guest profiles | `test-k3s-fixed-runtime.sh`, local lifecycle and snapshot suites | Host path exposure, unsafe mount propagation, capability leakage, guest-profile mismatch, helper replacement |
| Network and resources | DNS, CONNECT egress, reverse ingress, namespaces, cgroup v2, cleanup | `test-k3s-userspace-egress.sh`, `test-k3s-resource-limits.sh` | Metadata/private-address bypass, tunnel reuse, parser ambiguity, PID/memory/storage escape, leaked processes and sockets |
| Authorization and placement | Signed work orders, replay store, tenant/workspace scoping, epochs and fencing | Broker, autoscaling, and placement workspace tests | Signature substitution, replay after crash, canonicalization ambiguity, IDOR, stale assignment and split brain |
| Snapshot and recovery | AEAD snapshots, S3 conditional publication, claims, restore compatibility | `test-s3-artifacts.sh`, `test-k3s-multinode-recovery.sh`, local snapshot suite | Nonce/key misuse, rollback, truncation, concurrent publisher races, corrupted metadata, partial failure |
| Host-integrated compatibility | Host containerd, loop/ext4, mount helpers, nftables, external command execution | `examples/python-compose/run-local.sh`, `run-snapshot-local.sh`, dynamic runtime validation | Socket abuse, namespace crossover, mount-option injection, loop leakage, nftables collateral damage, executable/path replacement |

At minimum, execute the portable CI suite, the full local-only k3s suite, and
the privileged gVisor lifecycle/snapshot suite from the candidate checkout.
Record every command, exit status, start/end time, and unredacted output in the
private evidence store. Record the exact Kubernetes manifests after rendering,
Pod security contexts, image IDs/digests, kernel logs, remaining namespaces,
cgroups, mounts, loop devices, firewall rules, and processes after cleanup.

Live exploit details, credentials, tenant data, and working escape techniques
belong in the agreed private review channel or a GitHub private security
advisory, never a public issue or Actions artifact.

## Findings and release gate

Use [`finding-template.md`](finding-template.md) for every finding, including
informational findings. Severity, reproduction evidence, affected candidate,
remediation status, fix commit, regression test, and reviewer retest are
mandatory.

Critical and high findings must be fixed, regression-tested, and retested by
the independent reviewer against a new signed candidate before sandboxd is
positioned as production-ready or as a complete multi-tenant security boundary.
They cannot pass this gate through risk acceptance. Medium and lower findings
require an explicit disposition and tracked remediation or documented residual
risk.

Completion requires a public document derived from
[`public-summary-template.md`](public-summary-template.md). The reviewer must
approve it. It identifies the reviewer, candidate tag and commit, cohort,
scope, exclusions, finding counts, critical/high disposition, limitations, and
review conclusion without including weaponizable detail.
