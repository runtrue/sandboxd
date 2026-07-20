# Performance feedback

Pull request performance runs start only after an authorized user requests one.
Opening or updating a pull request does not start a run, and performance is not
a required merge check. This bounds hosted-runner use and keeps measurements
from shared virtual machines out of deterministic release gates.

## Starting a run

A repository collaborator with `write`, `maintain`, or `admin` permission can
comment exactly `/perf` on an open pull request targeting `main`. Alternatively,
they can dispatch the **PR performance** workflow from `main` and enter a pull
request number. Manual dispatch accepts 100–20,000 signed requests and
concurrency between 1 and 64.

The optional `PERF_APPROVERS` repository variable narrows authorization beyond
GitHub repository permissions. Its value is a comma-separated list of GitHub
usernames. When it is nonempty, the initiator must have one of the permissions
listed above and appear in that list.

The workflow maintains one bot comment per pull request. It first records who
started the run, then replaces that status with base-versus-head throughput,
latency, and release-binary-size measurements. Raw JSON results are retained as
a workflow artifact for 14 days. A failed benchmark updates the same comment
with a link to its logs.

## Security boundary

Comment-triggered workflows and the benchmark harness come from `main`. Manual
dispatch from any other ref is rejected. GitHub supplies the pull request base
and head commit IDs, and the benchmark job verifies both IDs after checkout.

The job that builds and executes pull request code has only `contents: read`,
does not persist checkout credentials, receives no repository secrets, and runs
on an ephemeral GitHub-hosted runner. The benchmark daemon runs as root to
exercise the supported `sandboxd` control path, so an authorized collaborator
must review the change before starting it. The authorization and reporting jobs
can write PR comments, but neither checks out nor executes pull request code.
The reporting job parses the retained JSON as data and validates its schema and
numeric fields before creating a comparison.

## Measurement scope

The hosted benchmark compares the signed workload control path at the pull
request base and head on the same runner. Each revision receives a fresh daemon,
state directory, replay journal, and audit journal. Measurements cover:

- fresh Unix-socket connections;
- signed work-order verification;
- replay and audit durability;
- bounded connection handling;
- sequential latency;
- concurrent latency and throughput; and
- stripped release-binary size.

The default 12,000-request sample crosses the replay journal's 10,000-append
compaction boundary instead of measuring only its initial steady state.

It does not run a guest or measure gVisor creation, pause, snapshot, or restore.
Those privileged lifecycle checks remain in the manually dispatched dedicated
gVisor workflow because a normal hosted runner is not a stable production-like
gVisor worker.

GitHub-hosted runners have variable CPU and storage neighbors. The PR comment
flags a possible regression when throughput falls by more than 10% or p99
latency rises by more than 15%; relative performance alone never fails the
workflow. Re-run a flagged comparison, then confirm it on a dedicated worker
before using it for a release decision.

## Running locally

The same harness can measure a local checkout:

```bash
tools/performance/run-control-plane.sh \
  --source /absolute/path/to/sandboxd \
  --output /tmp/sandboxd-performance.json
```

The caller needs passwordless `sudo`, Python 3, `setpriv`, and the pinned Rust
toolchain. No gVisor, Docker Engine, guest image, or external service is needed.
