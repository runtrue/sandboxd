# Performance testing

## Pull request benchmark

A collaborator with `write`, `maintain`, or `admin` permission can comment
exactly `/perf` on a pull request targeting `main`. The same test can be started
from the **PR performance** workflow with a pull request number, request count,
and concurrency.

`PERF_APPROVERS`, when set, further restricts who may start a run. Its value is a
comma-separated list of GitHub usernames.

The workflow compares the base and head commits on one ephemeral runner and
updates a single pull request comment. Raw JSON is retained as a workflow
artifact for 14 days. The benchmark measures:

- sequential and concurrent control-plane latency;
- concurrent throughput;
- signed work-order, replay-journal, and audit-journal overhead; and
- stripped release binary size.

It does not run a guest or measure gVisor lifecycle and snapshot operations.
Use the dedicated gVisor workflow for those tests.

### Security model

Workflow and harness code come from `main`. The benchmark job verifies the
GitHub-provided base and head commit IDs, has read-only repository access,
receives no repository secrets, and does not persist checkout credentials.

The benchmark executes pull request code as root on an ephemeral hosted runner.
Review the change before starting it. Jobs that authorize and report the run do
not execute pull request code.

## Local control-plane benchmark

```bash
tools/performance/run-control-plane.sh \
  --source /absolute/path/to/sandboxd \
  --output /tmp/sandboxd-performance.json
```

The caller needs passwordless `sudo`, Python 3, `setpriv`, and the pinned Rust
toolchain. gVisor and Docker Engine are not required.

## Lifecycle and snapshot measurements

Run the lifecycle fixture on a validated worker:

```bash
sudo ./examples/python-compose/run-snapshot-local.sh
```

Snapshot output reports logical and transferred bytes, reused objects,
checkpoint and publication latency, source cleanup, materialization, cohort
validation, transfer claims, and runtime restore. Writable-root snapshots also
report diff-export latency.

Runtime restore ends when runsc reports the selected services restored. It is
not guest time to first instruction; measuring that requires an instrumented
guest workload.

Measure the stripped worker binary with:

```bash
cargo build --release --package runtrue-sandboxd
stat --format=%s target/release/runtrue-sandboxd
```

## Artifact-provider benchmark

The conformance test compares the local and S3-compatible providers on the same
host:

```bash
./tools/test-s3-artifacts.sh
```

It covers single-part and multipart objects, cross-worker materialization,
concurrent publication, corruption, interrupted transfers, pagination,
garbage-collection races, and abandoned multipart cleanup.

Loopback MinIO measurements isolate provider overhead; they do not predict WAN
or AWS S3 latency. Record the commit, host cohort, configuration, and raw JSON
with any published result.
