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

## Snapshot measurements

Snapshot and restore responses retain storage measurements from the real
artifact path. Snapshot results include object count, logical bytes,
transferred bytes, reused objects, and publication latency. A sandbox created
by restore includes transferred bytes, materialization, cohort validation,
transfer claim, runtime restore, and total restore latency in its status.
Snapshot responses also retain checkpoint and source-cleanup latency; a
stop-and-move response adds durable-fence and transfer-grant latency. When a
topology has writable roots, the response also reports writable-diff export
latency and the object totals include those OCI diff archives. Storage values
cover hashing, envelope encryption, provider transfer, verified decryption, and
immutable local publication. Runtime restore ends when runsc reports all
selected services restored. Guest-level time to first instruction requires an
instrumented workload and is not inferred from that signal.

The local lifecycle fixture prints these fields while exercising both a live
copy and stop-and-move:

```bash
sudo ./examples/python-compose/run-snapshot-local.sh
```

Measure the stripped local-worker binary with:

```bash
cargo build --release --package runtrue-sandboxd
stat --format=%s target/release/runtrue-sandboxd
```

One local run on the validated x86-64 cohort on 2026-07-20 produced:

| Mode | Logical bytes | Publish transfer | Publish | Restore transfer | Materialize |
| --- | ---: | ---: | ---: | ---: | ---: |
| live | 24,617,897 | 24,620,662 | 281 ms | 24,621,308 | 176 ms |
| stop-and-move | 24,613,224 | 24,615,989 | 291 ms | 24,616,644 | 172 ms |

Both publications reused one metadata object. The same checkout produced a
3,159,488-byte release binary. `main` before the artifact-store change was
2,864,456 bytes. These are single-host reference values, not release thresholds.

After adding the fenced migration protocol, one local run on the same class of
worker on 2026-07-21 produced:

| Mode | Fence | Checkpoint | Publish | Source cleanup | Materialize | Cohort check | Claim | Runtime restore | Total restore |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| live | n/a | 222 ms | 283 ms | n/a | 170 ms | 21 ms | n/a | 641 ms | 836 ms |
| stop-and-move | 1 ms | 161 ms | 292 ms | 120 ms | 169 ms | 21 ms | 0 ms | 575 ms | 768 ms |

This run used the local provider and therefore exercised a same-worker transfer
grant and claim, not a cross-worker data transfer. The claim rounded below one
millisecond. These measurements end when runsc reports restoration complete;
they are not guest-level time to first instruction.

After adding one quota-backed writable root, a local run on 2026-07-21 produced:

| Mode | Logical bytes | Writable export | Checkpoint | Publish | Source cleanup | Materialize | Runtime restore | Total restore |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| live | 26,091,509 | 1 ms | 152 ms | 308 ms | n/a | 188 ms | 684 ms | 896 ms |
| stop-and-move | 26,091,557 | 1 ms | 152 ms | 314 ms | 243 ms | 187 ms | 622 ms | 834 ms |

This run reported a 2,180 ms cached create. After flushing the writable
filesystem, the sparse quota image had 1,220,608 allocated host bytes for the
1,100,000-byte payload, counter, and ext4 metadata—about 1.11 times the payload
alone. The payload retained its SHA-256 digest, mode `0640`, and length through
both restores. These are single-run local diagnostics rather than release
thresholds.

## S3 artifact-provider measurements

The S3 conformance gate runs an optimized artifact test against the pinned
MinIO image over loopback. It exercises both single-part and multipart objects,
cross-worker materialization, concurrent publication, corrupt-object rejection,
fault-injected upload and download interruption, two-page listing, concurrent
garbage collection, and abandoned multipart cleanup. The same process first
runs the fixture through the local provider so provider measurements share a
host and build:

```bash
./tools/test-s3-artifacts.sh
```

One run on 2026-07-22, using a tmpfs-backed MinIO data directory and a 5,242,915
byte logical fixture, produced:

| Provider | Cold initialization | Publish transfer | Publish | Publish throughput | Materialize transfer | Materialize | Materialize throughput |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| local | 32 µs | 5,244,991 B | 63 ms | 83,253,825 B/s | 5,244,991 B | 36 ms | 145,694,194 B/s |
| `s3-wire` + MinIO | 1,859 µs | 5,244,973 B | 179 ms | 29,301,525 B/s | 5,244,973 B | 44 ms | 119,203,931 B/s |

The same checkout's stripped release binaries measured:

| Build | Bytes |
| --- | ---: |
| default, with `s3-wire` artifact support | 7,881,912 |
| `--no-default-features`, local provider only | 4,271,552 |

These are retained single-run diagnostics, not release thresholds. The
loopback MinIO result isolates provider overhead but does not predict WAN or
AWS service latency. Re-run on the intended worker cohort before making a
capacity decision.

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
