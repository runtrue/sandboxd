# Local two-service fixture

This fixture resolves the official Python slim image through the containerd OCI
provider and runs separate `server` and `client` services over a private bridge.
The small Python programs are inline Compose commands, so the test requires no
custom image, Docker Engine, GNU tar, hosted builder, or artifact registry. The
client resolves `server`, verifies its HTTP response, and exits. The lifecycle
script then pauses the remaining server, inspects it, resumes it, stops the
complete sandbox, and verifies cleanup.

The lifecycle also publishes `artifact-volume.txt` twice through the operator
socket, proving publication is idempotent, mounts the verified digest into the
client without putting its host source path in Compose or the topology lock,
and garbage-collects the unreferenced object after the sandbox stops.

```bash
sudo ./examples/python-compose/run-local.sh
sudo ./examples/python-compose/run-snapshot-local.sh
```

The three limit Compose files exercise memory OOM, bounded output, and host PID
enforcement.

The local lifecycle script also runs `compose-oci-compat.yaml` under the
operator-enabled `oci-compat-v1` profile. That fixture exercises `CAP_CHOWN`,
`CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_FSETID`, `CAP_SETGID`, and `CAP_SETUID`,
then verifies the exact capability masks, empty ambient/inheritable sets,
`noNewPrivileges`, blocked raw sockets, masked proc paths, and read-only sysctl
paths.

The snapshot example keeps both containers running, creates and restores a live
copy while the source continues, then performs a stop-and-move restore under a
second sandbox identity. The client opts into a quota-backed writable OCI root
and atomically updates `/var/tmp/snapshot-counter`. Both paths verify that the
persistent connection and writable-root state survived and continued
advancing, and that a larger payload retains its digest, mode, and size. The
script prints cached-create and sparse-backing allocation diagnostics.
