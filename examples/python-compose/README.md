# Local two-service fixture

This fixture resolves the official Python slim image through the containerd OCI
provider and runs separate `server` and `client` services over a private bridge.
The Python programs are inline Compose commands. The client resolves `server`,
verifies its HTTP response, and exits. The lifecycle script then pauses,
inspects, resumes, and stops the sandbox before verifying cleanup.

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

The lifecycle script also runs `compose-oci-compat.yaml` under the
operator-enabled `oci-compat-v1` profile. It verifies the profile's capability
masks, `noNewPrivileges`, blocked raw sockets, masked proc paths, and read-only
sysctl paths.

The snapshot example keeps both containers running, creates and restores a live
copy while the source continues, then performs a stop-and-move restore under a
second sandbox identity. The client opts into a quota-backed writable OCI root
and atomically updates `/var/tmp/snapshot-counter`. Both paths verify that the
persistent connection and writable-root state survived and continued
advancing, and that a larger payload retains its digest, mode, and size.
