# Local two-service fixture

This fixture builds one Python image and runs separate `server` and `client`
services over a private bridge. The client resolves `server`, verifies its HTTP
response, and exits. The lifecycle script then pauses the remaining server,
inspects it, resumes it, stops the complete sandbox, and verifies cleanup.

```bash
./examples/python-compose/build-local.sh
sudo ./examples/python-compose/run-local.sh
sudo ./examples/python-compose/run-snapshot-local.sh
```

The three limit Compose files exercise memory OOM, bounded output, and host PID
enforcement.

The snapshot example keeps both containers running, creates and restores a live
copy while the source continues, then performs a stop-and-move restore under a
second sandbox identity. Both paths verify that the client's persistent
connection and `/tmp` counter survived and continued advancing.
