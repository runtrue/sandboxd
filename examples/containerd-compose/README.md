# Containerd image-provider fixture

This fixture resolves Alpine through an OCI registry, pins its index, platform
manifest, configuration, and layer descriptors, and stores the verified content
in containerd. The runtime mounts a read-only snapshotter view and passes only
the resulting provider handle to gVisor.

```bash
sudo runtrue-sandboxctl lock \
  --compose examples/containerd-compose/compose.yaml \
  --output /tmp/containerd-topology.lock.json

sudo runtrue-sandboxctl prepare-image \
  --reference docker.io/library/alpine:3.20
```

The topology starts a persistent BusyBox `nc` echo service and a client in one
shared gVisor sandbox. The client resolves `server` over the private sandbox
network and must print `containerd-provider-ok`.
