#!/usr/bin/env bash
set -euo pipefail

containerd_address=/run/containerd/containerd.sock
sandboxd_socket=/run/runtrue-sandboxd/control.sock

install -d -m 0700 \
  /run/containerd/state \
  /var/lib/pod-containerd/root \
  /var/lib/runtrue-sandboxd/images \
  /var/lib/runtrue-sandboxd/state

/usr/local/bin/containerd \
  --root /var/lib/pod-containerd/root \
  --state /run/containerd/state \
  --address "$containerd_address" \
  --log-level warn &
containerd_pid=$!
sandboxd_pid=

shutdown() {
  if [[ -n $sandboxd_pid ]]; then
    /usr/local/bin/runtrue-sandboxd shutdown \
      --socket "$sandboxd_socket" >/dev/null 2>&1 || true
  fi
  kill -TERM "$containerd_pid" >/dev/null 2>&1 || true
}
trap shutdown EXIT INT TERM

for _ in $(seq 1 100); do
  if /usr/bin/ctr --address "$containerd_address" version >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$containerd_pid" 2>/dev/null; then
    wait "$containerd_pid"
  fi
  sleep 0.1
done
/usr/bin/ctr --address "$containerd_address" version >/dev/null

/usr/local/bin/runtrue-sandboxd serve \
  --worker-id "worker-${SANDBOXD_WORKER_ID:-local}" \
  --resource-shape "${SANDBOXD_RESOURCE_SHAPE:-dynamic-v1}" \
  --sandbox-cpu-millis "${SANDBOXD_SANDBOX_CPU_MILLIS:-2000}" \
  --sandbox-memory-bytes "${SANDBOXD_SANDBOX_MEMORY_BYTES:-2147483648}" \
  --sandbox-pids "${SANDBOXD_SANDBOX_PIDS:-512}" \
  --sandbox-ephemeral-storage-bytes \
    "${SANDBOXD_SANDBOX_EPHEMERAL_STORAGE_BYTES:-6442450944}" \
  --maximum-services "${SANDBOXD_MAXIMUM_SERVICES:-16}" \
  --socket "$sandboxd_socket" \
  --state-root /var/lib/runtrue-sandboxd/state \
  --image-store /var/lib/runtrue-sandboxd/images \
  --ctr /usr/bin/ctr \
  --containerd-address "$containerd_address" \
  --containerd-namespace runtrue-sandboxd \
  --snapshotter native \
  --network-mode loopback \
  --cgroup-mode external \
  --runsc /usr/local/bin/runsc \
  --ip /usr/sbin/ip \
  --nft /usr/sbin/nft &
sandboxd_pid=$!

set +e
wait -n "$containerd_pid" "$sandboxd_pid"
status=$?
set -e
shutdown
wait "$sandboxd_pid" >/dev/null 2>&1 || true
wait "$containerd_pid" >/dev/null 2>&1 || true
exit "$status"
