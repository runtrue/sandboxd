#!/usr/bin/env bash
set -euo pipefail

socket=/run/runtrue-sandboxd/control.sock
containerd_address=${CONTAINERD_ADDRESS:-/run/k3s/containerd/containerd.sock}
snapshotter=${CONTAINERD_SNAPSHOTTER:-overlayfs}
image_store=/var/lib/runtrue-sandboxd/images
lock=/tmp/sandboxd-k3s-conformance.lock.json
sandbox="k3s-conformance-$(date +%s)"

ctl() {
  runtrue-sandboxctl \
    --containerd-address "$containerd_address" \
    --containerd-namespace runtrue-sandboxd \
    --snapshotter "$snapshotter" \
    "$@"
}

cleanup() {
  runtrue-sandboxd stop \
    --socket "$socket" \
    --sandbox "$sandbox" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== Outer Kubernetes pod =="
echo "kernel=$(uname -r)"
echo "cgroup=$(cat /proc/self/cgroup)"
if [[ -d /opt/runtrue-sandboxd/fixed-rootfs ]]; then
  echo "image_provider=pre-expanded-fixed-rootfs"
  lock=/opt/runtrue-sandboxd/fixed-runtime.lock.json
else
  echo "containerd=$(/usr/bin/ctr --address "$containerd_address" version | awk '/Version:/ {print $2}' | paste -sd, -)"
fi
runsc --version

echo "== Resolve and prepare nested OCI image =="
if [[ ! -d /opt/runtrue-sandboxd/fixed-rootfs ]]; then
  ctl lock \
    --compose /opt/runtrue-sandboxd/conformance-fixed.yaml \
    --output "$lock" \
    --image-store "$image_store"
  ctl prepare-image \
    --reference mirror.gcr.io/library/python:3.13-slim \
    --image-store "$image_store"
else
  jq -e '.schema_version == 6 and (.services | length == 2)' "$lock" >/dev/null
  echo "using pinned lock and pre-expanded rootfs baked into the pod image"
fi

echo "== Ask sandboxd to admit and create the nested topology =="
runtrue-sandboxd admit --socket "$socket" --lock "$lock"
runtrue-sandboxd create \
  --socket "$socket" \
  --lock "$lock" \
  --sandbox "$sandbox" \
  --timeout-seconds 30

echo "== Prove a gVisor Sentry is alive below sandboxd =="
for _ in $(seq 1 40); do
  if pgrep -a runsc >/tmp/runsc-processes; then
    break
  fi
  sleep 0.25
done
test -s /tmp/runsc-processes
cat /tmp/runsc-processes

echo "== Wait for nested client result =="
logs=
for _ in $(seq 1 80); do
  logs=$(runtrue-sandboxd logs \
    --socket "$socket" \
    --sandbox "$sandbox" \
    --container client)
  if jq -e '.result != null' >/dev/null <<<"$logs"; then
    break
  fi
  sleep 0.25
done
echo "$logs" | jq .
jq -e '
  .ok == true
  and .result.exit_code == 0
  and (.result.stdout | contains("nested-container-passed"))
' >/dev/null <<<"$logs"

echo "== Sandbox and cgroup accounting =="
runtrue-sandboxd inspect --socket "$socket" --sandbox "$sandbox" | jq .
runtrue-sandboxd stats --socket "$socket" | jq .

echo "CONFORMANCE_PASS: sandboxd running in k3s created two gVisor child containers."
