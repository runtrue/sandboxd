#!/usr/bin/env bash
set -euo pipefail

namespace=${SANDBOXD_K3S_NAMESPACE:-sandboxd-system}
worker_controller=sandboxd-fixed-runtime
label=app.kubernetes.io/name=sandboxd-fixed-runtime
socket=/run/runtrue-sandboxd/control.sock
suffix=${GITHUB_RUN_ID:-local}

if [[ $(id -u) -eq 0 ]]; then
  privilege=()
else
  privilege=(sudo -n)
fi

for kind in cpu memory pids storage; do
  test -s "deploy/k3s/conformance-${kind}.lock.json"
done

worker_pod=
worker_pid=
pod_cgroup=

start_worker() {
  kubectl delete deployment -n "$namespace" "$worker_controller" \
    --ignore-not-found --wait=true >/dev/null
  kubectl delete job -n "$namespace" "$worker_controller" \
    --ignore-not-found --wait=true >/dev/null
  kubectl apply -f deploy/k3s/sandboxd-fixed-runtime.yaml >/dev/null
  for _ in $(seq 1 180); do
    worker_pod=$(kubectl get pod -n "$namespace" -l "$label" \
      --field-selector=status.phase=Running \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    if [[ -n $worker_pod ]] && kubectl exec -n "$namespace" "$worker_pod" -- \
      runtrue-sandboxd ready --socket "$socket" >/dev/null 2>&1
    then
      local container_id
      container_id=$(kubectl get pod -n "$namespace" "$worker_pod" \
        -o jsonpath='{.status.containerStatuses[0].containerID}')
      container_id=${container_id#containerd://}
      worker_pid=$("${privilege[@]}" k3s crictl inspect "$container_id" | jq -r '.info.pid')
      local container_cgroup
      container_cgroup=$("${privilege[@]}" awk -F: '$1 == "0" {print $3}' \
        "/proc/$worker_pid/cgroup")
      pod_cgroup=$(dirname "$container_cgroup")
      test "$("${privilege[@]}" cat "/sys/fs/cgroup${pod_cgroup}/pids.max")" -eq 256
      return 0
    fi
    sleep 1
  done
  echo "resource conformance worker did not become ready" >&2
  return 1
}

create_sandbox() {
  local kind=$1
  local sandbox="resource-${kind}-${suffix}"
  local lock="deploy/k3s/conformance-${kind}.lock.json"
  kubectl exec -i -n "$namespace" "$worker_pod" -- \
    runtrue-sandboxd admit --socket "$socket" --lock /dev/stdin \
    <"$lock" >/dev/null
  kubectl exec -i -n "$namespace" "$worker_pod" -- \
    runtrue-sandboxd create \
    --socket "$socket" \
    --lock /dev/stdin \
    --sandbox "$sandbox" \
    --timeout-seconds 30 <"$lock" >/dev/null
}

stop_sandbox() {
  local kind=$1
  kubectl exec -n "$namespace" "$worker_pod" -- \
    runtrue-sandboxd stop \
    --socket "$socket" \
    --sandbox "resource-${kind}-${suffix}" >/dev/null 2>&1 || true
}

wait_for_marker() {
  local kind=$1
  local marker=$2
  local output=
  for _ in $(seq 1 120); do
    output=$(kubectl exec -n "$namespace" "$worker_pod" -- \
      runtrue-sandboxd logs \
      --socket "$socket" \
      --sandbox "resource-${kind}-${suffix}" \
      --container stress 2>/dev/null || true)
    if jq -e --arg marker "$marker" \
      '.ok == true and (.result.stdout | contains($marker))' \
      >/dev/null 2>&1 <<<"$output"
    then
      printf '%s' "$output"
      return 0
    fi
    sleep 0.25
  done
  echo "resource conformance marker $marker did not appear" >&2
  return 1
}

start_worker
cpu_before=$("${privilege[@]}" awk '/^nr_throttled / {print $2}' \
  "/sys/fs/cgroup${pod_cgroup}/cpu.stat")
create_sandbox cpu
cpu_after=$cpu_before
for _ in $(seq 1 40); do
  sleep 0.25
  cpu_after=$("${privilege[@]}" awk '/^nr_throttled / {print $2}' \
    "/sys/fs/cgroup${pod_cgroup}/cpu.stat")
  if ((cpu_after > cpu_before)); then
    break
  fi
done
((cpu_after > cpu_before))
stop_sandbox cpu

start_worker
create_sandbox pids
pids_output=$(wait_for_marker pids pid-ceiling-passed)
pids_children=$(jq -r '.result.stdout | fromjson | .children' <<<"$pids_output")
((pids_children > 0 && pids_children < 256))
stop_sandbox pids

start_worker
create_sandbox storage
storage_output=$(wait_for_marker storage storage-ceiling-passed)
storage_written=$(jq -r '.result.stdout | fromjson | .written' <<<"$storage_output")
((storage_written > 0 && storage_written <= 17825792))
stop_sandbox storage

start_worker
oom_before=$("${privilege[@]}" awk '/^oom_kill / {print $2}' \
  "/sys/fs/cgroup${pod_cgroup}/memory.events")
create_sandbox memory
oom_after=$oom_before
for _ in $(seq 1 120); do
  sleep 0.25
  oom_after=$("${privilege[@]}" awk '/^oom_kill / {print $2}' \
    "/sys/fs/cgroup${pod_cgroup}/memory.events" 2>/dev/null || echo "$oom_after")
  if ((oom_after > oom_before)); then
    break
  fi
done
((oom_after > oom_before))
kubectl wait --for=condition=Ready node --all --timeout=30s >/dev/null
stop_sandbox memory

printf '{"cpu_nr_throttled_delta":%d,"pid_children_before_ceiling":%d,"tmpfs_bytes_before_enospc":%d,"pod_oom_kill_delta":%d}\n' \
  "$((cpu_after - cpu_before))" \
  "$pids_children" \
  "$storage_written" \
  "$((oom_after - oom_before))"
