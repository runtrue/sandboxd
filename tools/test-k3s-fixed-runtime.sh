#!/usr/bin/env bash
set -euo pipefail

namespace=${SANDBOXD_K3S_NAMESPACE:-sandboxd-system}
worker_controller=sandboxd-fixed-runtime
worker_label=app.kubernetes.io/name=sandboxd-fixed-runtime
socket=/run/runtrue-sandboxd/control.sock
fixed_lock=deploy/k3s/fixed-runtime.lock.json
network_lock=deploy/k3s/conformance-network.lock.json
writable_lock=deploy/k3s/conformance-writable-root.lock.json
mismatch_lock=deploy/k3s/conformance-mismatch.lock.json
suffix=${GITHUB_RUN_ID:-local}
sandbox="ci-fixed-${suffix}"

if [[ $(id -u) -eq 0 ]]; then
  privilege=()
else
  privilege=(sudo -n)
fi

for command in jq kubectl; do
  command -v "$command" >/dev/null
done
for path in "$fixed_lock" "$network_lock" "$writable_lock" "$mismatch_lock"; do
  test -s "$path"
done

pod=
pod_uid=
active_sandbox=false
cleanup() {
  if [[ -n $pod ]] && [[ $active_sandbox == true ]]; then
    kubectl exec -n "$namespace" "$pod" -- \
      runtrue-sandboxd stop \
      --socket "$socket" \
      --sandbox "$sandbox" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_for_clean_worker() {
  local previous_uid=${1:-}
  local candidate
  local candidate_uid
  for _ in $(seq 1 180); do
    while IFS=$'\t' read -r candidate candidate_uid; do
      if [[ -n $candidate ]] && [[ $candidate_uid != "$previous_uid" ]]; then
        if kubectl exec -n "$namespace" "$candidate" -- \
          runtrue-sandboxd ready --socket "$socket" >/dev/null 2>&1
        then
          pod=$candidate
          pod_uid=$candidate_uid
          return 0
        fi
      fi
    done < <(
      kubectl get pod -n "$namespace" -l "$worker_label" -o json |
        jq -r '
          .items[]
          | select(.status.phase == "Running")
          | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
          | [.metadata.name, .metadata.uid]
          | @tsv
        '
    )
    sleep 1
  done
  echo "clean replacement worker did not become ready" >&2
  return 1
}

expect_stdin_failure() {
  local lock=$1
  local expected=$2
  shift 2
  local output
  local status
  set +e
  output=$(kubectl exec -i -n "$namespace" "$pod" -- "$@" <"$lock" 2>&1)
  status=$?
  set -e
  if [[ $status -eq 0 ]] || ! grep -Fq "$expected" <<<"$output"; then
    printf 'expected failure containing %q, got status %s:\n%s\n' \
      "$expected" "$status" "$output" >&2
    return 1
  fi
}

if ! kubectl get namespace "$namespace" >/dev/null 2>&1; then
  kubectl create namespace "$namespace"
fi

for manifest in \
  deploy/k3s/sandboxd-fixed-runtime.yaml \
  deploy/k3s/sandboxd-dynamic-runtime.yaml \
  deploy/k3s/sandboxd-host-integrated.yaml
do
  kubectl apply --dry-run=server -f "$manifest" >/dev/null
done

kubectl delete deployment -n "$namespace" "$worker_controller" \
  --ignore-not-found --wait=true >/dev/null
kubectl delete job -n "$namespace" "$worker_controller" \
  --ignore-not-found --wait=true >/dev/null
kubectl apply -f deploy/k3s/sandboxd-fixed-runtime.yaml
wait_for_clean_worker

pod_json=$(kubectl get pod -n "$namespace" "$pod" -o json)
jq -e '
  .spec.hostUsers == false
  and .spec.restartPolicy == "Always"
  and (.spec.hostNetwork // false) == false
  and (.spec.hostPID // false) == false
  and (.spec.hostIPC // false) == false
  and .spec.automountServiceAccountToken == false
  and .spec.enableServiceLinks == false
  and .spec.nodeSelector["runtrue.io/sandbox-node"] == "true"
  and .metadata.labels["runtrue.io/resource-shape"] == "standard-v1"
  and .metadata.ownerReferences[0].kind == "ReplicaSet"
  and .status.containerStatuses[0].restartCount == 0
  and ([.spec.volumes[] | select(has("hostPath") or has("projected"))] | length) == 0
  and (.spec.containers | length) == 1
  and .spec.containers[0].restartPolicy == "Never"
  and .spec.containers[0].securityContext.privileged == false
  and .spec.containers[0].securityContext.readOnlyRootFilesystem == true
  and .spec.containers[0].securityContext.allowPrivilegeEscalation == true
  and .spec.containers[0].securityContext.capabilities.drop == ["ALL"]
  and (.spec.containers[0].securityContext.capabilities.add | sort)
      == (["SETGID", "SETUID", "SYS_ADMIN", "SYS_CHROOT"] | sort)
  and (.spec.containers[0].env
      | any(.name == "POD_UID" and .valueFrom.fieldRef.fieldPath == "metadata.uid"))
  and (.spec.containers[0].args | index("--worker-id")) != null
  and (.spec.containers[0].args | index("--resource-shape")) != null
  and (.spec.containers[0].args | index("standard-v1")) != null
  and (.spec.containers[0].args | index("--sandbox-cpu-millis")) != null
  and (.spec.containers[0].args | index("--sandbox-memory-bytes")) != null
  and (.spec.containers[0].args | index("--sandbox-pids")) != null
  and (.spec.containers[0].args | index("--sandbox-ephemeral-storage-bytes")) != null
  and (.spec.containers[0].args | index("--network-mode")) != null
  and (.spec.containers[0].args | index("loopback")) != null
  and (.spec.containers[0].args | index("--cgroup-mode")) != null
  and (.spec.containers[0].args | index("external")) != null
' >/dev/null <<<"$pod_json"

kubectl get service -n "$namespace" -o json |
  jq -e '
    [.items[]
      | select(.spec.selector["app.kubernetes.io/name"]
          == "sandboxd-fixed-runtime")]
    | length == 0
  ' >/dev/null
kubectl get ingress -n "$namespace" -o json |
  jq -e '
    [.items[]
      | select(.metadata.labels["app.kubernetes.io/name"]
          == "sandboxd-fixed-runtime")]
    | length == 0
  ' >/dev/null
kubectl get networkpolicy -n "$namespace" sandboxd-default-deny >/dev/null

admit=$(kubectl exec -i -n "$namespace" "$pod" -- \
  runtrue-sandboxd admit --socket "$socket" --lock /dev/stdin <"$fixed_lock")
jq -e '
  .ok == true
  and (.result.admitted_images | length) == 1
  and .result.admitted_images[0].rootfs_digest
      == "sha256:c73e49867e5b68681c2222e1e7b60aca9218d5a83ded507226f89438cea40db1"
  and .result.admitted_images[0].rootfs_entries == 5621
  and .result.admitted_images[0].rootfs_bytes == 118293769
' >/dev/null <<<"$admit"

activation_started_ns=$(date +%s%N)
kubectl exec -i -n "$namespace" "$pod" -- \
  runtrue-sandboxd create \
  --socket "$socket" \
  --lock /dev/stdin \
  --sandbox "$sandbox" \
  --timeout-seconds 30 <"$fixed_lock" >/dev/null
active_sandbox=true

busy=$(kubectl exec -n "$namespace" "$pod" -- \
  runtrue-sandboxd ping --socket "$socket")
jq -e '
  .ok == true
  and .result.worker.state == "running"
  and .result.worker.ready == false
' >/dev/null <<<"$busy"

expect_stdin_failure "$fixed_lock" \
  "worker slot is not available" \
  runtrue-sandboxd create \
  --socket "$socket" \
  --lock /dev/stdin \
  --sandbox "ci-second-${suffix}" \
  --timeout-seconds 30

logs=
for _ in $(seq 1 80); do
  logs=$(kubectl exec -n "$namespace" "$pod" -- \
    runtrue-sandboxd logs \
    --socket "$socket" \
    --sandbox "$sandbox" \
    --container client)
  if jq -e '
    .result.exit_code == 0
    and (.result.stdout | contains("nested-container-passed"))
  ' >/dev/null 2>&1 <<<"$logs"; then
    break
  fi
  sleep 0.25
done
jq -e '
  .ok == true
  and .result.exit_code == 0
  and .result.stderr == ""
  and (.result.stdout | contains("\"kernel\": \"4.19.0-gvisor\""))
  and (.result.stdout | contains("\"marker\": \"nested-container-passed\""))
  and (.result.stdout | contains("\"uid\": 65534"))
' >/dev/null <<<"$logs"
first_output_ns=$(date +%s%N)

replacement_started_ns=$(date +%s%N)
kubectl exec -n "$namespace" "$pod" -- \
  runtrue-sandboxd stop \
  --socket "$socket" \
  --sandbox "$sandbox" >/dev/null
active_sandbox=false

previous_uid=$pod_uid
pod=
wait_for_clean_worker "$previous_uid"
replacement_ready_ns=$(date +%s%N)
stats=$(kubectl exec -n "$namespace" "$pod" -- \
  runtrue-sandboxd stats --socket "$socket")
jq -e '
  .ok == true
  and .result.worker.state == "clean"
  and .result.worker.ready == true
  and .result.active_operations == 0
  and .result.sandboxes == []
' >/dev/null <<<"$stats"

kubectl exec -i -n "$namespace" "$pod" -- \
  runtrue-sandboxd admit --socket "$socket" --lock /dev/stdin \
  <"$network_lock" >/dev/null
expect_stdin_failure "$network_lock" \
  "loopback network mode requires the none network profile" \
  runtrue-sandboxd create \
  --socket "$socket" \
  --lock /dev/stdin \
  --sandbox "ci-denied-network-${suffix}" \
  --timeout-seconds 30

previous_uid=$pod_uid
pod=
wait_for_clean_worker "$previous_uid"

kubectl exec -i -n "$namespace" "$pod" -- \
  runtrue-sandboxd admit --socket "$socket" --lock /dev/stdin \
  <"$writable_lock" >/dev/null
writable_sandbox="ci-writable-${suffix}"
writable_create_started_ns=$(date +%s%N)
writable_create=$(kubectl exec -i -n "$namespace" "$pod" -- \
  runtrue-sandboxd create \
  --socket "$socket" \
  --lock /dev/stdin \
  --sandbox "$writable_sandbox" \
  --timeout-seconds 30 <"$writable_lock")
active_sandbox=true
sandbox=$writable_sandbox
jq -e '
  .ok == true
  and .result.state == "running"
  and .result.running_services == 1
' >/dev/null <<<"$writable_create"
writable_create_ready_ns=$(date +%s%N)

writable_runtime=$(jq -r '.result.runtime_project' <<<"$writable_create")
writable_marker=
for _ in $(seq 1 80); do
  if writable_marker=$(kubectl exec -n "$namespace" "$pod" -- \
    /usr/local/bin/runsc \
    --root="/var/lib/runtrue-sandboxd/state/sandboxes/$writable_runtime/runsc" \
    --network=none \
    --ignore-cgroups=true \
    --platform=systrap \
    --overlay2="root:dir=/var/lib/runtrue-sandboxd/state/sandboxes/$writable_runtime/rootfs-overlay,size=67108864" \
    --file-access=exclusive \
    --file-access-mounts=exclusive \
    --directfs=false \
    --host-uds=none \
    --host-fifo=none \
    --net-raw=false \
    --allow-rootfs-tar-annotation=true \
    exec --user=65534:65534 \
    "rts-$writable_runtime-writer" \
    /bin/cat /var/tmp/result.txt 2>/dev/null)
  then
    break
  fi
  sleep 0.25
done
test "$writable_marker" = "writable-root-passed"

writable_quota=$(kubectl exec -n "$namespace" "$pod" -- \
  /usr/local/bin/runsc \
  --root="/var/lib/runtrue-sandboxd/state/sandboxes/$writable_runtime/runsc" \
  --network=none \
  --ignore-cgroups=true \
  --platform=systrap \
  --overlay2="root:dir=/var/lib/runtrue-sandboxd/state/sandboxes/$writable_runtime/rootfs-overlay,size=67108864" \
  --file-access=exclusive \
  --file-access-mounts=exclusive \
  --directfs=false \
  --host-uds=none \
  --host-fifo=none \
  --net-raw=false \
  --allow-rootfs-tar-annotation=true \
  exec --user=65534:65534 \
  "rts-$writable_runtime-writer" \
  /usr/local/bin/python3 -c \
  'import errno,json,os
p="/var/tmp/quota.bin"
written=0
result="no_enospc"
output=open(p,"wb",buffering=0)
try:
    for _ in range(80):
        output.write(b"x"*(1024*1024))
        written += 1024*1024
except OSError as error:
    result = "enospc" if error.errno == errno.ENOSPC else f"errno-{error.errno}"
finally:
    output.close()
    os.unlink(p)
print(json.dumps({"result":result,"written":written}))')
jq -e '
  .result == "enospc"
  and .written == 67108864
' >/dev/null <<<"$writable_quota"

writable_snapshot=$(kubectl exec -n "$namespace" "$pod" -- \
  runtrue-sandboxd snapshot \
  --socket "$socket" \
  --sandbox "$writable_sandbox" \
  --snapshot "ci-writable-live-${suffix}")
jq -e '
  .ok == true
  and .result.mode == "live"
  and .result.files >= 5
  and .result.size_bytes > 0
  and .result.writable_export_millis >= 0
' >/dev/null <<<"$writable_snapshot"
kubectl exec -n "$namespace" "$pod" -- \
  runtrue-sandboxd inspect \
  --socket "$socket" \
  --sandbox "$writable_sandbox" >/dev/null
kubectl exec -n "$namespace" "$pod" -- \
  runtrue-sandboxd stop \
  --socket "$socket" \
  --sandbox "$writable_sandbox" >/dev/null
active_sandbox=false

previous_uid=$pod_uid
pod=
wait_for_clean_worker "$previous_uid"

expect_stdin_failure "$mismatch_lock" \
  "locked image does not match the image bound to the fixed rootfs" \
  runtrue-sandboxd admit \
  --socket "$socket" \
  --lock /dev/stdin

container_id=$(kubectl get pod -n "$namespace" "$pod" \
  -o jsonpath='{.status.containerStatuses[?(@.name=="sandboxd")].containerID}')
container_id=${container_id#containerd://}
pid=$("${privilege[@]}" k3s crictl inspect "$container_id" | jq -r '.info.pid')
[[ $pid =~ ^[1-9][0-9]*$ ]]

cgroup_path=$("${privilege[@]}" awk -F: '$1 == "0" {print $3}' "/proc/$pid/cgroup")
test -n "$cgroup_path"
pod_cgroup_path=$(dirname "$cgroup_path")
test "$("${privilege[@]}" cat "/sys/fs/cgroup${pod_cgroup_path}/pids.max")" -eq 256

status_path="/proc/$pid/status"
test "$("${privilege[@]}" awk '/^Uid:/ {print $2}' "$status_path")" -ne 0
for field in CapPrm CapEff CapBnd; do
  test "$("${privilege[@]}" awk -v field="$field:" '$1 == field {print $2}' "$status_path")" \
    = "00000000002400c0"
done
test "$("${privilege[@]}" awk '/^NoNewPrivs:/ {print $2}' "$status_path")" -eq 0
"${privilege[@]}" awk '$5 == "/" && $6 ~ /^ro,/ {found=1} END {exit !found}' \
  "/proc/$pid/mountinfo"

for _ in $(seq 1 30); do
  if "${privilege[@]}" iptables-save 2>/dev/null |
    grep -F "DROP by policy $namespace/sandboxd-default-deny" >/dev/null
  then
    printf '{"resource_shape":"standard-v1","create_to_first_output_ms":%d,"terminal_to_clean_replacement_ms":%d}\n' \
      "$(((first_output_ns - activation_started_ns) / 1000000))" \
      "$(((replacement_ready_ns - replacement_started_ns) / 1000000))"
    printf '{"writable_create_ms":%d,"writable_checkpoint_ms":%d,"writable_export_ms":%d,"writable_snapshot_bytes":%d}\n' \
      "$(((writable_create_ready_ns - writable_create_started_ns) / 1000000))" \
      "$(jq -r '.result.checkpoint_millis' <<<"$writable_snapshot")" \
      "$(jq -r '.result.writable_export_millis' <<<"$writable_snapshot")" \
      "$(jq -r '.result.size_bytes' <<<"$writable_snapshot")"
    exit 0
  fi
  sleep 1
done
echo "default-deny NetworkPolicy was not installed in the node firewall" >&2
exit 1
