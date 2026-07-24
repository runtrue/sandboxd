#!/usr/bin/env bash
set -euo pipefail

namespace=${SANDBOXD_K3S_NAMESPACE:-sandboxd-system}
deployment=sandboxd-fixed-runtime
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
cleanup() {
  if [[ -n $pod ]]; then
    kubectl exec -n "$namespace" "$pod" -- \
      runtrue-sandboxd stop \
      --socket "$socket" \
      --sandbox "$sandbox" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

for manifest in \
  deploy/k3s/sandboxd-fixed-runtime.yaml \
  deploy/k3s/sandboxd-dynamic-runtime.yaml \
  deploy/k3s/sandboxd-host-integrated.yaml
do
  kubectl apply --dry-run=server -f "$manifest" >/dev/null
done

kubectl apply -f deploy/k3s/sandboxd-fixed-runtime.yaml
kubectl rollout status -n "$namespace" "deployment/$deployment" --timeout=180s
pod=$(kubectl get pod -n "$namespace" \
  -l app.kubernetes.io/name="$deployment" \
  -o jsonpath='{.items[0].metadata.name}')
test -n "$pod"

pod_json=$(kubectl get pod -n "$namespace" "$pod" -o json)
jq -e '
  .spec.hostUsers == false
  and (.spec.hostNetwork // false) == false
  and (.spec.hostPID // false) == false
  and (.spec.hostIPC // false) == false
  and .spec.automountServiceAccountToken == false
  and .spec.enableServiceLinks == false
  and .spec.nodeSelector["runtrue.io/sandbox-node"] == "true"
  and ([.spec.volumes[] | select(has("hostPath") or has("projected"))] | length) == 0
  and (.spec.containers | length) == 1
  and .spec.containers[0].securityContext.privileged == false
  and .spec.containers[0].securityContext.readOnlyRootFilesystem == true
  and .spec.containers[0].securityContext.allowPrivilegeEscalation == true
  and .spec.containers[0].securityContext.capabilities.drop == ["ALL"]
  and (.spec.containers[0].securityContext.capabilities.add | sort)
      == (["SETGID", "SETUID", "SYS_ADMIN", "SYS_CHROOT"] | sort)
  and (.spec.containers[0].env // []) == []
  and (.spec.containers[0].args | index("--network-mode")) != null
  and (.spec.containers[0].args | index("loopback")) != null
  and (.spec.containers[0].args | index("--cgroup-mode")) != null
  and (.spec.containers[0].args | index("external")) != null
' >/dev/null <<<"$pod_json"

test "$(kubectl get service -n "$namespace" -o name | wc -l)" -eq 0
test "$(kubectl get ingress -n "$namespace" -o name | wc -l)" -eq 0
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

kubectl exec -i -n "$namespace" "$pod" -- \
  runtrue-sandboxd create \
  --socket "$socket" \
  --lock /dev/stdin \
  --sandbox "$sandbox" \
  --timeout-seconds 30 <"$fixed_lock" >/dev/null

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

kubectl exec -n "$namespace" "$pod" -- \
  runtrue-sandboxd stop \
  --socket "$socket" \
  --sandbox "$sandbox" >/dev/null

stats=$(kubectl exec -n "$namespace" "$pod" -- \
  runtrue-sandboxd stats --socket "$socket")
jq -e '
  .ok == true
  and .result.active_operations == 0
  and .result.sandboxes == []
' >/dev/null <<<"$stats"

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
  if [[ $status -eq 0 ]] || ! grep -F "$expected" <<<"$output"; then
    printf 'expected failure containing %q, got status %s:\n%s\n' \
      "$expected" "$status" "$output" >&2
    return 1
  fi
}

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

kubectl exec -i -n "$namespace" "$pod" -- \
  runtrue-sandboxd admit --socket "$socket" --lock /dev/stdin \
  <"$writable_lock" >/dev/null
expect_stdin_failure "$writable_lock" \
  "fixed-rootfs image provider supports read-only roots only" \
  runtrue-sandboxd create \
  --socket "$socket" \
  --lock /dev/stdin \
  --sandbox "ci-denied-writable-${suffix}" \
  --timeout-seconds 30

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
    exit 0
  fi
  sleep 1
done
echo "default-deny NetworkPolicy was not installed in the node firewall" >&2
exit 1
