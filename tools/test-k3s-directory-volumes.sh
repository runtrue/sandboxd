#!/usr/bin/env bash
set -euo pipefail

namespace=${SANDBOXD_K3S_NAMESPACE:-sandboxd-system}
worker=sandboxd-fixed-runtime
worker_label=app.kubernetes.io/name=sandboxd-fixed-runtime
socket=/run/runtrue-sandboxd/control.sock
suffix=${GITHUB_RUN_ID:-local}
pv_name="sandboxd-directory-conformance-${suffix}"
ctl=${SANDBOXD_CTL:-target/release/runtrue-sandboxctl}
pv_path=
pod=

if [[ $(id -u) -eq 0 ]]; then
  privilege=()
else
  privilege=(sudo -n)
fi

cleanup() {
  kubectl delete deployment -n "$namespace" "$worker" \
    --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl delete pvc -n "$namespace" sandboxd-directory-state \
    --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl delete pv "$pv_name" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  if [[ $pv_path == /var/lib/runtrue-sandboxd-directory-conformance.* ]]; then
    "${privilege[@]}" rm -rf -- "$pv_path"
  fi
  kubectl apply -f deploy/k3s/sandboxd-fixed-runtime.yaml >/dev/null 2>&1 || true
}
trap cleanup EXIT

for command in jq kubectl "$ctl"; do
  command -v "$command" >/dev/null
done

wait_for_worker() {
  local previous=${1:-}
  local candidate
  for _ in $(seq 1 180); do
    candidate=$(kubectl get pods -n "$namespace" -l "$worker_label" -o json |
      jq -r --arg previous "$previous" '
        .items[]
        | select(.metadata.uid != $previous)
        | select(.status.phase == "Running")
        | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
        | [.metadata.name, .metadata.uid]
        | @tsv
      ' | head -1)
    if [[ -n $candidate ]]; then
      IFS=$'\t' read -r pod pod_uid <<<"$candidate"
      kubectl exec -n "$namespace" "$pod" -- \
        runtrue-sandboxd ready --socket "$socket" >/dev/null
      return 0
    fi
    sleep 1
  done
  echo "directory-volume worker did not become ready" >&2
  return 1
}

generate_lock() {
  local compose=$1
  local output=$2
  "$ctl" \
    --ctr /usr/bin/ctr \
    --containerd-address /run/k3s/containerd/containerd.sock \
    --containerd-namespace k8s.io \
    --snapshotter overlayfs \
    lock --compose "$compose" --output "$output" >/dev/null
}

create_sandbox() {
  local lock=$1
  local sandbox=$2
  kubectl exec -i -n "$namespace" "$pod" -- \
    runtrue-sandboxd create \
    --socket "$socket" \
    --lock /dev/stdin \
    --sandbox "$sandbox" \
    --timeout-seconds 30 <"$lock"
}

stop_sandbox() {
  local sandbox=$1
  kubectl exec -n "$namespace" "$pod" -- \
    runtrue-sandboxd stop --socket "$socket" --sandbox "$sandbox" >/dev/null
}

kubectl delete deployment -n "$namespace" "$worker" \
  --ignore-not-found --wait=true >/dev/null
kubectl delete pvc -n "$namespace" sandboxd-directory-state \
  --ignore-not-found --wait=true >/dev/null
kubectl delete pv "$pv_name" --ignore-not-found --wait=true >/dev/null

pv_path=$("${privilege[@]}" mktemp -d \
  /var/lib/runtrue-sandboxd-directory-conformance.XXXXXX)
node=$(kubectl get nodes -o json | jq -r '.items[0].metadata.name')
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: ${pv_name}
spec:
  capacity:
    storage: 4Gi
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ""
  local:
    path: ${pv_path}
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values:
                - ${node}
EOF

rendered=$(mktemp /tmp/sandboxd-directory-volumes.XXXXXX.yaml)
kubectl kustomize --load-restrictor LoadRestrictionsNone \
  deploy/k3s/directory-volumes >"$rendered"
kubectl apply -f "$rendered" >/dev/null
kubectl wait -n "$namespace" \
  --for=jsonpath='{.status.phase}'=Bound \
  pvc/sandboxd-directory-state --timeout=120s >/dev/null
wait_for_worker

pod_json=$(kubectl get pod -n "$namespace" "$pod" -o json)
jq -e '
  .spec.hostUsers == false
  and (.spec.containers[0].securityContext.privileged == false)
  and (.spec.containers[0].securityContext.capabilities.add | sort)
    == ["CHOWN","DAC_OVERRIDE","SETGID","SETUID","SYS_ADMIN","SYS_CHROOT"]
  and ([.spec.volumes[] | select(has("hostPath"))] | length) == 0
  and ([.spec.containers[].volumeMounts[] | select(.mountPropagation != null)]
    | length) == 0
' >/dev/null <<<"$pod_json"

strict_lock=$(mktemp /tmp/sandboxd-volume-strict.XXXXXX.lock.json)
reopen_lock=$(mktemp /tmp/sandboxd-volume-reopen.XXXXXX.lock.json)
generate_lock deploy/k3s/conformance-volume.yaml "$strict_lock"
generate_lock deploy/k3s/conformance-volume-reopen.yaml "$reopen_lock"

write_started_ns=$(date +%s%N)
create=$(create_sandbox "$strict_lock" "directory-strict-${suffix}")
write_ready_ns=$(date +%s%N)
jq -e '.ok == true and .result.running_services == 2' >/dev/null <<<"$create"
snapshot_started_ns=$(date +%s%N)
snapshot=$(kubectl exec -n "$namespace" "$pod" -- \
  runtrue-sandboxd snapshot \
  --socket "$socket" \
  --sandbox "directory-strict-${suffix}" \
  --snapshot "directory-live-${suffix}")
snapshot_ready_ns=$(date +%s%N)
jq -e '
  .ok == true
  and .result.mode == "live"
  and .result.files >= 6
  and .result.size_bytes > 0
  and .result.transferred_bytes > 0
' >/dev/null <<<"$snapshot"

previous_uid=$pod_uid
replacement_started_ns=$(date +%s%N)
kubectl delete pod -n "$namespace" "$pod" \
  --grace-period=0 --force --wait=true >/dev/null
wait_for_worker "$previous_uid"
replacement_ready_ns=$(date +%s%N)
reopen=$(create_sandbox "$reopen_lock" "directory-reopen-${suffix}")
jq -e '.ok == true and .result.running_services == 1' >/dev/null <<<"$reopen"
for _ in $(seq 1 80); do
  output=$(kubectl exec -n "$namespace" "$pod" -- \
    runtrue-sandboxd logs \
    --socket "$socket" \
    --sandbox "directory-reopen-${suffix}" \
    --container reader)
  if jq -e '
    .ok == true
    and .result.exit_code == 0
    and .result.stdout == "named-volume-passed\n"
  ' >/dev/null 2>&1 <<<"$output"; then
    break
  fi
  sleep 0.25
done
jq -e '
  .ok == true
  and .result.exit_code == 0
  and .result.stdout == "named-volume-passed\n"
' >/dev/null <<<"$output"
stop_sandbox "directory-reopen-${suffix}"

previous_uid=$pod_uid
wait_for_worker "$previous_uid"
missing_compose=$(mktemp /tmp/sandboxd-volume-missing.XXXXXX.yaml)
cp deploy/k3s/conformance-volume.yaml "$missing_compose"
sed -i 's#/mnt#/missing/nested/mnt#g' "$missing_compose"
missing_lock=$(mktemp /tmp/sandboxd-volume-missing.XXXXXX.lock.json)
generate_lock "$missing_compose" "$missing_lock"
set +e
missing=$(kubectl exec -i -n "$namespace" "$pod" -- \
  runtrue-sandboxd admit --socket "$socket" --lock /dev/stdin \
  <"$missing_lock" 2>&1)
status=$?
set -e
if [[ $status -eq 0 ]] ||
  ! grep -Fq "does not exist in the admitted image" <<<"$missing"; then
  echo "missing volume mountpoint was not rejected during admission: $missing" >&2
  exit 1
fi

quota_compose=$(mktemp /tmp/sandboxd-volume-quota.XXXXXX.yaml)
cp deploy/k3s/conformance-volume-profile.yaml "$quota_compose"
sed -i 's/quota_bytes: 8388608/quota_bytes: 3221225472/' "$quota_compose"
quota_lock=$(mktemp /tmp/sandboxd-volume-quota.XXXXXX.lock.json)
generate_lock "$quota_compose" "$quota_lock"
set +e
quota=$(kubectl exec -i -n "$namespace" "$pod" -- \
  runtrue-sandboxd admit --socket "$socket" --lock /dev/stdin \
  <"$quota_lock" 2>&1)
status=$?
set -e
if [[ $status -eq 0 ]] ||
  ! grep -Fq "exceeds worker resource shape" <<<"$quota"; then
  echo "aggregate storage demand above the worker boundary was not rejected: $quota" >&2
  exit 1
fi

for profile in root-in-sandbox-v1 oci-compat-v1; do
  profile_compose=$(mktemp "/tmp/sandboxd-volume-${profile}.XXXXXX.yaml")
  cp deploy/k3s/conformance-volume-profile.yaml "$profile_compose"
  sed -i "2i x-runtrue-guest-profile: ${profile}" "$profile_compose"
  profile_lock=$(mktemp "/tmp/sandboxd-volume-${profile}.XXXXXX.lock.json")
  generate_lock "$profile_compose" "$profile_lock"
  create=$(create_sandbox "$profile_lock" "directory-${profile}-${suffix}")
  jq -e '.ok == true and .result.running_services == 1' >/dev/null <<<"$create"
  stop_sandbox "directory-${profile}-${suffix}"
  previous_uid=$pod_uid
  wait_for_worker "$previous_uid"
done

jq -cn \
  --argjson write_millis "$(((write_ready_ns - write_started_ns) / 1000000))" \
  --argjson snapshot_millis "$(((snapshot_ready_ns - snapshot_started_ns) / 1000000))" \
  --argjson replacement_ready_millis "$(((replacement_ready_ns - replacement_started_ns) / 1000000))" \
  --argjson snapshot_bytes "$(jq '.result.size_bytes' <<<"$snapshot")" \
  --argjson transferred_bytes "$(jq '.result.transferred_bytes' <<<"$snapshot")" \
  '{
    write_millis: $write_millis,
    snapshot_millis: $snapshot_millis,
    replacement_ready_millis: $replacement_ready_millis,
    snapshot_bytes: $snapshot_bytes,
    transferred_bytes: $transferred_bytes
  }'
echo "directory-volume k3s conformance passed"
