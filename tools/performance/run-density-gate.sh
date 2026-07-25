#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --output FILE [--slots N]" >&2
}

output_file=
slots=8
while (($#)); do
  case "$1" in
    --output)
      output_file=${2:-}
      shift 2
      ;;
    --slots)
      slots=${2:-}
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$output_file" || ! "$slots" =~ ^[4-9]$|^[1-2][0-9]$|^3[0-2]$ ]]; then
  usage
  exit 2
fi

namespace="sandboxd-density-$(date +%s)-$$"
deployment=sandboxd-fixed-runtime
label=app.kubernetes.io/name=sandboxd-fixed-runtime
socket=/run/runtrue-sandboxd/control.sock
lock=deploy/k3s/fixed-runtime.lock.json
minimum_memory_reduction_percent=25
minimum_packing_gain_percent=20
# The production worker-pool broker request is counted conservatively in the
# scheduler model even though this fixed-runtime measurement has no sidecar.
broker_memory_request_bytes=$((16 * 1024 * 1024))
broker_cpu_request_millis=10
temporary=$(mktemp -d)

if [[ $(id -u) -eq 0 ]]; then
  privilege=()
else
  privilege=(sudo -n)
fi

cleanup() {
  kubectl delete namespace "$namespace" --ignore-not-found --wait=true \
    >/dev/null 2>&1 || true
  rm -rf -- "$temporary"
}
trap cleanup EXIT

for command in jq kubectl; do
  command -v "$command" >/dev/null
done
"${privilege[@]}" test -r /sys/fs/cgroup/cgroup.controllers
test -s "$lock"
test -n "$(git rev-parse HEAD)"
output_file=$(realpath -m "$output_file")
mkdir -p "$(dirname -- "$output_file")"
sed "s/sandboxd-system/${namespace}/g" \
  deploy/k3s/sandboxd-fixed-runtime.yaml \
  >"$temporary/sandboxd-fixed-runtime.yaml"

memory_bytes() {
  local value=$1
  if [[ "$value" =~ ^([0-9]+)Ki$ ]]; then
    echo "$((BASH_REMATCH[1] * 1024))"
  elif [[ "$value" =~ ^([0-9]+)Mi$ ]]; then
    echo "$((BASH_REMATCH[1] * 1024 * 1024))"
  elif [[ "$value" =~ ^([0-9]+)Gi$ ]]; then
    echo "$((BASH_REMATCH[1] * 1024 * 1024 * 1024))"
  elif [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$value"
  else
    echo "unsupported Kubernetes memory quantity: $value" >&2
    return 1
  fi
}

cpu_millis() {
  local value=$1
  if [[ "$value" =~ ^([0-9]+)m$ ]]; then
    echo "${BASH_REMATCH[1]}"
  elif [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$((value * 1000))"
  else
    echo "unsupported Kubernetes CPU quantity: $value" >&2
    return 1
  fi
}

ready_pods() {
  kubectl get pod -n "$namespace" -l "$label" -o json |
    jq -r '
      .items[]
      | select(.status.phase == "Running")
      | select(any(.status.conditions[]?;
          .type == "Ready" and .status == "True"))
      | [.metadata.name, .metadata.uid]
      | @tsv
    '
}

wait_for_ready_count() {
  local expected=$1
  local excluded_uids=${2:-}
  local observed
  for _ in $(seq 1 900); do
    observed=$(ready_pods |
      awk -F'\t' -v excluded="$excluded_uids" '
        BEGIN {
          count = 0
          split(excluded, values, ",")
          for (item in values) {
            old[values[item]] = 1
          }
        }
        !($2 in old) { count += 1 }
        END { print count }
      ')
    if [[ "$observed" -eq "$expected" ]]; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for $expected clean worker Pods" >&2
  return 1
}

pod_cgroup() {
  local pod=$1
  local container_id
  local pid
  local container_cgroup
  container_id=$(kubectl get pod -n "$namespace" "$pod" \
    -o jsonpath='{.status.containerStatuses[?(@.name=="sandboxd")].containerID}')
  container_id=${container_id#containerd://}
  pid=$("${privilege[@]}" k3s crictl inspect "$container_id" | jq -r '.info.pid')
  [[ "$pid" =~ ^[1-9][0-9]*$ ]]
  # shellcheck disable=SC2016
  container_cgroup=$("${privilege[@]}" awk -F: '$1 == "0" {print $3}' \
    "/proc/$pid/cgroup")
  test -n "$container_cgroup"
  dirname "$container_cgroup"
}

record_memory() {
  local destination=$1
  shift
  : >"$destination"
  for pod in "$@"; do
    cgroup=$(pod_cgroup "$pod")
    "${privilege[@]}" cat "/sys/fs/cgroup${cgroup}/memory.current" \
      >>"$destination"
  done
}

scale_started_ns=$(date +%s%N)
kubectl apply -f "$temporary/sandboxd-fixed-runtime.yaml" >/dev/null
kubectl scale deployment -n "$namespace" "$deployment" \
  --replicas="$slots" >/dev/null
wait_for_ready_count "$slots"
scale_ready_ms="$((($(date +%s%N) - scale_started_ns) / 1000000))"
mapfile -t pod_rows < <(ready_pods | sort)
test "${#pod_rows[@]}" -eq "$slots"
pods=()
old_uids=()
for row in "${pod_rows[@]}"; do
  pods+=("${row%%$'\t'*}")
  old_uids+=("${row##*$'\t'}")
done

sleep 2
record_memory "$temporary/idle-memory.jsonl" "${pods[@]}"
: >"$temporary/activation.jsonl"
started_ns=$(date +%s%N)
for index in "${!pods[@]}"; do
  pod=${pods[$index]}
  sandbox="density-${index}-$(date +%s)"
  begin=$(date +%s%N)
  kubectl exec -i -n "$namespace" "$pod" -- \
    runtrue-sandboxd create \
    --socket "$socket" \
    --lock /dev/stdin \
    --sandbox "$sandbox" \
    --timeout-seconds 30 <"$lock" \
    >"$temporary/create-${index}.json"
  end=$(date +%s%N)
  jq -e '.ok == true and .result.state == "running"' \
    "$temporary/create-${index}.json" >/dev/null
  echo "$(((end - begin) / 1000000))" \
    >"$temporary/activation-${index}"
done
activation_batch_ms="$((($(date +%s%N) - started_ns) / 1000000))"
for index in "${!pods[@]}"; do
  cat "$temporary/activation-${index}" >>"$temporary/activation.jsonl"
done

sleep 2
record_memory "$temporary/active-memory.jsonl" "${pods[@]}"

old_uid_csv=$(IFS=,; echo "${old_uids[*]}")
: >"$temporary/cleanup.jsonl"
cleanup_started_ns=$(date +%s%N)
stop_pids=()
for index in "${!pods[@]}"; do
  pod=${pods[$index]}
  sandbox="density-${index}-$(date +%s)"
  # The create and stop loops execute within the same second in normal runs.
  # Resolve the exact sandbox identity from the successful create response.
  sandbox=$(jq -r '.result.project' "$temporary/create-${index}.json")
  (
    kubectl exec -n "$namespace" "$pod" -- \
      runtrue-sandboxd stop \
      --socket "$socket" \
      --sandbox "$sandbox" >/dev/null
  ) &
  stop_pids+=("$!")
done
for pid in "${stop_pids[@]}"; do
  wait "$pid"
done

recorded=0
for _ in $(seq 1 900); do
  replacements=$(ready_pods |
    awk -F'\t' -v excluded="$old_uid_csv" '
      BEGIN {
        count = 0
        split(excluded, values, ",")
        for (item in values) {
          old[values[item]] = 1
        }
      }
      !($2 in old) { count += 1 }
      END { print count }
    ')
  while ((recorded < replacements)); do
    echo "$((($(date +%s%N) - cleanup_started_ns) / 1000000))" \
      >>"$temporary/cleanup.jsonl"
    recorded=$((recorded + 1))
  done
  if [[ "$recorded" -eq "$slots" ]]; then
    break
  fi
  sleep 0.1
done
test "$recorded" -eq "$slots"
cleanup_batch_ms="$((($(date +%s%N) - cleanup_started_ns) / 1000000))"

node=$(kubectl get nodes -o json | jq -r '
  first(
    .items[]
    | select(.metadata.labels["runtrue.io/sandbox-node"] == "true")
    | .metadata.name
  )
')
test -n "$node"
node_memory=$(memory_bytes "$(
  kubectl get node "$node" -o jsonpath='{.status.allocatable.memory}'
)")
node_cpu=$(cpu_millis "$(
  kubectl get node "$node" -o jsonpath='{.status.allocatable.cpu}'
)")
kubernetes_version=$(kubectl get node "$node" \
  -o jsonpath='{.status.nodeInfo.kubeletVersion}')
kernel_version=$(kubectl get node "$node" \
  -o jsonpath='{.status.nodeInfo.kernelVersion}')
os_image=$(kubectl get node "$node" \
  -o jsonpath='{.status.nodeInfo.osImage}')
version_pod=$(ready_pods | awk -F'\t' 'NR == 1 { value = $1 } END { print value }')
runsc_version=$(kubectl exec -n "$namespace" "$version_pod" \
  -- /usr/local/bin/runsc --version | sed -n '1p')
pod_memory_request=$(memory_bytes "$(
  kubectl get deployment -n "$namespace" "$deployment" -o json |
    jq -r '.spec.template.spec.containers[] |
      select(.name == "sandboxd") | .resources.requests.memory'
)")
pod_cpu_request=$(cpu_millis "$(
  kubectl get deployment -n "$namespace" "$deployment" -o json |
    jq -r '.spec.template.spec.containers[] |
      select(.name == "sandboxd") | .resources.requests.cpu'
)")

jq -s . "$temporary/idle-memory.jsonl" >"$temporary/idle-memory.json"
jq -s . "$temporary/active-memory.jsonl" >"$temporary/active-memory.json"
jq -s . "$temporary/activation.jsonl" >"$temporary/activation.json"
jq -s . "$temporary/cleanup.jsonl" >"$temporary/cleanup.json"

revision=$(git rev-parse HEAD)
jq -n \
  --arg revision "$revision" \
  --arg node "$node" \
  --arg kubernetes_version "$kubernetes_version" \
  --arg kernel_version "$kernel_version" \
  --arg os_image "$os_image" \
  --arg runsc_version "$runsc_version" \
  --argjson slots "$slots" \
  --argjson node_memory "$node_memory" \
  --argjson node_cpu "$node_cpu" \
  --argjson pod_memory_request "$pod_memory_request" \
  --argjson pod_cpu_request "$pod_cpu_request" \
  --argjson broker_memory_request "$broker_memory_request_bytes" \
  --argjson broker_cpu_request "$broker_cpu_request_millis" \
  --argjson scale_ready "$scale_ready_ms" \
  --argjson activation_batch "$activation_batch_ms" \
  --argjson cleanup_batch "$cleanup_batch_ms" \
  --argjson memory_threshold "$minimum_memory_reduction_percent" \
  --argjson packing_threshold "$minimum_packing_gain_percent" \
  --slurpfile idle "$temporary/idle-memory.json" \
  --slurpfile active "$temporary/active-memory.json" \
  --slurpfile activation "$temporary/activation.json" \
  --slurpfile cleanup "$temporary/cleanup.json" '
    def percentile($values; $quantile):
      ($values | sort) as $sorted
      | $sorted[
          (((($sorted | length) * $quantile) | ceil) - 1)
          | if . < 0 then 0 else . end
        ];
    def distribution($values):
      {
        samples:$values,
        p50:percentile($values; 0.50),
        p95:percentile($values; 0.95),
        p99:percentile($values; 0.99)
      };
    ($idle[0]) as $idle_values
    | ($active[0]) as $active_values
    | ($idle_values | add) as $idle_total
    | ($active_values | add) as $active_total
    | percentile($idle_values; 0.50) as $shared_control_upper_bound
    | ([
        range(0; $slots)
        | (($active_values[.] - $idle_values[.]) | if . < 0 then 0 else . end)
      ] | add) as $runtime_increment_total
    | ($shared_control_upper_bound + $runtime_increment_total) as $dense_total
    | (($active_total - $dense_total) * 10000 / $active_total | floor / 100)
        as $memory_reduction_percent
    | (($pod_memory_request * $dense_total + $active_total - 1)
        / $active_total | floor) as $dense_memory_request_per_slot
    | (($pod_cpu_request * $dense_total + $active_total - 1)
        / $active_total | floor) as $dense_cpu_request_per_slot
    | ($pod_memory_request + $broker_memory_request) as $one_slot_memory_request
    | ($pod_cpu_request + $broker_cpu_request) as $one_slot_cpu_request
    | ($dense_memory_request_per_slot
        + (($broker_memory_request + $slots - 1) / $slots | floor))
        as $dense_brokered_memory_request_per_slot
    | ($dense_cpu_request_per_slot
        + (($broker_cpu_request + $slots - 1) / $slots | floor))
        as $dense_brokered_cpu_request_per_slot
    | ([
        ($node_memory / $one_slot_memory_request | floor),
        ($node_cpu / $one_slot_cpu_request | floor)
      ] | min) as $one_pod_packing
    | ([
        ($node_memory / $dense_brokered_memory_request_per_slot | floor),
        ($node_cpu / $dense_brokered_cpu_request_per_slot | floor)
      ] | min) as $dense_packing_upper_bound
    | (($dense_packing_upper_bound - $one_pod_packing) * 10000
        / $one_pod_packing | floor / 100) as $packing_gain_percent
    | {
        schema_version:1,
        revision:$revision,
        node:$node,
        slots:$slots,
        environment:{
          os_image:$os_image,
          kernel_version:$kernel_version,
          kubernetes_version:$kubernetes_version,
          runsc_version:$runsc_version,
          allocatable_memory_bytes:$node_memory,
          allocatable_cpu_millis:$node_cpu
        },
        methodology:{
          baseline:"one active sandbox per Kubernetes worker Pod",
          dense_upper_bound:"one median clean-worker footprint plus every measured per-sandbox active increment",
          activation_issuance:"sequential while retaining earlier sandboxes so all slots are active for the memory sample",
          caveat:"optimistic model excludes dense slot bookkeeping, cgroup broker, monitoring, cleanup, and contention overhead"
        },
        one_sandbox_per_worker:{
          idle_memory_bytes:distribution($idle_values),
          active_memory_bytes:distribution($active_values),
          total_active_memory_bytes:$active_total,
          activation_milliseconds:distribution($activation[0]),
          cleanup_to_replacement_milliseconds:distribution($cleanup[0]),
          activation_batch_milliseconds:$activation_batch,
          cleanup_batch_milliseconds:$cleanup_batch,
          scale_to_ready_batch_milliseconds:$scale_ready,
          pod_objects:$slots,
          failure_blast_radius_sandboxes:1,
          declared_broker_memory_request_bytes_per_slot:$broker_memory_request,
          declared_broker_cpu_request_millis_per_slot:$broker_cpu_request,
          brokered_memory_request_bytes_per_slot:$one_slot_memory_request,
          brokered_cpu_request_millis_per_slot:$one_slot_cpu_request,
          brokered_node_packing_slots:$one_pod_packing
        },
        optimistic_dense_upper_bound:{
          shared_control_memory_bytes:$shared_control_upper_bound,
          total_active_memory_bytes:$dense_total,
          active_memory_bytes_per_slot:($dense_total / $slots | floor),
          memory_reduction_percent:$memory_reduction_percent,
          estimated_brokered_memory_request_per_slot:
            $dense_brokered_memory_request_per_slot,
          estimated_brokered_cpu_request_millis_per_slot:
            $dense_brokered_cpu_request_per_slot,
          brokered_node_packing_slots:$dense_packing_upper_bound,
          node_packing_gain_percent:$packing_gain_percent,
          pod_objects:1,
          failure_blast_radius_sandboxes:$slots
        },
        decision_thresholds:{
          minimum_memory_reduction_percent:$memory_threshold,
          minimum_node_packing_gain_percent:$packing_threshold,
          requires_standard_kubernetes_hard_resource_boundary:true
        },
        economic_gate_passed:(
          $memory_reduction_percent >= $memory_threshold
          and $packing_gain_percent >= $packing_threshold
        ),
        security_gate_passed:false,
        security_gate_reason:"Kubernetes does not provide hard per-sandbox cgroups inside one ordinary Pod; current options require delegated writable cgroups or a trusted node broker"
      }
  ' >"$temporary/result.json"

install -m 0644 "$temporary/result.json" "$output_file"
jq . "$output_file"
