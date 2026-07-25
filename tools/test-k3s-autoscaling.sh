#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${KUBECONFIG:-}" && -r /etc/rancher/k3s/k3s.yaml ]]; then
  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
fi

namespace=sandboxd-system
gateway_port=18082
database_port=15436
tenant_secret=tenant-secret-with-at-least-32-bytes-a
temporary=$(mktemp -d)
diagnostics_dir=${AUTOSCALE_DIAGNOSTICS_DIR:-}
gateway_forward=
database_forward=
autoscalers=()
events_client=
next_metrics_port=19090
active_metrics_port=

cleanup() {
  if [[ -n "$diagnostics_dir" ]]; then
    mkdir -p "$diagnostics_dir"
    for log in "$temporary"/*.log; do
      if [[ -f "$log" ]]; then
        install -m 0600 "$log" "$diagnostics_dir/$(basename "$log")"
      fi
    done
  fi
  if [[ -n "$events_client" ]]; then
    kill "$events_client" 2>/dev/null || true
  fi
  for process in "${autoscalers[@]}"; do
    kill "$process" 2>/dev/null || true
  done
  if [[ -n "$gateway_forward" ]]; then
    kill "$gateway_forward" 2>/dev/null || true
  fi
  if [[ -n "$database_forward" ]]; then
    kill "$database_forward" 2>/dev/null || true
  fi
  rm -rf "$temporary"
}
trap 'printf "autoscaling conformance failed at line %s\n" "$LINENO" >&2' ERR
trap cleanup EXIT

install -m 0600 deploy/k3s/worker-pools.json "$temporary/catalog.json"
printf %s \
  "postgres://sandboxd:sandboxd@127.0.0.1:${database_port}/sandboxd_placement_test" \
  >"$temporary/database-url"
chmod 0600 "$temporary/database-url"

kubectl apply -f deploy/k3s/sandboxd-worker-pools.yaml
test "$(kubectl get statefulset -n "$namespace" sandboxd-reviewed-cold \
  -o jsonpath='{.spec.replicas}')" = 0
node_ip=$(kubectl get nodes -o json | jq -r '
  .items[0].status.addresses[]
  | select(.type == "InternalIP")
  | .address
')
test -n "$node_ip"
kubectl apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sandboxd-host-autoscaler-probe
  namespace: ${namespace}
spec:
  podSelector:
    matchLabels:
      runtrue.io/autoscaled-worker: "true"
  policyTypes: [Ingress]
  ingress:
    - from:
        - ipBlock:
            cidr: ${node_ip}/32
      ports:
        - protocol: TCP
          port: 8081
EOF

kubectl port-forward -n "$namespace" deployment/sandbox-gateway \
  "${database_port}:5432" >"$temporary/database-forward.log" 2>&1 &
database_forward=$!
kubectl port-forward -n "$namespace" service/sandbox-gateway \
  "${gateway_port}:8080" >"$temporary/gateway-forward.log" 2>&1 &
gateway_forward=$!
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${gateway_port}/health/ready" >/dev/null; then
    break
  fi
  sleep 1
done

start_autoscaler() {
  local log=$1
  active_metrics_port=$next_metrics_port
  next_metrics_port=$((next_metrics_port + 1))
  target/release/runtrue-sandbox-autoscaler \
    --database-url-file "$temporary/database-url" \
    --database-insecure-local \
    --worker-pool-catalog "$temporary/catalog.json" \
    --namespace "$namespace" \
    --maximum-total-workers 4 \
    --reconcile-interval-milliseconds 250 \
    --metrics-listen "127.0.0.1:${active_metrics_port}" \
    >"$log" 2>&1 &
  autoscalers+=("$!")
}

start_autoscaler "$temporary/autoscaler-a.log"
for _ in $(seq 1 180); do
  desired=$(kubectl get statefulset -n "$namespace" sandboxd-fixed-standard-warm \
    -o jsonpath='{.spec.replicas}')
  ready=$(kubectl get statefulset -n "$namespace" sandboxd-fixed-standard-warm \
    -o jsonpath='{.status.readyReplicas}')
  if [[ "$desired" = 2 && "$ready" = 2 ]]; then
    break
  fi
  sleep 1
done
test "$(kubectl get statefulset -n "$namespace" sandboxd-fixed-standard-warm \
  -o jsonpath='{.spec.replicas}')" = 2

start_autoscaler "$temporary/autoscaler-b.log"
sleep 2
test "$(kubectl get statefulset -n "$namespace" sandboxd-fixed-standard-warm \
  -o jsonpath='{.spec.replicas}')" = 2

sandbox="autoscale-cold-$(date +%s)"
jq -n \
  --arg sandbox "$sandbox" \
  --slurpfile topology deploy/k3s/fixed-runtime.lock.json \
  '{
    workspace_id: "workspace-a",
    sandbox_id: $sandbox,
    deadline_ms: 120000,
    pool_name: "reviewed-cold-fallback",
    topology: "fixed-v1",
    resource_shape: "cold-standard-v1",
    compatibility_cohort: "runsc-20260714-fixed",
    operation: {
      kind: "run",
      parameters: {
        topology: $topology[0],
        project: $sandbox,
        wait_for: "client",
        timeout_ms: 30000
      }
    }
  }' >"$temporary/cold-request.json"
status=$(curl -sS -o "$temporary/cold-submitted.json" -w '%{http_code}' \
  -H "Authorization: Bearer tenant-key.${tenant_secret}" \
  -H "Idempotency-Key: autoscale-cold-e2e" \
  -H "Content-Type: application/json" \
  --data-binary @"$temporary/cold-request.json" \
  "http://127.0.0.1:${gateway_port}/v1/placements")
test "$status" = 202

curl -fsSN --max-time 180 \
  -H "Authorization: Bearer tenant-key.${tenant_secret}" \
  "http://127.0.0.1:${gateway_port}/v1/placements/autoscale-cold-e2e/events" \
  >"$temporary/cold-events.txt" &
events_client=$!

for _ in $(seq 1 180); do
  if [[ "$(kubectl get statefulset -n "$namespace" sandboxd-reviewed-cold \
    -o jsonpath='{.spec.replicas}')" = 1 ]]; then
    break
  fi
  sleep 1
done
test "$(kubectl get statefulset -n "$namespace" sandboxd-reviewed-cold \
  -o jsonpath='{.spec.replicas}')" = 1

for process in "${autoscalers[@]}"; do
  kill "$process" 2>/dev/null || true
  wait "$process" 2>/dev/null || true
done
autoscalers=()
start_autoscaler "$temporary/autoscaler-restarted.log"

result=
for _ in $(seq 1 180); do
  result=$(curl -fsS \
    -H "Authorization: Bearer tenant-key.${tenant_secret}" \
    "http://127.0.0.1:${gateway_port}/v1/placements/autoscale-cold-e2e")
  if [[ "$(jq -r .state <<<"$result")" = completed ]]; then
    break
  fi
  sleep 1
done
jq -e '
  .pool_name == "reviewed-cold-fallback"
  and (.worker_id | startswith("worker-"))
  and .response.ok
  and (.response.result.stdout | contains("nested-container-passed"))
  and (.response.result.stdout | contains("\"kernel\": \"4.19.0-gvisor\""))
' >/dev/null <<<"$result"
wait "$events_client"
events_client=
grep -F '"state":"completed"' "$temporary/cold-events.txt" >/dev/null

for _ in $(seq 1 90); do
  if [[ "$(kubectl get statefulset -n "$namespace" sandboxd-reviewed-cold \
    -o jsonpath='{.spec.replicas}')" = 0 ]]; then
    break
  fi
  sleep 1
done
test "$(kubectl get statefulset -n "$namespace" sandboxd-reviewed-cold \
  -o jsonpath='{.spec.replicas}')" = 0

warm_sandbox="autoscale-warm-$(date +%s)"
jq \
  --arg sandbox "$warm_sandbox" \
  '.sandbox_id = $sandbox
   | .pool_name = "fixed-standard-warm"
   | .resource_shape = "standard-v1"
   | .operation.parameters.project = $sandbox' \
  "$temporary/cold-request.json" >"$temporary/warm-request.json"
status=$(curl -sS -o "$temporary/warm-submitted.json" -w '%{http_code}' \
  -H "Authorization: Bearer tenant-key.${tenant_secret}" \
  -H "Idempotency-Key: autoscale-warm-e2e" \
  -H "Content-Type: application/json" \
  --data-binary @"$temporary/warm-request.json" \
  "http://127.0.0.1:${gateway_port}/v1/placements")
test "$status" = 202
warm_result=
for _ in $(seq 1 180); do
  warm_result=$(curl -fsS \
    -H "Authorization: Bearer tenant-key.${tenant_secret}" \
    "http://127.0.0.1:${gateway_port}/v1/placements/autoscale-warm-e2e")
  if [[ "$(jq -r .state <<<"$warm_result")" = completed ]]; then
    break
  fi
  sleep 1
done
jq -e '
  .pool_name == "fixed-standard-warm"
  and (.worker_id | startswith("worker-"))
  and .response.ok
' >/dev/null <<<"$warm_result"
for _ in $(seq 1 100); do
  desired=$(kubectl get statefulset -n "$namespace" sandboxd-fixed-standard-warm \
    -o jsonpath='{.spec.replicas}')
  ready=$(kubectl get statefulset -n "$namespace" sandboxd-fixed-standard-warm \
    -o jsonpath='{.status.readyReplicas}')
  if [[ "$desired" = 2 && "$ready" = 2 ]]; then
    break
  fi
  sleep 1
done
test "$(kubectl get statefulset -n "$namespace" sandboxd-fixed-standard-warm \
  -o jsonpath='{.spec.replicas}')" = 2

userspace_sandbox="userspace-ingress-$(date +%s)"
jq -n \
  --arg sandbox "$userspace_sandbox" \
  --slurpfile topology deploy/k3s/conformance-userspace-egress.lock.json \
  '{
    workspace_id: "workspace-a",
    sandbox_id: $sandbox,
    deadline_ms: 120000,
    pool_name: "userspace-ingress",
    topology: "userspace-v1",
    resource_shape: "standard-v1",
    compatibility_cohort: "runsc-20260714-fixed",
    operation: {
      kind: "create",
      parameters: {
        topology: $topology[0],
        sandbox: $sandbox,
        timeout_ms: 30000
      }
    }
  }' >"$temporary/userspace-request.json"
status=$(curl -sS -o "$temporary/userspace-submitted.json" -w '%{http_code}' \
  -H "Authorization: Bearer tenant-key.${tenant_secret}" \
  -H "Idempotency-Key: userspace-ingress-e2e" \
  -H "Content-Type: application/json" \
  --data-binary @"$temporary/userspace-request.json" \
  "http://127.0.0.1:${gateway_port}/v1/placements")
test "$status" = 202

userspace_result=
for _ in $(seq 1 240); do
  userspace_result=$(curl -fsS \
    -H "Authorization: Bearer tenant-key.${tenant_secret}" \
    "http://127.0.0.1:${gateway_port}/v1/placements/userspace-ingress-e2e")
  if [[ "$(jq -r .state <<<"$userspace_result")" = serving ]]; then
    break
  fi
  sleep 1
done
jq -e '
  .state == "serving"
  and .pool_name == "userspace-ingress"
  and (.worker_id | startswith("worker-"))
  and .response.ok
' >/dev/null <<<"$userspace_result"
test "$(kubectl get statefulset -n "$namespace" sandboxd-userspace-ingress \
  -o jsonpath='{.spec.replicas}')" = 1

userspace_pod=$(kubectl get pod -n "$namespace" \
  -l runtrue.io/worker-pool=userspace-ingress \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}')
kubectl get pod -n "$namespace" "$userspace_pod" -o json |
  jq -e '
    .spec.hostUsers == false
    and .spec.hostNetwork != true
    and .spec.automountServiceAccountToken == false
    and (.spec.containers[0].args | index("--network-mode")) != null
    and (.spec.containers[0].args | index("userspace")) != null
    and .spec.containers[0].securityContext.privileged == false
    and (.spec.containers[0].securityContext.capabilities.add | index("NET_ADMIN")) == null
    and (.spec.containers[0].securityContext.capabilities.add | index("NET_RAW")) == null
    and .spec.initContainers[0].securityContext.capabilities.drop == ["ALL"]
  ' >/dev/null

ingress_started_ns=$(date +%s%N)
ingress_status=
for _ in $(seq 1 60); do
  ingress_status=$(curl -sS -o "$temporary/userspace-ingress.json" -w '%{http_code}' \
    -H "Authorization: Bearer tenant-key.${tenant_secret}" \
    "http://127.0.0.1:${gateway_port}/v1/placements/userspace-ingress-e2e/ingress/server/8080/ready?full=1")
  if [[ "$ingress_status" = 200 ]]; then
    break
  fi
  sleep 0.25
done
test "$ingress_status" = 200
ingress_ms=$((($(date +%s%N) - ingress_started_ns) / 1000000))
jq -e '.from == "nested-server" and .ok == true' \
  "$temporary/userspace-ingress.json" >/dev/null
bulk_started_ns=$(date +%s%N)
bulk_status=
for _ in $(seq 1 60); do
  bulk_status=$(curl -sS -o "$temporary/userspace-ingress-bulk" -w '%{http_code}' \
    -H "Authorization: Bearer tenant-key.${tenant_secret}" \
    "http://127.0.0.1:${gateway_port}/v1/placements/userspace-ingress-e2e/ingress/server/8080/bulk")
  if [[ "$bulk_status" = 200 ]]; then
    break
  fi
  sleep 0.25
done
test "$bulk_status" = 200
bulk_ms=$((($(date +%s%N) - bulk_started_ns) / 1000000))
test "$(wc -c <"$temporary/userspace-ingress-bulk")" = 131072
undeclared_status=$(curl -sS -o "$temporary/userspace-undeclared.json" -w '%{http_code}' \
  -H "Authorization: Bearer tenant-key.${tenant_secret}" \
  "http://127.0.0.1:${gateway_port}/v1/placements/userspace-ingress-e2e/ingress/client/8080")
test "$undeclared_status" = 503

lease_before=$(kubectl exec -n "$namespace" deployment/sandbox-gateway -c postgres -- \
  env PGPASSWORD=sandboxd psql -h 127.0.0.1 -U sandboxd \
  -d sandboxd_placement_test -Atc \
  "SELECT lease_expires_unix_ms FROM sandboxd_placement.requests WHERE tenant_id = 'tenant-a' AND idempotency_key = 'userspace-ingress-e2e'")
sleep 2
lease_after=$(kubectl exec -n "$namespace" deployment/sandbox-gateway -c postgres -- \
  env PGPASSWORD=sandboxd psql -h 127.0.0.1 -U sandboxd \
  -d sandboxd_placement_test -Atc \
  "SELECT lease_expires_unix_ms FROM sandboxd_placement.requests WHERE tenant_id = 'tenant-a' AND idempotency_key = 'userspace-ingress-e2e'")
test "$lease_after" -gt "$lease_before"
curl -fsS \
  -H "Authorization: Bearer tenant-key.${tenant_secret}" \
  "http://127.0.0.1:${gateway_port}/v1/placements/userspace-ingress-e2e/ingress/server/8080/ready" \
  >/dev/null

cancel_status=$(curl -sS -o "$temporary/userspace-cancelled.json" -w '%{http_code}' \
  -X DELETE \
  -H "Authorization: Bearer tenant-key.${tenant_secret}" \
  "http://127.0.0.1:${gateway_port}/v1/placements/userspace-ingress-e2e")
test "$cancel_status" = 200
jq -e '.state == "cancelled"' "$temporary/userspace-cancelled.json" >/dev/null
withdrawn_status=$(curl -sS -o "$temporary/userspace-withdrawn.json" -w '%{http_code}' \
  -H "Authorization: Bearer tenant-key.${tenant_secret}" \
  "http://127.0.0.1:${gateway_port}/v1/placements/userspace-ingress-e2e/ingress/server/8080/ready")
test "$withdrawn_status" = 503

curl -fsS "http://127.0.0.1:${active_metrics_port}/metrics" \
  >"$temporary/autoscaler-metrics.txt"
grep -F 'phase="cold_wait",quantile="0.99"' \
  "$temporary/autoscaler-metrics.txt" >/dev/null
grep -F 'phase="warm_wait",quantile="0.99"' \
  "$temporary/autoscaler-metrics.txt" >/dev/null
grep -F 'phase="create_to_ready",quantile="0.99"' \
  "$temporary/autoscaler-metrics.txt" >/dev/null
grep -F 'sandboxd_pool_utilization_ratio{pool="fixed-standard-warm"}' \
  "$temporary/autoscaler-metrics.txt" >/dev/null

jq '
  .deadline_ms = 120000
  | .pool_name = "reviewed-cold-fallback"
  | .resource_shape = "cold-standard-v1"
  | .operation = {
      "kind": "inspect",
      "parameters": {"sandbox": "burst-placeholder"}
    }
' "$temporary/cold-request.json" >"$temporary/burst-template.json"
burst_processes=()
for index in $(seq 1 100); do
  (
    jq --arg sandbox "burst-${index}" \
      '.sandbox_id = $sandbox | .operation.parameters.sandbox = $sandbox' \
      "$temporary/burst-template.json" >"$temporary/burst-${index}.json"
    curl -sS -o "$temporary/burst-${index}-submitted.json" -w '%{http_code}' \
      -H "Authorization: Bearer tenant-key.${tenant_secret}" \
      -H "Idempotency-Key: autoscale-burst-${index}" \
      -H "Content-Type: application/json" \
      --data-binary @"$temporary/burst-${index}.json" \
      "http://127.0.0.1:${gateway_port}/v1/placements" \
      >"$temporary/burst-${index}.status"
  ) &
  burst_processes+=("$!")
  if (( index % 20 == 0 )); then
    for process in "${burst_processes[@]}"; do
      wait "$process"
    done
    burst_processes=()
  fi
done
test "$(grep -l '^202$' "$temporary"/burst-*.status | wc -l)" = 100
sleep 2
cold_desired=$(kubectl get statefulset -n "$namespace" sandboxd-reviewed-cold \
  -o jsonpath='{.spec.replicas}')
warm_desired=$(kubectl get statefulset -n "$namespace" sandboxd-fixed-standard-warm \
  -o jsonpath='{.spec.replicas}')
test "$cold_desired" -le 2
test "$((cold_desired + warm_desired))" -le 4
curl -fsS "http://127.0.0.1:${active_metrics_port}/metrics" \
  >"$temporary/burst-metrics.txt"
queued=$(awk '
  $1 == "sandboxd_pool_queued_assignments{pool=\"reviewed-cold-fallback\"}" {
    print $2
  }
' "$temporary/burst-metrics.txt")
test "$queued" -gt 0
test "$queued" -le 100
grep -F 'sandboxd_pool_saturated{pool="reviewed-cold-fallback"} 1' \
  "$temporary/burst-metrics.txt" >/dev/null
cancel_processes=()
for index in $(seq 1 100); do
  (
    curl -sS -o /dev/null -w '%{http_code}' -X DELETE \
      -H "Authorization: Bearer tenant-key.${tenant_secret}" \
      "http://127.0.0.1:${gateway_port}/v1/placements/autoscale-burst-${index}" \
      >"$temporary/burst-${index}.cancel-status"
  ) &
  cancel_processes+=("$!")
  if (( index % 20 == 0 )); then
    for process in "${cancel_processes[@]}"; do
      wait "$process"
    done
    cancel_processes=()
  fi
done
test "$(grep -l '^200$' "$temporary"/burst-*.cancel-status | wc -l)" = 100

kubectl get pod -n "$namespace" -l runtrue.io/autoscaled-worker=true -o json |
  jq -e '
    all(.items[];
      .spec.automountServiceAccountToken == false
      and .spec.hostUsers == false
      and all(.spec.initContainers[]; .securityContext.capabilities.drop == ["ALL"])
    )
  ' >/dev/null

printf 'userspace_ingress_gateway_ms=%s\n' "$ingress_ms"
printf 'userspace_ingress_gateway_bulk_128k_ms=%s\n' "$bulk_ms"
echo "$result"
