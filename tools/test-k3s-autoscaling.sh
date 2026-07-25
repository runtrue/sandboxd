#!/usr/bin/env bash
set -euo pipefail

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
trap cleanup EXIT

install -m 0600 deploy/k3s/worker-pools.json "$temporary/catalog.json"
printf %s \
  "postgres://sandboxd:sandboxd@127.0.0.1:${database_port}/sandboxd_placement_test" \
  >"$temporary/database-url"
chmod 0600 "$temporary/database-url"

kubectl apply -f deploy/k3s/sandboxd-worker-pools.yaml
test "$(kubectl get statefulset -n "$namespace" sandboxd-reviewed-cold \
  -o jsonpath='{.spec.replicas}')" = 0

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
  target/release/runtrue-sandbox-autoscaler \
    --database-url-file "$temporary/database-url" \
    --database-insecure-local \
    --worker-pool-catalog "$temporary/catalog.json" \
    --namespace "$namespace" \
    --maximum-total-workers 4 \
    --reconcile-interval-milliseconds 250 \
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

kubectl get pod -n "$namespace" -l runtrue.io/autoscaled-worker=true -o json |
  jq -e '
    all(.items[];
      .spec.automountServiceAccountToken == false
      and .spec.hostUsers == false
      and all(.spec.initContainers[]; .securityContext.capabilities.drop == ["ALL"])
    )
  ' >/dev/null

echo "$result"
