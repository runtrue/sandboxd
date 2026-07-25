#!/usr/bin/env bash
set -euo pipefail

namespace=sandboxd-system
gateway_port=18080
broker_port=18081
tenant_secret=tenant-secret-with-at-least-32-bytes-a
worker_secret=worker-secret-with-at-least-32-bytes-a
work_order_key=1111111111111111111111111111111111111111111111111111111111111111
temporary=$(mktemp -d)
gateway_forward=
broker_forward=
events_client=

cleanup() {
  if [[ -n "$gateway_forward" ]]; then
    kill "$gateway_forward" 2>/dev/null || true
  fi
  if [[ -n "$broker_forward" ]]; then
    kill "$broker_forward" 2>/dev/null || true
  fi
  if [[ -n "$events_client" ]]; then
    kill "$events_client" 2>/dev/null || true
  fi
  rm -rf "$temporary"
}
trap cleanup EXIT

kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f -
node=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
kubectl label node "$node" runtrue.io/sandbox-node=true --overwrite

tenant_digest=$(printf %s "$tenant_secret" | sha256sum | cut -d' ' -f1)
worker_digest=$(printf %s "$worker_secret" | sha256sum | cut -d' ' -f1)
printf %s \
  'postgres://sandboxd:sandboxd@127.0.0.1:5432/sandboxd_placement_test' \
  >"$temporary/url"
printf %s "$work_order_key" >"$temporary/key"

cat >"$temporary/policy.json" <<EOF
{
  "schema_version": 2,
  "credentials": {
    "tenant-key": {
      "token_sha256": "$tenant_digest",
      "tenant_id": "tenant-a",
      "subject_id": "integration-client",
      "workspaces": ["workspace-a"],
      "maximum_deadline_ms": 120000,
      "pools": ["fixed-standard-warm", "userspace-ingress", "reviewed-cold-fallback"],
      "topologies": ["fixed-v1", "userspace-v1"],
      "resource_shapes": ["standard-v1", "cold-standard-v1"],
      "compatibility_cohorts": ["runsc-20260714-fixed"],
      "service_levels": {
        "fixed-standard-warm": {
          "mode": "retained_warm",
          "clean_workers": 2
        },
        "userspace-ingress": {
          "mode": "scale_to_zero"
        },
        "reviewed-cold-fallback": {
          "mode": "scale_to_zero"
        }
      }
    }
  }
}
EOF

cat >"$temporary/worker-policy.json" <<EOF
{
  "schema_version": 1,
  "credentials": {
    "worker-key": {
      "token_sha256": "$worker_digest",
      "worker_id": "worker-fixed-a",
      "pool_name": "fixed-standard-warm",
      "topology": "fixed-v1",
      "resource_shape": "standard-v1",
      "compatibility_cohort": "runsc-20260714-fixed"
    }
  }
}
EOF

cat >"$temporary/registration.json" <<EOF
{
  "schema_version": 1,
  "key_id": "worker-key",
  "secret": "$worker_secret",
  "worker_id": "worker-fixed-a",
  "pool_name": "fixed-standard-warm",
  "topology": "fixed-v1",
  "resource_shape": "standard-v1",
  "compatibility_cohort": "runsc-20260714-fixed",
  "resource_ceilings": {
    "allowed_guest_profiles": [{"name": "strict", "version": 1}],
    "maximum_services": 8,
    "maximum_timeout_ms": 30000,
    "memory_bytes_per_service": 1073741824,
    "cpu_per_service_millis": 1000,
    "pids_per_service": 256,
    "tmpfs_bytes": 67108864,
    "writable_root_bytes_per_service": 67108864,
    "maximum_volumes": 8,
    "maximum_volume_bytes": 536870912,
    "maximum_output_bytes": 1048576
  }
}
EOF

kubectl create secret generic sandbox-gateway-local-database \
  -n "$namespace" \
  --from-file=url="$temporary/url" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic sandbox-gateway-auth \
  -n "$namespace" \
  --from-file=policy.json="$temporary/policy.json" \
  --from-file=worker-policy.json="$temporary/worker-policy.json" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic sandbox-work-order \
  -n "$namespace" \
  --from-file=key="$temporary/key" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic sandbox-worker-auth \
  -n "$namespace" \
  --from-file=registration.json="$temporary/registration.json" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap sandbox-worker-pools \
  -n "$namespace" \
  --from-file=catalog.json=deploy/k3s/worker-pools.json \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f deploy/k3s/sandbox-gateway-local-test.yaml
kubectl rollout restart -n "$namespace" deployment/sandbox-gateway
kubectl rollout status -n "$namespace" deployment/sandbox-gateway --timeout=180s
kubectl apply -f deploy/k3s/sandboxd-fixed-runtime-brokered.yaml
gateway_ip=$(kubectl get service -n "$namespace" sandbox-gateway \
  -o jsonpath='{.spec.clusterIP}')
kubectl create configmap sandbox-control-plane \
  -n "$namespace" \
  --from-literal="gateway-address=${gateway_ip}:8080" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart -n "$namespace" deployment/sandboxd-fixed-runtime-brokered
kubectl rollout status \
  -n "$namespace" deployment/sandboxd-fixed-runtime-brokered --timeout=240s

worker_pod=$(kubectl get pod -n "$namespace" \
  -l app.kubernetes.io/name=sandboxd-fixed-runtime-brokered \
  --field-selector=status.phase=Running \
  --sort-by=.metadata.creationTimestamp \
  -o jsonpath='{.items[-1:].metadata.name}')
worker_json=$(kubectl get pod -n "$namespace" "$worker_pod" -o json)
jq -e '
  .spec.hostUsers == false
  and .spec.automountServiceAccountToken == false
  and (.spec.initContainers | length) == 1
  and .spec.initContainers[0].name == "broker"
  and .spec.initContainers[0].restartPolicy == "Always"
  and .spec.initContainers[0].securityContext.runAsUser == 65533
  and .spec.initContainers[0].securityContext.allowPrivilegeEscalation == false
  and .spec.initContainers[0].securityContext.privileged == false
  and .spec.initContainers[0].securityContext.readOnlyRootFilesystem == true
  and .spec.initContainers[0].securityContext.capabilities.drop == ["ALL"]
  and (.spec.initContainers[0].volumeMounts | map(.name) | index("work-order-key")) == null
  and (.spec.initContainers[0].volumeMounts | map(.name) | index("sandboxd-operator-runtime")) == null
  and (.spec.containers[0].volumeMounts | map(.name) | index("worker-registration")) == null
  and (.spec.containers[0].volumeMounts | map(.name) | index("sandboxd-operator-runtime")) != null
  and .spec.containers[0].restartPolicy == "Never"
  and (.spec.containers[0].args | index("--workload-socket")) != null
  and (.spec.containers[0].args | index("--broker-uid")) != null
  and (.spec.containers[0].args | index("--broker-gid")) != null
  and (.spec.containers[0].args | index("65533")) != null
  and .spec.automountServiceAccountToken == false
' >/dev/null <<<"$worker_json"

kubectl port-forward -n "$namespace" service/sandbox-gateway \
  "${gateway_port}:8080" >"$temporary/gateway-forward.log" 2>&1 &
gateway_forward=$!
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${gateway_port}/health/ready" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${gateway_port}/health/ready" >/dev/null

kubectl port-forward -n "$namespace" "pod/${worker_pod}" \
  "${broker_port}:8081" >"$temporary/broker-forward.log" 2>&1 &
broker_forward=$!
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${broker_port}/health/ready" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${broker_port}/health/ready" >/dev/null
operator_status=$(curl -sS -o "$temporary/operator.json" -w '%{http_code}' \
  -H "Content-Type: application/json" \
  --data-binary '{"schema_version":2,"request_id":"operator-test","authorization":{"kind":"operator"},"operation":{"kind":"shutdown"}}' \
  "http://127.0.0.1:${broker_port}/v1/dispatch" || true)
case "$operator_status" in
  400|422) ;;
  *) exit 1 ;;
esac

sandbox="brokered-$(date +%s)"
jq -n \
  --arg sandbox "$sandbox" \
  --slurpfile topology deploy/k3s/fixed-runtime.lock.json \
  '{
    workspace_id: "workspace-a",
    sandbox_id: $sandbox,
    deadline_ms: 120000,
    pool_name: "fixed-standard-warm",
    topology: "fixed-v1",
    resource_shape: "standard-v1",
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
  }' >"$temporary/submission.json"

status=$(curl -sS -o "$temporary/submitted.json" -w '%{http_code}' \
  -H "Authorization: Bearer tenant-key.${tenant_secret}" \
  -H "Idempotency-Key: brokered-e2e" \
  -H "Content-Type: application/json" \
  --data-binary @"$temporary/submission.json" \
  "http://127.0.0.1:${gateway_port}/v1/placements")
test "$status" = 202

curl -fsSN --max-time 180 \
  -H "Authorization: Bearer tenant-key.${tenant_secret}" \
  "http://127.0.0.1:${gateway_port}/v1/placements/brokered-e2e/events" \
  >"$temporary/events.txt" &
events_client=$!

result=
for _ in $(seq 1 180); do
  result=$(curl -fsS \
    -H "Authorization: Bearer tenant-key.${tenant_secret}" \
    "http://127.0.0.1:${gateway_port}/v1/placements/brokered-e2e")
  if jq -e '.state == "completed"' >/dev/null 2>&1 <<<"$result"; then
    break
  fi
  sleep 1
done
jq -e '
  .state == "completed"
  and .worker_id == "worker-fixed-a"
  and .assignment_epoch == 1
  and (.result_digest | startswith("sha256:"))
  and .response.ok == true
  and .response.error == null
  and .response.result.wait_exit_code == 0
  and (.response.result.stdout | contains("\"marker\": \"nested-container-passed\""))
  and (.response.result.stdout | contains("\"kernel\": \"4.19.0-gvisor\""))
  and (.response.result.stdout | contains("\"uid\": 65534"))
' >/dev/null <<<"$result"
wait "$events_client"
events_client=
grep -F 'event: placement' "$temporary/events.txt" >/dev/null
grep -F '"state":"completed"' "$temporary/events.txt" >/dev/null
if grep -F 'queue_position' "$temporary/events.txt" >/dev/null; then
  exit 1
fi

retry_status=$(curl -sS -o "$temporary/retry.json" -w '%{http_code}' \
  -H "Authorization: Bearer tenant-key.${tenant_secret}" \
  -H "Idempotency-Key: brokered-e2e" \
  -H "Content-Type: application/json" \
  --data-binary @"$temporary/submission.json" \
  "http://127.0.0.1:${gateway_port}/v1/placements")
test "$retry_status" = 200
jq -e --arg request_id "$(jq -r .request_id "$temporary/submitted.json")" '
  .request_id == $request_id
  and .state == "completed"
' "$temporary/retry.json" >/dev/null

printf '%s\n' "$result"
