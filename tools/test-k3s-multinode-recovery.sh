#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${KUBECONFIG:-}" && -r /etc/rancher/k3s/k3s.yaml ]]; then
  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
fi

namespace=sandboxd-system
gateway_port=18084
database_port=15438
metrics_port=19094
maximum_rto_ms=${MULTINODE_RECOVERY_MAX_RTO_MS:-10000}
tenant_secret=tenant-secret-with-at-least-32-bytes-a
work_order_key=1111111111111111111111111111111111111111111111111111111111111111
minio_access=sandboxd-recovery-access
minio_secret=sandboxd-recovery-secret-key
minio_bucket=sandboxd-recovery-artifacts
agent_name=sandboxd-k3s-recovery-agent
agent_node=recovery-agent
agent_volume=sandboxd-k3s-recovery-agent-data
agent_identity_volume=sandboxd-k3s-recovery-agent-identity
api_forward=sandboxd-k3s-recovery-api-forward
agent_forward=sandboxd-k3s-recovery-agent-forward
minio_image='minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e'
minio_runtime_image='minio/minio:sandboxd-recovery-local'
k3s_image='rancher/k3s:v1.36.1-k3s1@sha256:08fdebd14db9ab7d5ea821d5bfa95d02341a6ef886842fcc8d9dfd0e9fa9e0cd'
socat_image='alpine/socat:1.8.0.3@sha256:beb4a68d9e4fe6b0f21ea774a0fde6c31f580dde6368939ed70100c5385b015e'
secret_prep_image='alpine/socat:sandboxd-secret-prep-local'
temporary=$(mktemp -d)
gateway_forward=
database_forward=
autoscaler=

if [[ $(id -u) -eq 0 ]]; then
  privilege=()
else
  privilege=(sudo -n)
fi

cleanup() {
  if [[ -n "${MULTINODE_DIAGNOSTICS_DIR:-}" ]]; then
    mkdir -p "$MULTINODE_DIAGNOSTICS_DIR"
    cp "$temporary/autoscaler.log" \
      "$temporary/database-forward.log" \
      "$temporary/gateway-forward.log" \
      "$MULTINODE_DIAGNOSTICS_DIR/" 2>/dev/null || true
    cp "$temporary"/*-submitted.json \
      "$temporary"/*-recovered.json \
      "$temporary"/*-observer.json \
      "$MULTINODE_DIAGNOSTICS_DIR/" 2>/dev/null || true
    docker logs "$agent_name" \
      >"$MULTINODE_DIAGNOSTICS_DIR/recovery-agent.log" 2>&1 || true
    kubectl get nodes,pods -A -o wide \
      >"$MULTINODE_DIAGNOSTICS_DIR/multinode-resources.txt" 2>&1 || true
    kubectl describe node "$agent_node" \
      >"$MULTINODE_DIAGNOSTICS_DIR/recovery-node.txt" 2>&1 || true
  fi
  if [[ -n "$autoscaler" ]]; then
    kill "$autoscaler" 2>/dev/null || true
    wait "$autoscaler" 2>/dev/null || true
  fi
  if [[ -n "$gateway_forward" ]]; then
    kill "$gateway_forward" 2>/dev/null || true
  fi
  if [[ -n "$database_forward" ]]; then
    kill "$database_forward" 2>/dev/null || true
  fi
  kubectl delete namespace "$namespace" --ignore-not-found --wait=false \
    >/dev/null 2>&1 || true
  kubectl delete node "$agent_node" --ignore-not-found --wait=false \
    >/dev/null 2>&1 || true
  docker rm --force \
    "$agent_forward" "$agent_name" "$api_forward" >/dev/null 2>&1 || true
  docker volume rm "$agent_volume" >/dev/null 2>&1 || true
  docker volume rm "$agent_identity_volume" >/dev/null 2>&1 || true
  rm -rf -- "$temporary"
}
trap 'printf "multi-node recovery failed at line %s\n" "$LINENO" >&2' ERR
trap cleanup EXIT

[[ "$maximum_rto_ms" =~ ^[1-9][0-9]*$ ]]
for command in curl docker jq kubectl sha256sum; do
  command -v "$command" >/dev/null
done
test -x target/release/runtrue-sandbox-autoscaler
test -x target/release/runtrue-sandboxctl

pull_image() {
  local image=$1
  for attempt in 1 2 3 4 5; do
    if docker pull "$image"; then
      return 0
    fi
    sleep "$attempt"
  done
  return 1
}

stop_autoscaler() {
  if [[ -n "$autoscaler" ]]; then
    kill "$autoscaler" 2>/dev/null || true
    wait "$autoscaler" 2>/dev/null || true
    autoscaler=
  fi
}

start_autoscaler() {
  stop_autoscaler
  target/release/runtrue-sandbox-autoscaler \
    --database-url-file "$temporary/autoscaler-database-url" \
    --database-insecure-local \
    --worker-pool-catalog "$temporary/catalog.json" \
    --namespace "$namespace" \
    --maximum-total-workers 4 \
    --reconcile-interval-milliseconds 250 \
    --metrics-listen "127.0.0.1:${metrics_port}" \
    >"$temporary/autoscaler.log" 2>&1 &
  autoscaler=$!
}

docker rm --force \
  "$agent_forward" "$agent_name" "$api_forward" >/dev/null 2>&1 || true
docker volume rm "$agent_volume" >/dev/null 2>&1 || true
docker volume rm "$agent_identity_volume" >/dev/null 2>&1 || true
kubectl delete pod sandboxd-agent-userns-check --ignore-not-found --wait=false \
  >/dev/null 2>&1 || true
kubectl delete node "$agent_node" --ignore-not-found --wait=false \
  >/dev/null 2>&1 || true
kubectl wait --for=delete "node/${agent_node}" --timeout=120s \
  >/dev/null 2>&1 || true

primary_node=$(kubectl get nodes -o json | jq -r '
  first(
    .items[]
    | select(.metadata.labels | has("node-role.kubernetes.io/control-plane"))
    | .metadata.name
  )
')
test -n "$primary_node"
primary_ip=$(kubectl get node "$primary_node" -o json | jq -r '
  .status.addresses[] | select(.type == "InternalIP") | .address
')
test -n "$primary_ip"
primary_pod_cidr_source=$(kubectl get node "$primary_node" \
  -o jsonpath='{.spec.podCIDR}' | cut -d/ -f1)
test -n "$primary_pod_cidr_source"
kubectl label node "$primary_node" \
  runtrue.io/sandbox-node=true runtrue.io/recovery-destination=true --overwrite

pull_image "$k3s_image"
pull_image "$socat_image"
pull_image "$minio_image"
docker tag "$socat_image" "$secret_prep_image"
docker tag "$minio_image" "$minio_runtime_image"
docker save \
  sandboxd-fixed-runtime:local \
  sandbox-gateway:local \
  sandbox-broker:local \
  postgres:17.5-alpine \
  "$minio_runtime_image" \
  "$secret_prep_image" |
  "${privilege[@]}" /usr/local/bin/k3s ctr images import - >/dev/null

docker run --detach --rm \
  --name "$api_forward" \
  --network host \
  "$socat_image" \
  TCP-LISTEN:16443,fork,reuseaddr TCP:127.0.0.1:6443 >/dev/null

k3s_token=$("${privilege[@]}" sh -c 'cat /var/lib/rancher/k3s/server/node-token')
start_agent() {
  docker rm --force "$agent_forward" "$agent_name" >/dev/null 2>&1 || true
  docker run --detach \
    --name "$agent_name" \
    --privileged \
    --hostname "$agent_node" \
    --add-host "${primary_node}:host-gateway" \
    --tmpfs /run \
    --tmpfs /var/run \
    --volume "${agent_volume}:/var/lib/rancher/k3s" \
    --volume "${agent_identity_volume}:/etc/rancher/node" \
    --env "K3S_URL=https://${primary_node}:16443" \
    --env "K3S_TOKEN=${k3s_token}" \
    "$k3s_image" \
    agent \
    --node-name "$agent_node" \
    --node-label runtrue.io/sandbox-node=true \
    --node-label runtrue.io/recovery-source=true >/dev/null
  docker run --detach --rm \
    --name "$agent_forward" \
    --network "container:${agent_name}" \
    "$socat_image" \
    TCP-LISTEN:6443,bind=127.0.0.1,fork,reuseaddr \
    "TCP:${primary_node}:16443" >/dev/null
  for _ in $(seq 1 120); do
    if [[ "$(docker inspect -f '{{.State.Running}}' "$agent_name" \
      2>/dev/null || true)" != true ]]; then
      docker logs "$agent_name" >&2 || true
      return 1
    fi
    if docker exec "$agent_name" \
      test -S /run/k3s/containerd/containerd.sock 2>/dev/null &&
      [[ "$(kubectl get node "$agent_node" \
        -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' \
        2>/dev/null || true)" = True ]]; then
      return 0
    fi
    sleep 1
  done
  docker logs "$agent_name" >&2
  return 1
}
start_agent
agent_gateway=$(docker inspect -f \
  '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' "$agent_name")
test -n "$agent_gateway"

docker save sandboxd-fixed-runtime:local sandbox-broker:local \
  "$secret_prep_image" |
  docker exec -i "$agent_name" \
    ctr --address /run/k3s/containerd/containerd.sock \
    --namespace k8s.io images import - >/dev/null

kubectl delete namespace "$namespace" --ignore-not-found --wait=true >/dev/null
kubectl create namespace "$namespace" >/dev/null
tenant_digest=$(printf %s "$tenant_secret" | sha256sum | cut -d' ' -f1)
printf %s \
  'postgres://sandboxd:sandboxd@127.0.0.1:5432/sandboxd_placement_test' \
  >"$temporary/gateway-database-url"
printf %s \
  "postgres://sandboxd:sandboxd@127.0.0.1:${database_port}/sandboxd_placement_test" \
  >"$temporary/autoscaler-database-url"
printf %s "$work_order_key" >"$temporary/work-order-key"
printf %s '01234567890123456789012345678901' >"$temporary/artifact-master-key"
cat >"$temporary/artifact-credentials.json" <<EOF
{"access_key_id":"${minio_access}","secret_access_key":"${minio_secret}"}
EOF
cat >"$temporary/policy.json" <<EOF
{
  "schema_version": 2,
  "credentials": {
    "tenant-key": {
      "token_sha256": "${tenant_digest}",
      "tenant_id": "tenant-recovery",
      "subject_id": "recovery-client",
      "workspaces": ["workspace-recovery"],
      "maximum_deadline_ms": 300000,
      "pools": ["fixed-standard-warm"],
      "topologies": ["fixed-v1"],
      "resource_shapes": ["standard-v1"],
      "compatibility_cohorts": ["runsc-20260714-fixed"],
      "service_levels": {
        "fixed-standard-warm": {
          "mode": "retained_warm",
          "clean_workers": 2
        }
      }
    }
  }
}
EOF
cat >"$temporary/worker-policy.json" <<'EOF'
{
  "schema_version": 1,
  "credentials": {
    "unused-key": {
      "token_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "worker_id": "unused-worker",
      "pool_name": "fixed-standard-warm",
      "topology": "fixed-v1",
      "resource_shape": "standard-v1",
      "compatibility_cohort": "runsc-20260714-fixed"
    }
  }
}
EOF
jq -e . "$temporary/policy.json" "$temporary/worker-policy.json" >/dev/null
jq '
  (.pools[] | select(.name == "fixed-standard-warm")
    | .policy.warm_headroom) = 2
' deploy/k3s/worker-pools.json >"$temporary/catalog.json"
chmod 0600 "$temporary/catalog.json"
chmod 0600 "$temporary"/*

kubectl create secret generic sandbox-gateway-local-database \
  -n "$namespace" \
  --from-file=url="$temporary/gateway-database-url" >/dev/null
kubectl create secret generic sandbox-gateway-auth \
  -n "$namespace" \
  --from-file=policy.json="$temporary/policy.json" \
  --from-file=worker-policy.json="$temporary/worker-policy.json" >/dev/null
kubectl create secret generic sandbox-work-order \
  -n "$namespace" \
  --from-file=key="$temporary/work-order-key" >/dev/null
kubectl create secret generic sandbox-recovery-artifact \
  -n "$namespace" \
  --from-file=master.key="$temporary/artifact-master-key" \
  --from-file=credentials.json="$temporary/artifact-credentials.json" >/dev/null
kubectl create configmap sandbox-worker-pools \
  -n "$namespace" \
  --from-file=catalog.json="$temporary/catalog.json" >/dev/null
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sandboxd-brokered
  namespace: ${namespace}
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sandboxd-minio
  namespace: ${namespace}
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: sandboxd-minio
  template:
    metadata:
      labels:
        app.kubernetes.io/name: sandboxd-minio
    spec:
      automountServiceAccountToken: false
      nodeSelector:
        kubernetes.io/hostname: ${primary_node}
      containers:
        - name: minio
          image: ${minio_runtime_image}
          imagePullPolicy: Never
          command: [/bin/sh, -c]
          args:
            - mkdir -p "/data/${minio_bucket}" && exec minio server /data --address :9000
          env:
            - name: MINIO_ROOT_USER
              value: ${minio_access}
            - name: MINIO_ROOT_PASSWORD
              value: ${minio_secret}
          ports:
            - name: s3
              containerPort: 9000
          readinessProbe:
            httpGet:
              path: /minio/health/ready
              port: s3
          securityContext:
            allowPrivilegeEscalation: false
            privileged: false
            capabilities:
              drop: [ALL]
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          emptyDir:
            sizeLimit: 2Gi
---
apiVersion: v1
kind: Service
metadata:
  name: sandboxd-minio
  namespace: ${namespace}
spec:
  selector:
    app.kubernetes.io/name: sandboxd-minio
  ports:
    - name: s3
      port: 9000
      targetPort: s3
EOF
kubectl rollout status -n "$namespace" deployment/sandboxd-minio --timeout=180s
minio_pod_ip=$(kubectl get pod -n "$namespace" \
  -l app.kubernetes.io/name=sandboxd-minio \
  -o jsonpath='{.items[0].status.podIP}')
test -n "$minio_pod_ip"

kubectl apply -f deploy/k3s/sandbox-gateway-local-test.yaml >/dev/null
kubectl scale deployment -n "$namespace" sandbox-gateway --replicas=0 >/dev/null
kubectl delete pod -n "$namespace" \
  -l app.kubernetes.io/name=sandbox-gateway --wait=false >/dev/null 2>&1 || true
gateway_args=$(kubectl get deployment -n "$namespace" sandbox-gateway -o json |
  jq -c '
    .spec.template.spec.containers[]
    | select(.name == "gateway")
    | .args + [
        "--worker-heartbeat-timeout-seconds", "30",
        "--lease-lifetime-seconds", "70",
        "--work-order-lifetime-seconds", "65",
        "--dispatch-timeout-seconds", "60",
        "--dispatch-interval-milliseconds", "250"
      ]
  ')
gateway_patch=$(jq -cn \
  --arg node "$primary_node" \
  --argjson args "$gateway_args" \
  '{spec:{template:{spec:{
    nodeSelector:{"kubernetes.io/hostname":$node},
    containers:[{name:"gateway",args:$args}]
  }}}}')
kubectl patch deployment -n "$namespace" sandbox-gateway \
  --type=strategic --patch "$gateway_patch" >/dev/null
kubectl scale deployment -n "$namespace" sandbox-gateway --replicas=1 >/dev/null
kubectl rollout status -n "$namespace" deployment/sandbox-gateway --timeout=180s

kubectl apply -f deploy/k3s/sandboxd-worker-pools.yaml >/dev/null
sandboxd_args=$(kubectl get statefulset -n "$namespace" \
  sandboxd-fixed-standard-warm -o json |
  jq -c --arg endpoint "http://${minio_pod_ip}:9000" '
    .spec.template.spec.containers[]
    | select(.name == "sandboxd")
    | .args + [
        "--artifact-master-key", "/run/secrets/artifact-master.key",
        "--artifact-s3-bucket", "sandboxd-recovery-artifacts",
        "--artifact-s3-region", "us-east-1",
        "--artifact-s3-endpoint", $endpoint,
        "--artifact-s3-allow-http-for-local-testing",
        "--artifact-s3-credentials-file",
          "/run/secrets/artifact-credentials.json"
      ]
  ')
worker_patch=$(jq -cn \
  --arg node "$agent_node" \
  --argjson args "$sandboxd_args" \
  '{
    spec:{
      replicas:1,
      updateStrategy:{type:"OnDelete",rollingUpdate:null},
      template:{spec:{
        nodeSelector:{"kubernetes.io/hostname":$node},
        affinity:{podAntiAffinity:{requiredDuringSchedulingIgnoredDuringExecution:[{
          labelSelector:{matchLabels:{"runtrue.io/worker-pool":"fixed-standard-warm"}},
          topologyKey:"kubernetes.io/hostname"
        }]}},
        initContainers:[{
          name:"artifact-secret-prep",
          image:"alpine/socat:sandboxd-secret-prep-local",
          imagePullPolicy:"Never",
          command:["/bin/sh","-ceu"],
          args:["cp /source/master.key /destination/master.key; chmod 0400 /destination/master.key; cp /source/credentials.json /destination/credentials.json; chmod 0400 /destination/credentials.json"],
          securityContext:{
            privileged:false,
            allowPrivilegeEscalation:false,
            readOnlyRootFilesystem:true,
            runAsUser:0,
            runAsGroup:0,
            capabilities:{drop:["ALL"]},
            seccompProfile:{type:"RuntimeDefault"},
            appArmorProfile:{type:"Unconfined"}
          },
          volumeMounts:[{
            name:"recovery-artifact",
            mountPath:"/source",
            readOnly:true
          },{
            name:"recovery-artifact-materialized",
            mountPath:"/destination"
          }]
        },{
          name:"broker",
          securityContext:{
            appArmorProfile:{type:"Unconfined"}
          }
        }],
        containers:[{
          name:"sandboxd",
          args:$args,
          env:[{
            name:"RUNTRUE_SANDBOXD_OPERATOR_TENANT_ID",
            value:"tenant-recovery"
          },{
            name:"RUNTRUE_SANDBOXD_OPERATOR_WORKSPACE_ID",
            value:"workspace-recovery"
          },{
            name:"RUNTRUE_SANDBOXD_OPERATOR_SUBJECT_ID",
            value:"multinode-recovery-test"
          }],
          securityContext:{
            privileged:false,
            allowPrivilegeEscalation:true,
            readOnlyRootFilesystem:true,
            runAsUser:0,
            runAsGroup:0,
            capabilities:{
              drop:["ALL"],
              add:["SETGID","SETUID","SYS_ADMIN","SYS_CHROOT"]
            },
            seccompProfile:{type:"Unconfined"},
            appArmorProfile:{type:"Unconfined"}
          },
          volumeMounts:[{
            name:"recovery-artifact-materialized",
            mountPath:"/run/secrets/artifact-master.key",
            subPath:"master.key",
            readOnly:true
          },{
            name:"recovery-artifact-materialized",
            mountPath:"/run/secrets/artifact-credentials.json",
            subPath:"credentials.json",
            readOnly:true
          }]
        }],
        volumes:[{
          name:"recovery-artifact",
          secret:{secretName:"sandbox-recovery-artifact",defaultMode:256}
        },{
          name:"recovery-artifact-materialized",
          emptyDir:{sizeLimit:"1Mi"}
        }]
      }}
    }
  }')
kubectl patch statefulset -n "$namespace" sandboxd-fixed-standard-warm \
  --type=strategic --patch "$worker_patch" >/dev/null
kubectl apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sandboxd-recovery-worker-egress
  namespace: ${namespace}
spec:
  podSelector:
    matchLabels:
      runtrue.io/worker-pool: fixed-standard-warm
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: sandboxd-minio
      ports:
        - {protocol: TCP, port: 9000}
---
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
            cidr: ${primary_ip}/32
        - ipBlock:
            cidr: ${agent_gateway}/32
        - ipBlock:
            cidr: ${primary_pod_cidr_source}/32
      ports:
        - {protocol: TCP, port: 8081}
EOF

kubectl port-forward -n "$namespace" deployment/sandbox-gateway \
  "${database_port}:5432" >"$temporary/database-forward.log" 2>&1 &
database_forward=$!
kubectl port-forward -n "$namespace" service/sandbox-gateway \
  "${gateway_port}:8080" >"$temporary/gateway-forward.log" 2>&1 &
gateway_forward=$!
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${gateway_port}/health/ready" >/dev/null; then
    break
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${gateway_port}/health/ready" >/dev/null

lock="$temporary/multinode-recovery.lock.json"
target/release/runtrue-sandboxctl \
  --ctr /usr/bin/ctr \
  --containerd-address /run/k3s/containerd/containerd.sock \
  --containerd-namespace k8s.io \
  --snapshotter overlayfs \
  lock \
  --compose deploy/k3s/conformance-multinode-recovery.yaml \
  --output "$lock" >/dev/null

prepare_workers() {
  stop_autoscaler
  kubectl scale statefulset -n "$namespace" \
    sandboxd-fixed-standard-warm --replicas=0 >/dev/null
  kubectl wait -n "$namespace" \
    --for=delete pod \
    -l runtrue.io/worker-pool=fixed-standard-warm --timeout=120s >/dev/null || true
  sleep 6
  kubectl patch statefulset -n "$namespace" sandboxd-fixed-standard-warm \
    --type=merge \
    --patch "{\"spec\":{\"template\":{\"spec\":{\"nodeSelector\":{\"kubernetes.io/hostname\":\"${agent_node}\"}}}}}" \
    >/dev/null
  kubectl scale statefulset -n "$namespace" \
    sandboxd-fixed-standard-warm --replicas=1 >/dev/null
  for _ in $(seq 1 120); do
    if kubectl get pod -n "$namespace" sandboxd-fixed-standard-warm-0 \
      >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  kubectl get pod -n "$namespace" sandboxd-fixed-standard-warm-0 \
    >/dev/null
  kubectl wait -n "$namespace" \
    --for=condition=Ready pod/sandboxd-fixed-standard-warm-0 \
    --timeout=240s >/dev/null
  test "$(kubectl get pod -n "$namespace" sandboxd-fixed-standard-warm-0 \
    -o jsonpath='{.spec.nodeName}')" = "$agent_node"
  start_autoscaler
  for _ in $(seq 1 180); do
    if kubectl get pod -n "$namespace" sandboxd-fixed-standard-warm-1 \
      >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  kubectl patch statefulset -n "$namespace" sandboxd-fixed-standard-warm \
    --type=merge \
    --patch "{\"spec\":{\"template\":{\"spec\":{\"nodeSelector\":{\"kubernetes.io/hostname\":\"${primary_node}\"}}}}}" \
    >/dev/null
  kubectl delete pod -n "$namespace" sandboxd-fixed-standard-warm-1 \
    --ignore-not-found --wait=false >/dev/null
  kubectl wait -n "$namespace" \
    --for=condition=Ready pod/sandboxd-fixed-standard-warm-1 \
    --timeout=240s >/dev/null
  test "$(kubectl get pod -n "$namespace" sandboxd-fixed-standard-warm-1 \
    -o jsonpath='{.spec.nodeName}')" = "$primary_node"
  source_uid=$(kubectl get pod -n "$namespace" sandboxd-fixed-standard-warm-0 \
    -o jsonpath='{.metadata.uid}')
  destination_uid=$(kubectl get pod -n "$namespace" sandboxd-fixed-standard-warm-1 \
    -o jsonpath='{.metadata.uid}')
  kubectl get pod -n "$namespace" sandboxd-fixed-standard-warm-0 -o json |
    jq -e '
      .spec.hostUsers == false
      and .spec.automountServiceAccountToken == false
      and .spec.hostNetwork != true
      and .spec.containers[0].securityContext.privileged == false
      and (.spec.containers[0].securityContext.capabilities.add | sort)
        == ["SETGID","SETUID","SYS_ADMIN","SYS_CHROOT"]
      and ([.spec.volumes[] | select(has("hostPath"))] | length) == 0
    ' >/dev/null
}

wait_for_checkpoint() {
  local idempotency=$1
  local result
  for _ in $(seq 1 180); do
    result=$(curl -fsS \
      -H "Authorization: Bearer tenant-key.${tenant_secret}" \
      "http://127.0.0.1:${gateway_port}/v1/placements/${idempotency}")
    if jq -e '
      .state == "serving"
      and .recovery.latest_snapshot_id != null
      and .recovery.latest_snapshot_unix_ms != null
    ' >/dev/null <<<"$result"; then
      printf %s "$result"
      return 0
    fi
    sleep 1
  done
  return 1
}

run_recovery() {
  local fault=$1
  local idempotency="multinode-recovery-${fault}"
  local sandbox
  sandbox="recovery-${fault}-$(date +%s)"
  local request="$temporary/${fault}-request.json"
  local cancelled
  local rpo_ms
  local rto_ms
  prepare_workers
  jq -n \
    --arg sandbox "$sandbox" \
    --slurpfile topology "$lock" \
    '{
      workspace_id:"workspace-recovery",
      sandbox_id:$sandbox,
      deadline_ms:300000,
      pool_name:"fixed-standard-warm",
      topology:"fixed-v1",
      resource_shape:"standard-v1",
      compatibility_cohort:"runsc-20260714-fixed",
      recovery_policy:{
        snapshot_interval_ms:2000,
        maximum_staleness_ms:120000,
        maximum_attempts:3
      },
      operation:{
        kind:"create",
        parameters:{
          topology:$topology[0],
          sandbox:$sandbox,
          timeout_ms:30000
        }
      }
    }' >"$request"
  status=$(curl -sS -o "$temporary/${fault}-submitted.json" -w '%{http_code}' \
    -H "Authorization: Bearer tenant-key.${tenant_secret}" \
    -H "Idempotency-Key: ${idempotency}" \
    -H "Content-Type: application/json" \
    --data-binary @"$request" \
    "http://127.0.0.1:${gateway_port}/v1/placements")
  test "$status" = 202
  initial=$(wait_for_checkpoint "$idempotency")
  jq -e \
    --arg worker "worker-${source_uid}" \
    '.worker_id == $worker and .assignment_epoch == 1' \
    >/dev/null <<<"$initial"
  loss_unix_ns=$(date +%s%N)
  if [[ "$fault" = pod ]]; then
    kubectl delete pod -n "$namespace" sandboxd-fixed-standard-warm-0 \
      --grace-period=0 --force --wait=false >/dev/null
  else
    docker stop --time 0 "$agent_name" >/dev/null
  fi
  recovered=
  for _ in $(seq 1 120); do
    recovered=$(curl -fsS \
      -H "Authorization: Bearer tenant-key.${tenant_secret}" \
      "http://127.0.0.1:${gateway_port}/v1/placements/${idempotency}")
    if jq -e \
      --arg worker "worker-${destination_uid}" \
      '.state == "serving"
       and .worker_id == $worker
       and .assignment_epoch > 1
       and .recovery.source_epoch == 1
       and .recovery.fence_confirmed == true
       and .recovery.recovered_unix_ms != null' \
      >/dev/null <<<"$recovered"; then
      break
    fi
    if jq -e '.state == "recovery_failed" or .state == "expired"' \
      >/dev/null <<<"$recovered"; then
      printf 'unexpected terminal recovery state: %s\n' "$recovered" >&2
      return 1
    fi
    sleep 1
  done
  jq -e \
    --arg worker "worker-${destination_uid}" \
    '.state == "serving" and .worker_id == $worker and .assignment_epoch > 1' \
    >/dev/null <<<"$recovered"
  printf '%s\n' "$recovered" >"$temporary/${fault}-recovered.json"

  output=
  for _ in $(seq 1 120); do
    output=$(kubectl exec -n "$namespace" sandboxd-fixed-standard-warm-1 \
      -c sandboxd -- \
      runtrue-sandboxd logs \
      --socket /run/runtrue-sandboxd-operator/control.sock \
      --sandbox "$sandbox" \
      --container observer 2>/dev/null || true)
    if jq -e '.ok and .result != null' >/dev/null 2>&1 <<<"$output"; then
      break
    fi
    sleep 1
  done
  printf '%s\n' "$output" >"$temporary/${fault}-observer.json"
  if ! jq -e '.ok and .result.exit_code == 0' >/dev/null 2>&1 <<<"$output"; then
    printf 'observer did not complete after recovery: %s\n' "$output" >&2
    return 1
  fi
  payload=$(jq -r '.result.stdout' <<<"$output")
  jq -e \
    --argjson loss "$loss_unix_ns" \
    '.boot_unix_ns < $loss
     and .observed_unix_ns > $loss
     and .counter > 0
     and (.memory_token | length) == 48
     and .tmpfs == "tmpfs-preserved\n"
     and .writable_root == "writable-root-preserved\n"' \
    >/dev/null <<<"$payload"

  request_id=$(jq -r .request_id <<<"$recovered")
  audit=$(kubectl exec -n "$namespace" deployment/sandbox-gateway \
    -c postgres -- \
    psql -U sandboxd -d sandboxd_placement_test -At -F, -c \
    "SELECT event,COALESCE(worker_id,''),COALESCE(assignment_epoch,0),COALESCE(snapshot_id,'')
     FROM sandboxd_placement.audit
     WHERE request_id='${request_id}'
     AND event IN (
       'checkpoint_published','source_fenced','recovery_queued',
       'source_fence_confirmed','recovery_assigned','recovery_completed'
     ) ORDER BY sequence")
  for event in checkpoint_published source_fenced recovery_queued \
    source_fence_confirmed recovery_assigned recovery_completed; do
    grep -q "^${event}," <<<"$audit"
  done
  snapshot_count=$(cut -d, -f4 <<<"$audit" | grep -cv '^$')
  test "$snapshot_count" = 6

  kubectl exec -n "$namespace" sandboxd-fixed-standard-warm-1 \
    -c sandboxd -- \
    runtrue-sandboxd stop \
    --socket /run/runtrue-sandboxd-operator/control.sock \
    --sandbox "$sandbox" >/dev/null
  cancelled=$(curl -fsS -X DELETE \
    -H "Authorization: Bearer tenant-key.${tenant_secret}" \
    "http://127.0.0.1:${gateway_port}/v1/placements/${idempotency}")
  jq -e '.state == "cancelled"' >/dev/null <<<"$cancelled"
  rpo_ms=$(jq -r \
    '.recovery.started_unix_ms - .recovery.latest_snapshot_unix_ms' \
    <<<"$recovered")
  rto_ms=$(jq -r \
    '.recovery.recovered_unix_ms - .recovery.started_unix_ms' \
    <<<"$recovered")
  test "$rpo_ms" -le 120000
  test "$rto_ms" -le "$maximum_rto_ms"
  printf '%s_source_epoch=1\n' "$fault"
  printf '%s_destination_epoch=%s\n' \
    "$fault" "$(jq -r .assignment_epoch <<<"$recovered")"
  printf '%s_rpo_ms=%s\n' "$fault" "$rpo_ms"
  printf '%s_rto_ms=%s\n' "$fault" "$rto_ms"
}

recovery_faults=${MULTINODE_RECOVERY_FAULTS:-all}
if [[ "$recovery_faults" != all && "$recovery_faults" != pod && "$recovery_faults" != node ]]; then
  printf 'MULTINODE_RECOVERY_FAULTS must be all, pod, or node\n' >&2
  exit 1
fi
if [[ "$recovery_faults" != node ]]; then
  run_recovery pod
fi
if [[ "$recovery_faults" != pod ]]; then
  if [[ "$recovery_faults" = all ]]; then
    stop_autoscaler
    kubectl scale statefulset -n "$namespace" \
      sandboxd-fixed-standard-warm --replicas=0 >/dev/null
    kubectl wait -n "$namespace" --for=delete pod \
      -l runtrue.io/worker-pool=fixed-standard-warm --timeout=120s >/dev/null || true
    start_agent
    docker save sandboxd-fixed-runtime:local sandbox-broker:local \
      "$secret_prep_image" |
      docker exec -i "$agent_name" \
        ctr --address /run/k3s/containerd/containerd.sock \
        --namespace k8s.io images import - >/dev/null
  fi
  run_recovery node
fi

metrics=$(curl -fsS "http://127.0.0.1:${metrics_port}/metrics")
for phase in recovery_rpo recovery_rto; do
  for quantile in 0.5 0.95 0.99; do
    grep -F \
      "sandboxd_pool_latency_milliseconds{pool=\"fixed-standard-warm\",phase=\"${phase}/standard-v1\",quantile=\"${quantile}\"}" \
      <<<"$metrics" >/dev/null
  done
done
