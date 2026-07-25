#!/usr/bin/env bash
set -euo pipefail

namespace=sandboxd-system
preparer_job=sandbox-image-preparer
artifact_pvc=sandbox-preparation-cache
storage_class=sandboxd-attestation-test
persistent_volume=sandboxd-attestation-test
cache_root=/tmp/runtrue-sandboxd-attestation-cache
temporary=$(mktemp -d /tmp/runtrue-sandboxd-attestation.XXXXXXXX)
positive_pod=sandboxd-attested-runtime
revoked_pod=sandboxd-attested-revoked
mismatch_pod=sandboxd-attested-mismatch

cleanup() {
  kubectl -n "$namespace" delete pod \
    "$positive_pod" "$revoked_pod" "$mismatch_pod" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl -n "$namespace" delete job \
    "$preparer_job" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl -n "$namespace" delete secret \
    sandbox-image-preparer-signing \
    sandbox-image-attestation-trust \
    sandbox-image-attestation-revoked \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl -n "$namespace" delete configmap \
    sandbox-image-preparer-evidence \
    sandbox-attested-runtime-topology \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl -n "$namespace" delete pvc \
    "$artifact_pvc" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete pv "$persistent_volume" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete storageclass "$storage_class" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
  rm -f -- \
    "$temporary/private-key" \
    "$temporary/public-key" \
    "$temporary/trust.json" \
    "$temporary/revoked.json"
  rmdir -- "$temporary" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

wait_for_job() {
  local name=$1
  kubectl -n "$namespace" wait \
    --for=condition=complete "job/$name" --timeout=300s
}

wait_for_failed_pod() {
  local name=$1
  for _ in $(seq 1 90); do
    if [[ $(kubectl -n "$namespace" get pod "$name" -o jsonpath='{.status.phase}') == Failed ]]; then
      return
    fi
    sleep 1
  done
  kubectl -n "$namespace" describe pod "$name"
  return 1
}

echo "== Provision isolated preparation cache =="
node=$(kubectl get node -o jsonpath='{.items[0].metadata.name}')
test -n "$node"
sudo install -d -m 0777 "$cache_root"
kubectl apply -f - <<YAML
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: $storage_class
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Retain
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: $persistent_volume
spec:
  capacity:
    storage: 5Gi
  volumeMode: Filesystem
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: $storage_class
  local:
    path: $cache_root
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values: [$node]
YAML

key_result=$(
  target/release/runtrue-sandboxctl generate-image-attestation-key \
    --private-key "$temporary/private-key" \
    --public-key "$temporary/public-key"
)
public_key=$(jq -er '.public_key_base64' <<<"$key_result")
kubectl -n "$namespace" create secret generic sandbox-image-preparer-signing \
  --from-file=private-key="$temporary/private-key"
kubectl -n "$namespace" create configmap sandbox-image-preparer-evidence \
  --from-literal=sbom.json='{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' \
  --from-literal=provenance.json='{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[]}'

echo "== Cold preparation =="
kubectl apply -f deploy/k3s/image-preparer.yaml
wait_for_job "$preparer_job"
cold=$(kubectl -n "$namespace" logs "job/$preparer_job" | tail -1)
jq -e '
  .schema_version == 1
  and .status == "published"
  and .provider_status == "prepared"
  and .preparation_ms > 0
  and .rootfs_bytes > 0
  and .rootfs_entries > 0
' >/dev/null <<<"$cold"

echo "== Duplicate preparation cache hit =="
kubectl -n "$namespace" delete job "$preparer_job" --wait=true
kubectl apply -f deploy/k3s/image-preparer.yaml
wait_for_job "$preparer_job"
cached=$(kubectl -n "$namespace" logs "job/$preparer_job" | tail -1)
jq -e --arg digest "$(jq -r '.worker_artifact_digest' <<<"$cold")" '
  .status == "cache_hit"
  and .worker_artifact_digest == $digest
' >/dev/null <<<"$cached"

artifact_digest=$(jq -er '.worker_artifact_digest' <<<"$cold")
artifact_key=${artifact_digest#sha256:}
artifact_directory="$cache_root/$artifact_key"
exact_reference=$(jq -er '.exact_reference' <<<"$cold")
expected_reference=$(
  jq -r '.services[].image.exact_reference' deploy/k3s/attested-runtime.lock.json \
    | sort -u
)
test "$exact_reference" = "$expected_reference"
test -d "$artifact_directory/rootfs"
test -s "$artifact_directory/attestation.json"
test -s "$artifact_directory/sbom.json"
test -s "$artifact_directory/provenance.json"
target/release/runtrue-sandboxctl verify-image-attestation \
  --attestation "$artifact_directory/attestation.json" \
  --public-key "$temporary/public-key" >/dev/null

private_digest=$(sha256sum "$temporary/private-key" | cut -d' ' -f1)
if find "$artifact_directory" -type f -size 32c -exec sha256sum {} + \
  | cut -d' ' -f1 \
  | grep -Fxq "$private_digest"; then
  echo "private preparation key was retained in the published artifact" >&2
  exit 1
fi

root_digest=$(jq -er '.attestation.expanded_root_digest' "$artifact_directory/attestation.json")
root_entries=$(jq -er '.attestation.expanded_root_entries' "$artifact_directory/attestation.json")
root_bytes=$(jq -er '.attestation.expanded_root_bytes' "$artifact_directory/attestation.json")
toolchain_digest=$(jq -er '.attestation.toolchain_digest' "$artifact_directory/attestation.json")

jq -n \
  --arg public_key "$public_key" \
  --arg toolchain_digest "$toolchain_digest" \
  '{
    trusted_public_keys: {"local-preparer": $public_key},
    allowed_preparation_policies: ["strict-v1"],
    allowed_toolchain_digests: [$toolchain_digest],
    allowed_vulnerability_policies: ["release-v1"],
    revoked_worker_artifact_digests: [],
    revoked_expanded_root_digests: [],
    maximum_attestation_age_ms: 31536000000
  }' >"$temporary/trust.json"
kubectl -n "$namespace" create secret generic sandbox-image-attestation-trust \
  --from-file=policy.json="$temporary/trust.json"
kubectl -n "$namespace" create configmap sandbox-attested-runtime-topology \
  --from-file=topology.json=deploy/k3s/attested-runtime.lock.json

echo "== Start reduced worker from signed immutable content =="
kubectl apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $positive_pod
  namespace: $namespace
  labels:
    app.kubernetes.io/name: sandboxd-attested-runtime
spec:
  hostUsers: false
  restartPolicy: Never
  serviceAccountName: sandboxd
  automountServiceAccountToken: false
  enableServiceLinks: false
  dnsPolicy: Default
  nodeSelector:
    runtrue.io/sandbox-node: "true"
  containers:
    - name: sandboxd
      image: sandboxd-fixed-runtime:local
      imagePullPolicy: Never
      args:
        - serve
        - --worker-id
        - attested-conformance
        - --resource-shape
        - standard-v1
        - --socket
        - /run/runtrue-sandboxd/control.sock
        - --state-root
        - /var/lib/runtrue-sandboxd/state
        - --image-store
        - /var/lib/runtrue-sandboxd/images
        - --fixed-rootfs
        - /artifact/rootfs
        - --fixed-topology-lock
        - /config/topology.json
        - --fixed-rootfs-digest
        - $root_digest
        - --fixed-rootfs-entries
        - "$root_entries"
        - --fixed-rootfs-bytes
        - "$root_bytes"
        - --image-attestation
        - /artifact/attestation.json
        - --image-attestation-trust-policy
        - /trust/policy.json
        - --worker-artifact-digest
        - $artifact_digest
        - --network-mode
        - loopback
        - --cgroup-mode
        - external
        - --runsc
        - /usr/local/bin/runsc
      securityContext:
        privileged: false
        allowPrivilegeEscalation: true
        readOnlyRootFilesystem: true
        runAsUser: 0
        runAsGroup: 0
        capabilities:
          drop: [ALL]
          add: [SETGID, SETUID, SYS_ADMIN, SYS_CHROOT]
        seccompProfile:
          type: Unconfined
        appArmorProfile:
          type: Unconfined
      readinessProbe:
        exec:
          command:
            - /usr/local/bin/runtrue-sandboxd
            - ready
            - --socket
            - /run/runtrue-sandboxd/control.sock
        periodSeconds: 2
      resources:
        requests:
          cpu: 100m
          memory: 256Mi
        limits:
          cpu: "2"
          memory: 2Gi
      volumeMounts:
        - name: artifact
          mountPath: /artifact
          subPath: $artifact_key
          readOnly: true
        - name: topology
          mountPath: /config
          readOnly: true
        - name: trust
          mountPath: /trust
          readOnly: true
        - name: tmp
          mountPath: /tmp
        - name: runtime
          mountPath: /run/runtrue-sandboxd
        - name: state
          mountPath: /var/lib/runtrue-sandboxd
  volumes:
    - name: artifact
      persistentVolumeClaim:
        claimName: $artifact_pvc
    - name: topology
      configMap:
        name: sandbox-attested-runtime-topology
    - name: trust
      secret:
        secretName: sandbox-image-attestation-trust
        defaultMode: 0444
    - name: tmp
      emptyDir:
        sizeLimit: 512Mi
    - name: runtime
      emptyDir:
        sizeLimit: 64Mi
    - name: state
      emptyDir:
        sizeLimit: 4Gi
YAML
kubectl -n "$namespace" wait \
  --for=condition=Ready "pod/$positive_pod" --timeout=180s

pod_spec=$(kubectl -n "$namespace" get pod "$positive_pod" -o json)
jq -e '
  .spec.hostUsers == false
  and .spec.automountServiceAccountToken == false
  and (.spec.hostNetwork // false) == false
  and (.spec.hostPID // false) == false
  and (.spec.hostIPC // false) == false
  and ([.spec.volumes[] | select(.hostPath != null)] | length) == 0
  and ([.spec.containers[0].volumeMounts[] | select(.mountPath | startswith("/run/secrets"))] | length) == 0
  and .spec.containers[0].securityContext.privileged == false
  and .spec.containers[0].securityContext.capabilities.add == ["SETGID", "SETUID", "SYS_ADMIN", "SYS_CHROOT"]
' >/dev/null <<<"$pod_spec"

echo "== Reject revoked and mismatched assignments before readiness =="
jq --arg artifact_digest "$artifact_digest" \
  '.revoked_worker_artifact_digests = [$artifact_digest]' \
  "$temporary/trust.json" >"$temporary/revoked.json"
kubectl -n "$namespace" create secret generic sandbox-image-attestation-revoked \
  --from-file=policy.json="$temporary/revoked.json"

kubectl -n "$namespace" get pod "$positive_pod" -o json \
  | jq --arg name "$revoked_pod" '
      {
        apiVersion,
        kind,
        metadata: {name: $name, namespace: .metadata.namespace, labels: .metadata.labels},
        spec
      }
      | del(.spec.nodeName, .spec.containers[0].readinessProbe)
      | (.spec.volumes[] | select(.name == "trust").secret.secretName) =
          "sandbox-image-attestation-revoked"
    ' \
  | kubectl create -f -
wait_for_failed_pod "$revoked_pod"
kubectl -n "$namespace" logs "$revoked_pod" \
  | grep -F "expired, revoked, or outside operator policy"

kubectl -n "$namespace" get pod "$positive_pod" -o json \
  | jq --arg name "$mismatch_pod" '
      {
        apiVersion,
        kind,
        metadata: {name: $name, namespace: .metadata.namespace, labels: .metadata.labels},
        spec
      }
      | del(.spec.nodeName, .spec.containers[0].readinessProbe)
      | (.spec.containers[0].args | index("--worker-artifact-digest")) as $index
      | .spec.containers[0].args[$index + 1] =
          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ' \
  | kubectl create -f -
wait_for_failed_pod "$mismatch_pod"
kubectl -n "$namespace" logs "$mismatch_pod" \
  | grep -F "does not match the admitted worker artifact"

echo "== Create child containers under gVisor =="
execution=$(
  kubectl -n "$namespace" exec "$positive_pod" -- \
    /usr/local/bin/runtrue-sandboxd run \
    --socket /run/runtrue-sandboxd/control.sock \
    --lock /config/topology.json \
    --project attested-conformance \
    --wait-for client \
    --timeout-seconds 30
)
jq -e '
  .ok == true
  and .result.wait_exit_code == 0
  and .result.image_integrity_verified == true
  and (.result.stdout | contains("\"marker\": \"attested-runtime-passed\""))
  and (.result.stdout | contains("\"kernel\": \"4.19.0-gvisor\""))
  and (.result.stdout | contains("\"uid\": 65534"))
' >/dev/null <<<"$execution"

jq -n \
  --argjson cold "$cold" \
  --argjson cached "$cached" \
  --argjson execution "$execution" \
  '{
    cold_preparation: $cold,
    cached_preparation: $cached,
    activation: {
      infrastructure_ms: $execution.result.infrastructure_ms,
      startup_ms: $execution.result.startup_ms,
      total_ms: $execution.result.total_ms
    },
    revocation_rejected: true,
    worker_identity_mismatch_rejected: true,
    private_key_absent: true
  }'
echo "ATTESTED_IMAGE_PREPARATION_PASS"
