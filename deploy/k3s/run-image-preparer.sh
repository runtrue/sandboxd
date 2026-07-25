#!/usr/bin/env bash
set -euo pipefail

containerd_address=/run/containerd/containerd.sock
result_path="/cache/.latest-result.$$"
install -d -m 0700 /run/containerd/state /workspace/containerd /workspace/images

/usr/local/bin/containerd \
  --config /etc/containerd/preparer.toml \
  --root /workspace/containerd \
  --state /run/containerd/state \
  --address "$containerd_address" \
  --log-level warn &
containerd_pid=$!

cleanup() {
  rm -f -- "$result_path"
  kill -TERM "$containerd_pid" >/dev/null 2>&1 || true
  for _ in $(seq 1 50); do
    if ! kill -0 "$containerd_pid" 2>/dev/null; then
      wait "$containerd_pid" >/dev/null 2>&1 || true
      return
    fi
    sleep 0.1
  done
  kill -KILL "$containerd_pid" >/dev/null 2>&1 || true
  wait "$containerd_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

for _ in $(seq 1 100); do
  if /usr/bin/ctr --address "$containerd_address" version >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$containerd_pid" 2>/dev/null; then
    wait "$containerd_pid"
  fi
  sleep 0.1
done
/usr/bin/ctr --address "$containerd_address" version >/dev/null

exec 3>&1
credential_arguments=()
if [[ -f /run/secrets/registry/credential.json ]]; then
  credential_arguments=(
    --registry-credential /run/secrets/registry/credential.json
  )
fi
result=$(
  /usr/local/bin/runtrue-sandboxctl \
    --ctr /usr/bin/ctr \
    --containerd-address "$containerd_address" \
    --containerd-namespace runtrue-preparation \
    --snapshotter native \
    publish-attested-root \
    --reference "$RUNTRUE_PREPARATION_REFERENCE" \
    --image-store /workspace/images \
    --cache /cache \
    --private-key /run/secrets/signing/private-key \
    --key-id "$RUNTRUE_PREPARATION_KEY_ID" \
    --preparation-policy "$RUNTRUE_PREPARATION_POLICY" \
    --toolchain-digest "$RUNTRUE_PREPARATION_TOOLCHAIN_DIGEST" \
    --sbom /run/evidence/sbom.json \
    --provenance /run/evidence/provenance.json \
    --vulnerability-policy "$RUNTRUE_VULNERABILITY_POLICY" \
    "${credential_arguments[@]}"
)
printf '%s\n' "$result" >&3
umask 077
printf '%s\n' "$result" >"$result_path"
mv -f -- "$result_path" /cache/latest-result.json
