#!/usr/bin/env bash
set -euo pipefail

namespace=${SANDBOXD_K3S_NAMESPACE:-sandboxd-system}
worker_controller=sandboxd-userspace-runtime
worker_label=app.kubernetes.io/name=sandboxd-userspace-runtime
socket=/run/runtrue-sandboxd/control.sock
lock=deploy/k3s/conformance-userspace-egress.lock.json
suffix=${GITHUB_RUN_ID:-local}
sandbox="ci-userspace-${suffix}"

if [[ $(id -u) -eq 0 ]]; then
  privilege=()
else
  privilege=(sudo -n)
fi

for command in ip jq kubectl nft pgrep sha256sum; do
  command -v "$command" >/dev/null
done
test -s "$lock"

pod=
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

wait_for_worker() {
  for _ in $(seq 1 180); do
    pod=$(
      kubectl get pod -n "$namespace" -l "$worker_label" -o json |
        jq -r '
          .items[]
          | select(.status.phase == "Running")
          | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
          | .metadata.name
        ' |
        head -n1
    )
    if [[ -n $pod ]] && kubectl exec -n "$namespace" "$pod" -- \
      runtrue-sandboxd ready --socket "$socket" >/dev/null 2>&1
    then
      return 0
    fi
    sleep 1
  done
  echo "userspace worker did not become ready" >&2
  return 1
}

capture_host_network_state() {
  local destination=$1
  "${privilege[@]}" ip -j link show |
    jq -S 'map({
      address,
      flags,
      ifindex,
      ifname,
      link_index,
      link_type,
      linkinfo,
      master,
      mtu
    }) | sort_by(.ifindex)' >"${destination}.links.json"
  "${privilege[@]}" ip netns list | sort >"${destination}.netns"
  "${privilege[@]}" nft -j list ruleset |
    jq -S '
      walk(
        if type == "object"
        then del(.bytes, .handle, .packets)
        else .
        end
      )
    ' >"${destination}.nft.json"
  {
    for path in \
      /proc/sys/net/ipv4/ip_forward \
      /proc/sys/net/ipv4/conf/all/forwarding \
      /proc/sys/net/ipv4/conf/default/forwarding \
      /proc/sys/net/ipv6/conf/all/forwarding \
      /proc/sys/net/ipv6/conf/default/forwarding
    do
      printf '%s=' "$path"
      "${privilege[@]}" sed -n '1p' "$path"
    done
  } >"${destination}.sysctls"
}

compare_host_network_state() {
  local before=$1
  local after=$2
  for suffix in links.json netns nft.json sysctls; do
    if ! diff -u "${before}.${suffix}" "${after}.${suffix}"; then
      echo "nested userspace networking mutated host ${suffix}" >&2
      return 1
    fi
  done
}

kubectl apply --dry-run=server \
  -f deploy/k3s/sandboxd-userspace-runtime.yaml >/dev/null
kubectl delete deployment -n "$namespace" "$worker_controller" \
  --ignore-not-found --wait=true >/dev/null
kubectl apply -f deploy/k3s/sandboxd-userspace-runtime.yaml >/dev/null
wait_for_worker

pod_json=$(kubectl get pod -n "$namespace" "$pod" -o json)
jq -e '
  .spec.hostUsers == false
  and (.spec.hostNetwork // false) == false
  and (.spec.hostPID // false) == false
  and (.spec.hostIPC // false) == false
  and .spec.automountServiceAccountToken == false
  and ([.spec.volumes[] | select(has("hostPath") or has("projected"))] | length) == 0
  and .spec.containers[0].securityContext.privileged == false
  and .spec.containers[0].securityContext.capabilities.drop == ["ALL"]
  and (.spec.containers[0].securityContext.capabilities.add | sort)
      == (["SETGID", "SETUID", "SYS_ADMIN", "SYS_CHROOT"] | sort)
  and (.spec.containers[0].securityContext.capabilities.add | index("NET_ADMIN")) == null
  and (.spec.containers[0].securityContext.capabilities.add | index("NET_RAW")) == null
  and (.spec.containers[0].args | index("--network-mode")) != null
  and (.spec.containers[0].args | index("userspace")) != null
' >/dev/null <<<"$pod_json"

if kubectl get service -n "$namespace" "$worker_controller" >/dev/null 2>&1; then
  echo "userspace worker must not have a Kubernetes Service" >&2
  exit 1
fi
if kubectl get ingress -n "$namespace" "$worker_controller" >/dev/null 2>&1; then
  echo "userspace worker must not have a Kubernetes Ingress" >&2
  exit 1
fi
kubectl get networkpolicy -n "$namespace" sandboxd-default-deny >/dev/null
kubectl get networkpolicy -n "$namespace" sandboxd-userspace-egress >/dev/null

state_directory=$(mktemp -d)
before="${state_directory}/before"
after="${state_directory}/after"
capture_host_network_state "$before"

admit=$(kubectl exec -i -n "$namespace" "$pod" -- \
  runtrue-sandboxd admit --socket "$socket" --lock /dev/stdin <"$lock")
jq -e '
  .ok == true
  and (.result.admitted_images | length) == 1
' >/dev/null <<<"$admit"

started_ns=$(date +%s%N)
create=$(kubectl exec -i -n "$namespace" "$pod" -- \
  runtrue-sandboxd create \
  --socket "$socket" \
  --lock /dev/stdin \
  --sandbox "$sandbox" \
  --timeout-seconds 30 <"$lock")
jq -e '
  .ok == true
  and .result.state == "running"
  and .result.running_services == 2
' >/dev/null <<<"$create"
runtime_project=$(jq -r '.result.runtime_project' <<<"$create")
active_sandbox=true

logs=
for _ in $(seq 1 160); do
  logs=$(kubectl exec -n "$namespace" "$pod" -- \
    runtrue-sandboxd logs \
    --socket "$socket" \
    --sandbox "$sandbox" \
    --container client)
  if jq -e '
    .result.exit_code == 0
    and (.result.stdout | contains("userspace-egress-passed"))
  ' >/dev/null 2>&1 <<<"$logs"; then
    break
  fi
  sleep 0.25
done
completed_ns=$(date +%s%N)

jq -e '
  .ok == true
  and .result.exit_code == 0
  and .result.stderr == ""
  and (.result.stdout | contains("\"approved_https\": true"))
  and (.result.stdout | contains("\"connection_limit_enforced\": true"))
  and (.result.stdout | contains("\"direct_dns_denied\": true"))
  and (.result.stdout | contains("\"direct_ip_denied\": true"))
  and (.result.stdout | contains("\"metadata_denied\": true"))
  and (.result.stdout | contains("\"raw_socket_denied\": true"))
  and (.result.stdout | contains("\"unapproved_domain_denied\": true"))
' >/dev/null <<<"$logs"

capture_host_network_state "$after"
compare_host_network_state "$before" "$after"

runsc_processes=$(
  "${privilege[@]}" pgrep -af "runsc.*sandboxes/${runtime_project}/"
)
grep -F -- "--network=none" <<<"$runsc_processes" >/dev/null
grep -F -- "--host-uds=open" <<<"$runsc_processes" >/dev/null
if grep -F -- "--network=sandbox" <<<"$runsc_processes" >/dev/null; then
  echo "userspace sandbox unexpectedly created a runsc network stack" >&2
  exit 1
fi

elapsed_ms=$(((completed_ns - started_ns) / 1000000))
guest_https_ms=$(
  jq -r '.result.stdout' <<<"$logs" |
    sed -n '/^{/p' |
    tail -n1 |
    jq -r '.approved_https_ms'
)
printf 'userspace_egress_total_ms=%s\n' "$elapsed_ms"
printf 'userspace_egress_guest_https_ms=%s\n' "$guest_https_ms"
printf 'host_network_state_sha256=%s\n' "$(
  sha256sum "${after}.links.json" "${after}.netns" \
    "${after}.nft.json" "${after}.sysctls" |
    sha256sum |
    cut -d' ' -f1
)"
echo "USERSPACE_EGRESS_PASS: approved HTTPS traversed the policy socket; direct, raw, private, and unapproved paths were denied without host network mutation."
