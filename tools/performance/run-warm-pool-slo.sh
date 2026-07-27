#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: run-warm-pool-slo.sh --output FILE
       [--policy FILE] [--catalog FILE] [--node NAME] [--skip-prime]
EOF
}

output_file=
policy_file=deploy/k3s/warm-pool-slo.json
catalog_file=deploy/k3s/worker-pools.json
prime=true
node=
while (($#)); do
  case "$1" in
    --output)
      output_file=${2:-}
      shift 2
      ;;
    --policy)
      policy_file=${2:-}
      shift 2
      ;;
    --catalog)
      catalog_file=${2:-}
      shift 2
      ;;
    --node)
      node=${2:-}
      shift 2
      ;;
    --skip-prime)
      prime=false
      shift
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$output_file" ]]; then
  usage
  exit 2
fi
for command_name in jq kubectl python3; do
  command -v "$command_name" >/dev/null
done
test -s "$policy_file"
test -s "$catalog_file"

slots=$(jq -er '.maximum_concurrent_starts_per_node' "$policy_file")
[[ "$slots" =~ ^[2-9]$|^[1-2][0-9]$|^3[0-2]$ ]]
minimum_samples=$(jq -er '.minimum_activation_samples' "$policy_file")
[[ "$minimum_samples" =~ ^[1-9][0-9]*$ ]]
activation_rounds=$(((minimum_samples + slots - 1) / slots))
((activation_rounds <= 100))
temporary=$(mktemp -d)
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

prime_arguments=()
node_arguments=()
if [[ -n "$node" ]]; then
  node_arguments=(--node "$node")
fi
if [[ "$prime" == true ]]; then
  tools/performance/run-density-gate.sh \
    --slots "$slots" \
    --activation-mode concurrent \
    "${node_arguments[@]}" \
    --output "$temporary/prime.json" >/dev/null
  prime_arguments=(--prime-measurement "$temporary/prime.json")
fi

tools/performance/run-density-gate.sh \
  --slots "$slots" \
  --activation-mode concurrent \
  --activation-rounds "$activation_rounds" \
  "${node_arguments[@]}" \
  --output "$temporary/measurement.json" >/dev/null

python3 tools/performance/warm_pool.py \
  --measurement "$temporary/measurement.json" \
  "${prime_arguments[@]}" \
  --policy "$policy_file" \
  --catalog "$catalog_file" \
  --output "$output_file"
