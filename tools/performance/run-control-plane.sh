#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --source DIR --output FILE [--samples N] [--concurrency N] [--warmup N] [--sequential N]" >&2
}

source_directory=""
output_file=""
samples=12000
concurrency=16
warmup=250
sequential=250

while (($#)); do
  case "$1" in
    --source) source_directory=${2:-}; shift 2 ;;
    --output) output_file=${2:-}; shift 2 ;;
    --samples) samples=${2:-}; shift 2 ;;
    --concurrency) concurrency=${2:-}; shift 2 ;;
    --warmup) warmup=${2:-}; shift 2 ;;
    --sequential) sequential=${2:-}; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done

if [[ -z "$source_directory" || -z "$output_file" ]]; then
  usage
  exit 2
fi

source_directory=$(realpath "$source_directory")
output_file=$(realpath -m "$output_file")
harness_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
test -f "$source_directory/Cargo.toml"
command -v cargo >/dev/null
command -v python3 >/dev/null
command -v sudo >/dev/null
sudo -n true

mkdir -p "$(dirname -- "$output_file")"
CARGO_TARGET_DIR="$source_directory/target" cargo build \
  --manifest-path "$source_directory/Cargo.toml" \
  --release --locked --bin runtrue-sandboxd

daemon_binary="$source_directory/target/release/runtrue-sandboxd"
revision=$(git -C "$source_directory" rev-parse HEAD)
binary_size=$(stat -c %s "$daemon_binary")
performance_root=$(mktemp -d /tmp/runtrue-control-perf.XXXXXX)
operator_socket="$performance_root/operator/control.sock"
workload_socket="$performance_root/workload/control.sock"
state_root="$performance_root/state"
image_store="$performance_root/images"
key_file="$performance_root/work-order.key"
daemon_log="$performance_root/daemon.log"
client_root="$performance_root/client"
result_file="$performance_root/result.json"
daemon_pid=""

cleanup() {
  if [[ -n "$daemon_pid" ]] && sudo kill -0 "$daemon_pid" 2>/dev/null; then
    if [[ -S "$operator_socket" ]]; then
      sudo "$daemon_binary" shutdown --socket "$operator_socket" >/dev/null 2>&1 || true
    fi
    for _ in $(seq 1 20); do
      if ! sudo kill -0 "$daemon_pid" 2>/dev/null; then
        break
      fi
      sleep 0.05
    done
    if sudo kill -0 "$daemon_pid" 2>/dev/null; then
      sudo kill "$daemon_pid" 2>/dev/null || true
    fi
    wait "$daemon_pid" 2>/dev/null || true
  fi
  sudo rm -rf -- "$performance_root"
}
trap cleanup EXIT

chmod 0755 "$performance_root"
mkdir -m 0755 "$client_root"
cp -R "$harness_directory/control_plane" "$client_root/"
chmod -R a+rX "$client_root"

key_hex=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
temporary_key="$performance_root/work-order.key.unprivileged"
printf '%s\n' "$key_hex" > "$temporary_key"
sudo install -o root -g root -m 0600 "$temporary_key" "$key_file"
rm "$temporary_key"

if [[ $(id -u) -eq 0 ]]; then
  broker_uid=65534
  command -v setpriv >/dev/null
  client_prefix=(setpriv --reuid="$broker_uid" --regid="$broker_uid" --clear-groups)
else
  broker_uid=$(id -u)
  client_prefix=()
fi

# The caller owns the private log path; only the daemon process needs sudo.
# shellcheck disable=SC2024
sudo "$daemon_binary" serve \
  --socket "$operator_socket" \
  --workload-socket "$workload_socket" \
  --broker-uid "$broker_uid" \
  --work-order-key "$key_file" \
  --maximum-connections 64 \
  --io-timeout-seconds 10 \
  --state-root "$state_root" \
  --image-store "$image_store" \
  --runsc /bin/false \
  --ip /bin/false >"$daemon_log" 2>&1 &
daemon_pid=$!

for _ in $(seq 1 200); do
  if [[ -S "$workload_socket" ]]; then
    break
  fi
  if ! sudo kill -0 "$daemon_pid" 2>/dev/null; then
    cat "$daemon_log" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ ! -S "$workload_socket" ]]; then
  cat "$daemon_log" >&2
  echo "sandboxd did not create the workload socket" >&2
  exit 1
fi

PYTHONPATH="$client_root" "${client_prefix[@]}" python3 -m control_plane \
  --socket "$workload_socket" \
  --key "$key_hex" \
  --revision "$revision" \
  --binary-size "$binary_size" \
  --samples "$samples" \
  --concurrency "$concurrency" \
  --warmup "$warmup" \
  --sequential "$sequential" > "$result_file"

install -m 0644 "$result_file" "$output_file"
