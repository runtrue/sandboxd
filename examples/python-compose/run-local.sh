#!/usr/bin/env bash
set -euo pipefail

example_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$example_dir/../.." && pwd)
binary="$repo_dir/target/release/runtrue-sandboxd"
lock_path="$example_dir/topology.lock.json"
image_store=/var/lib/runtrue-sandboxd/images
run_root=/tmp/runtrue-sandboxd-local
socket="$run_root/control.sock"
state_root="$run_root/state"
daemon_log="$run_root/daemon.log"
sandbox="sandboxd-local-$$"

if [[ $(id -u) -ne 0 ]]; then
  echo "run-local.sh requires root for cgroups and network namespaces" >&2
  exit 1
fi

cargo build --quiet --release --offline --manifest-path "$repo_dir/Cargo.toml" \
  --package runtrue-sandboxctl --package runtrue-sandboxd

"$repo_dir/target/release/runtrue-sandboxctl" \
  lock --compose "$example_dir/compose.yaml" --output "$lock_path"

"$repo_dir/target/release/runtrue-sandboxctl" \
  prepare-image --reference docker.io/library/python:3.13-slim \
  --image-store "$image_store" >/dev/null

install -d -m 0700 "$run_root"
"$binary" serve --socket "$socket" --state-root "$state_root" \
  --image-store "$image_store" >"$daemon_log" 2>&1 &
daemon_pid=$!

cleanup() {
  if [[ -S "$socket" ]]; then
    "$binary" stop --socket "$socket" --sandbox "$sandbox" >/dev/null 2>&1 || true
    "$binary" shutdown --socket "$socket" >/dev/null 2>&1 || true
  fi
  wait "$daemon_pid" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 100); do
  if "$binary" ping --socket "$socket" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    cat "$daemon_log" >&2
    exit 1
  fi
  sleep 0.05
done

"$binary" admit --socket "$socket" --lock "$lock_path"
"$binary" create --socket "$socket" --lock "$lock_path" \
  --sandbox "$sandbox" --timeout-seconds 20
sleep 1
"$binary" logs --socket "$socket" --sandbox "$sandbox" --container client
"$binary" pause --socket "$socket" --sandbox "$sandbox"
"$binary" inspect --socket "$socket" --sandbox "$sandbox"
"$binary" resume --socket "$socket" --sandbox "$sandbox"
"$binary" inspect --socket "$socket" --sandbox "$sandbox"
"$binary" stop --socket "$socket" --sandbox "$sandbox"
"$binary" stats --socket "$socket"
