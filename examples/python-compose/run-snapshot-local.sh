#!/usr/bin/env bash
set -euo pipefail

example_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$example_dir/../.." && pwd)
daemon="$repo_dir/target/release/runtrue-sandboxd"
control="$repo_dir/target/release/runtrue-sandboxctl"
lock_path="$example_dir/snapshot-topology.lock.json"
image_store=/var/lib/runtrue-sandboxd/images
run_root=$(mktemp -d /tmp/runtrue-snapshot-example.XXXXXX)
socket="$run_root/control.sock"
state_root="$run_root/state"
daemon_log="$run_root/daemon.log"
source_sandbox="ss-$$"
live_restored_sandbox="sl-$$"
live_snapshot="snapshot-live-$$"
move_snapshot="snapshot-move-$$"
passed=false

payload_state() {
  local runsc_root=$1
  local runtime=$2
  /usr/local/bin/runsc --root="$runsc_root" "${runsc_common[@]}" \
    exec --user=65534:65534 "rts-$runtime-client" /usr/local/bin/python3 -c \
    'import hashlib, pathlib, stat; p=pathlib.Path("/var/tmp/snapshot-payload"); d=p.read_bytes(); print(f"{hashlib.sha256(d).hexdigest()}:{stat.S_IMODE(p.stat().st_mode):04o}:{len(d)}")'
}

if [[ $(id -u) -ne 0 ]]; then
  echo "run-snapshot-local.sh requires root for cgroups and network namespaces" >&2
  exit 1
fi

cargo build --quiet --release --offline --manifest-path "$repo_dir/Cargo.toml" \
  --package runtrue-sandboxctl --package runtrue-sandboxd

"$control" lock --compose "$example_dir/compose-snapshot.yaml" --output "$lock_path"
"$control" prepare-image --reference docker.io/library/python:3.13-slim \
  --image-store "$image_store" >/dev/null

chmod 0700 "$run_root"
"$daemon" serve --socket "$socket" --state-root "$state_root" \
  --image-store "$image_store" >"$daemon_log" 2>&1 &
daemon_pid=$!

cleanup() {
  shutdown_ok=false
  if [[ -S "$socket" ]]; then
    "$daemon" stop --socket "$socket" --sandbox "$source_sandbox" >/dev/null 2>&1 || true
    "$daemon" stop --socket "$socket" --sandbox "$live_restored_sandbox" >/dev/null 2>&1 || true
    if "$daemon" shutdown --socket "$socket" >/dev/null 2>&1; then
      shutdown_ok=true
    fi
  fi
  for _ in $(seq 1 100); do
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      break
    fi
    sleep 0.05
  done
  if kill -0 "$daemon_pid" 2>/dev/null; then
    kill "$daemon_pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      if ! kill -0 "$daemon_pid" 2>/dev/null; then
        break
      fi
      sleep 0.05
    done
  fi
  if kill -0 "$daemon_pid" 2>/dev/null; then
    kill -KILL "$daemon_pid" 2>/dev/null || true
  fi
  wait "$daemon_pid" 2>/dev/null || true
  if [[ $passed == true ]] \
    && [[ $shutdown_ok == true ]] \
    && [[ -z $(find "$state_root/sandboxes" -name recovery.json -print -quit 2>/dev/null) ]]; then
    find "$run_root" -depth -delete 2>/dev/null || true
  else
    echo "retained failed-run state at $run_root" >&2
  fi
}
trap cleanup EXIT

for _ in $(seq 1 100); do
  "$daemon" ping --socket "$socket" >/dev/null 2>&1 && break
  sleep 0.05
done

"$daemon" admit --socket "$socket" --lock "$lock_path" >/dev/null
create_started=$(date +%s%N)
source_create=$("$daemon" create --socket "$socket" --lock "$lock_path" \
  --sandbox "$source_sandbox" --timeout-seconds 30)
cached_create_millis=$(( ($(date +%s%N) - create_started) / 1000000 ))
printf '%s\n' "$source_create"
source_runtime=$(sed -n 's/.*"runtime_project":"\([^"]*\)".*/\1/p' <<<"$source_create")
if [[ -z $source_runtime ]]; then
  echo "operator create response omitted runtime_project" >&2
  exit 1
fi

source_runsc_root="$state_root/sandboxes/$source_runtime/runsc"
runsc_common=(
  --network=sandbox
  --ignore-cgroups=true
  --platform=systrap
  --overlay2=none
  --file-access=exclusive
  --file-access-mounts=exclusive
  --directfs=false
  --host-uds=none
  --host-fifo=none
  --net-raw=false
)
client_healthy=false
for _ in $(seq 1 100); do
  if /usr/local/bin/runsc --root="$source_runsc_root" "${runsc_common[@]}" \
    exec --user=65534:65534 "rts-$source_runtime-client" \
    /usr/local/bin/python3 -c \
    'import pathlib,sys; p=pathlib.Path("/var/tmp/snapshot-counter"); sys.exit(0 if p.exists() and int(p.read_text()) >= 1 else 1)' \
    >/dev/null 2>&1; then
    client_healthy=true
    break
  fi
  sleep 0.05
done
if [[ $client_healthy != true ]]; then
  "$daemon" logs --socket "$socket" --sandbox "$source_sandbox" --container client >&2 || true
  exit 1
fi
counter_before=$(/usr/local/bin/runsc --root="$source_runsc_root" "${runsc_common[@]}" \
  exec --user=65534:65534 "rts-$source_runtime-client" /bin/cat /var/tmp/snapshot-counter)
payload_before=$(payload_state "$source_runsc_root" "$source_runtime")
writable_backing=$(find "$state_root/writable-roots" -name quota.ext4 -print -quit)
if [[ -z $writable_backing ]]; then
  echo "writable-root backing file was not created" >&2
  exit 1
fi
sync -f "$(dirname "$writable_backing")/storage"
writable_backing_allocated_bytes=$(( $(stat --format=%b "$writable_backing") * 512 ))

"$daemon" snapshot --socket "$socket" --sandbox "$source_sandbox" \
  --snapshot "$live_snapshot"
sleep 1
"$daemon" inspect --socket "$socket" --sandbox "$source_sandbox" >/dev/null
counter_after_live=$(/usr/local/bin/runsc --root="$source_runsc_root" "${runsc_common[@]}" \
  exec --user=65534:65534 "rts-$source_runtime-client" /bin/cat /var/tmp/snapshot-counter)
if (( counter_after_live <= counter_before )); then
  echo "source counter stopped after live snapshot: before=$counter_before after=$counter_after_live" >&2
  exit 1
fi

live_restore=$("$daemon" restore --socket "$socket" --lock "$lock_path" \
  --sandbox "$live_restored_sandbox" --snapshot "$live_snapshot" --timeout-seconds 30)
printf '%s\n' "$live_restore"
live_restored_runtime=$(sed -n 's/.*"runtime_project":"\([^"]*\)".*/\1/p' <<<"$live_restore")
if [[ -z $live_restored_runtime ]]; then
  echo "operator restore response omitted runtime_project" >&2
  exit 1
fi
sleep 1
live_restored_runsc_root="$state_root/sandboxes/$live_restored_runtime/runsc"
live_restored_counter=$(/usr/local/bin/runsc --root="$live_restored_runsc_root" "${runsc_common[@]}" \
  exec --user=65534:65534 "rts-$live_restored_runtime-client" /bin/cat /var/tmp/snapshot-counter)
live_restored_payload=$(payload_state "$live_restored_runsc_root" "$live_restored_runtime")
if (( live_restored_counter <= counter_before )); then
  echo "live-restored counter did not advance: before=$counter_before after=$live_restored_counter" >&2
  exit 1
fi
if [[ $live_restored_payload != "$payload_before" ]]; then
  echo "live-restored writable content or metadata changed" >&2
  exit 1
fi
"$daemon" stop --socket "$socket" --sandbox "$live_restored_sandbox" >/dev/null

counter_before_move=$(/usr/local/bin/runsc --root="$source_runsc_root" "${runsc_common[@]}" \
  exec --user=65534:65534 "rts-$source_runtime-client" /bin/cat /var/tmp/snapshot-counter)
"$daemon" snapshot --socket "$socket" --sandbox "$source_sandbox" \
  --snapshot "$move_snapshot" --stop-after
if "$daemon" inspect --socket "$socket" --sandbox "$source_sandbox" >/dev/null 2>&1; then
  echo "source assignment remained executable after stop-and-move" >&2
  exit 1
fi
move_restore=$("$daemon" restore --socket "$socket" --lock "$lock_path" \
  --sandbox "$source_sandbox" --snapshot "$move_snapshot" --timeout-seconds 30)
printf '%s\n' "$move_restore"
move_restored_runtime=$(sed -n 's/.*"runtime_project":"\([^"]*\)".*/\1/p' <<<"$move_restore")
if [[ -z $move_restored_runtime ]]; then
  echo "operator restore response omitted runtime_project" >&2
  exit 1
fi

sleep 1
move_restored_runsc_root="$state_root/sandboxes/$move_restored_runtime/runsc"
counter_after_move=$(/usr/local/bin/runsc --root="$move_restored_runsc_root" "${runsc_common[@]}" \
  exec --user=65534:65534 "rts-$move_restored_runtime-client" /bin/cat /var/tmp/snapshot-counter)
move_restored_payload=$(payload_state "$move_restored_runsc_root" "$move_restored_runtime")
if (( counter_after_move <= counter_before_move )); then
  echo "move-restored counter did not advance: before=$counter_before_move after=$counter_after_move" >&2
  exit 1
fi
if [[ $move_restored_payload != "$payload_before" ]]; then
  echo "move-restored writable content or metadata changed" >&2
  exit 1
fi

"$daemon" inspect --socket "$socket" --sandbox "$source_sandbox"
"$daemon" pause --socket "$socket" --sandbox "$source_sandbox" >/dev/null
"$daemon" resume --socket "$socket" --sandbox "$source_sandbox" >/dev/null
"$daemon" stop --socket "$socket" --sandbox "$source_sandbox" >/dev/null
printf 'snapshot_restore_passed live_source=%s live_copy=%s move_before=%s move_after=%s\n' \
  "$counter_after_live" "$live_restored_counter" "$counter_before_move" "$counter_after_move"
printf 'writable_metrics cached_create_ms=%s backing_allocated_bytes=%s payload=%s\n' \
  "$cached_create_millis" "$writable_backing_allocated_bytes" "$payload_before"
passed=true
