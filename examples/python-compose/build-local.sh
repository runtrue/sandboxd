#!/usr/bin/env bash
set -euo pipefail

example_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
docker build --pull=false --tag local/runtrue-sandbox-network-example:20260719 "$example_dir"
