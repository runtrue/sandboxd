#!/usr/bin/env bash
set -euo pipefail

minio_image='sandboxd-test-minio:local'
container_name="sandboxd-s3-test-$$"
access_key='sandboxd-test-access'
secret_key='sandboxd-test-secret-key'
bucket='sandboxd-artifacts-test'
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"

cleanup() {
  docker rm --force "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build --tag "$minio_image" \
  --file deploy/k3s/Dockerfile.test-minio .

docker run --detach --rm \
  --name "$container_name" \
  --publish "127.0.0.1:${port}:9000" \
  --env MINIO_ROOT_USER="$access_key" \
  --env MINIO_ROOT_PASSWORD="$secret_key" \
  --env MINIO_TEST_BUCKET="$bucket" \
  --tmpfs /data:rw,nosuid,nodev,noexec,size=128m \
  --entrypoint /bin/sh \
  "$minio_image" \
  -c 'mkdir -p "/data/$MINIO_TEST_BUCKET" && exec minio server /data --address :9000' \
  >/dev/null

for _ in $(seq 1 100); do
  if curl --fail --silent "http://127.0.0.1:${port}/minio/health/ready" >/dev/null; then
    break
  fi
  sleep 0.1
done
curl --fail --silent "http://127.0.0.1:${port}/minio/health/ready" >/dev/null

S3_TEST_ENDPOINT="http://127.0.0.1:${port}" \
S3_TEST_REGION='us-east-1' \
S3_TEST_BUCKET="$bucket" \
S3_TEST_ACCESS_KEY_ID="$access_key" \
S3_TEST_SECRET_ACCESS_KEY="$secret_key" \
  cargo test --locked --release --package runtrue-sandbox-artifact --features s3 \
  --test s3_minio -- --ignored --nocapture
