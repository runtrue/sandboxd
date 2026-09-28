#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  verify-target.sh \
    --tag security-review-candidate-YYYYMMDD.N \
    --repository OWNER/REPOSITORY \
    --image ROLE=LOCAL_IMAGE [--image ROLE=LOCAL_IMAGE ...] \
    [--cohort docs/security-review/cohort.json]

Verifies a signed GitHub review candidate, the exact pinned review host, and
the locally built image identities. Writes a machine-readable evidence record
to stdout. Run from a clean checkout of the candidate tag.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

expect_equal() {
  local label=$1
  local expected=$2
  local actual=$3
  [[ "$actual" == "$expected" ]] ||
    die "${label} mismatch: expected '${expected}', got '${actual}'"
}

binary_hash() {
  local algorithm=$1
  local command_name=$2
  local binary_path
  binary_path=$(command -v "$command_name")
  "$algorithm" "$binary_path" | awk '{print $1}'
}

tag=
expected_repository=
cohort_path=docs/security-review/cohort.json
declare -a image_arguments=()

while (($# > 0)); do
  case "$1" in
    --tag)
      (($# >= 2)) || die "--tag requires a value"
      tag=$2
      shift 2
      ;;
    --repository)
      (($# >= 2)) || die "--repository requires a value"
      expected_repository=$2
      shift 2
      ;;
    --cohort)
      (($# >= 2)) || die "--cohort requires a value"
      cohort_path=$2
      shift 2
      ;;
    --image)
      (($# >= 2)) || die "--image requires ROLE=LOCAL_IMAGE"
      image_arguments+=("$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ "$tag" =~ ^security-review-candidate-[0-9]{8}\.[0-9]+$ ]] ||
  die "--tag must use security-review-candidate-YYYYMMDD.N"
[[ "$expected_repository" =~ ^[^/]+/[^/]+$ ]] ||
  die "--repository must be OWNER/REPOSITORY"
[[ -f "$cohort_path" ]] || die "cohort file not found: $cohort_path"

for command_name in containerd docker gh git jq k3s rustc runsc sha256sum sha512sum; do
  require_command "$command_name"
done

git rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
  die "run inside the candidate Git worktree"
[[ -z "$(git status --porcelain)" ]] || die "candidate worktree must be clean"

origin_repository=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
expect_equal repository "${expected_repository,,}" "${origin_repository,,}"

git fetch --no-tags origin main "refs/tags/${tag}:refs/tags/${tag}"
head_commit=$(git rev-parse HEAD)
main_commit=$(git rev-parse refs/remotes/origin/main)
tag_commit=$(git rev-list -n 1 "$tag")
expect_equal "candidate checkout" "$tag_commit" "$head_commit"
expect_equal "current origin/main" "$main_commit" "$tag_commit"

tag_ref=$(
  gh api \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    "repos/${expected_repository}/git/ref/tags/${tag}"
)
expect_equal "GitHub tag object type" tag "$(jq -r '.object.type' <<<"$tag_ref")"
tag_object_id=$(jq -r '.object.sha' <<<"$tag_ref")
tag_object=$(
  gh api \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    "repos/${expected_repository}/git/tags/${tag_object_id}"
)
expect_equal "GitHub tag name" "$tag" "$(jq -r '.tag' <<<"$tag_object")"
expect_equal "GitHub tag target type" commit "$(jq -r '.object.type' <<<"$tag_object")"
expect_equal "GitHub tag target" "$tag_commit" "$(jq -r '.object.sha' <<<"$tag_object")"
[[ "$(jq -r '.verification.verified' <<<"$tag_object")" == true ]] ||
  die "GitHub rejected the candidate signature: $(jq -r '.verification.reason' <<<"$tag_object")"

# shellcheck disable=SC1091
source /etc/os-release

expect_equal "OS ID" "$(jq -r '.host.os_id' "$cohort_path")" "$ID"
expect_equal "OS version" "$(jq -r '.host.os_version_id' "$cohort_path")" "$VERSION_ID"
expect_equal "kernel" "$(jq -r '.host.kernel_release' "$cohort_path")" "$(uname -r)"
expect_equal "architecture" "$(jq -r '.host.architecture' "$cohort_path")" "$(uname -m)"
expect_equal \
  "cgroup filesystem" \
  "$(jq -r '.host.cgroup_filesystem' "$cohort_path")" \
  "$(stat -fc %T /sys/fs/cgroup)"

docker_info=$(docker info --format '{{json .}}')
expect_equal \
  "Docker version" \
  "$(jq -r '.host.docker.version' "$cohort_path")" \
  "$(jq -r '.ServerVersion' <<<"$docker_info")"
expect_equal \
  "Docker binary" \
  "$(jq -r '.host.docker.sha256' "$cohort_path")" \
  "$(binary_hash sha256sum docker)"
expect_equal \
  "Docker storage driver" \
  "$(jq -r '.host.docker.storage_driver' "$cohort_path")" \
  "$(jq -r '.Driver' <<<"$docker_info")"
expect_equal \
  "Docker cgroup driver" \
  "$(jq -r '.host.docker.cgroup_driver' "$cohort_path")" \
  "$(jq -r '.CgroupDriver' <<<"$docker_info")"
expect_equal \
  "Docker cgroup version" \
  "$(jq -r '.host.docker.cgroup_version' "$cohort_path")" \
  "$(jq -r '.CgroupVersion | tostring' <<<"$docker_info")"

containerd_version=$(containerd --version | awk '{print $3}')
expect_equal \
  "host containerd version" \
  "$(jq -r '.host.containerd.version' "$cohort_path")" \
  "$containerd_version"
expect_equal \
  "host containerd binary" \
  "$(jq -r '.host.containerd.sha256' "$cohort_path")" \
  "$(binary_hash sha256sum containerd)"

k3s_version_output=$(k3s --version)
k3s_version=$(awk 'NR == 1 {print $3}' <<<"$k3s_version_output")
k3s_commit=$(awk 'NR == 1 {gsub(/[()]/, "", $4); print $4}' <<<"$k3s_version_output")
expect_equal "k3s version" "$(jq -r '.toolchain.k3s.version' "$cohort_path")" "$k3s_version"
expect_equal "k3s commit" "$(jq -r '.toolchain.k3s.commit' "$cohort_path")" "$k3s_commit"
expect_equal \
  "k3s binary" \
  "$(jq -r '.toolchain.k3s.sha256' "$cohort_path")" \
  "$(binary_hash sha256sum k3s)"

runsc_version=$(runsc --version | awk 'NR == 1 {print $3}')
expect_equal \
  "runsc version" \
  "$(jq -r '.toolchain.runsc.version' "$cohort_path")" \
  "$runsc_version"
expect_equal \
  "runsc binary" \
  "$(jq -r '.toolchain.runsc.sha512' "$cohort_path")" \
  "$(binary_hash sha512sum runsc)"
expect_equal "rustc version" "$(jq -r '.toolchain.rustc' "$cohort_path")" "$(rustc --version)"

gvisor_pin=$(jq -r '.toolchain.runsc.version | sub("^release-"; "")' "$cohort_path")
private_containerd_pin=$(jq -r '.toolchain.private_containerd.version' "$cohort_path")
ubuntu_image=$(jq -r '.worker_build_inputs.ubuntu_image' "$cohort_path")
nested_rootfs_image=$(jq -r '.worker_build_inputs.nested_rootfs_image' "$cohort_path")

grep -Fqx "ARG GVISOR_VERSION=${gvisor_pin}" deploy/k3s/Dockerfile.fixed-runtime ||
  die "fixed-runtime gVisor source pin does not match the cohort"
grep -Fqx "ARG GVISOR_VERSION=${gvisor_pin}" deploy/k3s/Dockerfile.host-integrated ||
  die "host-integrated gVisor source pin does not match the cohort"
grep -Fqx "ARG CONTAINERD_VERSION=${private_containerd_pin}" \
  deploy/k3s/Dockerfile.host-integrated ||
  die "private containerd source pin does not match the cohort"
grep -Fq "FROM ${ubuntu_image}" deploy/k3s/Dockerfile.fixed-runtime ||
  die "fixed-runtime Ubuntu image does not match the cohort"
grep -Fq "FROM ${nested_rootfs_image}" deploy/k3s/Dockerfile.fixed-runtime ||
  die "fixed-runtime nested root image does not match the cohort"

declare -A image_references=()
for image_argument in "${image_arguments[@]}"; do
  [[ "$image_argument" == *=* ]] || die "--image requires ROLE=LOCAL_IMAGE"
  role=${image_argument%%=*}
  image_reference=${image_argument#*=}
  [[ -n "$role" && -n "$image_reference" ]] || die "--image requires ROLE=LOCAL_IMAGE"
  [[ -z "${image_references[$role]+present}" ]] || die "duplicate image role: $role"
  image_references["$role"]=$image_reference
done

while IFS= read -r required_role; do
  [[ -n "${image_references[$required_role]+present}" ]] ||
    die "missing required image role: $required_role"
done < <(jq -r '.required_image_roles[]' "$cohort_path")

images_json='[]'
for role in "${!image_references[@]}"; do
  image_reference=${image_references[$role]}
  image_inspect=$(docker image inspect "$image_reference")
  image_record=$(
    jq -c \
      --arg role "$role" \
      --arg reference "$image_reference" \
      '.[0] | {
        role: $role,
        reference: $reference,
        image_id: .Id,
        repo_digests: (.RepoDigests // [])
      }' <<<"$image_inspect"
  )
  images_json=$(jq -c --argjson record "$image_record" '. + [$record]' <<<"$images_json")
done

inputs_json=$(
  sha256sum \
    Cargo.lock \
    deploy/k3s/SECURITY-PROFILES.md \
    deploy/k3s/attested-runtime.lock.json \
    deploy/k3s/fixed-runtime.lock.json \
    deploy/k3s/worker-pools.json \
    | jq -Rsc '
        split("\n")
        | map(select(length > 0))
        | map(capture("^(?<sha256>[0-9a-f]+)  (?<path>.+)$"))
      '
)

jq -n \
  --arg verified_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg repository "$origin_repository" \
  --arg tag "$tag" \
  --arg tag_object "$tag_object_id" \
  --arg commit "$tag_commit" \
  --arg cohort "$(jq -r '.cohort' "$cohort_path")" \
  --arg kernel "$(uname -r)" \
  --arg architecture "$(uname -m)" \
  --arg k3s "$k3s_version" \
  --arg runsc "$runsc_version" \
  --arg containerd "$containerd_version" \
  --argjson images "$images_json" \
  --argjson inputs "$inputs_json" \
  '{
    schema_version: 1,
    verified_at: $verified_at,
    repository: $repository,
    candidate: {
      tag: $tag,
      tag_object: $tag_object,
      commit: $commit,
      github_signature_verified: true
    },
    cohort: {
      id: $cohort,
      kernel: $kernel,
      architecture: $architecture,
      k3s: $k3s,
      runsc: $runsc,
      host_containerd: $containerd
    },
    images: ($images | sort_by(.role)),
    reviewed_input_sha256: $inputs
  }'
