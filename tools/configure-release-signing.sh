#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  configure-release-signing.sh \
    --public-key /managed/path/sandboxd-release-signing.pub \
    --account GITHUB_ACCOUNT \
    --repository OWNER/REPOSITORY \
    [--title "sandboxd release signing"]

Registers a dedicated SSH public key as a GitHub signing key, configures the
current repository to sign annotated tags, and proves GitHub verification with
a temporary non-release tag. The matching private key must already be available
to Git through the operator's secret manager or SSH agent.

This command never generates, copies, prints, or uploads a private key.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

public_key_path=
expected_account=
expected_repository=
signing_key_title="sandboxd release signing"

while (($# > 0)); do
  case "$1" in
    --public-key)
      (($# >= 2)) || die "--public-key requires a value"
      public_key_path=$2
      shift 2
      ;;
    --account)
      (($# >= 2)) || die "--account requires a value"
      expected_account=$2
      shift 2
      ;;
    --repository)
      (($# >= 2)) || die "--repository requires a value"
      expected_repository=$2
      shift 2
      ;;
    --title)
      (($# >= 2)) || die "--title requires a value"
      signing_key_title=$2
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

[[ -n "$public_key_path" ]] || die "--public-key is required"
[[ -n "$expected_account" ]] || die "--account is required"
[[ "$expected_repository" =~ ^[^/]+/[^/]+$ ]] ||
  die "--repository must be an OWNER/REPOSITORY value"
[[ -n "$signing_key_title" ]] || die "--title cannot be empty"

for command_name in gh git jq realpath ssh-keygen; do
  require_command "$command_name"
done

git rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
  die "run this command inside the sandboxd Git worktree"

repository_root=$(git rev-parse --show-toplevel)
public_key_path=$(realpath "$public_key_path")
[[ -f "$public_key_path" ]] || die "public key is not a regular file: $public_key_path"

case "$public_key_path" in
  "$repository_root"|"$repository_root"/*)
    die "the signing key must be managed outside the repository worktree"
    ;;
esac

if [[ -n "$(git status --porcelain)" ]]; then
  die "the worktree must be clean before validating release signing"
fi

public_key=$(awk '
  NF {
    if (++lines > 1) {
      exit 2
    }
    print $0
  }
  END {
    if (lines != 1) {
      exit 3
    }
  }
' "$public_key_path") || die "public key must contain exactly one non-empty line"

public_key_type=$(awk '{print $1}' <<<"$public_key")
[[ "$public_key_type" == "ssh-ed25519" ]] ||
  die "release signing requires a dedicated Ed25519 SSH key"

public_key_identity=$(awk '{print $1 " " $2}' <<<"$public_key")
ssh-keygen -lf "$public_key_path" -E sha256 >/dev/null ||
  die "public key is not a valid SSH public key"

authenticated_account=$(gh api user --jq .login)
if [[ "${authenticated_account,,}" != "${expected_account,,}" ]]; then
  die "gh is authenticated as ${authenticated_account}, expected ${expected_account}"
fi

origin_repository=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
if [[ "${origin_repository,,}" != "${expected_repository,,}" ]]; then
  die "origin resolves to ${origin_repository}, expected ${expected_repository}"
fi

git fetch --no-tags origin main
main_commit=$(git rev-parse refs/remotes/origin/main)
head_commit=$(git rev-parse HEAD)
[[ "$head_commit" == "$main_commit" ]] ||
  die "HEAD must equal the current origin/main commit (${main_commit})"

api_error_file=$(mktemp)
tag_name=
tag_was_pushed=false

cleanup() {
  status=$?
  trap - EXIT
  cleanup_failed=false

  if [[ "$tag_was_pushed" == true && -n "$tag_name" ]]; then
    if ! git push --quiet origin ":refs/tags/${tag_name}"; then
      printf 'error: could not remove remote test tag %s\n' "$tag_name" >&2
      cleanup_failed=true
    fi
  fi

  if [[ -n "$tag_name" ]] &&
    git show-ref --verify --quiet "refs/tags/${tag_name}"; then
    git tag --delete "$tag_name" >/dev/null
  fi

  rm -f -- "$api_error_file"

  if [[ "$cleanup_failed" == true ]]; then
    exit 1
  fi
  exit "$status"
}
trap cleanup EXIT

if ! signing_keys_json=$(
  gh api \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    "user/ssh_signing_keys?per_page=100" \
    2>"$api_error_file"
); then
  if grep -Eq 'admin:ssh_signing_key|write:ssh_signing_key|Resource not accessible' \
    "$api_error_file"; then
    die "GitHub signing-key access is missing; run: gh auth refresh -h github.com -s admin:ssh_signing_key"
  fi
  sed 's/^/GitHub API: /' "$api_error_file" >&2
  die "could not list GitHub SSH signing keys"
fi

key_is_registered=false
while IFS= read -r registered_key; do
  registered_identity=$(awk '{print $1 " " $2}' <<<"$registered_key")
  if [[ "$registered_identity" == "$public_key_identity" ]]; then
    key_is_registered=true
    break
  fi
done < <(jq -r '.[].key' <<<"$signing_keys_json")

if [[ "$key_is_registered" == false ]]; then
  gh api \
    --method POST \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    user/ssh_signing_keys \
    --raw-field "title=${signing_key_title}" \
    --raw-field "key=${public_key}" \
    >/dev/null
fi

git config --local gpg.format ssh
git config --local user.signingkey "$public_key_path"
git config --local tag.gpgSign true

tag_name="release-signing-check-$(date -u +%Y%m%dT%H%M%SZ)-$$"
git tag \
  --sign \
  --message "sandboxd release signing verification (non-release)" \
  "$tag_name" \
  "$head_commit"
git push --quiet origin "refs/tags/${tag_name}:refs/tags/${tag_name}"
tag_was_pushed=true

tag_ref_json=$(
  gh api \
    --header "X-GitHub-Api-Version: 2022-11-28" \
    "repos/${expected_repository}/git/ref/tags/${tag_name}"
)
[[ "$(jq -r '.object.type' <<<"$tag_ref_json")" == "tag" ]] ||
  die "GitHub did not store the test tag as an annotated tag"
tag_object_id=$(jq -r '.object.sha' <<<"$tag_ref_json")

verification_json=
for _ in {1..12}; do
  verification_json=$(
    gh api \
      --header "X-GitHub-Api-Version: 2022-11-28" \
      "repos/${expected_repository}/git/tags/${tag_object_id}"
  )
  if [[ "$(jq -r '.verification.verified' <<<"$verification_json")" == "true" ]]; then
    break
  fi
  sleep 5
done

[[ "$(jq -r '.object.type' <<<"$verification_json")" == "commit" ]] ||
  die "the test tag does not target a commit"
[[ "$(jq -r '.object.sha' <<<"$verification_json")" == "$head_commit" ]] ||
  die "the test tag does not target the validated origin/main commit"
[[ "$(jq -r '.verification.verified' <<<"$verification_json")" == "true" ]] ||
  die "GitHub did not verify the signed test tag: $(jq -r '.verification.reason' <<<"$verification_json")"

git push --quiet origin ":refs/tags/${tag_name}"
tag_was_pushed=false
git tag --delete "$tag_name" >/dev/null
tag_name=

printf '{\n'
printf '  "account": "%s",\n' "$authenticated_account"
printf '  "repository": "%s",\n' "$origin_repository"
printf '  "commit": "%s",\n' "$head_commit"
printf '  "key_registered": true,\n'
printf '  "github_verified": true,\n'
printf '  "test_tag_removed": true\n'
printf '}\n'
