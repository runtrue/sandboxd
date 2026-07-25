# Release process

Releases are operator-triggered and must come from `main`.

## One-time signing setup

Release tags use a dedicated Ed25519 SSH signing key controlled by the release
operator. Generate and retain the private key under the normal maintainer secret
management policy, and make it available locally through the SSH agent or the
secret manager's SSH signing integration. The private key must not be copied
into this repository, a container image, or GitHub Actions.

Run the repository setup from a clean worktree at the current `origin/main`
commit, supplying only the managed public-key path:

```bash
./tools/configure-release-signing.sh \
  --public-key /managed/path/sandboxd-release-signing.pub \
  --account GITHUB_ACCOUNT \
  --repository runtrue/sandboxd
```

The command verifies the expected GitHub account and repository, registers the
public key as a GitHub signing key if necessary, and sets repository-local Git
configuration:

```text
gpg.format=ssh
user.signingkey=/managed/path/sandboxd-release-signing.pub
tag.gpgSign=true
```

It then signs and pushes a uniquely named `release-signing-check-*` annotated
tag, requires the GitHub tag API to report `verified: true`, and removes the
test tag from both GitHub and the local repository. The test prefix cannot
trigger the release workflow. If the GitHub CLI token lacks signing-key access,
authorize it once with:

```bash
gh auth refresh -h github.com -s admin:ssh_signing_key
```

Re-run the setup command after rotating the release-signing key. Remove the
retired public signing key from the maintainer's GitHub account only after all
supported historical releases remain attributable under the project's key
retention policy.

## Release checklist

1. Confirm `git config --local tag.gpgSign` is `true`, the configured public key
   is the current managed release key, and its private key is available to the
   operator's signing agent.
2. Confirm hosted `CI` passes on the intended `main` commit.
3. Run `gVisor integration` on a dedicated ephemeral worker matching the
   validated host cohort.
4. Run the manual AWS S3 compatibility check with temporary operator
   credentials.
5. Review open security and release-gate issues.
6. Update `CHANGELOG.md`, the workspace version, and validated host
   dependencies.
7. Create and push a signed annotated version tag from the validated `main`
   commit.

Example:

```bash
git switch main
git pull --ff-only
git tag -s v0.1.0-alpha.1 -m "sandboxd v0.1.0-alpha.1"
git push origin v0.1.0-alpha.1
```

The tag-triggered release workflow repeats portable tests, the S3/MinIO
conformance test, Clippy, RustSec audit, dependency policy checks, and a
same-run reproducibility comparison. It then creates a deterministic x86-64
Linux archive, publishes `SHA256SUMS`, and marks hyphenated versions as
prereleases.

Before any build begins, the workflow resolves the annotated tag object through
the GitHub API and requires GitHub's persistent signature verification to be
successful. Lightweight tags, unsigned tags, bad signatures, tags targeting a
different commit, and signatures from keys not registered to the signer are
rejected.

Tags are immutable release inputs. If a release job fails, diagnose the failure
and publish the fix from a new commit with an incremented prerelease identifier.
