# Release process

Releases are operator-triggered and must come from `main`.

## Release checklist

1. Confirm hosted `CI` passes on the intended `main` commit.
2. Run `gVisor integration` on a dedicated ephemeral worker matching the
   validated host cohort.
3. Run the manual AWS S3 compatibility check with temporary operator
   credentials.
4. Review open security and release-gate issues.
5. Update `CHANGELOG.md`, the workspace version, and validated host
   dependencies.
6. Create and push a signed annotated version tag from the validated `main`
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

Tags are immutable release inputs. If a release job fails, diagnose the failure
and publish the fix from a new commit with an incremented prerelease identifier.
