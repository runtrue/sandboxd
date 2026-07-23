## Summary

Describe the behavior changed and why.

## Security and lifecycle impact

- Trust boundary:
- Tenant isolation:
- Host resources and cleanup:
- Snapshot or portability contract:

Write `none` where an item does not apply.

## Validation

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo test --workspace --locked`
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- [ ] Dependency policy checks pass, or dependencies are unchanged
- [ ] Root-required integration checks pass, or privileged behavior is unchanged
- [ ] Documentation and retained performance measurements are updated where needed
