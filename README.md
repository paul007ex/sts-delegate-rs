# sts-delegate-rs

Rust-native successor to `sts-delegate`: an OAuth 2.1 / RFC 8693 security token service with explicit crate boundaries, contract-first migration from the Python oracle, classical signing support now, and explicit fail-closed PQC backend selection while native PQC work continues.

## Workspace shape

- `sts-core` - token exchange policy, claims, and request/response contract
- `sts-jose` - JOSE/JWK/JWKS, signing, and algorithm/backend selection
- `sts-verify` - trust anchors, issuer verification, client/actor assertion checks
- `sts-replay` - jti replay state and sender-constraining replay keys
- `sts-config` - configuration and bootstrap
- `sts-http` - `/token`, `/jwks`, discovery, and error mapping
- `sts-cli` - rotation, canary, smoke, and ops helpers

## Migration rule

The current Python implementation remains the behavior oracle until the Rust contract tests prove parity. The Rust repo must preserve observable endpoints, claim shapes, and failure classes while keeping the architecture explicit and maintainable.

## Release shape

Current releases are source releases from GitHub tags. Workspace crates inherit `publish = false`; crates.io publication is intentionally out of scope until the internal crate graph, package names, and public API stability are ready for an explicit publishing milestone.

Release validation currently uses:

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

GitHub tag source archives are the release artifacts for this phase. `cargo package --workspace` expects internal workspace crates such as `sts-core` to exist in the crates.io index after Cargo prepares local `path` dependencies for publication. That is not the current release model and remains out of scope until a crates.io publishing milestone is opened.
