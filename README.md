# sts-delegate-rs

Rust-native successor to `sts-delegate`: an OAuth 2.1 / RFC 8693 security token service with explicit crate boundaries, contract-first migration from the Python oracle, and first-class support for classical and PQC signing paths.

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

