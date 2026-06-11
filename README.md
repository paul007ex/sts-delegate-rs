# sts-delegate-rs

Rust-native successor to `sts-delegate`: an OAuth 2.1 / RFC 8693 security token service with explicit crate boundaries, contract-first migration from the Python oracle, classical signing support now, and explicit fail-closed PQC backend selection while native PQC work continues.

## Workspace shape

- `sts-core` - token exchange policy, claims, and request/response contract
- `sts-dpop` - RFC 9449 DPoP proof validation and holder-key binding
- `sts-jose` - JOSE/JWK/JWKS, signing, and algorithm/backend selection
- `sts-verify` - trust anchors, issuer verification, client/actor assertion checks
- `sts-replay` - jti replay state and sender-constraining replay keys
- `sts-config` - configuration and bootstrap
- `sts-http` - `/token`, `/jwks`, discovery, and error mapping
- `sts-cli` - rotation, canary, smoke, and ops helpers

## Migration rule

The current Python implementation remains the behavior oracle until the Rust contract tests prove parity. The Rust repo must preserve observable endpoints, claim shapes, and failure classes while keeping the architecture explicit and maintainable.

## Runtime bootstrap

`sts-cli` now exposes the Rust HTTP runtime boundary:

```bash
cargo run -p sts-cli -- bootstrap-check
cargo run -p sts-cli -- serve
```

`bootstrap-check` loads runtime config, the STS signing key, IdP/actor/client
JWKS, and replay policy, then exits before binding a socket. `serve` performs the
same checks and starts the Axum server only after they pass.

Required environment includes `IDP_ISSUER` or `OKTA_ISSUER`,
`EXPECTED_SUBJECT_AUD`, `ACTOR_IDS` or `GATEWAY_ACTOR_ID`,
`OBO_STS_KEY_FILE`, `ACTOR_JWKS_FILE`, and either `IDP_JWKS_FILE` or
`IDP_JWKS_URI`/OIDC discovery. `STS_HTTP_ADDR` defaults to
`127.0.0.1:8888`.

## HTTP Ops

The Rust HTTP runtime serves a curated OpenAPI artifact at `/openapi.json`.
Interactive docs routes such as `/docs` and `/redoc` are not served by default.

Prometheus-style metrics are opt-in with `STS_ENABLE_METRICS=true`; when enabled,
`/metrics` reports exchange outcomes, denial counts by OAuth error code, and the
current in-process replay-cache size. When disabled, `/metrics` is absent.

## Operator CLI

`sts-cli` also includes offline-safe operator checks:

```bash
cargo run -p sts-cli -- smoke
cargo run -p sts-cli -- smoke --allow-network
cargo run -p sts-cli -- canary check-config
cargo run -p sts-cli -- jwks inspect --file public_jwks.json
cargo run -p sts-cli -- key inspect --file public_jwk.json
cargo run -p sts-cli -- key rotate --dry-run \
  --key-file secrets/obo_sts_private_key.json \
  --extra-jwks-file secrets/obo_sts_retiring_jwks.json
cargo run -p sts-cli -- key rotate \
  --key-file secrets/obo_sts_private_key.json \
  --extra-jwks-file secrets/obo_sts_retiring_jwks.json
```

`smoke` runs the same startup bootstrap path as the server, but defaults to
offline mode and requires `IDP_JWKS_FILE`; pass `--allow-network` only when live
IdP JWKS retrieval is intentional. `canary check-config` reports only missing
`CANARY_*` names. Key and JWKS inspection print public metadata only and refuse
private or symmetric JWK input.

`key rotate` is the file-backed RSA private JWK rotation workflow. It validates
the current private JWK and existing public overlap JWKS, stages the old public
key in `OBO_STS_EXTRA_JWKS_FILE` format, then atomically replaces the private key
with a new RSA private JWK using restrictive file permissions on Unix. The
command prints only public key ids, file paths, counts, and restart status; it
does not print private key material. KMS/HSM and PQC rotation remain separate
future work.

## Release shape

Current releases are source releases from GitHub tags. Workspace crates inherit `publish = false`; crates.io publication is intentionally out of scope until the internal crate graph, package names, and public API stability are ready for an explicit publishing milestone.

Release validation currently uses:

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

GitHub tag source archives are the release artifacts for this phase. `cargo package --workspace` expects internal workspace crates such as `sts-core` to exist in the crates.io index after Cargo prepares local `path` dependencies for publication. That is not the current release model and remains out of scope until a crates.io publishing milestone is opened.
