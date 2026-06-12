# sts-delegate-rs

Rust-native successor to `sts-delegate`: an RFC 8693 token-exchange STS with OAuth 2.1-aligned token-endpoint behavior where applicable, explicit crate boundaries, contract-first migration from the Python oracle, classical RS256 signing by default, and opt-in RFC 9964 ML-DSA support behind an explicit experimental feature gate.

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

## Install and package locally

For Rust users, run the CLI directly from source:

```bash
cargo run -p sts-cli -- --help
```

After runtime configuration is present, run startup checks or the server:

```bash
cargo run -p sts-cli -- bootstrap-check
cargo run -p sts-cli -- serve
```

To build an installable local archive without hosted GitHub Actions:

```bash
scripts/package_release.sh
shasum -a 256 -c dist/SHA256SUMS
tar -tzf dist/sts-cli-*-*.tar.gz
```

Install the binary from the archive:

```bash
mkdir -p ~/.local/bin
tar -xzf dist/sts-cli-*-*.tar.gz -C /tmp
install -m 0755 /tmp/sts-cli-*-*/sts-cli ~/.local/bin/sts-cli
sts-cli --help
```

The local archive contains the `sts-cli` binary plus public README/LICENSE material
when present. It does not include generated keys, tokens, environment files, or
runtime policy files. `dist/` is ignored by git.

Tagged releases publish hosted `sts-cli` archives to GitHub Releases after the
release workflow succeeds. Verify downloaded archives before installing:

```bash
release_tag=v0.1.0
gh release download "$release_tag" \
  --repo paul007ex/sts-delegate-rs \
  --pattern 'sts-cli-*.tar.gz' \
  --pattern SHA256SUMS
shasum -a 256 -c SHA256SUMS
```

Homebrew users can install from the live `paul007ex/sts-delegate-rs` tap. The
formula downloads the hosted release archive and verifies its checksum:

```bash
brew tap paul007ex/sts-delegate-rs
brew install sts-cli
brew test sts-cli
```

Without a separate tap step:

```bash
brew install paul007ex/sts-delegate-rs/sts-cli
```

Published GHCR images, `cargo-binstall`, and crates.io publication are not
shipped in this phase. Track those as separate release follow-ups instead of
treating local archives, hosted CLI archives, local Docker builds, or the direct
Homebrew tap as those distribution channels.

To build a local Docker image:

```bash
docker build -t sts-delegate-rs:local .
scripts/docker_smoke.sh sts-delegate-rs:local
docker run --rm sts-delegate-rs:local --help
```

The Dockerfile is a local build path, not a GHCR publication claim. Runtime
configuration and secrets must be supplied at `docker run` time with env vars and
read-only mounted files; they are not baked into the image:

```bash
docker run --rm -p 8888:8888 \
  --env-file sts.env \
  -v "$PWD/secrets:/run/secrets/sts:ro" \
  sts-delegate-rs:local serve
```

The image runs as a non-root `sts` user. Mounted key/JWKS files must be readable
by that user or by a compatible group.

The default signing runtime is classical RS256. Experimental ML-DSA signing,
AKP JWKS publication, and ML-DSA verification can be compiled with
`pqc-openssl-unstable`; runtime selection then requires a concrete
`STS_SIGNING_ALG` such as `ML-DSA-65` and an RFC 9964 AKP private JWK seed file
with matching public material. The published JWKS contains only public `AKP`
members (`kty`, `kid`, `use`, `alg`, `pub`) and never `priv`. This path uses
OpenSSL 3.5+ ML-DSA through `openssl-rs` and is not a FIPS-validation claim.

## HTTP Ops

The Rust HTTP runtime serves a curated OpenAPI artifact at `/openapi.json`.
Interactive docs routes such as `/docs` and `/redoc` are not served by default.

Prometheus-style metrics are opt-in with `STS_ENABLE_METRICS=true`; when enabled,
`/metrics` reports exchange outcomes, denial counts by OAuth error code, and the
current replay-cache size. When disabled, `/metrics` is absent.

Replay storage defaults to in-process memory, which is suitable only for local and
single-replica deployments:

```bash
STS_REPLAY_BACKEND=memory
```

For multi-replica deployments, configure a shared file-backed replay directory on a
POSIX shared volume. The replay crate hashes caller-controlled replay keys before
using them as filenames and records with atomic create-new semantics:

```bash
STS_REPLAY_BACKEND=file
STS_REPLAY_DIR=/var/lib/sts-delegate/replay
```

If the shared replay directory is unavailable at startup or while serving, replay
enforcement fails closed with service-unavailable semantics. Do not run more than
one STS replica on the default in-memory backend.

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
cargo run -p sts-cli -- dpop key generate \
  --out secrets/dpop_holder_private_jwk.json
cargo run -p sts-cli -- exchange \
  --sts-url http://127.0.0.1:8888/tenant1 \
  --subject-token-file user_access_token.txt \
  --actor-token-file chat-mcp.jwt \
  --audience api://databricks-mcp \
  --scope databricks.read \
  --dpop-key-file secrets/dpop_holder_private_jwk.json \
  --jwks-url http://127.0.0.1:8888/tenant1/jwks
```

`smoke` runs the same startup bootstrap path as the server, but defaults to
offline mode and requires `IDP_JWKS_FILE`; pass `--allow-network` only when live
IdP JWKS retrieval is intentional. `canary check-config` reports only missing
`CANARY_*` names. Key and JWKS inspection print public metadata only and refuse
private or symmetric JWK input.

`exchange` is a safe RFC 8693 token-exchange client for the Rust STS. It posts
`application/x-www-form-urlencoded` to `/token`, reads subject, actor, and
client assertion values from files, and prints response metadata plus decoded
safe claims by default. Submitted tokens, client assertions, DPoP proofs, raw
JWT IDs, holder-key thumbprints, and the minted access token are not printed
unless `--print-token` is set explicitly. Pass `--jwks-file` or `--jwks-url` to
verify the minted JWT before claims are rendered. `dpop key generate` writes a
private P-256 holder JWK to a new `0600` file without printing private material;
`exchange --dpop-key-file` signs a fresh RFC 9449 token-endpoint proof for the
resolved `POST /token` request and verifies the minted token `cnf.jkt` matches
the holder key. `--dpop-proof-file` remains available to forward a precomputed
DPoP proof in the `DPoP` header for advanced/debug workflows.

`key rotate` is the file-backed RSA private JWK rotation workflow. It validates
the current private JWK and existing public overlap JWKS, stages the old public
key in `OBO_STS_EXTRA_JWKS_FILE` format, then atomically replaces the private key
with a new RSA private JWK using restrictive file permissions on Unix. The
command prints only public key ids, file paths, counts, and restart status; it
does not print private key material. KMS/HSM and ML-DSA/PQC rotation remain
separate future work.

## Release shape

Current releases use GitHub tag source archives, tag-driven hosted `sts-cli`
archives when `.github/workflows/release.yml` succeeds, plus locally
reproducible archives from `scripts/package_release.sh`. Workspace crates
inherit `publish = false`; crates.io publication is intentionally out of scope
until the internal crate graph, package names, and public API stability are ready
for an explicit publishing milestone.

Release validation currently uses:

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
python3 scripts/live_rust_sts_canary.py --self-test-redaction
scripts/package_release.sh
shasum -a 256 -c dist/SHA256SUMS
docker build -t sts-delegate-rs:local .
scripts/docker_smoke.sh sts-delegate-rs:local
```

GitHub tag source archives, hosted release archives attached by successful
release workflow runs, and local `dist/` archives are the CLI release artifacts
for this phase. `cargo package --workspace` expects internal workspace crates
such as `sts-core` to exist in the crates.io index after Cargo prepares local
`path` dependencies for publication. That is not the current release model and
remains out of scope until a crates.io publishing milestone is opened.

When real Okta inputs are configured locally, the live Rust process canary proves
the customer flow without printing tokens:

```bash
python3 scripts/live_rust_sts_canary.py --require-live
```

The canary builds or reuses `target/debug/sts-cli`, starts a fresh
`sts-cli serve` on a random loopback port, fetches public Okta JWKS into a
temporary file, generates an ephemeral actor key/JWKS for that process, performs
Bearer and DPoP token exchange, verifies minted JWTs against the Rust `/jwks`,
and confirms DPoP replay rejection.
