# sts-delegate-rs

Rust-native successor to `sts-delegate`: an RFC 8693 token-exchange STS with OAuth 2.1-aligned token-endpoint behavior where applicable, explicit crate boundaries, contract-first migration from the Python oracle, and PQC-first RFC 9964 ML-DSA signing by default.

## Workspace shape

- `sts-core` - token exchange policy, claims, and request/response contract
- `sts-dpop` - RFC 9449 DPoP proof validation and holder-key binding
- `sts-jose` - JOSE/JWK/JWKS, signing, and algorithm/backend selection
- `sts-verify` - trust anchors, issuer verification, client/actor assertion checks
- `sts-replay` - jti replay state and sender-constraining replay keys
- `sts-config` - configuration and bootstrap
- `sts-http` - `/token`, `/introspect`, `/revoke`, `/jwks`, discovery, protected-resource metadata, and error mapping
- `sts-cli` - rotation, canary, smoke, and ops helpers

## Migration rule

The current Python implementation remains the behavior oracle until the Rust contract tests prove parity. The Rust repo must preserve observable endpoints, claim shapes, and failure classes while keeping the architecture explicit and maintainable.

## Rust docs

- [Rust product surface](docs/reference/product-surface.md) maps endpoints, claims,
  config, errors, and Python-oracle reference docs to current Rust behavior.
- [Okta, OBO, and MCP docs plan](docs/explanation/okta-mcp-obo-plan.md) separates
  OIDC login, Okta-documented OBO, and Rust token exchange.
- [obo-lab contract coverage plan](docs/requirements/obo-lab-contract-coverage.md)
  classifies scenario-level lab tests against Rust contract coverage.
- [Production runbook](docs/operations/production-runbook.md) covers startup checks,
  alerts, rotation, incident response, and deployment evidence.
- [Release security](docs/operations/release-security.md) records current checksum
  verification and the remaining SBOM/provenance/signing work.
- [Cloud deployment roadmap](docs/operations/cloud-roadmap.md) keeps KMS/HSM, shared
  replay, and Helm/Terraform work explicit instead of overclaiming it.

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
`IDP_JWKS_URI`/OIDC discovery. The default `OBO_STS_KEY_FILE` content is an
RFC 9964 AKP ML-DSA private JWK for `STS_SIGNING_ALG=ML-DSA-65`.
Classical RS256 remains available only as an explicit compatibility mode by
setting `STS_SIGNING_ALG=RS256`, `STS_PQC_PREFERRED=false`, and
`STS_ALLOW_NON_PQC=true`. Inbound actor and `private_key_jwt` assertions default
to `ML-DSA-65` as well; RS256 inbound assertion compatibility requires
`STS_INBOUND_PQC_PREFERRED=false`, `STS_ALLOW_NON_PQC_INBOUND=true`, and
`STS_INBOUND_ASSERTION_ALGS=RS256`. `STS_HTTP_ADDR` defaults to
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
for sbom in dist/sts-cli-*.spdx.json; do python3 -m json.tool "$sbom" >/dev/null; done
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
  --pattern 'sts-cli-*.spdx.json' \
  --pattern SHA256SUMS
shasum -a 256 -c SHA256SUMS
gh attestation verify sts-cli-*.tar.gz \
  --repo paul007ex/sts-delegate-rs \
  --cert-identity-regex 'https://github.com/paul007ex/sts-delegate-rs/.github/workflows/release.yml@refs/tags/.*'
gh attestation verify sts-cli-*.spdx.json \
  --repo paul007ex/sts-delegate-rs \
  --cert-identity-regex 'https://github.com/paul007ex/sts-delegate-rs/.github/workflows/release.yml@refs/tags/.*'
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

Reference Kubernetes raw manifests and a Terraform Kubernetes module live under
`deploy/`. They mount config and secrets at runtime, keep `replicas=1` until
shared replay is configured, and expect TLS termination at ingress.

The default signing runtime is PQC ML-DSA-65. Default Cargo builds include the
OpenSSL-backed `pqc-openssl-unstable` feature, and unset `STS_SIGNING_ALG`
selects `ML-DSA-65(default)`. Startup requires an RFC 9964 AKP private JWK seed
file with matching public material. The published JWKS contains only public
`AKP` members (`kty`, `kid`, `use`, `alg`, `pub`) and never `priv`. This path
uses OpenSSL 3.5+ ML-DSA through `openssl-rs` and is not a FIPS-validation claim.

Builds made with `--no-default-features` or deployments with an RSA/PEM signing
key fail closed under the default selector. They do not silently fall back to
RS256. To run classical compatibility mode, configure it explicitly:

```bash
STS_SIGNING_ALG=RS256
STS_PQC_PREFERRED=false
STS_ALLOW_NON_PQC=true
```

PQC preference is STS/resource-server policy, not OAuth-standard client
negotiation. Token requests must not contain a caller-selected minted-token
signing algorithm. The default runtime is already PQC-preferred with non-PQC
fallback disabled:

```bash
STS_PQC_PREFERRED=true
STS_ALLOW_NON_PQC=false
STS_PQC_PREFERRED_ALGS=ML-DSA-65,ML-DSA-87,ML-DSA-44
STS_INBOUND_PQC_PREFERRED=true
STS_ALLOW_NON_PQC_INBOUND=false
STS_INBOUND_ASSERTION_ALGS=ML-DSA-65
```

Target policy can express downstream verification capability:

```json
{
  "api://pqc-vpn": {
    "scopes": ["vpn.connect"],
    "accepted_token_signing_algs": ["ML-DSA-65", "RS256"],
    "pqc_required": true
  }
}
```

When `STS_PQC_PREFERRED=true`, `STS_ALLOW_NON_PQC` defaults to false. If a target
requires PQC, a non-PQC runtime signer fails closed even when non-PQC fallback is
otherwise allowed. If explicit fallback is allowed and RS256 is minted under a
PQC-preferred profile, the token response and metrics include safe evidence such
as `signing_alg_selected`, `pqc_fallback`, and a sanitized fallback reason.

Check compiled PQC/OpenSSL readiness without loading deployment keys:

```bash
cargo run -p sts-cli -- pqc preflight
```

Generate and inspect a local ML-DSA signing key without printing private
material:

```bash
cargo run -p sts-cli -- \
  pqc key generate \
  --alg ML-DSA-65 \
  --out ./secrets/sts_mldsa_private.json \
  --public-jwks-out ./secrets/sts_mldsa_public.jwks.json

cargo run -p sts-cli -- \
  pqc key inspect --file ./secrets/sts_mldsa_private.json
```

Current PQC support is limited to ML-DSA JWS signing, public AKP JWKS
publication, downstream verification, inbound actor/`private_key_jwt` assertion
verification, and a local file-backed ML-DSA generate/inspect/rotate CLI
workflow. External IdP subject-token verification remains governed by the
configured IdP JWKS; do not claim Okta or another IdP issues ML-DSA subject
tokens without live tenant proof. JWE, ML-KEM, encrypt/decrypt endpoints, and
real cloud KMS/HSM providers are not shipped here.

External signing uses an explicit provider selection. The default remains the
file-backed signer:

```bash
STS_SIGNING_PROVIDER=file
OBO_STS_KEY_FILE=/run/secrets/sts/obo_sts_private_key.json
```

`mock-external` is available for CI and local provider-boundary proof. It loads
public key metadata from a public-only JWKS file and signs through the
JOSE-level external-provider trait; it must not be used as a cloud KMS/HSM
claim:

```bash
STS_SIGNING_PROVIDER=mock-external
STS_SIGNING_ALG=RS256
STS_SIGNING_KID=<public-key-id>
STS_SIGNING_PUBLIC_JWKS_FILE=/run/secrets/sts/signing-public-jwks.json
STS_MOCK_EXTERNAL_SIGNER_KEY_FILE=/run/secrets/sts/mock-external-private.json
```

Unsupported providers such as `aws-kms`, `gcp-kms`, and `pkcs11` fail closed
until concrete providers are implemented and tested.

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

The HTTP server also ships online validation endpoints for resource servers and
operators:

- `POST /introspect` implements RFC 7662-style introspection for STS-issued
  access tokens. Callers authenticate with `private_key_jwt`; inactive,
  malformed, expired, revoked, wrong-issuer, or unverifiable tokens return only
  `{"active":false}`.
- `POST /revoke` implements RFC 7009-style revocation for STS-issued access
  tokens. Revocation stores a bounded token fingerprint, not the raw token or
  raw `jti`; unknown or malformed tokens still return HTTP 200.
- `GET /.well-known/oauth-protected-resource` implements RFC 9728 protected
  resource metadata for the resource represented by the metadata URL. It does
  not imply a full `/authorize` or OIDC server.
- Protected-resource style endpoints such as `/mcp` and `/{resource}/mcp`
  return an RFC 9728 `WWW-Authenticate: Bearer resource_metadata="..."`
  challenge when the bearer token is missing or unusable. STS/AS endpoints
  such as `/token`, `/introspect`, `/revoke`, `/jwks`, and RFC 8414 metadata do
  not emit that protected-resource challenge.

Offline JWT validation through `/jwks` cannot observe revocation. Resource
servers that need revocation status must call `/introspect` or another online
validation path.

`key rotate` is the file-backed RSA private JWK rotation workflow. `pqc key
rotate` is the matching feature-gated local ML-DSA AKP rotation workflow. Each
command validates the current private JWK and existing public overlap JWKS,
stages the old public key in `OBO_STS_EXTRA_JWKS_FILE`-compatible format, then
atomically replaces the private key using restrictive file permissions on Unix.
The commands print only public key ids, file paths, counts, and restart status;
they do not print private key material. Cloud KMS/HSM rotation remains a
provider-specific future workflow.

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
python3 scripts/live_rust_sts_canary.py --pqc --require-live
```

The canary builds or reuses `target/debug/sts-cli`, starts a fresh
`sts-cli serve` on a random loopback port, fetches public Okta JWKS into a
temporary file, generates an ephemeral actor key/JWKS for that process, performs
Bearer and DPoP token exchange, verifies minted JWTs against the Rust `/jwks`,
and confirms DPoP replay rejection. When run without `--pqc`, the canary
intentionally sets explicit RS256 compatibility values to preserve the
Python-oracle classical smoke path. In `--pqc` mode it generates a temporary
ML-DSA STS signing key, starts the server with the PQC runtime defaults, and
requires `signing_alg_selected=ML-DSA-65` with `pqc_fallback=false`.
`--prove-mcp --require-mcp` additionally mints and
verifies one token per configured MCP server, then calls the FastMCP tools. By
default the MCP inbound call uses the original Okta subject token, which matches
the current configured gateway/backend contract. Use
`--mcp-token-source sts-issued` only for explicit interop or negative testing
against a resource server that is expected to accept STS-issued delegated tokens
at its own edge.
