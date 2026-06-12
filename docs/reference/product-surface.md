# Rust Product Surface

This page inventories the Python `sts-delegate` product reference material against the
current Rust implementation. It is a planning reference for issue #57, not a claim that
the Rust repo has copied every Python document.

## Current Rust Shape

| Surface | Rust status | Primary evidence | Python oracle source |
| --- | --- | --- | --- |
| Token exchange endpoint | Shipped: `POST /token` only. The legacy `/exchange` route is absent. | `crates/sts-http/src/lib.rs`; `crates/sts-http/tests/http_contract.rs`; ledger R-023/R-041 | `sts_delegate/docs/reference/api.md` |
| Metadata | Shipped: `GET /.well-known/oauth-authorization-server`, including path-aware issuer aliases. No authorization endpoint is shipped. | ledger R-024 through R-031A | `sts_delegate/docs/reference/api.md` |
| JWKS | Shipped: `GET /jwks` publishes public STS signing keys only. | ledger R-032/R-079 | `sts_delegate/docs/reference/claims.md` |
| CLI | Shipped: `serve`, `bootstrap-check`, `smoke`, `canary check-config`, JWKS/key inspection, file-backed RSA rotation, DPoP key generation, and redacted `exchange`. | `README.md`; `crates/sts-cli/src/main.rs`; ledger R-129 | Python CLI/docs are historical only |
| Delegation | Shipped: subject `sub` is preserved and actor is recorded in `act.sub`. | `crates/sts-core/src/lib.rs`; ledger R-068/R-070 | `claims.md`; `rfc8693-mapping.md` |
| Impersonation | Shipped as opt-in policy path; minted token omits `act`. | ledger R-069/R-094 through R-101 | `configuration.md`; `rfc8693-mapping.md` |
| DPoP | Shipped for token-endpoint proof validation and minted `cnf.jkt`; resource-server proof validation is out of scope. | `crates/sts-dpop`; ledger R-107 through R-120 | Python `tests/test_dpop.py` |
| PQC | Shipped as explicit experimental OpenSSL-backed feature gate with PQC-preferred target policy and no silent downgrade. Not default and not FIPS validated. | README; ledger R-082/R-130; issues #72/#73/#74/#78 | Python PQC intent docs |
| Metrics | Shipped opt-in `/metrics`; disabled by default. | README; ledger R-044 | Python transport docs |
| Release artifacts | Shipped as source tags, hosted/local `sts-cli` archives, Homebrew tap, and local Docker build. | README; `.github/workflows/release.yml`; `scripts/package_release.sh` | No direct Python equivalent |

## Claims Vocabulary

| Claim or field | Rust behavior | Notes |
| --- | --- | --- |
| `iss` | Minted token issuer is `OBO_STS_ISSUER` or the default loopback STS issuer. | Must match metadata `issuer`. |
| `sub` | Preserved from the validated subject token. | Delegation is not impersonation. |
| `aud` | Resolved from non-empty `audience` or `resource` and checked against target policy. | The minted token has one target audience. |
| `scope` | Downscoped against target policy and, when configured, subject scopes. | Rust emits `scope`, not `scp`, in the minted access token. |
| `act` | Present on delegation tokens; nested prior actor chains are sanitized and preserved. | `act.sub` names the actor. |
| `may_act` | Read from the subject token to authorize delegation when present. | It is not copied into the minted token as an authorization grant. |
| `client_id` | Names the authenticated caller/client for the exchange. | Distinct from RFC 8693 `act`, even when the same deployment identity is used. |
| `cnf.jkt` | Present only on DPoP-bound minted tokens. | Resource-server DPoP proof checking remains outside current Rust scope. |

## Configuration Inventory

| Python doc topic | Rust equivalent | Current status |
| --- | --- | --- |
| IdP issuer | `IDP_ISSUER` or `OKTA_ISSUER` | Required for runtime config. |
| Subject audience | `EXPECTED_SUBJECT_AUD` | Required; accepts configured audience set. |
| STS issuer | `OBO_STS_ISSUER` | Defaults to loopback; production should be HTTPS. |
| Actor identities | `ACTOR_IDS` or `GATEWAY_ACTOR_ID` | Required via resolved config. |
| Actor JWKS | `ACTOR_JWKS_FILE` | Required actor trust anchor. |
| Client JWKS | `CLIENT_JWKS_FILE` | Defaults through config policy when not separate. |
| Target policy | target policy env/file support in `sts-config` | Deny-by-default if no target permits the requested target. |
| Metrics | `STS_ENABLE_METRICS=true` | Opt-in only. |
| Signing key | `OBO_STS_KEY_FILE` | File-backed RSA default; KMS/HSM tracked separately in #43. |
| PQC signing policy | `STS_PQC_PREFERRED`, `STS_ALLOW_NON_PQC`, `STS_PQC_PREFERRED_ALGS`, target `accepted_token_signing_algs`, target `pqc_required` | Product policy only; not OAuth-standard client negotiation. |
| Replay store | In-process `InMemoryReplayStore` | Multi-replica shared replay tracked separately in #44. |

## Error and Endpoint Mapping

| Error class | Rust surface | Notes |
| --- | --- | --- |
| `unsupported_grant_type` | JSON OAuth error from `/token` | Bad token-exchange grant. |
| `invalid_request` | JSON OAuth error from `/token` | Malformed form, unsupported token type, missing actor pair, bad subject token, or DPoP proof failure depending on gate. |
| `invalid_client` | JSON OAuth error plus caller-auth status/header behavior | Caller authentication failures, private-key JWT failures, or actor-token caller-auth failures. |
| `invalid_target` | JSON OAuth error from `/token` | Unknown target, invalid resource URI, or audience/resource mismatch. |
| `invalid_scope` | JSON OAuth error from `/token` | No scope remains after downscoping. |
| `server_error` | Sanitized JSON OAuth error | Signing/internal failures should not leak private detail. |
| HTTP 503 | Deployment/runtime exhaustion path | Replay-store exhaustion is fail-closed. |

## Docs Port Plan

| Python source | Rust doc action |
| --- | --- |
| `reference/claims.md` | Convert into a Rust claims/reference page after issue #57, using the table above as the source map. |
| `reference/configuration.md` | Convert into a Rust env/config page tied to `sts-config` tests and README commands. |
| `reference/errors.md` | Convert into a Rust endpoint error page tied to `sts-http` contract tests. |
| `reference/api.md` | Convert into Rust crate/API and HTTP API references; keep full Authorization Server routes as non-goals. |
| `reference/glossary.md` | Convert into a Rust glossary using protocol terms, not Python module names. |
| `how-to/run-as-a-service.md` | Convert into Rust `sts-cli serve` operations guidance and link to the production runbook. |
| `how-to/configure-your-idp.md` | Convert into Rust config guidance. Live Okta proof must stay separate from offline fixtures. |
| `how-to/configure-target-policy.md` | Convert into target policy examples backed by `sts-config` behavior. |
| `how-to/verify-a-scoped-token.md` | Convert into Rust `/jwks` and CLI verification guidance with redacted tokens. |

## Non-Goals

- Do not document Rust as a full OAuth Authorization Server. It does not ship `/authorize`,
  revocation, introspection, dynamic registration, or refresh-token issuance.
- Do not claim KMS/HSM key custody until #43 lands.
- Do not claim JWE, ML-KEM, encrypt/decrypt endpoints, PQC key rotation, or PQC VPN
  readiness from ML-DSA sign/JWKS/verify alone.
- Do not claim multi-replica replay safety until #44 lands.
- Do not claim a hosted live-tenant run unless the run used configured real tenant values and
  redacted all bearer tokens and private material.
