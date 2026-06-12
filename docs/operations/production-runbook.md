# Production Runbook

This runbook addresses issue #45 for the current Rust STS surface. It assumes
`sts-cli serve` is the runtime entrypoint and that the deployment supplies runtime
configuration, signing key material, IdP/actor/client JWKS, and target policy through
environment variables and mounted files.

## Pre-Deploy Checks

Run these from the exact artifact or image candidate:

```bash
sts-cli --help
sts-cli bootstrap-check
sts-cli smoke
```

Use `sts-cli smoke --allow-network` only when live IdP JWKS retrieval is intentional.
For a configured real tenant, run:

```bash
python3 scripts/live_rust_sts_canary.py --require-live
```

The canary must redact bearer tokens, assertions, private keys, DPoP proofs,
Authorization headers, and raw replay identifiers.

## Required Startup Invariants

| Check | Why it matters |
| --- | --- |
| `IDP_ISSUER` or `OKTA_ISSUER` is set | Pins the subject-token issuer. |
| `EXPECTED_SUBJECT_AUD` is set | Prevents audience confusion with user tokens minted for another resource. |
| `OBO_STS_ISSUER` is the public HTTPS issuer, or loopback HTTP for dev | Metadata, token `iss`, and client assertion audiences depend on exact issuer identity. |
| `ACTOR_IDS` or `GATEWAY_ACTOR_ID` is set | Defines which actors may delegate. |
| `ACTOR_JWKS_FILE` and, when separate, `CLIENT_JWKS_FILE` are mounted read-only | Trust anchors must not be writable by the runtime process. |
| `OBO_STS_KEY_FILE` is mounted with private-key file permissions | The STS signing key is high-value key material. |
| Target policy is loaded | Unknown targets deny by default. |
| `STS_ENABLE_METRICS=true` only where metrics scraping is expected | `/metrics` is absent by default. |

## Recommended Alerts

| Signal | Alert when | Likely cause |
| --- | --- | --- |
| Token exchange denial rate | sustained increase in `sts_exchanges_total{result="denied"}` or `sts_denials_total` | client rollout, IdP key drift, bad target policy, attack traffic |
| `invalid_client` denials | sudden spike | actor/client key mismatch, expired assertions, unsupported Authorization header auth |
| `invalid_target` or `invalid_scope` denials | sudden spike | target policy drift or caller requesting wrong audience/scope |
| `invalid_dpop_proof` denials | sudden spike | DPoP clock skew, proof replay, method/path mismatch, or malformed client library |
| Replay cache size | approaching configured replay capacity | replay attack, long leeway, or capacity too small |
| Bootstrap failures | any production deploy failure | bad env, bad key/JWKS material, unavailable IdP discovery/JWKS |
| Signing failures | any nonzero sanitized `server_error` around minting | private key/provider outage or key format mismatch |
| JWKS availability | `/jwks` not reachable or key set does not contain active `kid` | rollout or key publication regression |

## Key Rotation

Current Rust key rotation is file-backed RSA private JWK rotation:

```bash
sts-cli key rotate --dry-run \
  --key-file /run/secrets/sts/obo_sts_private_key.json \
  --extra-jwks-file /run/secrets/sts/obo_sts_retiring_jwks.json

sts-cli key rotate \
  --key-file /run/secrets/sts/obo_sts_private_key.json \
  --extra-jwks-file /run/secrets/sts/obo_sts_retiring_jwks.json
```

Operational sequence:

1. Run `--dry-run` against the mounted files.
2. Rotate the key.
3. Restart or roll the STS so the active signer changes.
4. Keep the retiring public key published for at least `SCOPED_TOKEN_TTL + CLOCK_SKEW_LEEWAY`.
5. Confirm `/jwks` contains the active public key and expected retiring key overlap.
6. Remove the retiring key after the overlap window.

KMS/HSM-backed custody is not shipped yet; track it in #43.

## Incident Response

| Incident | Immediate action | Follow-up |
| --- | --- | --- |
| Subject token leak | Revoke or disable the upstream user/session at the IdP when supported; reduce TTL exposure through normal expiry. | Preserve redacted logs and affected `sub`/audience metadata only. |
| Scoped token leak | Treat as valid until `exp`; rotate downstream authorization if needed. | Search by safe token fingerprint or decoded non-secret claims, not raw token text. |
| Actor key compromise | Remove the actor key from `ACTOR_JWKS_FILE`, rotate actor credential, restart/reload deployment, and invalidate affected actor assertions by `jti` horizon. | Review actor audit trail and target policy. |
| STS signing key compromise | Rotate STS signing key immediately, remove compromised public key from `/jwks` after emergency decision, and notify resource servers. | Consider rejecting tokens signed by the compromised `kid` at resource servers. |
| Replay backend exhaustion | Fail closed, scale capacity, investigate replay volume. | Multi-replica shared replay remains #44. |
| IdP JWKS outage | Do not disable verification. Use cached or mounted JWKS only if that is already configured and trusted. | Restore discovery/JWKS path and run canary. |

## Evidence Handling

- Do not paste raw bearer tokens, private JWK members, client assertions, DPoP proofs,
  Authorization headers, or raw `jti` values into tickets or chat.
- Prefer decoded non-secret claims, `kid`, issuer, audience, scope, expiration,
  token length, and SHA-256 fingerprints.
- Keep full sensitive logs in the approved incident evidence store only.

## Rollback Criteria

Rollback a deployment when any of these are true:

- `bootstrap-check` fails.
- `/jwks` does not publish the active signing key.
- Metadata issuer/token/JWKS URLs do not match the public issuer.
- Valid configured exchanges fail after deployment.
- Broad subject tokens are accepted by a downstream resource that should require scoped STS tokens.
- Denial/error metrics show a sustained new failure mode after release.

## Release/Deploy Checklist

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
python3 scripts/security_audit_loop.py
scripts/package_release.sh
shasum -a 256 -c dist/SHA256SUMS
docker build -t sts-delegate-rs:local .
scripts/docker_smoke.sh sts-delegate-rs:local
```

Supply-chain signing, SBOMs, and provenance are tracked in #46.
