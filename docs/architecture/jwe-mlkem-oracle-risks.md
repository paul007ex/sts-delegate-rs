# JWE / ML-KEM Endpoint Risk ADR

Status: proposed for issue #80.

## Context

`sts-delegate-rs` now has OpenSSL-backed ML-DSA JWS signing, AKP JWKS publication,
and downstream verification as the default signing path. That does not imply
JWE, ML-KEM, HPKE, encrypt, or decrypt support. Adding public encryption or
decryption routes to an STS would create a new cryptographic service boundary,
not a small extension to `/token`.

## Decision

Do not add a public unauthenticated HTTP decrypt endpoint.

The first safe implementation lane, if product-approved later, should be an
offline/admin CLI design for encryption and decryption primitives. A networked
surface should require a separate admin/authz model, key-use separation, rate
limits, audit events, and intentionally vague error mapping before any handler is
added to `sts-http`.

## Boundaries

- `/token` remains an RFC 8693 token-exchange endpoint.
- `/jwks` remains public signing-key metadata only.
- ML-DSA keys are signing keys; they must not be reused for KEM/decrypt.
- Any future ML-KEM key material must live behind a separate provider/key-custody
  boundary from the JWS signer.
- A decrypt operation must never return distinguishable parse, padding,
  recipient, key, or plaintext-policy errors to an unauthenticated caller.

## Oracle Risks

| Risk | Failure Mode | Required Control Before Network Endpoint |
| --- | --- | --- |
| Decrypt oracle | Caller submits arbitrary ciphertext and learns validity from status/body/timing. | Authenticated admin-only access, uniform error shape, rate limits, and constant-time-adjacent handling where the primitive requires it. |
| Key confusion | Signing keys, KEM keys, and token-verification keys become interchangeable. | Typed key-use metadata and hard rejection of wrong `use`, `alg`, `kty`, or provider family. |
| Algorithm confusion | Caller controls `alg`/`enc` and forces weak or unsupported behavior. | Deployment-owned allowlist, no request-selected fallback, and negative tests for unsupported algorithms. |
| Cross-protocol reuse | One key is used for token signing and content decrypt. | Separate key IDs, providers, env vars, and docs for each key family. |
| Plaintext logging | Debug/error output leaks decrypted content or secrets. | Redaction tests, no plaintext in structured logs, and CLI output modes that default to metadata only. |
| Error detail leak | Error text reveals recipient, key presence, plaintext format, or authz policy. | OAuth/admin error mapping that returns coarse inactive/denied results only. |

## Alternatives

1. Public `/decrypt`: rejected for now because it is too easy to expose a
   high-value oracle before authz, logging, and error timing are designed.
2. Public `/encrypt`: still deferred; encryption-only is lower risk than decrypt
   but still needs key-use metadata and claim honesty.
3. Offline CLI first: preferred next step because it can prove JOSE/HPKE library
   behavior without exposing a network oracle.

## Migration Impact

None for current token exchange clients. This ADR keeps the shipped PQC claim
limited to ML-DSA signing/JWKS/verification and avoids implying PQC content
encryption support.

## Non-Goals

- No JWE route is implemented by this ADR.
- No ML-KEM provider is implemented by this ADR.
- No VPN profile or full authorization-server profile is implemented by this ADR.

## Next Patch Shape

If issue #80 is approved for implementation, start with:

1. Add a `sts-jose` feature-gated JWE/HPKE experiment module with deterministic
   accepted/rejected tests.
2. Add `sts-cli jwe encrypt` and `sts-cli jwe decrypt` admin/offline commands
   that read input from files and default to metadata-only output.
3. Add redaction and wrong-key/wrong-alg tests before considering `sts-http`.
4. File a separate issue for any authenticated HTTP admin surface.
