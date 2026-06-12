# Cloud Deployment Roadmap

This page keeps the open cloud issues explicit so docs do not overclaim production
deployment features.

## Open Issues

| Issue | Status | Current product behavior | Done means |
| --- | --- | --- | --- |
| #43 KMS/HSM signer and key custody | Roadmap | File-backed RSA private JWK signer; experimental PQC feature gate is separate. | Provider SPI or concrete provider, public-key-only JWKS publication, no local fallback, tests for success/failure/rotation. |
| #44 shared replay backend | Roadmap | In-process replay store, correct for single-process/local operation. | Operator-selectable shared backend, fail-closed outage behavior, two-logical-replica replay tests. |
| #42 Helm or Terraform reference deployment | Roadmap | Local Docker build and local smoke script. | Minimal deploy reference with mounted config/secrets, health guidance, TLS/ingress notes, and render/lint/smoke validation. |

## Dependency Order

1. Define and test KMS/HSM key-custody boundary (#43).
2. Add shared replay backend for multi-replica correctness (#44).
3. Add Helm/Terraform reference once key custody and replay mode are explicit enough to
   avoid teaching an unsafe deployment pattern (#42).

## Non-Claims

- The current Dockerfile is a local image build path, not a signed published image.
- The current replay cache does not protect against replay across independent replicas.
- The current signer loads local private key material; it is not a KMS/HSM custody path.
