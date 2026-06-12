# KMS/HSM Signer SPI Draft

This draft supports issue #43. It is not implemented on `main`.

## Current Boundary

`sts-http` loads local private key material from `OBO_STS_KEY_FILE` during
bootstrap and stores an `Arc<dyn JoseSigner>` in `HttpState`. `sts-jose` owns the
`JoseSigner` trait:

```rust
pub trait JoseSigner: Send + Sync {
    fn alg(&self) -> &'static str;
    fn sign_claims(&self, claims: &MintedClaims) -> Result<String, JoseError>;
    fn public_jwks(&self) -> JwksDocument;
    fn verify_claims(&self, token: &str) -> Result<MintedClaims, JoseError>;
}
```

That shape works for local RSA and feature-gated ML-DSA signers. A cloud KMS or
HSM signer should not load private JWK members into `sts-http`, and it should not
silently fall back to the file signer when provider calls fail.

## Provider Direction

Add an external-signer provider that keeps JOSE serialization in Rust but delegates
the private signing operation:

- `alg`: initially `RS256`;
- `kid`: configured expected key ID;
- `public_jwk`: derived from provider public-key metadata, not from private key
  material;
- `sign`: signs the exact JWS signing input bytes;
- `verify_claims`: verifies the compact JWS against `public_jwks()` just like local
  signers.

The first implementation can be a tested mock provider plus config and HTTP
bootstrap wiring. A later provider can target AWS KMS, Google Cloud KMS, or
PKCS#11/HSM.

## Provider Examples To Evaluate

| Provider | Public-key path | Signing path | Notes |
| --- | --- | --- | --- |
| AWS KMS asymmetric signing key | `GetPublicKey` returns public key material for an asymmetric KMS key. | `Sign` signs messages with an asymmetric KMS key. | Use RSA signing key specs and `RSASSA_PKCS1_V1_5_SHA_256` for RS256 compatibility. |
| Google Cloud KMS asymmetric signing key | Public key is available for asymmetric keys. | Asymmetric signing uses key purpose `ASYMMETRIC_SIGN`. | Needs algorithm mapping and IAM docs. |
| PKCS#11/HSM | Token exposes public key/certificate object. | `C_Sign` with an RSA signing mechanism. | Needs slot/session/login lifecycle and careful blocking behavior. |

## Config Shape

Do not overload `OBO_STS_KEY_FILE` for KMS/HSM:

```text
STS_SIGNING_PROVIDER=file | mock-external | aws-kms | gcp-kms | pkcs11
STS_SIGNING_ALG=RS256
STS_SIGNING_KID=<expected kid>
STS_SIGNING_PUBLIC_JWKS_FILE=<public-only JWKS cache, optional>
AWS_KMS_KEY_ID=<provider key id, provider-specific>
```

Provider credentials should come from the cloud runtime identity or a mounted
credential file managed by the deployment, never from command-line arguments or
issue evidence.

## Acceptance Tests

- mock external signer mints a token that verifies against the Rust `/jwks`;
- `/jwks` includes only public JWK members;
- wrong configured `kid` or provider public key mismatch fails bootstrap;
- provider signing failure maps to sanitized OAuth `server_error`;
- provider unavailable does not fall back to `OBO_STS_KEY_FILE` or RS256 local key;
- file-backed signer remains the default unless `STS_SIGNING_PROVIDER` selects an
  external provider.

## Open Design Choice

The current `JoseSigner` trait is synchronous. Real KMS/HSM providers may need
network or blocking FFI. The implementation PR should choose one of:

- make signing async through the HTTP path; or
- keep the trait synchronous and isolate provider calls in a bounded blocking pool.

Do not perform blocking network or HSM calls on the async executor.
