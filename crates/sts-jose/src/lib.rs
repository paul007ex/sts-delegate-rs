#![forbid(unsafe_code)]

//! JOSE/JWK/JWKS, signing, and backend-selection crate for `sts-delegate-rs`.
//!
//! This crate owns the classical signing surface and the fail-closed selector
//! for PQC requests. The first shipped backend is RS256; PQC selectors are
//! recognized explicitly but refuse to silently downgrade until a real PQC
//! backend is added.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs1v15::{Signature as RsaSignature, SigningKey, VerifyingKey},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use signature::{SignatureEncoding, Signer as _, Verifier as _};
use sts_core::MintedClaims;

/// The signing backend requested by policy/config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendSelection {
    Classical,
    RequestedPqc(String),
}

impl BackendSelection {
    pub fn parse(value: &str) -> Self {
        let trimmed = value.trim();
        match trimmed.to_ascii_lowercase().as_str() {
            "" | "classical" | "rs256" => Self::Classical,
            other if other.starts_with("ml-dsa") || other.starts_with("pqc") => {
                Self::RequestedPqc(trimmed.to_string())
            }
            other => Self::RequestedPqc(other.to_string()),
        }
    }
}

/// Fail-closed selection error categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoseErrorKind {
    InvalidKey,
    UnsupportedAlgorithm,
    InvalidClaims,
    VerificationFailed,
    InvalidCompactJws,
}

impl fmt::Display for JoseErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::InvalidKey => "invalid_key",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::InvalidClaims => "invalid_claims",
            Self::VerificationFailed => "verification_failed",
            Self::InvalidCompactJws => "invalid_compact_jws",
        };
        f.write_str(code)
    }
}

/// Stable JOSE-layer error with a narrow boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoseError {
    pub kind: JoseErrorKind,
    pub message: String,
}

impl JoseError {
    pub fn new(kind: JoseErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
}

impl fmt::Display for JoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for JoseError {}

/// A public JWK representing the active signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicJwk {
    pub kty: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
    pub n: String,
    pub e: String,
}

/// The JWKS document published by the STS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<PublicJwk>,
}

impl JwksDocument {
    pub fn new(keys: Vec<PublicJwk>) -> Self {
        Self { keys }
    }
}

/// Deserialized claims plus the protected-header key id selected for verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJws<T> {
    pub claims: T,
    pub kid: String,
}

/// The crypto/signing surface the STS needs from the JOSE backend.
pub trait JoseSigner {
    fn alg(&self) -> &'static str;
    fn sign_claims(&self, claims: &MintedClaims) -> Result<String, JoseError>;
    fn public_jwks(&self) -> JwksDocument;
    fn verify_claims(&self, token: &str) -> Result<MintedClaims, JoseError>;
}

/// Parse a public RSA key from an RSA JWK.
///
/// This keeps key material handling in the JOSE crate instead of making the HTTP
/// or verification layers decode `n`/`e` on their own.
pub fn rsa_public_key_from_jwk(jwk: &PublicJwk) -> Result<RsaPublicKey, JoseError> {
    if jwk.kty != "RSA" {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("unsupported JWK key type {}", jwk.kty),
        ));
    }
    let n = URL_SAFE_NO_PAD.decode(jwk.n.as_bytes()).map_err(|e| {
        JoseError::new(JoseErrorKind::InvalidKey, format!("invalid RSA modulus encoding: {e}"))
    })?;
    let e = URL_SAFE_NO_PAD.decode(jwk.e.as_bytes()).map_err(|e| {
        JoseError::new(JoseErrorKind::InvalidKey, format!("invalid RSA exponent encoding: {e}"))
    })?;
    RsaPublicKey::new(rsa::BigUint::from_bytes_be(&n), rsa::BigUint::from_bytes_be(&e)).map_err(
        |e| JoseError::new(JoseErrorKind::InvalidKey, format!("invalid RSA public key: {e}")),
    )
}

/// Verify a compact JWS against a JWKS and deserialize the payload.
///
/// RFC 8693 and RFC 9068 both rely on normal JWT/JWS behavior once the token is
/// minted; this helper keeps signature verification and header/kid selection in
/// the JOSE layer so the transport and policy layers do not reimplement it.
pub fn verify_claims_against_jwks<T: DeserializeOwned>(
    token: &str,
    jwks: &JwksDocument,
) -> Result<T, JoseError> {
    verify_claims_against_jwks_with_header(token, jwks).map(|verified| verified.claims)
}

/// Verify a compact JWS against a JWKS and return claims plus selected header data.
pub fn verify_claims_against_jwks_with_header<T: DeserializeOwned>(
    token: &str,
    jwks: &JwksDocument,
) -> Result<VerifiedJws<T>, JoseError> {
    let (header_b64, payload_b64, sig_b64) = RsaJoseSigner::parse_compact_jws(token)?;
    let header_json = URL_SAFE_NO_PAD.decode(header_b64.as_bytes()).map_err(|e| {
        JoseError::new(
            JoseErrorKind::InvalidCompactJws,
            format!("invalid compact JWS header encoding: {e}"),
        )
    })?;
    let header: serde_json::Value = serde_json::from_slice(&header_json).map_err(|e| {
        JoseError::new(
            JoseErrorKind::InvalidCompactJws,
            format!("invalid compact JWS header JSON: {e}"),
        )
    })?;
    let kid = header.get("kid").and_then(|v| v.as_str()).ok_or_else(|| {
        JoseError::new(JoseErrorKind::InvalidCompactJws, "compact JWS header missing kid")
    })?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("RS256") {
        return Err(JoseError::new(JoseErrorKind::VerificationFailed, "unexpected JWS algorithm"));
    }

    let jwk = jwks.keys.iter().find(|key| key.kid == kid).ok_or_else(|| {
        JoseError::new(JoseErrorKind::VerificationFailed, format!("no JWK found for kid {kid}"))
    })?;
    let public_key = rsa_public_key_from_jwk(jwk)?;

    let payload_json = URL_SAFE_NO_PAD.decode(payload_b64.as_bytes()).map_err(|e| {
        JoseError::new(
            JoseErrorKind::InvalidCompactJws,
            format!("invalid compact JWS payload encoding: {e}"),
        )
    })?;
    let claims: T = serde_json::from_slice(&payload_json).map_err(|e| {
        JoseError::new(JoseErrorKind::InvalidClaims, format!("invalid token claims JSON: {e}"))
    })?;

    let signature = URL_SAFE_NO_PAD.decode(sig_b64.as_bytes()).map_err(|e| {
        JoseError::new(
            JoseErrorKind::InvalidCompactJws,
            format!("invalid compact JWS signature encoding: {e}"),
        )
    })?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    verifying_key
        .verify(
            RsaJoseSigner::signing_input(header_json.as_slice(), payload_json.as_slice())
                .as_bytes(),
            &RsaSignature::try_from(signature.as_slice()).map_err(|e| {
                JoseError::new(
                    JoseErrorKind::InvalidCompactJws,
                    format!("invalid signature bytes: {e}"),
                )
            })?,
        )
        .map_err(|e| {
            JoseError::new(
                JoseErrorKind::VerificationFailed,
                format!("RSA verification failed: {e}"),
            )
        })?;

    Ok(VerifiedJws { claims, kid: kid.to_string() })
}

/// Classical RS256 backend; PQC is reserved for a future explicit backend.
#[derive(Debug, Clone)]
pub struct RsaJoseSigner {
    kid: String,
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RsaJoseSigner {
    /// Build the RS256 signer only when backend policy selected the classical path.
    ///
    /// This keeps fail-closed backend selection at the key-loading boundary: a
    /// requested PQC backend must not accidentally instantiate the classical
    /// signer and continue as RS256.
    pub fn from_pkcs1_pem_for_backend(
        selection: &BackendSelection,
        private_pem: impl AsRef<str>,
        kid: impl Into<String>,
    ) -> Result<Self, JoseError> {
        resolve_backend(selection)?;
        Self::from_pkcs1_pem(private_pem, kid)
    }

    pub fn from_pkcs1_pem(
        private_pem: impl AsRef<str>,
        kid: impl Into<String>,
    ) -> Result<Self, JoseError> {
        let private_pem = private_pem.as_ref().trim().to_string();
        let private_key = RsaPrivateKey::from_pkcs1_pem(&private_pem).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidKey, format!("invalid RSA private key: {e}"))
        })?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok(Self { kid: kid.into(), private_key, public_key })
    }

    /// Build a test/generated RS256 signer only for the selected classical backend.
    pub fn from_generated_for_backend(
        selection: &BackendSelection,
        private_key: &RsaPrivateKey,
        kid: impl Into<String>,
    ) -> Result<Self, JoseError> {
        resolve_backend(selection)?;
        Self::from_generated(private_key, kid)
    }

    pub fn from_generated(
        private_key: &RsaPrivateKey,
        kid: impl Into<String>,
    ) -> Result<Self, JoseError> {
        let public_key = RsaPublicKey::from(private_key);
        Ok(Self { kid: kid.into(), private_key: private_key.clone(), public_key })
    }

    fn public_jwk(&self) -> PublicJwk {
        PublicJwk {
            kty: "RSA".to_string(),
            kid: self.kid.clone(),
            use_: "sig".to_string(),
            alg: self.alg().to_string(),
            n: URL_SAFE_NO_PAD.encode(self.public_key.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(self.public_key.e().to_bytes_be()),
        }
    }

    fn signing_input(header_json: &[u8], payload_json: &[u8]) -> String {
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
        format!("{header_b64}.{payload_b64}")
    }

    /// Sign an arbitrary JSON payload as a compact JWS.
    ///
    /// This keeps compact-JWS construction in the JOSE layer while allowing
    /// verifier tests and adjacent JWT-shaped payloads to reuse the same RSA
    /// signing boundary.
    pub fn sign_json_claims<T: Serialize>(&self, claims: &T) -> Result<String, JoseError> {
        self.sign_json_claims_with_typ(claims, "JWT")
    }

    fn sign_json_claims_with_typ<T: Serialize>(
        &self,
        claims: &T,
        typ: &str,
    ) -> Result<String, JoseError> {
        let header = serde_json::json!({
            "alg": self.alg(),
            "kid": self.kid,
            "typ": typ,
        });
        let header_json = serde_json::to_vec(&header).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidClaims, format!("encode header failed: {e}"))
        })?;
        let payload_json = serde_json::to_vec(claims).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidClaims, format!("encode claims failed: {e}"))
        })?;
        let signing_input = Self::signing_input(&header_json, &payload_json);
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let signature: RsaSignature = signing_key.sign(signing_input.as_bytes());
        Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())))
    }

    fn parse_compact_jws(token: &str) -> Result<(&str, &str, &str), JoseError> {
        let mut parts = token.split('.');
        let header = parts.next().ok_or_else(|| {
            JoseError::new(JoseErrorKind::InvalidCompactJws, "compact JWS must have three parts")
        })?;
        let payload = parts.next().ok_or_else(|| {
            JoseError::new(JoseErrorKind::InvalidCompactJws, "compact JWS must have three parts")
        })?;
        let signature = parts.next().ok_or_else(|| {
            JoseError::new(JoseErrorKind::InvalidCompactJws, "compact JWS must have three parts")
        })?;
        if parts.next().is_some() {
            return Err(JoseError::new(
                JoseErrorKind::InvalidCompactJws,
                "compact JWS must have exactly three parts",
            ));
        }
        Ok((header, payload, signature))
    }
}

impl JoseSigner for RsaJoseSigner {
    fn alg(&self) -> &'static str {
        "RS256"
    }

    fn sign_claims(&self, claims: &MintedClaims) -> Result<String, JoseError> {
        self.sign_json_claims_with_typ(claims, "at+jwt")
    }

    fn public_jwks(&self) -> JwksDocument {
        JwksDocument::new(vec![self.public_jwk()])
    }

    fn verify_claims(&self, token: &str) -> Result<MintedClaims, JoseError> {
        let (header_b64, payload_b64, sig_b64) = Self::parse_compact_jws(token)?;
        let header_json = URL_SAFE_NO_PAD.decode(header_b64.as_bytes()).map_err(|e| {
            JoseError::new(
                JoseErrorKind::InvalidCompactJws,
                format!("invalid compact JWS header encoding: {e}"),
            )
        })?;
        let header: serde_json::Value = serde_json::from_slice(&header_json).map_err(|e| {
            JoseError::new(
                JoseErrorKind::InvalidCompactJws,
                format!("invalid compact JWS header JSON: {e}"),
            )
        })?;
        if header.get("alg").and_then(|v| v.as_str()) != Some(self.alg()) {
            return Err(JoseError::new(
                JoseErrorKind::VerificationFailed,
                "unexpected JWS algorithm",
            ));
        }
        if header.get("kid").and_then(|v| v.as_str()) != Some(self.kid.as_str()) {
            return Err(JoseError::new(JoseErrorKind::VerificationFailed, "unexpected JWS kid"));
        }

        let payload_json = URL_SAFE_NO_PAD.decode(payload_b64.as_bytes()).map_err(|e| {
            JoseError::new(
                JoseErrorKind::InvalidCompactJws,
                format!("invalid compact JWS payload encoding: {e}"),
            )
        })?;
        let claims: MintedClaims = serde_json::from_slice(&payload_json).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidClaims, format!("invalid token claims JSON: {e}"))
        })?;

        let signature = URL_SAFE_NO_PAD.decode(sig_b64.as_bytes()).map_err(|e| {
            JoseError::new(
                JoseErrorKind::InvalidCompactJws,
                format!("invalid compact JWS signature encoding: {e}"),
            )
        })?;
        let verifying_key = VerifyingKey::<Sha256>::new(self.public_key.clone());
        verifying_key
            .verify(
                Self::signing_input(header_json.as_slice(), payload_json.as_slice()).as_bytes(),
                &RsaSignature::try_from(signature.as_slice()).map_err(|e| {
                    JoseError::new(
                        JoseErrorKind::InvalidCompactJws,
                        format!("invalid signature bytes: {e}"),
                    )
                })?,
            )
            .map_err(|e| {
                JoseError::new(
                    JoseErrorKind::VerificationFailed,
                    format!("RSA verification failed: {e}"),
                )
            })?;

        Ok(claims)
    }
}

/// Resolve backend selection in a fail-closed way.
pub fn resolve_backend(selection: &BackendSelection) -> Result<(), JoseError> {
    match selection {
        BackendSelection::Classical => Ok(()),
        BackendSelection::RequestedPqc(requested) => Err(JoseError::new(
            JoseErrorKind::UnsupportedAlgorithm,
            format!(
                "requested PQC signing backend {requested:?} is not available yet; refusing to fall back to RS256"
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn test_signer() -> RsaJoseSigner {
        let mut rng = StdRng::seed_from_u64(7);
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa key");
        RsaJoseSigner::from_generated(&private_key, "kid-1").expect("signer")
    }

    fn claims() -> MintedClaims {
        MintedClaims::new(
            "https://sts.example/",
            "user@example.com",
            "api://chat-mcp",
            "chat.read",
            1,
            2,
            "jti-1",
            "chat-mcp",
        )
    }

    #[test]
    fn classical_backend_parses_as_classical() {
        assert!(matches!(BackendSelection::parse(""), BackendSelection::Classical));
        assert!(matches!(BackendSelection::parse("RS256"), BackendSelection::Classical));
    }

    #[test]
    fn pqc_backend_selector_fails_closed() {
        let err = resolve_backend(&BackendSelection::parse("ML-DSA-65")).unwrap_err();
        assert_eq!(err.kind, JoseErrorKind::UnsupportedAlgorithm);
    }

    #[test]
    fn unknown_backend_selector_fails_closed() {
        let err = resolve_backend(&BackendSelection::parse("ed25519")).unwrap_err();
        assert_eq!(err.kind, JoseErrorKind::UnsupportedAlgorithm);
    }

    #[test]
    fn selected_classical_backend_can_construct_rsa_signer() {
        let mut rng = StdRng::seed_from_u64(17);
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa key");
        let signer = RsaJoseSigner::from_generated_for_backend(
            &BackendSelection::Classical,
            &private_key,
            "kid-1",
        )
        .expect("signer");
        assert_eq!(signer.alg(), "RS256");
    }

    #[test]
    fn selected_pqc_backend_cannot_construct_rsa_signer() {
        let mut rng = StdRng::seed_from_u64(19);
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa key");
        let err = RsaJoseSigner::from_generated_for_backend(
            &BackendSelection::parse("ML-DSA-65"),
            &private_key,
            "kid-1",
        )
        .unwrap_err();
        assert_eq!(err.kind, JoseErrorKind::UnsupportedAlgorithm);
    }

    #[test]
    fn rsa_signer_publishes_public_jwks() {
        let signer = test_signer();
        let jwks = signer.public_jwks();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "RSA");
        assert_eq!(jwks.keys[0].alg, "RS256");
        assert_eq!(jwks.keys[0].use_, "sig");
        assert_eq!(jwks.keys[0].kid, "kid-1");
    }

    #[test]
    fn rsa_signer_round_trips_a_claims_payload() {
        let signer = test_signer();
        let token = signer.sign_claims(&claims()).expect("sign");
        let decoded = signer.verify_claims(&token).expect("verify");
        assert_eq!(decoded.sub, "user@example.com");
        assert_eq!(decoded.aud, "api://chat-mcp");
        assert_eq!(decoded.client_id, "chat-mcp");
        assert_eq!(decoded.scope, "chat.read");
    }

    #[test]
    fn rsa_signer_emits_three_segment_jws() {
        let signer = test_signer();
        let token = signer.sign_claims(&claims()).expect("sign");
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn rsa_signer_header_alg_stays_rs256() {
        let signer = test_signer();
        let token = signer.sign_claims(&claims()).expect("sign");
        let header_b64 = token.split('.').next().unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64.as_bytes()).unwrap())
                .unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], "kid-1");
        assert_eq!(header["typ"], "at+jwt");
    }

    #[test]
    fn generic_json_signer_keeps_jwt_typ_for_assertions() {
        let signer = test_signer();
        let token = signer.sign_json_claims(&claims()).expect("sign");
        let header_b64 = token.split('.').next().unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64.as_bytes()).unwrap())
                .unwrap();
        assert_eq!(header["typ"], "JWT");
    }

    #[test]
    fn jwks_verifier_round_trips_the_signed_claims() {
        let signer = test_signer();
        let token = signer.sign_claims(&claims()).expect("sign");
        let decoded: MintedClaims =
            verify_claims_against_jwks(&token, &signer.public_jwks()).expect("verify");
        assert_eq!(decoded.sub, "user@example.com");
        assert_eq!(decoded.aud, "api://chat-mcp");
    }

    #[test]
    fn jwks_verifier_returns_selected_kid_with_claims() {
        let signer = test_signer();
        let token = signer.sign_claims(&claims()).expect("sign");
        let verified: VerifiedJws<MintedClaims> =
            verify_claims_against_jwks_with_header(&token, &signer.public_jwks()).expect("verify");
        assert_eq!(verified.kid, "kid-1");
        assert_eq!(verified.claims.sub, "user@example.com");
    }
}
