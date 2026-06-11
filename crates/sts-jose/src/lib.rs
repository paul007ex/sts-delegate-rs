#![forbid(unsafe_code)]

//! JOSE/JWK/JWKS, signing, and backend-selection crate for `sts-delegate-rs`.
//!
//! This crate owns the classical signing surface and the fail-closed selector
//! for PQC requests. The first shipped backend is RS256; PQC selectors are
//! recognized explicitly but refuse to silently downgrade until a real PQC
//! backend is added.

use std::fmt;

use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der},
    signature::{KeyPair as AwsKeyPair, RsaKeyPair, RsaPublicKeyComponents},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
    errors::{Error as JwtError, ErrorKind as JwtErrorKind},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use simple_asn1::{ASN1Block, BigInt, BigUint};
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
    #[serde(default = "default_jwk_use")]
    #[serde(rename = "use")]
    pub use_: String,
    #[serde(default = "default_jwk_alg")]
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

fn default_jwk_use() -> String {
    "sig".to_string()
}

fn default_jwk_alg() -> String {
    "RS256".to_string()
}

#[derive(Debug, Deserialize)]
struct PrivateRsaJwk {
    kty: String,
    kid: Option<String>,
    n: String,
    e: String,
    d: String,
    p: String,
    q: String,
    dp: Option<String>,
    dq: Option<String>,
    qi: Option<String>,
}

/// Deserialized claims plus the protected-header key id selected for verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJws<T> {
    pub claims: T,
    pub kid: String,
}

/// Decoded public RSA JWK components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRsaPublicKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

/// The crypto/signing surface the STS needs from the JOSE backend.
pub trait JoseSigner: Send + Sync {
    fn alg(&self) -> &'static str;
    fn sign_claims(&self, claims: &MintedClaims) -> Result<String, JoseError>;
    fn public_jwks(&self) -> JwksDocument;
    fn verify_claims(&self, token: &str) -> Result<MintedClaims, JoseError>;
}

/// Parse a public RSA key from an RSA JWK.
///
/// This keeps key material handling in the JOSE crate instead of making the HTTP
/// or verification layers decode `n`/`e` on their own.
pub fn rsa_public_key_from_jwk(jwk: &PublicJwk) -> Result<DecodedRsaPublicKey, JoseError> {
    if jwk.kty != "RSA" {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("unsupported JWK key type {}", jwk.kty),
        ));
    }
    let n = decode_jwk_component("n", &jwk.n)?;
    let e = decode_jwk_component("e", &jwk.e)?;
    validate_public_components(&n, &e)?;
    Ok(DecodedRsaPublicKey { n, e })
}

/// Return the RSA modulus size for public-key policy checks.
pub fn rsa_public_key_bits_from_jwk(jwk: &PublicJwk) -> Result<usize, JoseError> {
    let public_key = rsa_public_key_from_jwk(jwk)?;
    Ok(rsa_modulus_bits(&public_key.n))
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
    RsaJoseSigner::parse_compact_jws(token)?;
    let header = decode_header(token).map_err(map_jwt_header_error)?;
    let kid = header.kid.as_deref().ok_or_else(|| {
        JoseError::new(JoseErrorKind::InvalidCompactJws, "compact JWS header missing kid")
    })?;
    if header.alg != Algorithm::RS256 {
        return Err(JoseError::new(JoseErrorKind::VerificationFailed, "unexpected JWS algorithm"));
    }

    let jwk = jwks.keys.iter().find(|key| key.kid == kid).ok_or_else(|| {
        JoseError::new(JoseErrorKind::VerificationFailed, format!("no JWK found for kid {kid}"))
    })?;
    let _ = rsa_public_key_from_jwk(jwk)?;
    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| {
        JoseError::new(JoseErrorKind::InvalidKey, format!("invalid RSA public JWK: {e}"))
    })?;
    let claims = decode::<T>(token, &decoding_key, &signature_only_rs256_validation())
        .map_err(map_jwt_decode_error)?
        .claims;

    Ok(VerifiedJws { claims, kid: kid.to_string() })
}

/// Classical RS256 backend; PQC is reserved for a future explicit backend.
#[derive(Debug, Clone)]
pub struct RsaJoseSigner {
    kid: String,
    encoding_key: EncodingKey,
    public_jwk: PublicJwk,
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

    /// Build the RS256 signer from a private RSA JWK only when the selected
    /// backend is classical.
    pub fn from_private_jwk_for_backend(
        selection: &BackendSelection,
        private_jwk_json: impl AsRef<str>,
        fallback_kid: impl Into<String>,
    ) -> Result<Self, JoseError> {
        resolve_backend(selection)?;
        Self::from_private_jwk(private_jwk_json, fallback_kid)
    }

    /// Build the RS256 signer from a private RSA JWK.
    pub fn from_private_jwk(
        private_jwk_json: impl AsRef<str>,
        fallback_kid: impl Into<String>,
    ) -> Result<Self, JoseError> {
        let jwk: PrivateRsaJwk = serde_json::from_str(private_jwk_json.as_ref()).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidKey, format!("invalid RSA private JWK JSON: {e}"))
        })?;
        if jwk.kty != "RSA" {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                format!("unsupported private JWK key type {}", jwk.kty),
            ));
        }
        let n = decode_jwk_component("n", &jwk.n)?;
        let e = decode_jwk_component("e", &jwk.e)?;
        validate_public_components(&n, &e)?;
        if rsa_modulus_bits(&n) < 2048 {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                "RSA signing key modulus must be at least 2048 bits",
            ));
        }
        let private_der = rsa_private_jwk_to_pkcs1_der(&jwk)?;
        let kid = jwk.kid.unwrap_or_else(|| fallback_kid.into());
        Self::from_pkcs1_der(private_der, kid)
    }

    pub fn from_pkcs1_pem(
        private_pem: impl AsRef<str>,
        kid: impl Into<String>,
    ) -> Result<Self, JoseError> {
        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_ref().trim().as_bytes())
            .map_err(map_jwt_key_error)?;
        Self::from_pkcs1_der(encoding_key.inner(), kid)
    }

    /// Build the RS256 signer from a DER-encoded RSA private key only when the
    /// selected backend is classical. PKCS#1 and PKCS#8 DER are both accepted.
    pub fn from_private_key_der_for_backend(
        selection: &BackendSelection,
        private_der: impl AsRef<[u8]>,
        kid: impl Into<String>,
    ) -> Result<Self, JoseError> {
        resolve_backend(selection)?;
        Self::from_private_key_der(private_der, kid)
    }

    /// Build the RS256 signer from a DER-encoded RSA private key.
    ///
    /// This accepts PKCS#1 `RSAPrivateKey` DER directly and PKCS#8
    /// `PrivateKeyInfo` DER by extracting the embedded PKCS#1 key.
    pub fn from_private_key_der(
        private_der: impl AsRef<[u8]>,
        kid: impl Into<String>,
    ) -> Result<Self, JoseError> {
        let private_der = normalize_rsa_private_key_der(private_der.as_ref())?;
        Self::from_pkcs1_der(private_der, kid)
    }

    fn from_pkcs1_der(
        private_der: impl AsRef<[u8]>,
        kid: impl Into<String>,
    ) -> Result<Self, JoseError> {
        let private_der = private_der.as_ref();
        let key_pair = RsaKeyPair::from_der(private_der).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidKey, format!("invalid RSA private key: {e}"))
        })?;
        if key_pair.public_modulus_len() * 8 < 2048 {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                "RSA signing key modulus must be at least 2048 bits",
            ));
        }
        let public = key_pair.public_key();
        let components = RsaPublicKeyComponents::<Vec<u8>>::from(public);
        let kid = kid.into();
        let public_jwk = PublicJwk {
            kty: "RSA".to_string(),
            kid: kid.clone(),
            use_: "sig".to_string(),
            alg: "RS256".to_string(),
            n: URL_SAFE_NO_PAD.encode(&components.n),
            e: URL_SAFE_NO_PAD.encode(&components.e),
        };
        Ok(Self { kid, encoding_key: EncodingKey::from_rsa_der(private_der), public_jwk })
    }

    /// Generate an ephemeral 2048-bit RSA signer for tests and local fixtures.
    pub fn generate_for_tests(kid: impl Into<String>) -> Result<Self, JoseError> {
        let key_pair = RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidKey, format!("generate RSA key failed: {e}"))
        })?;
        let private_der = AsDer::<Pkcs8V1Der>::as_der(&key_pair).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidKey, format!("encode RSA key failed: {e}"))
        })?;
        Self::from_private_key_der(private_der.as_ref(), kid)
    }

    fn public_jwk(&self) -> PublicJwk {
        self.public_jwk.clone()
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
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        header.typ = Some(typ.to_string());
        encode(&header, claims, &self.encoding_key).map_err(map_jwt_encode_error)
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

fn signature_only_rs256_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation
}

fn decode_jwk_component(name: &str, value: &str) -> Result<Vec<u8>, JoseError> {
    let bytes = URL_SAFE_NO_PAD.decode(value.as_bytes()).map_err(|e| {
        JoseError::new(JoseErrorKind::InvalidKey, format!("invalid RSA JWK {name} encoding: {e}"))
    })?;
    if bytes.is_empty() {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("invalid RSA JWK {name}: empty unsigned integer"),
        ));
    }
    Ok(bytes)
}

fn decode_required_private_component(
    name: &str,
    value: Option<&str>,
) -> Result<Vec<u8>, JoseError> {
    let value = value.ok_or_else(|| {
        JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("RSA private JWK missing CRT member {name}"),
        )
    })?;
    decode_jwk_component(name, value)
}

fn validate_public_components(n: &[u8], e: &[u8]) -> Result<(), JoseError> {
    if n.is_empty() || e.is_empty() {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            "RSA public key components must be non-empty",
        ));
    }
    if n[0] == 0 || e[0] == 0 {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            "RSA public key components must use minimal unsigned encoding",
        ));
    }
    Ok(())
}

fn rsa_modulus_bits(n: &[u8]) -> usize {
    let Some(first_nonzero) = n.iter().position(|byte| *byte != 0) else {
        return 0;
    };
    let bytes = &n[first_nonzero..];
    (bytes.len() - 1) * 8 + (8 - bytes[0].leading_zeros() as usize)
}

fn rsa_private_jwk_to_pkcs1_der(jwk: &PrivateRsaJwk) -> Result<Vec<u8>, JoseError> {
    let n = decode_jwk_component("n", &jwk.n)?;
    let e = decode_jwk_component("e", &jwk.e)?;
    let d = decode_jwk_component("d", &jwk.d)?;
    let p = decode_jwk_component("p", &jwk.p)?;
    let q = decode_jwk_component("q", &jwk.q)?;
    let dp = decode_required_private_component("dp", jwk.dp.as_deref())?;
    let dq = decode_required_private_component("dq", jwk.dq.as_deref())?;
    let qi = decode_required_private_component("qi", jwk.qi.as_deref())?;

    let blocks = vec![
        ASN1Block::Integer(0, BigInt::from(0)),
        positive_integer_block("n", &n)?,
        positive_integer_block("e", &e)?,
        positive_integer_block("d", &d)?,
        positive_integer_block("p", &p)?,
        positive_integer_block("q", &q)?,
        positive_integer_block("dp", &dp)?,
        positive_integer_block("dq", &dq)?,
        positive_integer_block("qi", &qi)?,
    ];
    simple_asn1::to_der(&ASN1Block::Sequence(0, blocks)).map_err(|e| {
        JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("failed to encode RSA private JWK as PKCS#1 DER: {e}"),
        )
    })
}

fn positive_integer_block(name: &str, bytes: &[u8]) -> Result<ASN1Block, JoseError> {
    if bytes.is_empty() || bytes.iter().all(|byte| *byte == 0) {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("invalid RSA private JWK {name}: zero unsigned integer"),
        ));
    }
    Ok(ASN1Block::Integer(0, BigInt::from(BigUint::from_bytes_be(bytes))))
}

fn normalize_rsa_private_key_der(private_der: &[u8]) -> Result<Vec<u8>, JoseError> {
    if RsaKeyPair::from_der(private_der).is_ok() {
        return Ok(private_der.to_vec());
    }
    extract_pkcs8_private_key_octets(private_der)
}

fn extract_pkcs8_private_key_octets(private_der: &[u8]) -> Result<Vec<u8>, JoseError> {
    let blocks = simple_asn1::from_der(private_der).map_err(|e| {
        JoseError::new(JoseErrorKind::InvalidKey, format!("invalid RSA private key DER: {e}"))
    })?;
    find_first_octet_string(&blocks).ok_or_else(|| {
        JoseError::new(
            JoseErrorKind::InvalidKey,
            "invalid RSA private key DER: PKCS#8 privateKey octets not found",
        )
    })
}

fn find_first_octet_string(blocks: &[ASN1Block]) -> Option<Vec<u8>> {
    for block in blocks {
        match block {
            ASN1Block::OctetString(_, value) => return Some(value.clone()),
            ASN1Block::Sequence(_, values) | ASN1Block::Set(_, values) => {
                if let Some(value) = find_first_octet_string(values) {
                    return Some(value);
                }
            }
            ASN1Block::Explicit(_, _, _, inner) => {
                if let Some(value) = find_first_octet_string(std::slice::from_ref(inner.as_ref())) {
                    return Some(value);
                }
            }
            _ => {}
        }
    }
    None
}

fn map_jwt_key_error(err: JwtError) -> JoseError {
    JoseError::new(JoseErrorKind::InvalidKey, format!("invalid RSA private key: {err}"))
}

fn map_jwt_encode_error(err: JwtError) -> JoseError {
    match err.kind() {
        JwtErrorKind::Json(_) => {
            JoseError::new(JoseErrorKind::InvalidClaims, format!("encode claims failed: {err}"))
        }
        JwtErrorKind::InvalidKeyFormat
        | JwtErrorKind::InvalidRsaKey(_)
        | JwtErrorKind::RsaFailedSigning
        | JwtErrorKind::Signing(_) => {
            JoseError::new(JoseErrorKind::InvalidKey, format!("RSA signing failed: {err}"))
        }
        _ => {
            JoseError::new(JoseErrorKind::VerificationFailed, format!("JWT signing failed: {err}"))
        }
    }
}

fn map_jwt_header_error(err: JwtError) -> JoseError {
    JoseError::new(JoseErrorKind::InvalidCompactJws, format!("invalid compact JWS header: {err}"))
}

fn map_jwt_decode_error(err: JwtError) -> JoseError {
    match err.kind() {
        JwtErrorKind::InvalidToken | JwtErrorKind::Base64(_) | JwtErrorKind::Utf8(_) => {
            JoseError::new(JoseErrorKind::InvalidCompactJws, format!("invalid compact JWS: {err}"))
        }
        JwtErrorKind::Json(_)
        | JwtErrorKind::MissingRequiredClaim(_)
        | JwtErrorKind::InvalidClaimFormat(_)
        | JwtErrorKind::ExpiredSignature
        | JwtErrorKind::InvalidIssuer
        | JwtErrorKind::InvalidAudience
        | JwtErrorKind::InvalidSubject
        | JwtErrorKind::ImmatureSignature => {
            JoseError::new(JoseErrorKind::InvalidClaims, format!("invalid token claims: {err}"))
        }
        JwtErrorKind::InvalidSignature
        | JwtErrorKind::InvalidAlgorithm
        | JwtErrorKind::MissingAlgorithm
        | JwtErrorKind::InvalidKeyFormat
        | JwtErrorKind::InvalidRsaKey(_) => JoseError::new(
            JoseErrorKind::VerificationFailed,
            format!("JWT verification failed: {err}"),
        ),
        _ => JoseError::new(
            JoseErrorKind::VerificationFailed,
            format!("JWT verification failed: {err}"),
        ),
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
        Self::parse_compact_jws(token)?;
        let header = decode_header(token).map_err(map_jwt_header_error)?;
        if header.alg != Algorithm::RS256 {
            return Err(JoseError::new(
                JoseErrorKind::VerificationFailed,
                "unexpected JWS algorithm",
            ));
        }
        if header.kid.as_deref() != Some(self.kid.as_str()) {
            return Err(JoseError::new(JoseErrorKind::VerificationFailed, "unexpected JWS kid"));
        }
        verify_claims_against_jwks(token, &self.public_jwks())
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

    fn test_signer() -> RsaJoseSigner {
        RsaJoseSigner::generate_for_tests("kid-1").expect("signer")
    }

    fn generated_private_key_der() -> Vec<u8> {
        let key_pair = RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).expect("rsa key");
        AsDer::<Pkcs8V1Der>::as_der(&key_pair).expect("pkcs8 der").as_ref().to_vec()
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
        let signer = RsaJoseSigner::from_private_key_der_for_backend(
            &BackendSelection::Classical,
            generated_private_key_der(),
            "kid-1",
        )
        .expect("signer");
        assert_eq!(signer.alg(), "RS256");
    }

    #[test]
    fn selected_pqc_backend_cannot_construct_rsa_signer() {
        let err = RsaJoseSigner::from_private_key_der_for_backend(
            &BackendSelection::parse("ML-DSA-65"),
            generated_private_key_der(),
            "kid-1",
        )
        .unwrap_err();
        assert_eq!(err.kind, JoseErrorKind::UnsupportedAlgorithm);
    }

    #[test]
    fn private_jwk_without_crt_members_fails_closed() {
        let jwk = serde_json::json!({
            "kty": "RSA",
            "kid": "kid-1",
            "n": URL_SAFE_NO_PAD.encode(vec![0xff; 256]),
            "e": URL_SAFE_NO_PAD.encode([0x01, 0x00, 0x01]),
            "d": URL_SAFE_NO_PAD.encode(vec![0x7f; 256]),
            "p": URL_SAFE_NO_PAD.encode(vec![0x7f; 128]),
            "q": URL_SAFE_NO_PAD.encode(vec![0x7f; 128]),
        });
        let err = RsaJoseSigner::from_private_jwk(jwk.to_string(), "fallback").unwrap_err();
        assert_eq!(err.kind, JoseErrorKind::InvalidKey);
        assert!(err.message.contains("missing CRT member"));
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
