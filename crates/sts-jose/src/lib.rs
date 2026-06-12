#![forbid(unsafe_code)]

//! JOSE/JWK/JWKS, signing, and backend-selection crate for `sts-delegate-rs`.
//!
//! This crate owns the signing surface and fail-closed backend selection. The
//! default backend is RS256; RFC 9964 ML-DSA support is available only behind
//! the explicit `pqc-openssl-unstable` feature and never falls back to RS256.

use std::fmt;
use std::sync::Arc;

use aws_lc_rs::{
    digest::{SHA256, digest as aws_digest},
    encoding::{AsDer, Pkcs8V1Der},
    rand::SystemRandom,
    signature::{KeyPair as AwsKeyPair, RSA_PKCS1_SHA256, RsaKeyPair, RsaPublicKeyComponents},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode,
    errors::{Error as JwtError, ErrorKind as JwtErrorKind},
};
#[cfg(feature = "pqc-openssl-unstable")]
use openssl::pkey::{KeyType, PKey, Private, Public};
#[cfg(feature = "pqc-openssl-unstable")]
use openssl::sign::{Signer as OpenSslSigner, Verifier as OpenSslVerifier};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(default, rename = "pub", skip_serializing_if = "Option::is_none")]
    pub pub_: Option<String>,
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

#[cfg(feature = "pqc-openssl-unstable")]
#[derive(Debug, Deserialize)]
struct PrivateAkpJwk {
    kty: String,
    kid: Option<String>,
    alg: String,
    #[serde(rename = "pub")]
    pub_: String,
    #[serde(rename = "priv")]
    priv_: String,
}

#[derive(Debug, Deserialize)]
struct CompactJwsHeader {
    alg: String,
    kid: Option<String>,
}

/// Deserialized claims plus the protected-header key id selected for verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJws<T> {
    pub claims: T,
    pub alg: String,
    pub kid: String,
}

/// Decoded public RSA JWK components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRsaPublicKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

/// Decoded public AKP JWK components for RFC 9964 ML-DSA keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAkpPublicKey {
    pub algorithm: MlDsaAlgorithm,
    pub public_key: Vec<u8>,
}

/// RFC 9964 ML-DSA algorithms this crate can model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsaAlgorithm {
    pub fn jose_alg(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    pub fn from_jose_alg(value: &str) -> Option<Self> {
        match value {
            "ML-DSA-44" => Some(Self::MlDsa44),
            "ML-DSA-65" => Some(Self::MlDsa65),
            "ML-DSA-87" => Some(Self::MlDsa87),
            _ => None,
        }
    }

    fn from_selector(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ml-dsa-44" | "mldsa44" => Some(Self::MlDsa44),
            "ml-dsa-65" | "mldsa65" => Some(Self::MlDsa65),
            "ml-dsa-87" | "mldsa87" => Some(Self::MlDsa87),
            _ => None,
        }
    }

    pub fn public_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    pub fn signature_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    fn key_type(self) -> KeyType {
        match self {
            Self::MlDsa44 => KeyType::ML_DSA_44,
            Self::MlDsa65 => KeyType::ML_DSA_65,
            Self::MlDsa87 => KeyType::ML_DSA_87,
        }
    }
}

/// Algorithms accepted by compact-JWS verification in this build.
pub fn supported_jws_signing_algs() -> Vec<String> {
    #[cfg(feature = "pqc-openssl-unstable")]
    {
        let mut algs = vec!["RS256".to_string()];
        algs.extend(
            [MlDsaAlgorithm::MlDsa44, MlDsaAlgorithm::MlDsa65, MlDsaAlgorithm::MlDsa87]
                .into_iter()
                .map(|algorithm| algorithm.jose_alg().to_string()),
        );
        algs
    }
    #[cfg(not(feature = "pqc-openssl-unstable"))]
    {
        vec!["RS256".to_string()]
    }
}

/// The crypto/signing surface the STS needs from the JOSE backend.
pub trait JoseSigner: Send + Sync {
    fn alg(&self) -> &'static str;
    fn sign_claims(&self, claims: &MintedClaims) -> Result<String, JoseError>;
    fn public_jwks(&self) -> JwksDocument;
    fn verify_claims(&self, token: &str) -> Result<MintedClaims, JoseError>;
}

/// Minimal provider boundary for external RS256 key custody.
///
/// The JOSE crate owns compact-JWS serialization and public JWKS verification.
/// Providers receive only the JWS signing input bytes and return the raw RS256
/// signature bytes. Real KMS/HSM providers can implement this trait without
/// exposing private key material to HTTP or token-policy crates.
pub trait ExternalRs256SignerProvider: Send + Sync {
    fn sign_rs256(&self, signing_input: &[u8]) -> Result<Vec<u8>, JoseError>;
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
    if jwk.alg != "RS256" {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("RSA JWK alg must be RS256, got {}", jwk.alg),
        ));
    }
    let n = decode_jwk_component(
        "n",
        jwk.n
            .as_deref()
            .ok_or_else(|| JoseError::new(JoseErrorKind::InvalidKey, "RSA public JWK missing n"))?,
    )?;
    let e = decode_jwk_component(
        "e",
        jwk.e
            .as_deref()
            .ok_or_else(|| JoseError::new(JoseErrorKind::InvalidKey, "RSA public JWK missing e"))?,
    )?;
    validate_public_components(&n, &e)?;
    Ok(DecodedRsaPublicKey { n, e })
}

/// Return the RSA modulus size for public-key policy checks.
pub fn rsa_public_key_bits_from_jwk(jwk: &PublicJwk) -> Result<usize, JoseError> {
    let public_key = rsa_public_key_from_jwk(jwk)?;
    Ok(rsa_modulus_bits(&public_key.n))
}

/// Parse a public AKP key from an RFC 9964 JWK.
pub fn akp_public_key_from_jwk(jwk: &PublicJwk) -> Result<DecodedAkpPublicKey, JoseError> {
    if jwk.kty != "AKP" {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("unsupported JWK key type {}", jwk.kty),
        ));
    }
    let algorithm = MlDsaAlgorithm::from_jose_alg(&jwk.alg).ok_or_else(|| {
        JoseError::new(JoseErrorKind::InvalidKey, format!("unsupported AKP alg {}", jwk.alg))
    })?;
    if jwk.n.is_some() || jwk.e.is_some() {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            "AKP public JWK must not contain RSA n/e members",
        ));
    }
    let public_key = decode_jwk_octets(
        "AKP public JWK pub",
        jwk.pub_.as_deref().ok_or_else(|| {
            JoseError::new(JoseErrorKind::InvalidKey, "AKP public JWK missing pub")
        })?,
    )?;
    if public_key.len() != algorithm.public_key_len() {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            format!(
                "AKP public JWK pub length must be {} bytes for {}",
                algorithm.public_key_len(),
                algorithm.jose_alg()
            ),
        ));
    }
    Ok(DecodedAkpPublicKey { algorithm, public_key })
}

/// Validate a public JWK without exposing or decoding private material.
pub fn validate_public_jwk(jwk: &PublicJwk) -> Result<(), JoseError> {
    match jwk.kty.as_str() {
        "RSA" => rsa_public_key_from_jwk(jwk).map(|_| ()),
        "AKP" => akp_public_key_from_jwk(jwk).map(|_| ()),
        other => Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("unsupported JWK key type {other}"),
        )),
    }
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
    verify_claims_against_jwks_inner(token, jwks, None)
}

/// Verify a compact JWS against a JWKS with an explicit algorithm allowlist.
pub fn verify_claims_against_jwks_with_allowed_algs<T: DeserializeOwned>(
    token: &str,
    jwks: &JwksDocument,
    allowed_algs: &[&str],
) -> Result<VerifiedJws<T>, JoseError> {
    verify_claims_against_jwks_inner(token, jwks, Some(allowed_algs))
}

fn verify_claims_against_jwks_inner<T: DeserializeOwned>(
    token: &str,
    jwks: &JwksDocument,
    allowed_algs: Option<&[&str]>,
) -> Result<VerifiedJws<T>, JoseError> {
    let header = decode_compact_jws_header(token)?;
    if let Some(allowed_algs) = allowed_algs
        && !allowed_algs.iter().any(|allowed| *allowed == header.alg)
    {
        return Err(JoseError::new(
            JoseErrorKind::UnsupportedAlgorithm,
            format!("JWS algorithm {} is not allowed for this verification context", header.alg),
        ));
    }
    let kid = header.kid.as_deref().ok_or_else(|| {
        JoseError::new(JoseErrorKind::InvalidCompactJws, "compact JWS header missing kid")
    })?;
    let jwk = jwks.keys.iter().find(|key| key.kid == kid).ok_or_else(|| {
        JoseError::new(JoseErrorKind::VerificationFailed, format!("no JWK found for kid {kid}"))
    })?;
    let claims = match header.alg.as_str() {
        "RS256" => verify_rs256_claims_against_jwk(token, jwk)?,
        alg if MlDsaAlgorithm::from_jose_alg(alg).is_some() => {
            verify_mldsa_claims_against_jwk(token, jwk, alg)?
        }
        _ => {
            return Err(JoseError::new(
                JoseErrorKind::UnsupportedAlgorithm,
                format!("unsupported JWS algorithm {}", header.alg),
            ));
        }
    };

    Ok(VerifiedJws { claims, alg: header.alg, kid: kid.to_string() })
}

fn verify_rs256_claims_against_jwk<T: DeserializeOwned>(
    token: &str,
    jwk: &PublicJwk,
) -> Result<T, JoseError> {
    let _ = rsa_public_key_from_jwk(jwk)?;
    let n = jwk
        .n
        .as_deref()
        .ok_or_else(|| JoseError::new(JoseErrorKind::InvalidKey, "RSA public JWK missing n"))?;
    let e = jwk
        .e
        .as_deref()
        .ok_or_else(|| JoseError::new(JoseErrorKind::InvalidKey, "RSA public JWK missing e"))?;
    let decoding_key = DecodingKey::from_rsa_components(n, e).map_err(|e| {
        JoseError::new(JoseErrorKind::InvalidKey, format!("invalid RSA public JWK: {e}"))
    })?;
    decode::<T>(token, &decoding_key, &signature_only_rs256_validation())
        .map(|decoded| decoded.claims)
        .map_err(map_jwt_decode_error)
}

#[cfg(feature = "pqc-openssl-unstable")]
fn verify_mldsa_claims_against_jwk<T: DeserializeOwned>(
    token: &str,
    jwk: &PublicJwk,
    header_alg: &str,
) -> Result<T, JoseError> {
    let header_algorithm = MlDsaAlgorithm::from_jose_alg(header_alg).ok_or_else(|| {
        JoseError::new(JoseErrorKind::UnsupportedAlgorithm, "unsupported ML-DSA algorithm")
    })?;
    let decoded_public = akp_public_key_from_jwk(jwk)?;
    if decoded_public.algorithm != header_algorithm {
        return Err(JoseError::new(
            JoseErrorKind::VerificationFailed,
            "JWS alg does not match AKP public key alg",
        ));
    }
    let (header_segment, payload_segment, signature_segment) = parse_compact_jws(token)?;
    let signature = decode_compact_segment("JWS signature", signature_segment)?;
    if signature.len() != header_algorithm.signature_len() {
        return Err(JoseError::new(
            JoseErrorKind::VerificationFailed,
            format!(
                "JWS signature length must be {} bytes for {}",
                header_algorithm.signature_len(),
                header_algorithm.jose_alg()
            ),
        ));
    }
    let signing_input = format!("{header_segment}.{payload_segment}");
    let public_key =
        openssl_public_key_from_raw_bytes(header_algorithm, &decoded_public.public_key)?;
    let mut verifier = OpenSslVerifier::new_without_digest(&public_key).map_err(|e| {
        JoseError::new(JoseErrorKind::InvalidKey, format!("create ML-DSA verifier failed: {e}"))
    })?;
    let valid = verifier.verify_oneshot(&signature, signing_input.as_bytes()).map_err(|e| {
        JoseError::new(
            JoseErrorKind::VerificationFailed,
            format!("ML-DSA verification failed: {e}"),
        )
    })?;
    if !valid {
        return Err(JoseError::new(JoseErrorKind::VerificationFailed, "JWS verification failed"));
    }
    decode_payload_claims(payload_segment)
}

#[cfg(not(feature = "pqc-openssl-unstable"))]
fn verify_mldsa_claims_against_jwk<T: DeserializeOwned>(
    _token: &str,
    _jwk: &PublicJwk,
    header_alg: &str,
) -> Result<T, JoseError> {
    Err(JoseError::new(
        JoseErrorKind::UnsupportedAlgorithm,
        format!("JWS algorithm {header_alg} requires the pqc-openssl-unstable feature"),
    ))
}

/// Classical RS256 backend.
#[derive(Debug, Clone)]
pub struct RsaJoseSigner {
    kid: String,
    encoding_key: EncodingKey,
    public_jwk: PublicJwk,
}

/// RS256 JOSE signer that delegates the private signing operation to a provider.
pub struct ExternalRs256JoseSigner {
    kid: String,
    public_jwk: PublicJwk,
    provider: Arc<dyn ExternalRs256SignerProvider>,
}

impl fmt::Debug for ExternalRs256JoseSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalRs256JoseSigner")
            .field("kid", &self.kid)
            .field("alg", &"RS256")
            .finish()
    }
}

impl ExternalRs256JoseSigner {
    pub fn new(
        kid: impl Into<String>,
        public_jwk: PublicJwk,
        provider: Arc<dyn ExternalRs256SignerProvider>,
    ) -> Result<Self, JoseError> {
        let kid = kid.into();
        if kid.trim().is_empty() {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                "external signer kid is required",
            ));
        }
        validate_public_jwk(&public_jwk)?;
        if public_jwk.kty != "RSA" || public_jwk.alg != "RS256" {
            return Err(JoseError::new(
                JoseErrorKind::UnsupportedAlgorithm,
                "external signer currently supports RS256 RSA public keys only",
            ));
        }
        if public_jwk.kid != kid {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                "external signer kid does not match public JWK kid",
            ));
        }
        Ok(Self { kid, public_jwk, provider })
    }

    fn sign_json_claims_with_typ<T: Serialize>(
        &self,
        claims: &T,
        typ: &str,
    ) -> Result<String, JoseError> {
        #[derive(Serialize)]
        struct ProtectedHeader<'a> {
            alg: &'a str,
            kid: &'a str,
            typ: &'a str,
        }

        let header = ProtectedHeader { alg: "RS256", kid: &self.kid, typ };
        let protected = serde_json::to_vec(&header).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidClaims, format!("encode JWS header failed: {e}"))
        })?;
        let payload = serde_json::to_vec(claims).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidClaims, format!("encode claims failed: {e}"))
        })?;
        let signing_input =
            format!("{}.{}", URL_SAFE_NO_PAD.encode(protected), URL_SAFE_NO_PAD.encode(payload));
        let signature = self.provider.sign_rs256(signing_input.as_bytes())?;
        Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }
}

impl JoseSigner for ExternalRs256JoseSigner {
    fn alg(&self) -> &'static str {
        "RS256"
    }

    fn sign_claims(&self, claims: &MintedClaims) -> Result<String, JoseError> {
        self.sign_json_claims_with_typ(claims, "at+jwt")
    }

    fn public_jwks(&self) -> JwksDocument {
        JwksDocument::new(vec![self.public_jwk.clone()])
    }

    fn verify_claims(&self, token: &str) -> Result<MintedClaims, JoseError> {
        let header = decode_compact_jws_header(token)?;
        if header.alg != "RS256" {
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

/// Test/mock provider for exercising the external signer boundary without cloud SDKs.
///
/// This is intentionally named and documented as a mock provider. Production KMS/HSM
/// integrations should implement `ExternalRs256SignerProvider` without loading local
/// private key material.
pub struct MockExternalRs256Provider {
    key_pair: RsaKeyPair,
    signature_len: usize,
}

impl fmt::Debug for MockExternalRs256Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockExternalRs256Provider").finish_non_exhaustive()
    }
}

impl MockExternalRs256Provider {
    pub fn from_private_jwk_for_backend(
        selection: &BackendSelection,
        private_jwk_json: impl AsRef<str>,
    ) -> Result<Self, JoseError> {
        ensure_classical_backend(selection)?;
        let jwk: PrivateRsaJwk = serde_json::from_str(private_jwk_json.as_ref()).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidKey, format!("invalid RSA private JWK JSON: {e}"))
        })?;
        if jwk.kty != "RSA" {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                format!("unsupported private JWK key type {}", jwk.kty),
            ));
        }
        let private_der = rsa_private_jwk_to_pkcs1_der(&jwk)?;
        let key_pair = RsaKeyPair::from_der(&private_der).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidKey, format!("invalid RSA private key: {e}"))
        })?;
        if key_pair.public_modulus_len() * 8 < 2048 {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                "RSA signing key modulus must be at least 2048 bits",
            ));
        }
        let signature_len = key_pair.public_modulus_len();
        Ok(Self { key_pair, signature_len })
    }
}

impl ExternalRs256SignerProvider for MockExternalRs256Provider {
    fn sign_rs256(&self, signing_input: &[u8]) -> Result<Vec<u8>, JoseError> {
        let rng = SystemRandom::new();
        let mut signature = vec![0_u8; self.signature_len];
        self.key_pair.sign(&RSA_PKCS1_SHA256, &rng, signing_input, &mut signature).map_err(
            |e| {
                JoseError::new(
                    JoseErrorKind::InvalidKey,
                    format!("external RS256 signing failed: {e}"),
                )
            },
        )?;
        Ok(signature)
    }
}

/// A freshly generated classical RSA signing key for file-backed operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedRsaKey {
    pub private_jwk_json: String,
    pub public_jwk: PublicJwk,
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
        ensure_classical_backend(selection)?;
        Self::from_pkcs1_pem(private_pem, kid)
    }

    /// Build the RS256 signer from a private RSA JWK only when the selected
    /// backend is classical.
    pub fn from_private_jwk_for_backend(
        selection: &BackendSelection,
        private_jwk_json: impl AsRef<str>,
        fallback_kid: impl Into<String>,
    ) -> Result<Self, JoseError> {
        ensure_classical_backend(selection)?;
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
        ensure_classical_backend(selection)?;
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
            n: Some(URL_SAFE_NO_PAD.encode(&components.n)),
            e: Some(URL_SAFE_NO_PAD.encode(&components.e)),
            pub_: None,
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

    /// Generate a 2048-bit RSA private JWK plus its public JWK.
    ///
    /// The public `kid` is the RFC 7638-style SHA-256 thumbprint of the RSA public
    /// JWK members so rotations get a deterministic key id for the generated key.
    pub fn generate_private_jwk() -> Result<GeneratedRsaKey, JoseError> {
        let key_pair = RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidKey, format!("generate RSA key failed: {e}"))
        })?;
        let private_der = AsDer::<Pkcs8V1Der>::as_der(&key_pair).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidKey, format!("encode RSA key failed: {e}"))
        })?;
        let public = key_pair.public_key();
        let components = RsaPublicKeyComponents::<Vec<u8>>::from(public);
        let n = URL_SAFE_NO_PAD.encode(&components.n);
        let e = URL_SAFE_NO_PAD.encode(&components.e);
        let kid = rsa_jwk_thumbprint(&n, &e);
        let public_jwk = PublicJwk {
            kty: "RSA".to_string(),
            kid,
            use_: "sig".to_string(),
            alg: "RS256".to_string(),
            n: Some(n),
            e: Some(e),
            pub_: None,
        };
        let private_jwk_json = private_jwk_json_from_pkcs8_der(private_der.as_ref(), &public_jwk)?;

        Ok(GeneratedRsaKey { private_jwk_json, public_jwk })
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
        parse_compact_jws(token)
    }
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

fn decode_compact_jws_header(token: &str) -> Result<CompactJwsHeader, JoseError> {
    let (header, _, _) = parse_compact_jws(token)?;
    let bytes = decode_compact_segment("JWS header", header)?;
    serde_json::from_slice(&bytes).map_err(|e| {
        JoseError::new(JoseErrorKind::InvalidCompactJws, format!("invalid compact JWS header: {e}"))
    })
}

#[cfg(feature = "pqc-openssl-unstable")]
fn decode_payload_claims<T: DeserializeOwned>(payload_segment: &str) -> Result<T, JoseError> {
    let bytes = decode_compact_segment("JWS payload", payload_segment)?;
    serde_json::from_slice(&bytes).map_err(|e| {
        JoseError::new(JoseErrorKind::InvalidClaims, format!("invalid token claims: {e}"))
    })
}

fn signature_only_rs256_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation
}

fn decode_jwk_component(name: &str, value: &str) -> Result<Vec<u8>, JoseError> {
    let bytes = decode_jwk_octets(&format!("RSA JWK {name}"), value)?;
    if bytes.is_empty() {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("invalid RSA JWK {name}: empty unsigned integer"),
        ));
    }
    Ok(bytes)
}

fn decode_jwk_octets(label: &str, value: &str) -> Result<Vec<u8>, JoseError> {
    URL_SAFE_NO_PAD.decode(value.as_bytes()).map_err(|e| {
        JoseError::new(JoseErrorKind::InvalidKey, format!("invalid {label} encoding: {e}"))
    })
}

fn decode_compact_segment(label: &str, value: &str) -> Result<Vec<u8>, JoseError> {
    URL_SAFE_NO_PAD.decode(value.as_bytes()).map_err(|e| {
        JoseError::new(
            JoseErrorKind::InvalidCompactJws,
            format!("invalid compact {label} encoding: {e}"),
        )
    })
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

fn rsa_jwk_thumbprint(n: &str, e: &str) -> String {
    let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
    URL_SAFE_NO_PAD.encode(aws_digest(&SHA256, canonical.as_bytes()).as_ref())
}

#[cfg(feature = "pqc-openssl-unstable")]
fn akp_jwk_thumbprint(alg: &str, public: &str) -> String {
    let canonical = format!(r#"{{"alg":"{alg}","kty":"AKP","pub":"{public}"}}"#);
    URL_SAFE_NO_PAD.encode(aws_digest(&SHA256, canonical.as_bytes()).as_ref())
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

fn private_jwk_json_from_pkcs8_der(
    private_der: &[u8],
    public_jwk: &PublicJwk,
) -> Result<String, JoseError> {
    let pkcs1_der = normalize_rsa_private_key_der(private_der)?;
    let blocks = simple_asn1::from_der(&pkcs1_der).map_err(|e| {
        JoseError::new(JoseErrorKind::InvalidKey, format!("invalid generated RSA key DER: {e}"))
    })?;
    let sequence = match blocks.as_slice() {
        [ASN1Block::Sequence(_, sequence)] => sequence,
        _ => {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                "invalid generated RSA key DER: expected PKCS#1 sequence",
            ));
        }
    };
    if sequence.len() < 9 {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            "invalid generated RSA key DER: missing RSA private key components",
        ));
    }

    let jwk = serde_json::json!({
        "kty": "RSA",
        "kid": public_jwk.kid.clone(),
        "use": "sig",
        "alg": "RS256",
        "n": rsa_integer_component(sequence, 1, "n")?,
        "e": rsa_integer_component(sequence, 2, "e")?,
        "d": rsa_integer_component(sequence, 3, "d")?,
        "p": rsa_integer_component(sequence, 4, "p")?,
        "q": rsa_integer_component(sequence, 5, "q")?,
        "dp": rsa_integer_component(sequence, 6, "dp")?,
        "dq": rsa_integer_component(sequence, 7, "dq")?,
        "qi": rsa_integer_component(sequence, 8, "qi")?,
    });
    serde_json::to_string_pretty(&jwk).map(|json| format!("{json}\n")).map_err(|e| {
        JoseError::new(JoseErrorKind::InvalidKey, format!("encode generated RSA JWK failed: {e}"))
    })
}

fn rsa_integer_component(
    sequence: &[ASN1Block],
    index: usize,
    name: &str,
) -> Result<String, JoseError> {
    let Some(ASN1Block::Integer(_, value)) = sequence.get(index) else {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("invalid generated RSA key DER: missing integer {name}"),
        ));
    };
    if value <= &BigInt::from(0) {
        return Err(JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("invalid generated RSA key DER: non-positive integer {name}"),
        ));
    }
    let (_, bytes) = value.to_bytes_be();
    Ok(URL_SAFE_NO_PAD.encode(bytes))
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

#[cfg(feature = "pqc-openssl-unstable")]
fn openssl_private_key_from_seed(
    algorithm: MlDsaAlgorithm,
    seed: &[u8],
) -> Result<PKey<Private>, JoseError> {
    PKey::private_key_from_seed(None, algorithm.key_type(), None, seed).map_err(|e| {
        JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("AKP private JWK seed was rejected by OpenSSL: {e}"),
        )
    })
}

#[cfg(feature = "pqc-openssl-unstable")]
fn openssl_public_key_from_raw_bytes(
    algorithm: MlDsaAlgorithm,
    public_key: &[u8],
) -> Result<PKey<Public>, JoseError> {
    PKey::public_key_from_raw_bytes_ex(None, algorithm.key_type(), None, public_key).map_err(|e| {
        JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("AKP public JWK pub was rejected by OpenSSL: {e}"),
        )
    })
}

#[cfg(feature = "pqc-openssl-unstable")]
fn openssl_raw_public_key(key_pair: &PKey<Private>) -> Result<Vec<u8>, JoseError> {
    key_pair.raw_public_key().map_err(|e| {
        JoseError::new(
            JoseErrorKind::InvalidKey,
            format!("derive ML-DSA public key from OpenSSL private key failed: {e}"),
        )
    })
}

#[cfg(feature = "pqc-openssl-unstable")]
pub struct MlDsaJoseSigner {
    kid: String,
    algorithm: MlDsaAlgorithm,
    key_pair: PKey<Private>,
    public_jwk: PublicJwk,
}

#[cfg(feature = "pqc-openssl-unstable")]
impl fmt::Debug for MlDsaJoseSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaJoseSigner")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm.jose_alg())
            .finish()
    }
}

#[cfg(feature = "pqc-openssl-unstable")]
impl MlDsaJoseSigner {
    /// Build an ML-DSA signer from an RFC 9964 private AKP JWK.
    ///
    /// RFC 9964 uses a 32-byte seed in the `priv` member; expanded private key
    /// encodings are intentionally not accepted here.
    pub fn from_private_jwk_for_backend(
        selection: &BackendSelection,
        private_jwk_json: impl AsRef<str>,
        fallback_kid: impl Into<String>,
    ) -> Result<Self, JoseError> {
        resolve_backend(selection)?;
        let selected_algorithm = selected_pqc_algorithm(selection)?;
        let jwk: PrivateAkpJwk = serde_json::from_str(private_jwk_json.as_ref()).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidKey, format!("invalid AKP private JWK JSON: {e}"))
        })?;
        if jwk.kty != "AKP" {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                format!("unsupported private JWK key type {}", jwk.kty),
            ));
        }
        let algorithm = MlDsaAlgorithm::from_jose_alg(&jwk.alg).ok_or_else(|| {
            JoseError::new(
                JoseErrorKind::UnsupportedAlgorithm,
                format!("unsupported AKP private JWK alg {}", jwk.alg),
            )
        })?;
        if algorithm != selected_algorithm {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                "selected signing algorithm does not match AKP private JWK alg",
            ));
        }
        let seed = decode_jwk_octets("AKP private JWK priv", &jwk.priv_)?;
        if seed.len() != 32 {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                "AKP private JWK priv must be a 32-byte seed",
            ));
        }
        let supplied_public = decode_jwk_octets("AKP private JWK pub", &jwk.pub_)?;
        if supplied_public.len() != algorithm.public_key_len() {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                format!(
                    "AKP private JWK pub length must be {} bytes for {}",
                    algorithm.public_key_len(),
                    algorithm.jose_alg()
                ),
            ));
        }
        let key_pair = openssl_private_key_from_seed(algorithm, &seed)?;
        let derived_public = openssl_raw_public_key(&key_pair)?;
        if derived_public.as_slice() != supplied_public.as_slice() {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                "AKP private JWK pub does not match priv-derived public key",
            ));
        }
        let public = URL_SAFE_NO_PAD.encode(&derived_public);
        let fallback_kid = fallback_kid.into();
        let kid = jwk.kid.unwrap_or_else(|| {
            if fallback_kid.is_empty() {
                akp_jwk_thumbprint(algorithm.jose_alg(), &public)
            } else {
                fallback_kid
            }
        });
        let public_jwk = PublicJwk {
            kty: "AKP".to_string(),
            kid: kid.clone(),
            use_: "sig".to_string(),
            alg: algorithm.jose_alg().to_string(),
            n: None,
            e: None,
            pub_: Some(public),
        };
        Ok(Self { kid, algorithm, key_pair, public_jwk })
    }

    /// Generate a deterministic test signer from a 32-byte seed.
    pub fn from_seed_for_tests(
        algorithm: MlDsaAlgorithm,
        seed: [u8; 32],
        kid: impl Into<String>,
    ) -> Result<Self, JoseError> {
        let key_pair = openssl_private_key_from_seed(algorithm, &seed)?;
        let public = URL_SAFE_NO_PAD.encode(openssl_raw_public_key(&key_pair)?);
        let kid = kid.into();
        let public_jwk = PublicJwk {
            kty: "AKP".to_string(),
            kid: kid.clone(),
            use_: "sig".to_string(),
            alg: algorithm.jose_alg().to_string(),
            n: None,
            e: None,
            pub_: Some(public),
        };
        Ok(Self { kid, algorithm, key_pair, public_jwk })
    }

    pub fn sign_json_claims<T: Serialize>(&self, claims: &T) -> Result<String, JoseError> {
        self.sign_json_claims_with_typ(claims, "JWT")
    }

    fn sign_json_claims_with_typ<T: Serialize>(
        &self,
        claims: &T,
        typ: &str,
    ) -> Result<String, JoseError> {
        #[derive(Serialize)]
        struct ProtectedHeader<'a> {
            alg: &'a str,
            kid: &'a str,
            typ: &'a str,
        }

        let header = ProtectedHeader { alg: self.algorithm.jose_alg(), kid: &self.kid, typ };
        let protected = serde_json::to_vec(&header).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidClaims, format!("encode JWS header failed: {e}"))
        })?;
        let payload = serde_json::to_vec(claims).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidClaims, format!("encode claims failed: {e}"))
        })?;
        let signing_input =
            format!("{}.{}", URL_SAFE_NO_PAD.encode(protected), URL_SAFE_NO_PAD.encode(payload));
        let mut signer = OpenSslSigner::new_without_digest(&self.key_pair).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidKey, format!("create ML-DSA signer failed: {e}"))
        })?;
        let signature = signer.sign_oneshot_to_vec(signing_input.as_bytes()).map_err(|e| {
            JoseError::new(JoseErrorKind::InvalidKey, format!("ML-DSA signing failed: {e}"))
        })?;
        if signature.len() != self.algorithm.signature_len() {
            return Err(JoseError::new(
                JoseErrorKind::InvalidKey,
                format!(
                    "ML-DSA signature length was {} bytes, expected {} for {}",
                    signature.len(),
                    self.algorithm.signature_len(),
                    self.algorithm.jose_alg()
                ),
            ));
        }
        Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    fn public_jwk(&self) -> PublicJwk {
        self.public_jwk.clone()
    }
}

#[cfg(feature = "pqc-openssl-unstable")]
impl JoseSigner for MlDsaJoseSigner {
    fn alg(&self) -> &'static str {
        self.algorithm.jose_alg()
    }

    fn sign_claims(&self, claims: &MintedClaims) -> Result<String, JoseError> {
        self.sign_json_claims_with_typ(claims, "at+jwt")
    }

    fn public_jwks(&self) -> JwksDocument {
        JwksDocument::new(vec![self.public_jwk()])
    }

    fn verify_claims(&self, token: &str) -> Result<MintedClaims, JoseError> {
        let header = decode_compact_jws_header(token)?;
        if header.alg != self.algorithm.jose_alg() {
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
        let header = decode_compact_jws_header(token)?;
        if header.alg != "RS256" {
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
        BackendSelection::RequestedPqc(requested) => {
            let _algorithm = MlDsaAlgorithm::from_selector(requested).ok_or_else(|| {
                JoseError::new(
                    JoseErrorKind::UnsupportedAlgorithm,
                    format!(
                        "requested signing backend {requested:?} is not supported; refusing to fall back to RS256"
                    ),
                )
            })?;
            #[cfg(feature = "pqc-openssl-unstable")]
            {
                Ok(())
            }
            #[cfg(not(feature = "pqc-openssl-unstable"))]
            {
                Err(JoseError::new(
                    JoseErrorKind::UnsupportedAlgorithm,
                    format!(
                        "requested PQC signing backend {requested:?} requires the pqc-openssl-unstable feature; refusing to fall back to RS256"
                    ),
                ))
            }
        }
    }
}

fn ensure_classical_backend(selection: &BackendSelection) -> Result<(), JoseError> {
    match selection {
        BackendSelection::Classical => Ok(()),
        BackendSelection::RequestedPqc(requested) => Err(JoseError::new(
            JoseErrorKind::UnsupportedAlgorithm,
            format!(
                "requested PQC signing backend {requested:?} cannot instantiate the RS256 signer; refusing to fall back to RS256"
            ),
        )),
    }
}

#[cfg(feature = "pqc-openssl-unstable")]
fn selected_pqc_algorithm(selection: &BackendSelection) -> Result<MlDsaAlgorithm, JoseError> {
    match selection {
        BackendSelection::Classical => Err(JoseError::new(
            JoseErrorKind::UnsupportedAlgorithm,
            "classical signing selection does not identify an ML-DSA algorithm",
        )),
        BackendSelection::RequestedPqc(requested) => MlDsaAlgorithm::from_selector(requested)
            .ok_or_else(|| {
                JoseError::new(
                    JoseErrorKind::UnsupportedAlgorithm,
                    format!("requested PQC signing backend {requested:?} is not supported"),
                )
            }),
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

    #[cfg(not(feature = "pqc-openssl-unstable"))]
    #[test]
    fn pqc_backend_selector_fails_closed() {
        let err = resolve_backend(&BackendSelection::parse("ML-DSA-65")).unwrap_err();
        assert_eq!(err.kind, JoseErrorKind::UnsupportedAlgorithm);
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    #[test]
    fn concrete_pqc_backend_selector_is_available_when_feature_enabled() {
        resolve_backend(&BackendSelection::parse("ML-DSA-65")).expect("backend");
        let err = resolve_backend(&BackendSelection::parse("pqc")).unwrap_err();
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
    fn generated_private_jwk_round_trips_to_public_jwks() {
        let generated = RsaJoseSigner::generate_private_jwk().expect("generated key");
        assert!(generated.private_jwk_json.contains(r#""d""#));
        assert_eq!(generated.public_jwk.kty, "RSA");
        assert_eq!(generated.public_jwk.alg, "RS256");
        assert_eq!(generated.public_jwk.use_, "sig");

        let signer = RsaJoseSigner::from_pkcs1_pem(
            &generated.private_jwk_json,
            generated.public_jwk.kid.clone(),
        )
        .expect_err("private JWK must not be parsed as PEM");
        assert_eq!(signer.kind, JoseErrorKind::InvalidKey);

        let signer = RsaJoseSigner::from_private_jwk(
            &generated.private_jwk_json,
            generated.public_jwk.kid.clone(),
        )
        .expect("parse generated key");
        assert_eq!(signer.public_jwks().keys, vec![generated.public_jwk]);
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
    fn external_rs256_signer_round_trips_with_mock_provider() {
        let generated = RsaJoseSigner::generate_private_jwk().expect("generated key");
        let provider = Arc::new(
            MockExternalRs256Provider::from_private_jwk_for_backend(
                &BackendSelection::Classical,
                &generated.private_jwk_json,
            )
            .expect("provider"),
        );
        let signer = ExternalRs256JoseSigner::new(
            generated.public_jwk.kid.clone(),
            generated.public_jwk,
            provider,
        )
        .expect("external signer");

        let token = signer.sign_claims(&claims()).expect("sign");
        let decoded = signer.verify_claims(&token).expect("verify");
        assert_eq!(decoded.sub, "user@example.com");
        assert_eq!(decoded.aud, "api://chat-mcp");
        let jwks_json = serde_json::to_value(signer.public_jwks()).expect("jwks");
        assert!(jwks_json["keys"][0].get("d").is_none());
        assert!(jwks_json["keys"][0].get("p").is_none());
        assert!(jwks_json["keys"][0].get("q").is_none());
    }

    #[test]
    fn external_rs256_signer_rejects_public_kid_mismatch() {
        let generated = RsaJoseSigner::generate_private_jwk().expect("generated key");
        let provider = Arc::new(
            MockExternalRs256Provider::from_private_jwk_for_backend(
                &BackendSelection::Classical,
                &generated.private_jwk_json,
            )
            .expect("provider"),
        );
        let err =
            ExternalRs256JoseSigner::new("wrong-kid", generated.public_jwk, provider).unwrap_err();
        assert_eq!(err.kind, JoseErrorKind::InvalidKey);
        assert!(err.message.contains("kid"));
    }

    #[test]
    fn external_rs256_provider_failure_fails_closed() {
        #[derive(Debug)]
        struct FailingProvider;

        impl ExternalRs256SignerProvider for FailingProvider {
            fn sign_rs256(&self, _signing_input: &[u8]) -> Result<Vec<u8>, JoseError> {
                Err(JoseError::new(JoseErrorKind::InvalidKey, "provider refused signing"))
            }
        }

        let public_jwk = RsaJoseSigner::generate_private_jwk().expect("generated key").public_jwk;
        let signer = ExternalRs256JoseSigner::new(
            public_jwk.kid.clone(),
            public_jwk,
            Arc::new(FailingProvider),
        )
        .expect("external signer");
        let err = signer.sign_claims(&claims()).unwrap_err();
        assert_eq!(err.kind, JoseErrorKind::InvalidKey);
        assert!(err.message.contains("provider"));
    }

    #[test]
    fn mock_external_provider_honors_backend_selection() {
        let generated = RsaJoseSigner::generate_private_jwk().expect("generated key");
        let err = MockExternalRs256Provider::from_private_jwk_for_backend(
            &BackendSelection::parse("ML-DSA-65"),
            generated.private_jwk_json,
        )
        .unwrap_err();
        assert_eq!(err.kind, JoseErrorKind::UnsupportedAlgorithm);
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
        assert_eq!(verified.alg, "RS256");
        assert_eq!(verified.kid, "kid-1");
        assert_eq!(verified.claims.sub, "user@example.com");
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    fn mldsa_private_jwk(seed: [u8; 32], kid: &str) -> String {
        let signer =
            MlDsaJoseSigner::from_seed_for_tests(MlDsaAlgorithm::MlDsa65, seed, kid).unwrap();
        let public = signer.public_jwks().keys[0].pub_.clone().expect("public key");
        serde_json::json!({
            "kty": "AKP",
            "kid": kid,
            "use": "sig",
            "alg": "ML-DSA-65",
            "pub": public,
            "priv": URL_SAFE_NO_PAD.encode(seed),
        })
        .to_string()
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    fn rewrite_header_alg(token: &str, alg: &str) -> String {
        let (header, payload, signature) = parse_compact_jws(token).expect("compact");
        let mut header_json: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header.as_bytes()).expect("header"))
                .expect("header json");
        header_json["alg"] = serde_json::Value::String(alg.to_string());
        format!(
            "{}.{payload}.{signature}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_json).expect("header encode"))
        )
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    #[test]
    fn mldsa_signer_publishes_akp_and_round_trips_claims() {
        let private_jwk = mldsa_private_jwk([9_u8; 32], "ml-kid");
        let signer = MlDsaJoseSigner::from_private_jwk_for_backend(
            &BackendSelection::parse("ML-DSA-65"),
            &private_jwk,
            "fallback",
        )
        .expect("mldsa signer");

        let token = signer.sign_claims(&claims()).expect("sign");
        let header_b64 = token.split('.').next().unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64.as_bytes()).unwrap())
                .unwrap();
        assert_eq!(header["alg"], "ML-DSA-65");
        assert_eq!(header["kid"], "ml-kid");
        assert_eq!(header["typ"], "at+jwt");

        let jwks = signer.public_jwks();
        let public = &jwks.keys[0];
        assert_eq!(public.kty, "AKP");
        assert_eq!(public.alg, "ML-DSA-65");
        assert_eq!(public.pub_.as_ref().map(|value| !value.is_empty()), Some(true));
        assert!(public.n.is_none());
        assert!(public.e.is_none());
        let public_json = serde_json::to_value(&jwks).expect("jwks json");
        assert!(public_json["keys"][0].get("priv").is_none());

        let decoded: MintedClaims = verify_claims_against_jwks(&token, &jwks).expect("verify");
        assert_eq!(decoded.sub, "user@example.com");
        assert_eq!(decoded.aud, "api://chat-mcp");
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    #[test]
    fn mldsa_verifier_rejects_tampered_algorithm_header() {
        let private_jwk = mldsa_private_jwk([10_u8; 32], "ml-kid");
        let signer = MlDsaJoseSigner::from_private_jwk_for_backend(
            &BackendSelection::parse("ML-DSA-65"),
            &private_jwk,
            "fallback",
        )
        .expect("mldsa signer");
        let token = signer.sign_claims(&claims()).expect("sign");
        let tampered = rewrite_header_alg(&token, "ML-DSA-44");

        let err = verify_claims_against_jwks::<MintedClaims>(&tampered, &signer.public_jwks())
            .unwrap_err();
        assert_eq!(err.kind, JoseErrorKind::VerificationFailed);
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    #[test]
    fn mldsa_verifier_respects_context_algorithm_allowlist() {
        let private_jwk = mldsa_private_jwk([13_u8; 32], "ml-kid");
        let signer = MlDsaJoseSigner::from_private_jwk_for_backend(
            &BackendSelection::parse("ML-DSA-65"),
            &private_jwk,
            "fallback",
        )
        .expect("mldsa signer");
        let token = signer.sign_claims(&claims()).expect("sign");

        let verified: VerifiedJws<MintedClaims> =
            verify_claims_against_jwks_with_header(&token, &signer.public_jwks()).expect("verify");
        assert_eq!(verified.alg, "ML-DSA-65");

        let err = verify_claims_against_jwks_with_allowed_algs::<MintedClaims>(
            &token,
            &signer.public_jwks(),
            &["RS256"],
        )
        .unwrap_err();
        assert_eq!(err.kind, JoseErrorKind::UnsupportedAlgorithm);
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    #[test]
    fn mldsa_private_jwk_rejects_mismatched_public_key() {
        let good_private = mldsa_private_jwk([11_u8; 32], "ml-kid");
        let wrong_public =
            MlDsaJoseSigner::from_seed_for_tests(MlDsaAlgorithm::MlDsa65, [12_u8; 32], "wrong")
                .unwrap()
                .public_jwks()
                .keys[0]
                .pub_
                .clone()
                .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&good_private).unwrap();
        value["pub"] = serde_json::Value::String(wrong_public);

        let err = MlDsaJoseSigner::from_private_jwk_for_backend(
            &BackendSelection::parse("ML-DSA-65"),
            value.to_string(),
            "fallback",
        )
        .unwrap_err();
        assert_eq!(err.kind, JoseErrorKind::InvalidKey);
    }

    #[test]
    fn akp_public_jwk_rejects_wrong_public_key_size() {
        let jwk = PublicJwk {
            kty: "AKP".to_string(),
            kid: "ml-kid".to_string(),
            use_: "sig".to_string(),
            alg: "ML-DSA-65".to_string(),
            n: None,
            e: None,
            pub_: Some(URL_SAFE_NO_PAD.encode([0_u8; 32])),
        };
        let err = akp_public_key_from_jwk(&jwk).unwrap_err();
        assert_eq!(err.kind, JoseErrorKind::InvalidKey);
    }
}
