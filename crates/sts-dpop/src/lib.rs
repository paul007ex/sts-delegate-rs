#![forbid(unsafe_code)]

//! RFC 9449 DPoP proof validation for `sts-delegate-rs`.
//!
//! DPoP proof verification is intentionally separate from trusted-token
//! verification: a proof is self-signed by the holder key embedded in the JOSE
//! header, then bound into the minted access token as `cnf.jkt`.

use std::fmt;
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, ThumbprintHash};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

/// Public DPoP signing algorithms that this verifier enforces.
///
/// The list is also suitable for RFC 8414 `dpop_signing_alg_values_supported`
/// because metadata must never advertise an algorithm that the verifier does
/// not actually accept.
pub const DPOP_SIGNING_ALGS_SUPPORTED: &[&str] =
    &["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"];

/// Local anti-DoS cap for one compact DPoP proof.
pub const MAX_DPOP_PROOF_LEN: usize = 8_192;

/// Local anti-DoS cap for caller-controlled proof `jti` values.
pub const MAX_DPOP_JTI_LEN: usize = 128;

const DPOP_TYP: &str = "dpop+jwt";
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Input needed to validate one DPoP proof.
#[derive(Debug, Clone, Copy)]
pub struct DpopProofRequest<'a> {
    pub proof: &'a str,
    pub htm: &'a str,
    pub htu: &'a str,
    pub now: i64,
    pub clock_skew_leeway: i64,
}

/// Sender-constraining data returned after stateless DPoP proof validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopBinding {
    pub jkt: String,
    pub jti: String,
    pub iat: i64,
    pub replay_expires_at: i64,
}

/// DPoP validation failure category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpopErrorKind {
    InvalidProof,
}

impl fmt::Display for DpopErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProof => f.write_str("invalid_dpop_proof"),
        }
    }
}

/// Stable DPoP-layer error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopError {
    pub kind: DpopErrorKind,
    pub message: String,
}

impl DpopError {
    fn invalid(message: impl Into<String>) -> Self {
        Self { kind: DpopErrorKind::InvalidProof, message: message.into() }
    }
}

impl fmt::Display for DpopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for DpopError {}

#[derive(Debug, Clone, Deserialize)]
struct VerifiedDpopClaims {
    #[serde(default)]
    jti: Option<Value>,
    #[serde(default)]
    htm: Option<Value>,
    #[serde(default)]
    htu: Option<Value>,
    #[serde(default)]
    iat: Option<Value>,
}

/// Validate the stateless RFC 9449 token-endpoint DPoP proof requirements.
///
/// This performs proof size checks, JOSE header checks, embedded public JWK
/// validation, signature verification, `htm` / `htu` matching, `iat` skew
/// enforcement, and `jti` bounds. Replay recording remains in `sts-replay` so
/// storage side effects happen only after the token-exchange gates succeed.
pub fn validate_dpop_proof(input: DpopProofRequest<'_>) -> Result<DpopBinding, DpopError> {
    check_proof_input(input)?;
    let (header_b64, _, _) = compact_parts(input.proof)?;
    let header = decode_json_part(header_b64, "header")?;
    let (alg, jwk) = validate_header(&header)?;
    let claims = verify_proof_signature(input.proof, alg, &jwk)?;
    let jti = validate_jti(required_string_claim(&claims.jti, "jti")?)?;
    validate_htm(required_string_claim(&claims.htm, "htm")?, input.htm)?;
    validate_htu(required_string_claim(&claims.htu, "htu")?, input.htu)?;
    let iat = validate_iat(&claims.iat, input.now, input.clock_skew_leeway)?;
    let leeway = input.clock_skew_leeway.max(0);

    Ok(DpopBinding {
        jkt: jwk.thumbprint(ThumbprintHash::SHA256),
        jti: jti.to_string(),
        iat,
        replay_expires_at: iat.saturating_add(leeway),
    })
}

fn check_proof_input(input: DpopProofRequest<'_>) -> Result<(), DpopError> {
    if input.proof.trim().is_empty() {
        return Err(DpopError::invalid("DPoP proof missing or not a string"));
    }
    if input.proof.len() > MAX_DPOP_PROOF_LEN {
        return Err(DpopError::invalid("DPoP proof exceeds maximum allowed length"));
    }
    if input.htm.trim().is_empty() || input.htu.trim().is_empty() {
        return Err(DpopError::invalid(
            "DPoP request method/URI not available for proof validation",
        ));
    }
    Ok(())
}

fn compact_parts(proof: &str) -> Result<(&str, &str, &str), DpopError> {
    let mut parts = proof.split('.');
    let header = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| DpopError::invalid("DPoP proof must be a compact JWT"))?;
    let payload = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| DpopError::invalid("DPoP proof must be a compact JWT"))?;
    let signature = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| DpopError::invalid("DPoP proof must be a compact JWT"))?;
    if parts.next().is_some() {
        return Err(DpopError::invalid("DPoP proof must be a compact JWT"));
    }
    Ok((header, payload, signature))
}

fn decode_json_part(part: &str, name: &str) -> Result<Value, DpopError> {
    let bytes = URL_SAFE_NO_PAD.decode(part.as_bytes()).map_err(|_| {
        DpopError::invalid(format!("DPoP proof {name} is not valid base64url JSON"))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|_| DpopError::invalid(format!("DPoP proof {name} is not valid JSON")))
}

fn validate_header(header: &Value) -> Result<(Algorithm, Jwk), DpopError> {
    let Some(header) = header.as_object() else {
        return Err(DpopError::invalid("DPoP proof header is not a JSON object"));
    };
    if header.get("typ").and_then(Value::as_str) != Some(DPOP_TYP) {
        return Err(DpopError::invalid("DPoP proof typ must be dpop+jwt"));
    }
    let alg_name = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| DpopError::invalid("DPoP proof alg is required"))?;
    if !DPOP_SIGNING_ALGS_SUPPORTED.contains(&alg_name) {
        return Err(DpopError::invalid(format!(
            "DPoP proof alg {alg_name:?} is not an allowed asymmetric algorithm",
        )));
    }
    let alg = Algorithm::from_str(alg_name)
        .map_err(|_| DpopError::invalid("DPoP proof alg is not supported"))?;
    let jwk_value = header
        .get("jwk")
        .ok_or_else(|| DpopError::invalid("DPoP proof header must carry a public jwk"))?;
    let Some(jwk_object) = jwk_value.as_object() else {
        return Err(DpopError::invalid("DPoP proof header must carry a public jwk"));
    };
    if PRIVATE_JWK_MEMBERS.iter().any(|member| jwk_object.contains_key(*member)) {
        return Err(DpopError::invalid("DPoP proof jwk must not contain private key material"));
    }
    if let Some(jwk_alg) = jwk_object.get("alg").and_then(Value::as_str)
        && jwk_alg != alg_name
    {
        return Err(DpopError::invalid("DPoP proof jwk alg does not match header alg"));
    }
    let jwk = serde_json::from_value::<Jwk>(jwk_value.clone())
        .map_err(|_| DpopError::invalid("DPoP proof jwk is not a valid public key"))?;
    ensure_asymmetric_key_matches_alg(&jwk, alg)?;
    Ok((alg, jwk))
}

fn ensure_asymmetric_key_matches_alg(jwk: &Jwk, alg: Algorithm) -> Result<(), DpopError> {
    match (&jwk.algorithm, alg) {
        (
            AlgorithmParameters::RSA(_),
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512,
        )
        | (AlgorithmParameters::EllipticCurve(_), Algorithm::ES256 | Algorithm::ES384)
        | (AlgorithmParameters::OctetKeyPair(_), Algorithm::EdDSA) => Ok(()),
        _ => Err(DpopError::invalid("DPoP proof jwk key type is not compatible with header alg")),
    }
}

fn verify_proof_signature(
    proof: &str,
    alg: Algorithm,
    jwk: &Jwk,
) -> Result<VerifiedDpopClaims, DpopError> {
    let key = DecodingKey::from_jwk(jwk)
        .map_err(|_| DpopError::invalid("DPoP proof jwk is not a valid public key"))?;
    let mut validation = Validation::new(alg);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    decode::<VerifiedDpopClaims>(proof, &key, &validation)
        .map(|data| data.claims)
        .map_err(|_| DpopError::invalid("DPoP proof signature does not verify"))
}

fn required_string_claim<'a>(value: &'a Option<Value>, claim: &str) -> Result<&'a str, DpopError> {
    value
        .as_ref()
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DpopError::invalid(format!("DPoP proof {claim} must be a non-empty string")))
}

fn validate_jti(jti: &str) -> Result<&str, DpopError> {
    if jti.len() > MAX_DPOP_JTI_LEN {
        return Err(DpopError::invalid("DPoP proof jti exceeds maximum allowed length"));
    }
    Ok(jti)
}

fn validate_htm(claim_htm: &str, htm: &str) -> Result<(), DpopError> {
    if !claim_htm.eq_ignore_ascii_case(htm) {
        return Err(DpopError::invalid("DPoP proof htm does not match the request method"));
    }
    Ok(())
}

fn validate_htu(claim_htu: &str, htu: &str) -> Result<(), DpopError> {
    let claim_htu = canonical_htu(claim_htu)
        .ok_or_else(|| DpopError::invalid("DPoP proof htu is not a valid absolute URI"))?;
    let request_htu = canonical_htu(htu)
        .ok_or_else(|| DpopError::invalid("DPoP request URI is not a valid absolute URI"))?;
    if claim_htu != request_htu {
        return Err(DpopError::invalid("DPoP proof htu does not match the request URI"));
    }
    Ok(())
}

fn validate_iat(value: &Option<Value>, now: i64, leeway: i64) -> Result<i64, DpopError> {
    let value = value
        .as_ref()
        .ok_or_else(|| DpopError::invalid("DPoP proof missing required claim iat"))?;
    let iat = value_to_i64(value)
        .ok_or_else(|| DpopError::invalid("DPoP proof iat must be a finite number"))?;
    if now.abs_diff(iat) > leeway.max(0) as u64 {
        return Err(DpopError::invalid("DPoP proof iat is outside the acceptable window"));
    }
    Ok(iat)
}

fn value_to_i64(value: &Value) -> Option<i64> {
    if let Some(value) = value.as_i64() {
        return Some(value);
    }
    if let Some(value) = value.as_u64() {
        return i64::try_from(value).ok();
    }
    let value = value.as_f64()?;
    if value.is_finite() && value >= i64::MIN as f64 && value <= i64::MAX as f64 {
        Some(value as i64)
    } else {
        None
    }
}

fn canonical_htu(value: &str) -> Option<String> {
    let parsed = Url::parse(value).ok()?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    let host = parsed.host_str()?.to_ascii_lowercase();
    let netloc = match parsed.port() {
        Some(port) if Some(port) != default_port(&scheme) => format!("{host}:{port}"),
        _ => host,
    };
    let mut canonical = format!("{scheme}://{netloc}{}", parsed.path());
    while canonical.ends_with('/') {
        canonical.pop();
    }
    Some(canonical)
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;
    use rand_core::OsRng;
    use serde_json::json;

    fn es256_proof(now: i64, jti: &str, htm: &str, htu: &str) -> String {
        es256_proof_with_claims(json!({
            "jti": jti,
            "htm": htm,
            "htu": htu,
            "iat": now,
        }))
    }

    fn es256_proof_with_claims(claims: Value) -> String {
        let signing_key = SigningKey::random(&mut OsRng);
        es256_proof_with_header_and_claims(signing_key, claims, |header| header)
    }

    fn es256_proof_with_header_and_claims(
        signing_key: SigningKey,
        claims: Value,
        mutate_header: impl FnOnce(Header) -> Header,
    ) -> String {
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().expect("x coordinate")),
            "y": URL_SAFE_NO_PAD.encode(point.y().expect("y coordinate")),
            "alg": "ES256",
        });
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(DPOP_TYP.to_string());
        header.jwk = Some(serde_json::from_value(jwk).expect("jwk"));
        let header = mutate_header(header);
        let der = signing_key.to_pkcs8_der().expect("pkcs8 der");
        encode(&header, &claims, &EncodingKey::from_ec_der(der.as_bytes())).expect("dpop proof")
    }

    fn mutate_header_segment(proof: &str, mutate: impl FnOnce(&mut Value)) -> String {
        let mut parts = proof.split('.');
        let header = parts.next().expect("header");
        let payload = parts.next().expect("payload");
        let signature = parts.next().expect("signature");
        let mut header_json: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header.as_bytes()).expect("header b64"))
                .expect("header json");
        mutate(&mut header_json);
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_json).expect("header encode")),
            payload,
            signature
        )
    }

    #[test]
    fn accepts_valid_es256_proof_and_computes_binding() {
        let proof = es256_proof(100, "proof-1", "POST", "https://STS.EXAMPLE:443/token?x=1");
        let binding = validate_dpop_proof(DpopProofRequest {
            proof: &proof,
            htm: "post",
            htu: "https://sts.example/token",
            now: 100,
            clock_skew_leeway: 30,
        })
        .expect("valid proof");
        assert_eq!(binding.jti, "proof-1");
        assert_eq!(binding.iat, 100);
        assert_eq!(binding.replay_expires_at, 130);
        assert!(!binding.jkt.is_empty());
    }

    #[test]
    fn rejects_wrong_typ() {
        let signing_key = SigningKey::random(&mut OsRng);
        let proof = es256_proof_with_header_and_claims(
            signing_key,
            json!({
                "jti": "proof-2",
                "htm": "POST",
                "htu": "https://sts.example/token",
                "iat": 100,
            }),
            |mut header| {
                header.typ = Some("JWT".to_string());
                header
            },
        );
        let err = validate_dpop_proof(DpopProofRequest {
            proof: &proof,
            htm: "POST",
            htu: "https://sts.example/token",
            now: 100,
            clock_skew_leeway: 30,
        })
        .unwrap_err();
        assert!(err.message.contains("typ"));
    }

    #[test]
    fn rejects_none_or_mac_alg_before_signature_use() {
        let proof = es256_proof(100, "proof-alg", "POST", "https://sts.example/token");
        for alg in ["none", "HS256"] {
            let proof = mutate_header_segment(&proof, |header| {
                header
                    .as_object_mut()
                    .expect("header object")
                    .insert("alg".to_string(), json!(alg));
            });
            let err = validate_dpop_proof(DpopProofRequest {
                proof: &proof,
                htm: "POST",
                htu: "https://sts.example/token",
                now: 100,
                clock_skew_leeway: 30,
            })
            .unwrap_err();
            assert!(err.message.contains("not an allowed asymmetric algorithm"));
        }
    }

    #[test]
    fn rejects_bad_signature() {
        let proof = es256_proof(100, "proof-bad-sig", "POST", "https://sts.example/token");
        let mut parts = proof.rsplitn(2, '.');
        let signature = parts.next().expect("signature");
        let signed = parts.next().expect("signed content");
        let mut signature = signature.to_string();
        let replacement = if signature.ends_with('A') { 'B' } else { 'A' };
        signature.pop();
        signature.push(replacement);
        let proof = format!("{signed}.{signature}");
        let err = validate_dpop_proof(DpopProofRequest {
            proof: &proof,
            htm: "POST",
            htu: "https://sts.example/token",
            now: 100,
            clock_skew_leeway: 30,
        })
        .unwrap_err();
        assert!(err.message.contains("signature"));
    }

    #[test]
    fn rejects_missing_required_claim() {
        let proof = es256_proof_with_claims(json!({
            "htm": "POST",
            "htu": "https://sts.example/token",
            "iat": 100,
        }));
        let err = validate_dpop_proof(DpopProofRequest {
            proof: &proof,
            htm: "POST",
            htu: "https://sts.example/token",
            now: 100,
            clock_skew_leeway: 30,
        })
        .unwrap_err();
        assert!(err.message.contains("jti"));
    }

    #[test]
    fn rejects_method_or_uri_mismatch() {
        let wrong_method =
            es256_proof(100, "proof-wrong-method", "GET", "https://sts.example/token");
        let err = validate_dpop_proof(DpopProofRequest {
            proof: &wrong_method,
            htm: "POST",
            htu: "https://sts.example/token",
            now: 100,
            clock_skew_leeway: 30,
        })
        .unwrap_err();
        assert!(err.message.contains("htm"));

        let wrong_uri = es256_proof(100, "proof-wrong-uri", "POST", "https://sts.example/other");
        let err = validate_dpop_proof(DpopProofRequest {
            proof: &wrong_uri,
            htm: "POST",
            htu: "https://sts.example/token",
            now: 100,
            clock_skew_leeway: 30,
        })
        .unwrap_err();
        assert!(err.message.contains("htu"));
    }

    #[test]
    fn rejects_private_jwk_members_before_signature_use() {
        let proof = es256_proof(100, "proof-3", "POST", "https://sts.example/token");
        let proof = mutate_header_segment(&proof, |header| {
            header
                .get_mut("jwk")
                .expect("jwk")
                .as_object_mut()
                .expect("jwk object")
                .insert("d".to_string(), json!("secret"));
        });
        let err = validate_dpop_proof(DpopProofRequest {
            proof: &proof,
            htm: "POST",
            htu: "https://sts.example/token",
            now: 100,
            clock_skew_leeway: 30,
        })
        .unwrap_err();
        assert!(err.message.contains("private key"));
    }

    #[test]
    fn rejects_stale_iat_and_oversized_jti() {
        let stale = es256_proof(60, "proof-4", "POST", "https://sts.example/token");
        let err = validate_dpop_proof(DpopProofRequest {
            proof: &stale,
            htm: "POST",
            htu: "https://sts.example/token",
            now: 100,
            clock_skew_leeway: 30,
        })
        .unwrap_err();
        assert!(err.message.contains("outside"));

        let future = es256_proof(131, "proof-future", "POST", "https://sts.example/token");
        let err = validate_dpop_proof(DpopProofRequest {
            proof: &future,
            htm: "POST",
            htu: "https://sts.example/token",
            now: 100,
            clock_skew_leeway: 30,
        })
        .unwrap_err();
        assert!(err.message.contains("outside"));

        let long_jti = "x".repeat(MAX_DPOP_JTI_LEN + 1);
        let oversized = es256_proof(100, &long_jti, "POST", "https://sts.example/token");
        let err = validate_dpop_proof(DpopProofRequest {
            proof: &oversized,
            htm: "POST",
            htu: "https://sts.example/token",
            now: 100,
            clock_skew_leeway: 30,
        })
        .unwrap_err();
        assert!(err.message.contains("jti"));
    }

    #[test]
    fn rejects_oversized_proof_before_parsing() {
        let proof = "x".repeat(MAX_DPOP_PROOF_LEN + 1);
        let err = validate_dpop_proof(DpopProofRequest {
            proof: &proof,
            htm: "POST",
            htu: "https://sts.example/token",
            now: 100,
            clock_skew_leeway: 30,
        })
        .unwrap_err();
        assert!(err.message.contains("exceeds"));
    }
}
