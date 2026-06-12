#![forbid(unsafe_code)]

//! Trust-anchor, discovery, and token-verification policy for `sts-delegate-rs`.
//!
//! This crate owns the side-effect-free trust configuration boundary plus the
//! HTTP-based discovery/JWKS fetchers and JWT verification helpers that the
//! transport/service layers will call.

use std::collections::BTreeSet;
use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sts_jose::{JwksDocument, verify_claims_against_jwks_with_allowed_algs};
use subtle::ConstantTimeEq;
use url::{Host, Url};

/// The class of trust anchor being configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAnchorKind {
    Idp,
    Actor,
    Client,
}

impl fmt::Display for TrustAnchorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Idp => "idp",
            Self::Actor => "actor",
            Self::Client => "client",
        };
        f.write_str(value)
    }
}

/// A resolved trust-anchor source without doing network or file IO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchorRef {
    pub kind: TrustAnchorKind,
    pub issuer: Option<String>,
    pub jwks_url: Option<String>,
    pub jwks_file: Option<String>,
}

/// The verification policy for the three trust-anchor classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationPlan {
    pub idp: TrustAnchorRef,
    pub actor: TrustAnchorRef,
    pub client: TrustAnchorRef,
}

/// Failure categories that the verification layer must preserve at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyErrorKind {
    InvalidIssuer,
    InvalidUrl,
    InvalidAnchor,
    AnchorCollision,
    InvalidToken,
    InvalidClaims,
    InvalidAudience,
    InvalidLifetime,
    KeyBindingMismatch,
    DiscoveryFailed,
    FetchFailed,
}

impl fmt::Display for VerifyErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::InvalidIssuer => "invalid_issuer",
            Self::InvalidUrl => "invalid_url",
            Self::InvalidAnchor => "invalid_anchor",
            Self::AnchorCollision => "anchor_collision",
            Self::InvalidToken => "invalid_token",
            Self::InvalidClaims => "invalid_claims",
            Self::InvalidAudience => "invalid_audience",
            Self::InvalidLifetime => "invalid_lifetime",
            Self::KeyBindingMismatch => "key_binding_mismatch",
            Self::DiscoveryFailed => "discovery_failed",
            Self::FetchFailed => "fetch_failed",
        };
        f.write_str(code)
    }
}

/// A stable verification-layer error for policy validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    pub kind: VerifyErrorKind,
    pub message: String,
}

impl VerifyError {
    pub fn new(kind: VerifyErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for VerifyError {}

/// The OIDC discovery payload we need for trust-anchor fetches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
}

/// JWT claims used for inbound subject-token verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectTokenClaims {
    pub iss: String,
    pub sub: Option<String>,
    pub aud: serde_json::Value,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub scp: Option<serde_json::Value>,
    pub exp: i64,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    #[serde(default)]
    pub act: Option<serde_json::Value>,
    #[serde(default)]
    pub may_act: Option<serde_json::Value>,
    #[serde(default)]
    pub auth_time: Option<i64>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Option<Vec<String>>,
}

/// JWT claims used for inbound actor/client assertion verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionClaims {
    pub iss: String,
    pub sub: String,
    pub aud: serde_json::Value,
    pub exp: i64,
    pub iat: Option<i64>,
    pub jti: Option<String>,
    #[serde(default)]
    pub sub_tok_hash: Option<String>,
}

/// Policy inputs for inbound actor/client assertion verification.
#[derive(Debug, Clone, Copy)]
pub struct AssertionVerificationOptions<'a> {
    pub expected_issuer: &'a str,
    pub expected_audiences: &'a [String],
    pub clock_skew_leeway: i64,
    pub max_ttl: i64,
    pub binding_subject_token: Option<&'a str>,
    pub require_subject_binding: bool,
    pub key_binding_registry: Option<&'a BTreeSet<String>>,
}

const INBOUND_JWT_SIGNING_ALGS: &[&str] = &["RS256"];

/// Algorithms accepted for inbound subject, actor, and client assertion JWTs.
pub fn inbound_jwt_signing_algs() -> Vec<String> {
    INBOUND_JWT_SIGNING_ALGS.iter().map(|alg| (*alg).to_string()).collect()
}

/// Validate an issuer value without making network calls.
pub fn validate_issuer(value: &str) -> Result<String, VerifyError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(VerifyError::new(VerifyErrorKind::InvalidIssuer, "issuer must not be empty"));
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(VerifyError::new(
            VerifyErrorKind::InvalidIssuer,
            "issuer must not contain whitespace",
        ));
    }
    let parsed = Url::parse(trimmed).map_err(|err| {
        VerifyError::new(
            VerifyErrorKind::InvalidIssuer,
            format!("issuer must be an absolute URL: {err}"),
        )
    })?;
    if parsed.host_str().is_none() {
        return Err(VerifyError::new(VerifyErrorKind::InvalidIssuer, "issuer must include a host"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(VerifyError::new(
            VerifyErrorKind::InvalidIssuer,
            "issuer must not contain a query or fragment component",
        ));
    }
    let is_loopback = match parsed.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(host)) => host.is_loopback(),
        Some(Host::Ipv6(host)) => host.is_loopback(),
        None => false,
    };
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_loopback) {
        return Err(VerifyError::new(
            VerifyErrorKind::InvalidIssuer,
            "issuer must use https, except http is allowed for loopback local development",
        ));
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

/// Validate a JWKS URL without making network calls.
pub fn validate_jwks_url(value: &str) -> Result<String, VerifyError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(VerifyError::new(VerifyErrorKind::InvalidUrl, "JWKS URL must not be empty"));
    }
    if !trimmed.starts_with("https://") {
        return Err(VerifyError::new(VerifyErrorKind::InvalidUrl, "JWKS URL must use https://"));
    }
    if trimmed.contains('#') {
        return Err(VerifyError::new(
            VerifyErrorKind::InvalidUrl,
            "JWKS URL must not contain a fragment",
        ));
    }
    Ok(trimmed.to_string())
}

/// Build a trust-anchor reference with normalized policy checks.
pub fn build_anchor_ref(
    kind: TrustAnchorKind,
    issuer: Option<&str>,
    jwks_url: Option<&str>,
    jwks_file: Option<&str>,
) -> Result<TrustAnchorRef, VerifyError> {
    let issuer = issuer.map(validate_issuer).transpose()?;
    let jwks_url = jwks_url.map(validate_jwks_url).transpose()?;
    let jwks_file =
        jwks_file.map(str::trim).filter(|value| !value.is_empty()).map(ToOwned::to_owned);

    if jwks_url.is_none() && jwks_file.is_none() {
        return Err(VerifyError::new(
            VerifyErrorKind::InvalidAnchor,
            format!("{kind} anchor needs at least one JWKS source"),
        ));
    }

    Ok(TrustAnchorRef { kind, issuer, jwks_url, jwks_file })
}

/// Validate that actor and client anchors do not accidentally collapse into one source.
pub fn require_distinct_actor_client_anchors(
    actor: &TrustAnchorRef,
    client: &TrustAnchorRef,
) -> Result<(), VerifyError> {
    if actor.jwks_file == client.jwks_file && actor.jwks_url == client.jwks_url {
        return Err(VerifyError::new(
            VerifyErrorKind::AnchorCollision,
            "actor and client anchors must remain distinct",
        ));
    }
    Ok(())
}

/// Build the current trust plan from the three anchors.
pub fn build_verification_plan(
    idp: TrustAnchorRef,
    actor: TrustAnchorRef,
    client: TrustAnchorRef,
) -> Result<VerificationPlan, VerifyError> {
    require_distinct_actor_client_anchors(&actor, &client)?;
    Ok(VerificationPlan { idp, actor, client })
}

/// Fetch an OpenID discovery document from a validated issuer.
pub async fn discover_document(
    http: &Client,
    issuer: &str,
) -> Result<DiscoveryDocument, VerifyError> {
    let issuer = validate_issuer(issuer)?;
    let discovery_url =
        format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let response = http
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| VerifyError::new(VerifyErrorKind::DiscoveryFailed, format!("{e}")))?;
    if !response.status().is_success() {
        return Err(VerifyError::new(
            VerifyErrorKind::DiscoveryFailed,
            format!("OIDC discovery returned HTTP {}", response.status()),
        ));
    }
    response.json::<DiscoveryDocument>().await.map_err(|e| {
        VerifyError::new(VerifyErrorKind::DiscoveryFailed, format!("invalid discovery JSON: {e}"))
    })
}

/// Fetch a JWKS document from a validated HTTPS URL.
pub async fn fetch_jwks(http: &Client, jwks_url: &str) -> Result<JwksDocument, VerifyError> {
    let jwks_url = validate_jwks_url(jwks_url)?;
    let response = http
        .get(&jwks_url)
        .send()
        .await
        .map_err(|e| VerifyError::new(VerifyErrorKind::FetchFailed, format!("{e}")))?;
    if !response.status().is_success() {
        return Err(VerifyError::new(
            VerifyErrorKind::FetchFailed,
            format!("JWKS fetch returned HTTP {}", response.status()),
        ));
    }
    response.json::<JwksDocument>().await.map_err(|e| {
        VerifyError::new(VerifyErrorKind::FetchFailed, format!("invalid JWKS JSON: {e}"))
    })
}

/// Resolve the IdP JWKS with an optional explicit JWKS URI.
///
/// An explicit URI mirrors the Python oracle's `IDP_JWKS_URI` /
/// `OKTA_JWKS_URL` escape hatch. Without it, bootstrap uses OIDC discovery.
pub async fn resolve_idp_jwks(
    issuer: &str,
    explicit_jwks_uri: Option<&str>,
) -> Result<JwksDocument, VerifyError> {
    let http = Client::new();
    if let Some(jwks_uri) = explicit_jwks_uri.map(str::trim).filter(|value| !value.is_empty()) {
        return fetch_jwks(&http, jwks_uri).await;
    }
    let discovery = discover_document(&http, issuer).await?;
    if discovery.issuer.trim_end_matches('/') != validate_issuer(issuer)? {
        return Err(VerifyError::new(
            VerifyErrorKind::DiscoveryFailed,
            "OIDC discovery issuer did not match configured issuer",
        ));
    }
    fetch_jwks(&http, &discovery.jwks_uri).await
}

/// Verify an inbound subject token against a JWKS document and expected audience.
///
/// RFC 8693 requires the subject token to be validated before token exchange; the
/// local policy here pins `iss`, requires `exp`, and keeps the audience gate explicit.
pub fn verify_subject_token(
    token: &str,
    jwks: &JwksDocument,
    expected_issuer: &str,
    expected_audiences: &[String],
    clock_skew_leeway: i64,
) -> Result<SubjectTokenClaims, VerifyError> {
    let claims: SubjectTokenClaims =
        verify_claims_against_jwks_with_allowed_algs(token, jwks, INBOUND_JWT_SIGNING_ALGS)
            .map_err(map_jose_error)?
            .claims;
    let expected_issuer = validate_issuer(expected_issuer).map_err(map_verify_error)?;
    if claims.iss != expected_issuer {
        return Err(VerifyError::new(
            VerifyErrorKind::InvalidIssuer,
            format!("unexpected issuer {}", claims.iss),
        ));
    }
    validate_time_window(claims.exp, claims.nbf, clock_skew_leeway)?;
    ensure_audience_matches(&claims.aud, expected_audiences)?;
    Ok(claims)
}

/// Verify a client or actor assertion against a JWKS document.
pub fn verify_assertion(
    token: &str,
    jwks: &JwksDocument,
    options: AssertionVerificationOptions<'_>,
) -> Result<AssertionClaims, VerifyError> {
    let verified = verify_claims_against_jwks_with_allowed_algs::<AssertionClaims>(
        token,
        jwks,
        INBOUND_JWT_SIGNING_ALGS,
    )
    .map_err(map_jose_error)?;
    let claims = verified.claims;
    let _expected_issuer = validate_issuer(options.expected_issuer).map_err(map_verify_error)?;
    if claims.iss != claims.sub {
        return Err(VerifyError::new(
            VerifyErrorKind::InvalidClaims,
            "assertion iss and sub must match",
        ));
    }
    // RFC 7523 Section 3 requires every assertion to identify this authorization
    // server as an intended audience. Issuer equality is not an audience substitute.
    let aud_ok =
        options.expected_audiences.iter().any(|value| audience_matches(&claims.aud, value));
    if !aud_ok {
        return Err(VerifyError::new(
            VerifyErrorKind::InvalidAudience,
            "assertion audience does not identify this authorization server",
        ));
    }
    if let Some(registry) = options.key_binding_registry
        && !kid_belongs_to_claimed_identity(&verified.kid, &claims.sub, registry)
    {
        return Err(VerifyError::new(
            VerifyErrorKind::KeyBindingMismatch,
            "assertion signing key does not belong to the claimed identity",
        ));
    }
    validate_time_window(claims.exp, None, options.clock_skew_leeway)?;
    validate_assertion_lifetime(&claims, options.max_ttl, options.clock_skew_leeway)?;
    if options.require_subject_binding {
        let presented = claims.sub_tok_hash.as_deref().unwrap_or("");
        let expected = subject_token_hash(options.binding_subject_token.unwrap_or(""));
        if presented.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 0 {
            return Err(VerifyError::new(
                VerifyErrorKind::KeyBindingMismatch,
                "assertion not bound to the presented subject token",
            ));
        }
    }
    Ok(claims)
}

fn kid_belongs_to_claimed_identity(
    kid: &str,
    claimed_identity: &str,
    registry: &BTreeSet<String>,
) -> bool {
    if kid.is_empty() || claimed_identity.is_empty() {
        return false;
    }

    fn prefix_match(kid: &str, identity: &str) -> bool {
        kid == identity
            || kid.strip_prefix(identity).is_some_and(|suffix| {
                suffix.starts_with('-') || suffix.starts_with('/') || suffix.starts_with('.')
            })
    }

    if !prefix_match(kid, claimed_identity) {
        return false;
    }
    !registry.iter().any(|other| {
        other != claimed_identity
            && other.len() > claimed_identity.len()
            && prefix_match(kid, other)
    })
}

fn validate_time_window(
    exp: i64,
    nbf: Option<i64>,
    clock_skew_leeway: i64,
) -> Result<(), VerifyError> {
    let now = now_unix();
    if exp + clock_skew_leeway < now {
        return Err(VerifyError::new(VerifyErrorKind::InvalidLifetime, "token has expired"));
    }
    if let Some(nbf) = nbf
        && nbf - clock_skew_leeway > now
    {
        return Err(VerifyError::new(VerifyErrorKind::InvalidLifetime, "token is not yet valid"));
    }
    Ok(())
}

fn validate_assertion_lifetime(
    claims: &AssertionClaims,
    max_ttl: i64,
    clock_skew_leeway: i64,
) -> Result<(), VerifyError> {
    let cap = max_ttl + clock_skew_leeway;
    let span = match claims.iat {
        Some(iat) => claims.exp - iat,
        _ => claims.exp - now_unix(),
    };
    if span > cap {
        return Err(VerifyError::new(
            VerifyErrorKind::InvalidLifetime,
            "assertion lifetime exceeds the allowed maximum",
        ));
    }
    Ok(())
}

fn ensure_audience_matches(
    aud: &serde_json::Value,
    expected: &[String],
) -> Result<(), VerifyError> {
    if expected.iter().any(|value| audience_matches(aud, value)) {
        return Ok(());
    }
    Err(VerifyError::new(VerifyErrorKind::InvalidAudience, "subject token audience not accepted"))
}

fn audience_matches(aud: &serde_json::Value, expected: &str) -> bool {
    match aud {
        serde_json::Value::String(value) => value == expected,
        serde_json::Value::Array(values) => {
            values.iter().any(|item| item.as_str() == Some(expected))
        }
        _ => false,
    }
}

fn subject_token_hash(subject_token: &str) -> String {
    let digest = Sha256::digest(subject_token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn map_jose_error(err: sts_jose::JoseError) -> VerifyError {
    let kind = match err.kind {
        sts_jose::JoseErrorKind::InvalidKey => VerifyErrorKind::InvalidToken,
        sts_jose::JoseErrorKind::UnsupportedAlgorithm => VerifyErrorKind::InvalidToken,
        sts_jose::JoseErrorKind::InvalidClaims => VerifyErrorKind::InvalidClaims,
        sts_jose::JoseErrorKind::VerificationFailed => VerifyErrorKind::InvalidToken,
        sts_jose::JoseErrorKind::InvalidCompactJws => VerifyErrorKind::InvalidToken,
    };
    VerifyError::new(kind, err.message)
}

fn map_verify_error(err: VerifyError) -> VerifyError {
    err
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use sts_jose::{JoseSigner, RsaJoseSigner};
    use tokio::net::TcpListener;

    fn signer() -> RsaJoseSigner {
        RsaJoseSigner::generate_for_tests("issuer-key").expect("signer")
    }

    fn subject_claims() -> sts_core::MintedClaims {
        sts_core::MintedClaims::new(
            "https://issuer.example/oauth2/default",
            "user@example.com",
            "api://obo",
            "obo.read",
            1_000,
            4_000_000_000,
            "jti-subject",
            "chat-mcp",
        )
    }

    #[derive(Debug, Clone, Serialize)]
    struct AssertionWireClaims {
        iss: String,
        sub: String,
        aud: String,
        exp: i64,
        iat: i64,
        jti: String,
        sub_tok_hash: String,
    }

    #[test]
    fn validate_issuer_accepts_https_urls() {
        assert_eq!(validate_issuer("https://issuer.example/").unwrap(), "https://issuer.example");
    }

    #[test]
    fn validate_issuer_accepts_loopback_http_urls() {
        for (raw, expected) in [
            ("http://localhost:8888/", "http://localhost:8888"),
            ("http://127.0.0.1:9000/", "http://127.0.0.1:9000"),
            ("http://[::1]:9000/", "http://[::1]:9000"),
        ] {
            assert_eq!(validate_issuer(raw).unwrap(), expected);
        }
    }

    #[test]
    fn validate_issuer_rejects_unsafe_components() {
        for raw in [
            "https://issuer.example/?q=1",
            "https://issuer.example#fragment",
            "http://issuer.example/",
        ] {
            let err = validate_issuer(raw).unwrap_err();
            assert_eq!(err.kind, VerifyErrorKind::InvalidIssuer);
        }
    }

    #[test]
    fn build_anchor_ref_requires_a_jwks_source() {
        let err =
            build_anchor_ref(TrustAnchorKind::Idp, Some("https://issuer.example/"), None, None)
                .unwrap_err();
        assert_eq!(err.kind, VerifyErrorKind::InvalidAnchor);
    }

    #[test]
    fn build_anchor_ref_accepts_https_jwks_url() {
        let anchor = build_anchor_ref(
            TrustAnchorKind::Idp,
            Some("https://issuer.example/"),
            Some("https://issuer.example/jwks"),
            None,
        )
        .unwrap();
        assert_eq!(anchor.kind, TrustAnchorKind::Idp);
        assert_eq!(anchor.jwks_url.as_deref(), Some("https://issuer.example/jwks"));
    }

    #[test]
    fn build_verification_plan_rejects_collapsed_actor_and_client_anchors() {
        let idp = build_anchor_ref(
            TrustAnchorKind::Idp,
            Some("https://issuer.example/"),
            Some("https://issuer.example/jwks"),
            None,
        )
        .unwrap();
        let actor = build_anchor_ref(
            TrustAnchorKind::Actor,
            None,
            Some("https://anchor.example/actor.jwks"),
            None,
        )
        .unwrap();
        let client = build_anchor_ref(
            TrustAnchorKind::Client,
            None,
            Some("https://anchor.example/actor.jwks"),
            None,
        )
        .unwrap();

        let err = build_verification_plan(idp, actor, client).unwrap_err();
        assert_eq!(err.kind, VerifyErrorKind::AnchorCollision);
    }

    #[test]
    fn key_binding_uses_longest_registered_identity_prefix() {
        let registry =
            BTreeSet::from(["svc".to_string(), "svc-staging".to_string(), "chat-mcp".to_string()]);
        assert!(kid_belongs_to_claimed_identity("svc-key-1", "svc", &registry));
        assert!(kid_belongs_to_claimed_identity("svc-staging-key-1", "svc-staging", &registry));
        assert!(!kid_belongs_to_claimed_identity("svc-staging-key-1", "svc", &registry));
        assert!(!kid_belongs_to_claimed_identity("other-client-key-1", "chat-mcp", &registry));
    }

    #[tokio::test]
    async fn discovery_fetches_jwks_uri_from_local_server() {
        let app = axum::Router::new().route(
            "/.well-known/openid-configuration",
            axum::routing::get(|| async {
                axum::Json(DiscoveryDocument {
                    issuer: "https://issuer.example/oauth2/default".to_string(),
                    jwks_uri: "https://issuer.example/oauth2/default/jwks".to_string(),
                })
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        let client = Client::new();
        let doc = discover_document(&client, &format!("http://{}", addr))
            .await
            .expect("loopback discovery should be allowed for local development");
        assert_eq!(doc.jwks_uri, "https://issuer.example/oauth2/default/jwks");
    }

    #[test]
    fn subject_token_verification_round_trips_against_jwks() {
        let signer = signer();
        let token = signer.sign_claims(&subject_claims()).expect("sign");
        let claims = verify_subject_token(
            &token,
            &signer.public_jwks(),
            "https://issuer.example/oauth2/default",
            &[String::from("api://obo")],
            30,
        )
        .unwrap();
        assert_eq!(claims.iss, "https://issuer.example/oauth2/default");
        assert_eq!(claims.sub.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn assertion_verification_requires_subject_binding() {
        let signer = signer();
        let issued_at = now_unix();
        let token = signer
            .sign_json_claims(&AssertionWireClaims {
                iss: "chat-mcp".to_string(),
                sub: "chat-mcp".to_string(),
                aud: "https://sts.example/".to_string(),
                exp: issued_at + 600,
                iat: issued_at,
                jti: "jti-1".to_string(),
                sub_tok_hash: subject_token_hash("subject-token"),
            })
            .expect("sign");
        let claims = verify_assertion(
            &token,
            &signer.public_jwks(),
            AssertionVerificationOptions {
                expected_issuer: "https://sts.example/",
                expected_audiences: &[
                    "https://sts.example/".to_string(),
                    "https://sts.example/token".to_string(),
                ],
                clock_skew_leeway: 30,
                max_ttl: 3600,
                binding_subject_token: Some("subject-token"),
                require_subject_binding: true,
                key_binding_registry: None,
            },
        )
        .unwrap();
        assert_eq!(claims.sub, "chat-mcp");
        assert!(claims.sub_tok_hash.is_some());
    }

    #[test]
    fn rfc7523_assertion_audience_is_always_validated() {
        let signer = signer();
        let issued_at = now_unix();
        let token = signer
            .sign_json_claims(&AssertionWireClaims {
                iss: "https://sts.example".to_string(),
                sub: "https://sts.example".to_string(),
                aud: "https://attacker.example/token".to_string(),
                exp: issued_at + 600,
                iat: issued_at,
                jti: "jti-audience-bypass".to_string(),
                sub_tok_hash: subject_token_hash("subject-token"),
            })
            .expect("sign");

        let err = match verify_assertion(
            &token,
            &signer.public_jwks(),
            AssertionVerificationOptions {
                expected_issuer: "https://sts.example/",
                expected_audiences: &[
                    "https://sts.example".to_string(),
                    "https://sts.example/token".to_string(),
                ],
                clock_skew_leeway: 30,
                max_ttl: 3600,
                binding_subject_token: Some("subject-token"),
                require_subject_binding: true,
                key_binding_registry: None,
            },
        ) {
            Ok(_) => panic!("assertion with wrong audience was accepted"),
            Err(err) => err,
        };
        assert_eq!(err.kind, VerifyErrorKind::InvalidAudience);
    }
}
