#![forbid(unsafe_code)]

//! Trust-anchor and token-verification policy crate for `sts-delegate-rs`.
//!
//! This crate owns the side-effect-free trust configuration boundary:
//! issuer discovery policy, JWKS source validation, and the separation between
//! IdP, actor, and client anchors.

use std::fmt;

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
}

impl fmt::Display for VerifyErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::InvalidIssuer => "invalid_issuer",
            Self::InvalidUrl => "invalid_url",
            Self::InvalidAnchor => "invalid_anchor",
            Self::AnchorCollision => "anchor_collision",
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

/// Validate an issuer value without making network calls.
pub fn validate_issuer(value: &str) -> Result<String, VerifyError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(VerifyError::new(VerifyErrorKind::InvalidIssuer, "issuer must not be empty"));
    }
    if !trimmed.starts_with("https://") {
        return Err(VerifyError::new(VerifyErrorKind::InvalidIssuer, "issuer must use https://"));
    }
    if trimmed.contains('#') {
        return Err(VerifyError::new(
            VerifyErrorKind::InvalidIssuer,
            "issuer must not contain a fragment",
        ));
    }
    Ok(trimmed.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_issuer_accepts_https_urls() {
        assert_eq!(validate_issuer("https://issuer.example/").unwrap(), "https://issuer.example/");
    }

    #[test]
    fn validate_issuer_rejects_plain_http() {
        let err = validate_issuer("http://issuer.example/").unwrap_err();
        assert_eq!(err.kind, VerifyErrorKind::InvalidIssuer);
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
}
