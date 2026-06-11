#![forbid(unsafe_code)]

//! Core token-exchange policy and claim-shaping crate for `sts-delegate-rs`.
//!
//! This crate owns the stable, protocol-facing semantics that the current Python
//! implementation already proves through contract tests.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The token-exchange grant type URN.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// RFC 8693 access-token type URN.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// RFC 8693 JWT token type URN.
pub const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";

/// The minimum public contract shape for a token-exchange request.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExchangeRequest {
    pub grant_type: String,
    pub subject_token: String,
    pub subject_token_type: String,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
    pub scope: Option<String>,
    pub requested_token_type: Option<String>,
    pub client_id: Option<String>,
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
}

/// The delegation marker that rides inside a minted token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActClaim {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActClaim>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConfirmationClaim {
    jkt: String,
}

/// The minted claim contract the STS must preserve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintedClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub scope: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<ActClaim>,
    #[serde(
        default,
        rename = "cnf",
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_cnf_jkt",
        deserialize_with = "deserialize_cnf_jkt"
    )]
    pub cnf_jkt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
}

impl MintedClaims {
    /// Build the minimal contract-bearing payload for a scoped token.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        iss: impl Into<String>,
        sub: impl Into<String>,
        aud: impl Into<String>,
        scope: impl Into<String>,
        iat: i64,
        exp: i64,
        jti: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Self {
        Self {
            iss: iss.into(),
            sub: sub.into(),
            aud: aud.into(),
            scope: scope.into(),
            iat,
            exp,
            jti: jti.into(),
            client_id: client_id.into(),
            act: None,
            cnf_jkt: None,
            auth_time: None,
            acr: None,
            amr: Vec::new(),
        }
    }
}

/// Failure categories that the Rust port must keep stable at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreErrorKind {
    InvalidRequest,
    InvalidClient,
    InvalidTarget,
    InvalidScope,
}

impl fmt::Display for CoreErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidScope => "invalid_scope",
        };
        f.write_str(code)
    }
}

/// Core error with a stable OAuth error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreError {
    pub kind: CoreErrorKind,
    pub message: String,
}

impl CoreError {
    pub fn new(kind: CoreErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for CoreError {}

/// Resolve the target audience from `audience` / `resource`.
///
/// RFC 8693 defines both `audience` and `resource` as request inputs. This
/// function is the local normalization gate: it accepts either parameter and,
/// when both are present, requires them to agree so the token is minted for one
/// downstream target only.
pub fn resolve_target(audience: Option<&str>, resource: Option<&str>) -> Result<String, CoreError> {
    match (audience, resource) {
        (Some(aud), None) => validate_target_value(aud),
        (None, Some(res)) => validate_resource_value(res),
        (Some(aud), Some(res)) => {
            let aud = validate_target_value(aud)?;
            let res = validate_resource_value(res)?;
            if aud == res {
                Ok(aud)
            } else {
                Err(CoreError::new(
                    CoreErrorKind::InvalidTarget,
                    "audience and resource must agree when both are present",
                ))
            }
        }
        (None, None) => {
            Err(CoreError::new(CoreErrorKind::InvalidTarget, "no target audience supplied"))
        }
    }
}

/// Downscope a requested scope against target and subject limits.
///
/// This is local authorization-policy logic layered on top of RFC 8693 token
/// exchange. The RFC defines token exchange and its delegation semantics; this
/// crate keeps the issued scope no broader than the deployment allowlist and any
/// subject-scoped bound that the caller enabled.
pub fn downscope(
    requested: Option<&str>,
    target_allowed: &str,
    subject_scopes: Option<&str>,
    subject_scope_bound_required: bool,
) -> Result<String, CoreError> {
    let requested = split_scopes(requested);
    let target_allowed = split_scopes(Some(target_allowed));
    let mut result = intersect_scopes(&requested, &target_allowed);

    if let Some(subject) = subject_scopes {
        let subject_scopes = split_scopes(Some(subject));
        let subject_intersection = intersect_scopes(&result, &subject_scopes);
        if subject_scope_bound_required || !subject_scopes.is_empty() {
            result = subject_intersection;
        }
    }

    if result.is_empty() {
        return Err(CoreError::new(
            CoreErrorKind::InvalidScope,
            "no scopes remain after downscoping",
        ));
    }

    Ok(join_scopes(&result))
}

/// Build the RFC 8693 `act` claim.
///
/// RFC 8693 §4.1 defines `act` as the actor claim used to express delegation.
/// The nested shape preserves prior actors when the caller is already acting
/// through another actor.
pub fn build_act(actor_sub: impl Into<String>, prior_act: Option<ActClaim>) -> ActClaim {
    ActClaim { sub: actor_sub.into(), iss: None, act: prior_act.map(Box::new) }
}

/// Build the minted payload while preserving the contract shape.
///
/// The top-level claim set follows the JWT access-token profile (RFC 9068) and
/// the token-exchange actor/client fields from RFC 8693 §4.3. The `cnf_jkt`
/// field is the local sender-constraining hook used by the DPoP lane.
#[allow(clippy::too_many_arguments)]
pub fn build_scoped_payload(
    iss: impl Into<String>,
    sub: impl Into<String>,
    aud: impl Into<String>,
    scope: impl Into<String>,
    iat: i64,
    exp: i64,
    jti: impl Into<String>,
    client_id: impl Into<String>,
    act: Option<ActClaim>,
    cnf_jkt: Option<String>,
) -> MintedClaims {
    MintedClaims {
        iss: iss.into(),
        sub: sub.into(),
        aud: aud.into(),
        scope: scope.into(),
        iat,
        exp,
        jti: jti.into(),
        client_id: client_id.into(),
        act,
        cnf_jkt,
        auth_time: None,
        acr: None,
        amr: Vec::new(),
    }
}

fn serialize_cnf_jkt<S>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    value.as_ref().map(|jkt| ConfirmationClaim { jkt: jkt.clone() }).serialize(serializer)
}

fn deserialize_cnf_jkt<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<ConfirmationClaim>::deserialize(deserializer).map(|cnf| cnf.map(|value| value.jkt))
}

fn validate_target_value(value: &str) -> Result<String, CoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CoreError::new(CoreErrorKind::InvalidTarget, "target must not be empty"));
    }
    Ok(trimmed.to_string())
}

fn validate_resource_value(value: &str) -> Result<String, CoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CoreError::new(CoreErrorKind::InvalidTarget, "resource must not be empty"));
    }
    if !trimmed.contains("://") || trimmed.starts_with('/') {
        return Err(CoreError::new(
            CoreErrorKind::InvalidTarget,
            "resource must be an absolute URI",
        ));
    }
    if trimmed.contains('#') {
        return Err(CoreError::new(
            CoreErrorKind::InvalidTarget,
            "resource must not contain a fragment",
        ));
    }
    Ok(trimmed.to_string())
}

fn split_scopes(input: Option<&str>) -> Vec<String> {
    input
        .unwrap_or("")
        .split_whitespace()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect()
}

fn intersect_scopes(left: &[String], right: &[String]) -> Vec<String> {
    left.iter().filter(|scope| right.iter().any(|candidate| candidate == *scope)).cloned().collect()
}

fn join_scopes(scopes: &[String]) -> String {
    scopes.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_target_accepts_matching_audience_and_resource() {
        assert_eq!(
            resolve_target(Some("api://chat-mcp"), Some("api://chat-mcp")).unwrap(),
            "api://chat-mcp"
        );
    }

    #[test]
    fn resolve_target_rejects_mismatched_audience_and_resource() {
        let err = resolve_target(Some("api://chat-mcp"), Some("api://other")).unwrap_err();
        assert_eq!(err.kind, CoreErrorKind::InvalidTarget);
    }

    #[test]
    fn resolve_target_rejects_relative_resource() {
        let err = resolve_target(None, Some("logical-name")).unwrap_err();
        assert_eq!(err.kind, CoreErrorKind::InvalidTarget);
    }

    #[test]
    fn downscope_intersects_requested_target_and_subject() {
        let out = downscope(
            Some("chat.read chat.write"),
            "chat.read chat.admin",
            Some("chat.read profile"),
            false,
        )
        .unwrap();
        assert_eq!(out, "chat.read");
    }

    #[test]
    fn downscope_requires_some_scope_to_remain() {
        let err = downscope(Some("chat.write"), "chat.read", None, false).unwrap_err();
        assert_eq!(err.kind, CoreErrorKind::InvalidScope);
    }

    #[test]
    fn build_act_nests_prior_chain() {
        let prior = build_act("gateway", None);
        let act = build_act("agent", Some(prior));
        assert_eq!(act.sub, "agent");
        assert_eq!(act.act.as_ref().unwrap().sub, "gateway");
    }

    #[test]
    fn payload_serializes_as_expected_shape() {
        let payload = build_scoped_payload(
            "https://sts.example/",
            "user@example.com",
            "api://chat-mcp",
            "chat.read",
            1,
            2,
            "jti-1",
            "chat-mcp",
            Some(build_act("chat-mcp", None)),
            Some("thumbprint".to_string()),
        );
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(value["sub"], "user@example.com");
        assert_eq!(value["act"]["sub"], "chat-mcp");
        assert!(value["act"].get("iss").is_none());
        assert!(value["act"].get("act").is_none());
        assert_eq!(value["client_id"], "chat-mcp");
        assert_eq!(value["cnf"]["jkt"], "thumbprint");
    }

    #[test]
    fn payload_omits_absent_optional_claims() {
        let payload = build_scoped_payload(
            "https://sts.example/",
            "user@example.com",
            "api://chat-mcp",
            "chat.read",
            1,
            2,
            "jti-1",
            "chat-mcp",
            None,
            None,
        );
        let value = serde_json::to_value(&payload).unwrap();
        assert!(value.get("act").is_none());
        assert!(value.get("cnf").is_none());
        assert!(value.get("auth_time").is_none());
        assert!(value.get("acr").is_none());
        assert!(value.get("amr").is_none());
    }

    #[test]
    fn payload_deserializes_cnf_jkt_wire_shape() {
        let value = serde_json::json!({
            "iss": "https://sts.example/",
            "sub": "user@example.com",
            "aud": "api://chat-mcp",
            "scope": "chat.read",
            "iat": 1,
            "exp": 2,
            "jti": "jti-1",
            "client_id": "chat-mcp",
            "cnf": { "jkt": "thumbprint" }
        });
        let claims: MintedClaims = serde_json::from_value(value).unwrap();
        assert_eq!(claims.cnf_jkt.as_deref(), Some("thumbprint"));
    }
}
