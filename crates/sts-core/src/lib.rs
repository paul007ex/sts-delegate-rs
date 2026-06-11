#![forbid(unsafe_code)]

//! Core token-exchange policy and claim-shaping crate for `sts-delegate-rs`.
//!
//! This crate owns the stable, protocol-facing semantics that the current Python
//! implementation already proves through contract tests.

use std::fmt;

/// The token-exchange grant type URN.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// RFC 8693 access-token type URN.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// RFC 8693 JWT token type URN.
pub const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";

/// The minimum public contract shape for a token-exchange request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActClaim {
    pub sub: String,
    pub iss: Option<String>,
    pub act: Option<Box<ActClaim>>,
}

/// The minted claim contract the STS must preserve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub scope: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub client_id: String,
    pub act: Option<ActClaim>,
    pub cnf_jkt: Option<String>,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
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
pub fn build_act(actor_sub: impl Into<String>, prior_act: Option<ActClaim>) -> ActClaim {
    ActClaim { sub: actor_sub.into(), iss: None, act: prior_act.map(Box::new) }
}

/// Build the minted payload while preserving the contract shape.
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
        let value = serde_json::to_value(&payload_to_json(&payload)).unwrap();
        assert_eq!(value["sub"], "user@example.com");
        assert_eq!(value["act"]["sub"], "chat-mcp");
        assert_eq!(value["client_id"], "chat-mcp");
        assert_eq!(value["cnf"]["jkt"], "thumbprint");
    }

    fn payload_to_json(payload: &MintedClaims) -> serde_json::Value {
        let act = payload.act.as_ref().map(|act| act_to_json(act));
        serde_json::json!({
            "iss": payload.iss,
            "sub": payload.sub,
            "aud": payload.aud,
            "scope": payload.scope,
            "iat": payload.iat,
            "exp": payload.exp,
            "jti": payload.jti,
            "client_id": payload.client_id,
            "act": act,
            "cnf": payload.cnf_jkt.as_ref().map(|jkt| serde_json::json!({ "jkt": jkt })),
        })
    }

    fn act_to_json(act: &ActClaim) -> serde_json::Value {
        serde_json::json!({
            "sub": act.sub,
            "iss": act.iss,
            "act": act.act.as_deref().map(act_to_json),
        })
    }
}
