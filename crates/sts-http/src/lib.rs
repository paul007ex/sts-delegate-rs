#![forbid(unsafe_code)]

//! HTTP surface for `sts-delegate-rs`.
//!
//! This crate owns route names, response headers, form parsing, and OAuth-shaped
//! error rendering. Token policy, verification, replay, and signing remain in
//! their owning crates.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, HeaderName, HeaderValue, PRAGMA, WWW_AUTHENTICATE,
};
use http::{HeaderMap, StatusCode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sts_config::{ClientAuthPolicy, RuntimeConfig, TokenExchangeMode};
use sts_core::{
    ACCESS_TOKEN_TYPE, ActClaim, ExchangeRequest, JWT_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE,
    build_act, build_scoped_payload, downscope, resolve_target,
};
use sts_dpop::{
    DPOP_SIGNING_ALGS_SUPPORTED, DpopBinding, DpopError, DpopProofRequest, validate_dpop_proof,
};
use sts_jose::{JoseSigner, JwksDocument, RsaJoseSigner};
use sts_replay::{ReplayErrorKind, ReplayPolicy, dpop_replay_key};
use sts_verify::{
    AssertionClaims, AssertionVerificationOptions, SubjectTokenClaims, VerifyError,
    VerifyErrorKind, verify_assertion, verify_subject_token,
};
use url::Url;

const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
const DPOP_HEADER: HeaderName = HeaderName::from_static("dpop");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectiveExchangeMode {
    Delegation,
    Impersonation,
}

struct VerifiedExchange {
    subject_claims: SubjectTokenClaims,
    subject_sub: String,
    target: String,
    scope: String,
    client_claims: Option<AssertionClaims>,
    dpop_binding: Option<DpopBinding>,
}

/// Shared HTTP runtime state.
#[derive(Clone)]
pub struct HttpState {
    pub config: RuntimeConfig,
    pub signer: RsaJoseSigner,
    pub subject_jwks: JwksDocument,
    pub actor_jwks: JwksDocument,
    pub client_jwks: JwksDocument,
    pub replay: Arc<ReplayPolicy>,
}

impl HttpState {
    pub fn new(
        config: RuntimeConfig,
        signer: RsaJoseSigner,
        subject_jwks: JwksDocument,
        actor_jwks: JwksDocument,
        client_jwks: JwksDocument,
        replay: ReplayPolicy,
    ) -> Self {
        Self { config, signer, subject_jwks, actor_jwks, client_jwks, replay: Arc::new(replay) }
    }

    fn token_endpoint(&self) -> String {
        format!("{}/token", self.config.our_issuer.trim_end_matches('/'))
    }

    fn jwks_uri(&self) -> String {
        format!("{}/jwks", self.config.our_issuer.trim_end_matches('/'))
    }

    fn issuer_path(&self) -> Option<String> {
        let parsed = Url::parse(&self.config.our_issuer).ok()?;
        let path = parsed.path().trim_end_matches('/');
        (!path.is_empty()).then(|| path.to_string())
    }
}

/// Build the Axum router for the public STS endpoints.
///
/// RFC 8414 metadata, RFC 8693 token exchange, and JWKS publication are exposed
/// here; the route handlers call lower crates for policy, verification, replay,
/// and signing instead of reimplementing those rules in transport.
pub fn router(state: HttpState) -> Router {
    let mut app = Router::new()
        .route("/token", post(token))
        .route("/jwks", get(jwks))
        .route("/.well-known/oauth-authorization-server", get(metadata));

    if let Some(path) = state.issuer_path() {
        app = app
            .route(&format!("{path}/token"), post(token))
            .route(&format!("{path}/jwks"), get(jwks))
            .route(&format!("/.well-known/oauth-authorization-server{path}"), get(metadata));
    }

    app.with_state(state)
}

/// RFC 8414 authorization-server metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    pub dpop_signing_alg_values_supported: Vec<String>,
}

/// OAuth token response for RFC 8693 token exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub issued_token_type: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct TokenForm {
    grant_type: Option<String>,
    subject_token: Option<String>,
    subject_token_type: Option<String>,
    actor_token: Option<String>,
    actor_token_type: Option<String>,
    audience: Option<String>,
    resource: Option<String>,
    scope: Option<String>,
    requested_token_type: Option<String>,
    client_id: Option<String>,
    client_assertion: Option<String>,
    client_assertion_type: Option<String>,
}

impl TokenForm {
    fn into_exchange_request(self) -> ExchangeRequest {
        ExchangeRequest {
            grant_type: self.grant_type.unwrap_or_default(),
            subject_token: self.subject_token.unwrap_or_default(),
            subject_token_type: self.subject_token_type.unwrap_or_default(),
            actor_token: self.actor_token,
            actor_token_type: self.actor_token_type,
            audience: self.audience,
            resource: self.resource,
            scope: self.scope,
            requested_token_type: self.requested_token_type,
            client_id: self.client_id,
            client_assertion: self.client_assertion,
            client_assertion_type: self.client_assertion_type,
        }
    }
}

/// OAuth-shaped HTTP error rendered at the transport boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError {
    status: StatusCode,
    error: Option<&'static str>,
    description: String,
    retry_after: Option<&'static str>,
    www_authenticate: Option<String>,
}

impl HttpError {
    fn oauth(status: StatusCode, error: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            error: Some(error),
            description: description.into(),
            retry_after: None,
            www_authenticate: None,
        }
    }

    fn invalid_request(description: impl Into<String>) -> Self {
        Self::oauth(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    fn invalid_client(description: impl Into<String>) -> Self {
        Self::oauth(StatusCode::UNAUTHORIZED, "invalid_client", description)
    }

    fn unsupported_authorization_client_auth(
        description: impl Into<String>,
        challenge: &str,
    ) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: Some("invalid_client"),
            description: description.into(),
            retry_after: None,
            www_authenticate: Some(challenge.to_string()),
        }
    }

    fn invalid_target(description: impl Into<String>) -> Self {
        Self::oauth(StatusCode::BAD_REQUEST, "invalid_target", description)
    }

    fn invalid_scope(description: impl Into<String>) -> Self {
        Self::oauth(StatusCode::BAD_REQUEST, "invalid_scope", description)
    }

    fn invalid_grant(description: impl Into<String>) -> Self {
        Self::oauth(StatusCode::BAD_REQUEST, "invalid_grant", description)
    }

    fn unsupported_grant_type(description: impl Into<String>) -> Self {
        Self::oauth(StatusCode::BAD_REQUEST, "unsupported_grant_type", description)
    }

    fn invalid_dpop_proof(description: impl Into<String>) -> Self {
        Self::oauth(StatusCode::BAD_REQUEST, "invalid_dpop_proof", description)
    }

    fn service_unavailable(description: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            error: None,
            description: description.into(),
            retry_after: Some("2"),
            www_authenticate: None,
        }
    }

    fn server_error(description: impl Into<String>) -> Self {
        Self::oauth(StatusCode::INTERNAL_SERVER_ERROR, "server_error", description)
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = self.error {
            write!(f, "{}: {}", error, self.description)
        } else {
            f.write_str(&self.description)
        }
    }
}

impl std::error::Error for HttpError {}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
        if let Some(retry_after) = self.retry_after {
            headers.insert("retry-after", HeaderValue::from_static(retry_after));
        }
        if let Some(challenge) = self.www_authenticate
            && let Ok(value) = HeaderValue::from_str(&challenge)
        {
            headers.insert(WWW_AUTHENTICATE, value);
        }
        let body = match self.error {
            Some(error) => serde_json::json!({
                "error": error,
                "error_description": self.description,
            }),
            None => serde_json::json!({
                "error_description": self.description,
            }),
        };
        (self.status, headers, Json(body)).into_response()
    }
}

async fn jwks(State(state): State<HttpState>) -> impl IntoResponse {
    (public_cache_headers(state.config.jwks_cache_max_age), Json(state.signer.public_jwks()))
}

async fn metadata(State(state): State<HttpState>) -> impl IntoResponse {
    let document = AuthorizationServerMetadata {
        issuer: state.config.our_issuer.clone(),
        token_endpoint: state.token_endpoint(),
        jwks_uri: state.jwks_uri(),
        response_types_supported: Vec::new(),
        grant_types_supported: vec![TOKEN_EXCHANGE_GRANT_TYPE.to_string()],
        token_endpoint_auth_methods_supported: vec!["private_key_jwt".to_string()],
        token_endpoint_auth_signing_alg_values_supported: vec!["RS256".to_string()],
        dpop_signing_alg_values_supported: DPOP_SIGNING_ALGS_SUPPORTED
            .iter()
            .map(|alg| (*alg).to_string())
            .collect(),
    };
    (public_cache_headers(state.config.jwks_cache_max_age), Json(document))
}

fn parse_token_form(headers: &HeaderMap, body: &[u8]) -> Result<TokenForm, HttpError> {
    require_form_urlencoded(headers)?;
    reject_authorization_header_client_auth(headers)?;
    let pairs = url::form_urlencoded::parse(body).into_owned().collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut form = TokenForm::default();
    for (key, value) in pairs {
        if !seen.insert(key.clone()) {
            if matches!(key.as_str(), "audience" | "resource") {
                return Err(HttpError::invalid_target(format!(
                    "multiple {key} values are not supported; send one target"
                )));
            }
            return Err(HttpError::invalid_request(format!(
                "parameter {key:?} is included more than once"
            )));
        }
        assign_token_form_value(&mut form, &key, value);
    }
    Ok(form)
}

fn require_form_urlencoded(headers: &HeaderMap) -> Result<(), HttpError> {
    let content_type =
        headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok()).unwrap_or("");
    let media_type = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if media_type != "application/x-www-form-urlencoded" {
        return Err(HttpError::invalid_request(
            "Content-Type must be application/x-www-form-urlencoded",
        ));
    }
    Ok(())
}

fn reject_authorization_header_client_auth(headers: &HeaderMap) -> Result<(), HttpError> {
    let Some(value) = headers.get(AUTHORIZATION) else {
        return Ok(());
    };
    let authorization = value.to_str().unwrap_or("");
    let scheme = authorization.split_whitespace().next().unwrap_or("Basic");
    let challenge = if scheme.eq_ignore_ascii_case("basic") { "Basic" } else { scheme };
    Err(HttpError::unsupported_authorization_client_auth(
        "Authorization header client authentication is not supported; use private_key_jwt",
        challenge,
    ))
}

fn assign_token_form_value(form: &mut TokenForm, key: &str, value: String) {
    match key {
        "grant_type" => form.grant_type = Some(value),
        "subject_token" => form.subject_token = Some(value),
        "subject_token_type" => form.subject_token_type = Some(value),
        "actor_token" => form.actor_token = Some(value),
        "actor_token_type" => form.actor_token_type = Some(value),
        "audience" => form.audience = Some(value),
        "resource" => form.resource = Some(value),
        "scope" => form.scope = Some(value),
        "requested_token_type" => form.requested_token_type = Some(value),
        "client_id" => form.client_id = Some(value),
        "client_assertion" => form.client_assertion = Some(value),
        "client_assertion_type" => form.client_assertion_type = Some(value),
        _ => {}
    }
}

async fn token(
    headers: HeaderMap,
    State(state): State<HttpState>,
    body: Bytes,
) -> Result<(HeaderMap, Json<TokenResponse>), HttpError> {
    let form = parse_token_form(&headers, &body)?;
    let request = form.into_exchange_request();
    validate_request_params(&request, state.config.max_token_len)?;
    let mode = effective_exchange_mode(&state.config, &request);
    let client_claims = authenticate_client_if_present(&state, &request, mode)?;
    let dpop_binding = validate_dpop_header(&headers, &state, unix_now())?;

    let expected_subject_audiences =
        state.config.expected_subject_aud.iter().cloned().collect::<Vec<_>>();
    let subject_claims = verify_subject_token(
        &request.subject_token,
        &state.subject_jwks,
        &state.config.idp_issuer,
        &expected_subject_audiences,
        state.config.clock_skew_leeway,
    )
    .map_err(|err| map_subject_verify_error(&err))?;

    let target = resolve_target_for_request(&request, &state)?;
    let scope = resolve_scope_for_request(&request, &state, &subject_claims, &target)?;
    let subject_sub = subject_claims
        .sub
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| HttpError::invalid_grant("subject token missing sub"))?;
    let exchange = VerifiedExchange {
        subject_claims,
        subject_sub,
        target,
        scope,
        client_claims,
        dpop_binding,
    };

    match mode {
        EffectiveExchangeMode::Delegation => exchange_delegation(state, request, exchange),
        EffectiveExchangeMode::Impersonation => exchange_impersonation(state, request, exchange),
    }
}

fn exchange_delegation(
    state: HttpState,
    request: ExchangeRequest,
    exchange: VerifiedExchange,
) -> Result<(HeaderMap, Json<TokenResponse>), HttpError> {
    let client_authenticated = exchange.client_claims.is_some();
    let actor_token = request.actor_token.as_deref().ok_or_else(|| {
        if client_authenticated {
            HttpError::invalid_request("actor_token required for delegation")
        } else {
            HttpError::invalid_client(
                "no client authentication: send a client_assertion or an actor_token",
            )
        }
    })?;
    let actor_claims = verify_actor_token(&state, actor_token, &request.subject_token)?;
    validate_actor_identity(&state, &actor_claims)?;
    gate_may_act(&exchange.subject_claims, &actor_claims)?;

    let now = unix_now();
    let actor_jti =
        actor_claims.jti.as_deref().filter(|value| !value.trim().is_empty()).ok_or_else(|| {
            HttpError::invalid_client("actor_token jti must be a non-empty string")
        })?;
    state
        .replay
        .check_and_record(&format!("act:{}:{actor_jti}", actor_claims.sub), actor_claims.exp, now)
        .map_err(map_replay_error)?;
    if let Some(client_claims) = &exchange.client_claims {
        record_client_assertion_replay(&state, client_claims, now)?;
    }
    if let Some(binding) = &exchange.dpop_binding {
        record_dpop_replay(&state, binding, now)?;
    }

    let exp = [now + state.config.scoped_token_ttl, exchange.subject_claims.exp, actor_claims.exp]
        .into_iter()
        .min()
        .unwrap_or(now + state.config.scoped_token_ttl);
    let prior_act = exchange.subject_claims.act.as_ref().map(act_claim_from_value).transpose()?;
    let act = build_act(actor_claims.sub.clone(), prior_act);
    let mut payload = build_scoped_payload(
        state.config.our_issuer.clone(),
        exchange.subject_sub,
        exchange.target,
        exchange.scope.clone(),
        now,
        exp,
        new_jti(),
        actor_claims.sub.clone(),
        Some(act),
        exchange.dpop_binding.as_ref().map(|binding| binding.jkt.clone()),
    );
    payload.auth_time = exchange.subject_claims.auth_time;
    payload.acr = exchange.subject_claims.acr.clone();
    payload.amr = exchange.subject_claims.amr.clone().unwrap_or_default();

    let access_token = state.signer.sign_claims(&payload).map_err(|err| {
        HttpError::server_error(format!("failed to sign scoped token: {}", err.message))
    })?;

    Ok((
        token_headers(),
        Json(TokenResponse {
            access_token,
            issued_token_type: ACCESS_TOKEN_TYPE.to_string(),
            token_type: token_type_for_sender(&exchange.dpop_binding).to_string(),
            expires_in: (exp - now).max(0),
            scope: exchange.scope,
        }),
    ))
}

fn exchange_impersonation(
    state: HttpState,
    request: ExchangeRequest,
    exchange: VerifiedExchange,
) -> Result<(HeaderMap, Json<TokenResponse>), HttpError> {
    if request.actor_token.is_some() {
        return Err(HttpError::invalid_client(
            "impersonation requires client_assertion, not actor_token",
        ));
    }
    let client_claims = exchange
        .client_claims
        .ok_or_else(|| HttpError::invalid_client("impersonation requires client_assertion"))?;
    let Some(policy_entry) = state.config.impersonation_policy.clients.get(&client_claims.sub)
    else {
        return Err(HttpError::invalid_request(format!(
            "impersonation not authorized for client {:?}",
            client_claims.sub
        )));
    };
    if !policy_entry.targets.allows(&exchange.target) {
        return Err(HttpError::invalid_target(format!(
            "impersonation to {:?} not authorized for client {:?}",
            exchange.target, client_claims.sub
        )));
    }
    if !policy_entry.subjects.allows(&exchange.subject_sub) {
        return Err(HttpError::invalid_request(format!(
            "impersonation of subject {:?} not authorized for client {:?}",
            exchange.subject_sub, client_claims.sub
        )));
    }

    let now = unix_now();
    record_client_assertion_replay(&state, &client_claims, now)?;
    if let Some(binding) = &exchange.dpop_binding {
        record_dpop_replay(&state, binding, now)?;
    }
    let exp = [now + state.config.scoped_token_ttl, exchange.subject_claims.exp, client_claims.exp]
        .into_iter()
        .min()
        .unwrap_or(now + state.config.scoped_token_ttl);
    let mut payload = build_scoped_payload(
        state.config.our_issuer.clone(),
        exchange.subject_sub,
        exchange.target,
        exchange.scope.clone(),
        now,
        exp,
        new_jti(),
        client_claims.sub.clone(),
        None,
        exchange.dpop_binding.as_ref().map(|binding| binding.jkt.clone()),
    );
    payload.auth_time = exchange.subject_claims.auth_time;
    payload.acr = exchange.subject_claims.acr.clone();
    payload.amr = exchange.subject_claims.amr.clone().unwrap_or_default();

    let access_token = state.signer.sign_claims(&payload).map_err(|err| {
        HttpError::server_error(format!("failed to sign scoped token: {}", err.message))
    })?;

    Ok((
        token_headers(),
        Json(TokenResponse {
            access_token,
            issued_token_type: ACCESS_TOKEN_TYPE.to_string(),
            token_type: token_type_for_sender(&exchange.dpop_binding).to_string(),
            expires_in: (exp - now).max(0),
            scope: exchange.scope,
        }),
    ))
}

fn validate_dpop_header(
    headers: &HeaderMap,
    state: &HttpState,
    now: i64,
) -> Result<Option<DpopBinding>, HttpError> {
    let mut proofs = headers.get_all(&DPOP_HEADER).iter();
    let Some(proof) = proofs.next() else {
        return Ok(None);
    };
    if proofs.next().is_some() {
        return Err(HttpError::invalid_dpop_proof("multiple DPoP header fields are not allowed"));
    }
    let proof = proof
        .to_str()
        .map_err(|_| HttpError::invalid_dpop_proof("DPoP proof missing or not a string"))?;
    validate_dpop_proof(DpopProofRequest {
        proof,
        htm: "POST",
        htu: &state.token_endpoint(),
        now,
        clock_skew_leeway: state.config.clock_skew_leeway,
    })
    .map(Some)
    .map_err(map_dpop_error)
}

fn record_dpop_replay(state: &HttpState, binding: &DpopBinding, now: i64) -> Result<(), HttpError> {
    state
        .replay
        .check_and_record(
            &dpop_replay_key(&binding.jkt, &binding.jti),
            binding.replay_expires_at,
            now,
        )
        .map_err(map_dpop_replay_error)
}

fn token_type_for_sender(binding: &Option<DpopBinding>) -> &'static str {
    if binding.is_some() { "DPoP" } else { "Bearer" }
}

/// Resolve RFC 8693 delegation versus impersonation before caller authentication.
///
/// In `Both`, request shape is the dispatch signal: an `actor_token` selects
/// delegation, and its absence selects the private_key_jwt impersonation path.
fn effective_exchange_mode(
    config: &RuntimeConfig,
    request: &ExchangeRequest,
) -> EffectiveExchangeMode {
    match config.token_exchange_mode {
        TokenExchangeMode::Delegation => EffectiveExchangeMode::Delegation,
        TokenExchangeMode::Impersonation => EffectiveExchangeMode::Impersonation,
        TokenExchangeMode::Both => {
            if request.actor_token.is_some() {
                EffectiveExchangeMode::Delegation
            } else {
                EffectiveExchangeMode::Impersonation
            }
        }
    }
}

/// Validate RFC 7523 private_key_jwt when any client-auth parameter is present.
///
/// This is intentionally stateless. Replay recording happens only after subject,
/// target, scope, actor/impersonation, and signing preconditions all pass.
fn authenticate_client_if_present(
    state: &HttpState,
    request: &ExchangeRequest,
    mode: EffectiveExchangeMode,
) -> Result<Option<AssertionClaims>, HttpError> {
    let has_client_auth = request.client_assertion.is_some()
        || request.client_assertion_type.is_some()
        || request.client_id.is_some();

    if mode == EffectiveExchangeMode::Impersonation {
        if request.actor_token.is_some() {
            return Err(HttpError::invalid_client(
                "impersonation requires client_assertion, not actor_token",
            ));
        }
        if !has_client_auth {
            return Err(HttpError::invalid_client("impersonation requires client_assertion"));
        }
    }

    if matches!(state.config.client_auth_policy, ClientAuthPolicy::PrivateKeyJwtRequired)
        && !has_client_auth
    {
        return Err(HttpError::invalid_client("client_assertion required by CLIENT_AUTH_POLICY"));
    }
    if !has_client_auth {
        return Ok(None);
    }

    for (field, value) in [
        ("client_assertion", request.client_assertion.as_ref()),
        ("client_assertion_type", request.client_assertion_type.as_ref()),
        ("client_id", request.client_id.as_ref()),
    ] {
        if value.is_some_and(|value| value.trim().is_empty()) {
            return Err(HttpError::invalid_client(format!("{field} present but empty")));
        }
    }

    validate_client_assertion_type(request)?;
    let assertion = request
        .client_assertion
        .as_deref()
        .ok_or_else(|| HttpError::invalid_client("client_assertion required"))?;
    let audiences = vec![state.config.our_issuer.clone(), state.token_endpoint()];
    let key_binding_registry = key_binding_registry(state);
    let claims = verify_assertion(
        assertion,
        &state.client_jwks,
        AssertionVerificationOptions {
            expected_issuer: &state.config.our_issuer,
            expected_audiences: &audiences,
            clock_skew_leeway: state.config.clock_skew_leeway,
            max_ttl: state.config.assertion_max_ttl,
            binding_subject_token: None,
            require_subject_binding: false,
            key_binding_registry: Some(&key_binding_registry),
        },
    )
    .map_err(|err| HttpError::invalid_client(err.message))?;

    if !state.config.client_ids.contains(&claims.sub) {
        return Err(HttpError::invalid_client(format!("client {:?} not permitted", claims.sub)));
    }
    if let Some(client_id) = request.client_id.as_deref()
        && client_id != claims.sub
    {
        return Err(HttpError::invalid_client(
            "client_id does not match the authenticated client_assertion",
        ));
    }
    client_assertion_jti(&claims)?;
    if mode == EffectiveExchangeMode::Delegation && request.actor_token.is_none() {
        return Err(HttpError::invalid_request("actor_token required for delegation"));
    }
    Ok(Some(claims))
}

fn key_binding_registry(state: &HttpState) -> BTreeSet<String> {
    let mut identities = state.config.actor_ids.clone();
    identities.extend(state.config.client_ids.iter().cloned());
    identities
}

fn record_client_assertion_replay(
    state: &HttpState,
    claims: &AssertionClaims,
    now: i64,
) -> Result<(), HttpError> {
    let jti = client_assertion_jti(claims)?;
    state
        .replay
        .check_and_record(&format!("ca:{}:{jti}", claims.sub), claims.exp, now)
        .map_err(map_client_assertion_replay_error)
}

fn client_assertion_jti(claims: &AssertionClaims) -> Result<&str, HttpError> {
    claims
        .jti
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| HttpError::invalid_client("client_assertion jti must be a non-empty string"))
}

fn validate_request_params(
    request: &ExchangeRequest,
    max_token_len: usize,
) -> Result<(), HttpError> {
    if request.grant_type != TOKEN_EXCHANGE_GRANT_TYPE {
        return Err(HttpError::unsupported_grant_type(format!(
            "grant_type must be {TOKEN_EXCHANGE_GRANT_TYPE}"
        )));
    }
    if request.subject_token.is_empty() || request.subject_token_type.is_empty() {
        return Err(HttpError::invalid_request(
            "subject_token and subject_token_type are required",
        ));
    }
    if request.subject_token.len() > max_token_len {
        return Err(HttpError::invalid_request("subject_token too large"));
    }
    if let Some(actor_token) = &request.actor_token {
        if actor_token.is_empty() {
            return Err(HttpError::invalid_request("actor_token must be a non-empty string"));
        }
        if actor_token.len() > max_token_len {
            return Err(HttpError::invalid_request("actor_token too large"));
        }
        if request.actor_token_type.as_deref().unwrap_or("").is_empty() {
            return Err(HttpError::invalid_request(
                "actor_token_type required when actor_token is present",
            ));
        }
    }
    if request.actor_token_type.is_some() && request.actor_token.is_none() {
        return Err(HttpError::invalid_request("actor_token_type present without actor_token"));
    }
    if !is_supported_input_token_type(&request.subject_token_type) {
        return Err(HttpError::invalid_request(format!(
            "unsupported subject_token_type {}",
            request.subject_token_type
        )));
    }
    if let Some(actor_type) = &request.actor_token_type
        && !is_supported_input_token_type(actor_type)
    {
        return Err(HttpError::invalid_request(format!(
            "unsupported actor_token_type {actor_type}"
        )));
    }
    if let Some(requested_type) = &request.requested_token_type
        && !is_supported_requested_token_type(requested_type)
    {
        return Err(HttpError::invalid_request(format!(
            "unsupported requested_token_type {requested_type}"
        )));
    }
    for (field, value) in [
        ("scope", request.scope.as_ref()),
        ("audience", request.audience.as_ref()),
        ("resource", request.resource.as_ref()),
        ("client_assertion", request.client_assertion.as_ref()),
    ] {
        if let Some(value) = value
            && value.len() > max_token_len
        {
            return Err(HttpError::invalid_request(format!("{field} too large")));
        }
    }
    Ok(())
}

fn validate_client_assertion_type(request: &ExchangeRequest) -> Result<(), HttpError> {
    if request.client_assertion_type.as_deref() != Some(CLIENT_ASSERTION_TYPE) {
        return Err(HttpError::invalid_client(format!(
            "client_assertion_type must be {CLIENT_ASSERTION_TYPE}"
        )));
    }
    Ok(())
}

fn is_supported_input_token_type(value: &str) -> bool {
    matches!(value, ACCESS_TOKEN_TYPE | JWT_TOKEN_TYPE)
}

fn is_supported_requested_token_type(value: &str) -> bool {
    value == ACCESS_TOKEN_TYPE
}

fn verify_actor_token(
    state: &HttpState,
    actor_token: &str,
    subject_token: &str,
) -> Result<AssertionClaims, HttpError> {
    let audiences = vec![state.config.our_issuer.clone(), state.token_endpoint()];
    let key_binding_registry = key_binding_registry(state);
    verify_assertion(
        actor_token,
        &state.actor_jwks,
        AssertionVerificationOptions {
            expected_issuer: &state.config.our_issuer,
            expected_audiences: &audiences,
            clock_skew_leeway: state.config.clock_skew_leeway,
            max_ttl: state.config.assertion_max_ttl,
            binding_subject_token: Some(subject_token),
            require_subject_binding: state.config.require_subject_binding,
            key_binding_registry: Some(&key_binding_registry),
        },
    )
    .map_err(|err| HttpError::invalid_client(err.message))
}

fn validate_actor_identity(
    state: &HttpState,
    actor_claims: &AssertionClaims,
) -> Result<(), HttpError> {
    if !state.config.actor_ids.contains(&actor_claims.sub) {
        return Err(HttpError::invalid_client(format!(
            "actor identity {:?} not permitted",
            actor_claims.sub
        )));
    }
    if actor_claims.iss != actor_claims.sub {
        return Err(HttpError::invalid_client("actor_token iss and sub must match"));
    }
    Ok(())
}

fn gate_may_act(
    subject_claims: &SubjectTokenClaims,
    actor_claims: &AssertionClaims,
) -> Result<(), HttpError> {
    let Some(may_act) = &subject_claims.may_act else {
        return Ok(());
    };
    let Some(may_act) = may_act.as_object() else {
        return Err(HttpError::invalid_request("may_act must be a JSON object"));
    };
    if may_act.is_empty() {
        return Err(HttpError::invalid_request("may_act present but empty: no actor authorized"));
    }
    if may_act.get("sub").and_then(|value| value.as_str()) != Some(actor_claims.sub.as_str()) {
        return Err(HttpError::invalid_request("may_act does not authorize this actor"));
    }
    if let Some(want_iss) = may_act.get("iss")
        && want_iss.as_str() != Some(actor_claims.iss.as_str())
    {
        return Err(HttpError::invalid_request("may_act issuer does not match this actor"));
    }
    Ok(())
}

fn resolve_target_for_request(
    request: &ExchangeRequest,
    state: &HttpState,
) -> Result<String, HttpError> {
    if request.audience.as_deref() == Some("") {
        return Err(HttpError::invalid_request("audience must not be empty"));
    }
    if request.resource.as_deref() == Some("") {
        return Err(HttpError::invalid_target("resource must not be empty"));
    }
    let target = resolve_target(request.audience.as_deref(), request.resource.as_deref())
        .map_err(map_core_error)?;
    if state.config.target_policy.get(&target).is_none() {
        return Err(HttpError::invalid_target(format!("unknown/forbidden target {target:?}")));
    }
    Ok(target)
}

fn resolve_scope_for_request(
    request: &ExchangeRequest,
    state: &HttpState,
    subject_claims: &SubjectTokenClaims,
    target: &str,
) -> Result<String, HttpError> {
    let policy =
        state.config.target_policy.get(target).ok_or_else(|| {
            HttpError::invalid_target(format!("unknown/forbidden target {target:?}"))
        })?;
    let allowed = join_scopes(&policy.allowed_scopes);
    let default_scope = join_scopes(&policy.default_scopes);
    let requested_scope = request
        .scope
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| (!default_scope.is_empty()).then_some(default_scope.as_str()));
    downscope(
        requested_scope,
        &allowed,
        subject_scope_string(subject_claims)?.as_deref(),
        state.config.subject_scope_bound_required,
    )
    .map_err(map_core_error)
}

fn subject_scope_string(claims: &SubjectTokenClaims) -> Result<Option<String>, HttpError> {
    let mut scopes = BTreeSet::new();
    if let Some(scope) = &claims.scope {
        scopes.extend(scope.split_whitespace().map(ToString::to_string));
    }
    match &claims.scp {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::String(scope)) => {
            scopes.extend(scope.split_whitespace().map(ToString::to_string));
        }
        Some(serde_json::Value::Array(values)) => {
            for value in values {
                let Some(scope) = value.as_str() else {
                    return Err(HttpError::invalid_request("malformed scope claim"));
                };
                scopes.extend(scope.split_whitespace().map(ToString::to_string));
            }
        }
        Some(_) => return Err(HttpError::invalid_request("malformed scope claim")),
    }
    Ok((!scopes.is_empty()).then(|| join_scopes(&scopes)))
}

fn act_claim_from_value(value: &serde_json::Value) -> Result<ActClaim, HttpError> {
    act_claim_from_value_at_depth(value, 1)
}

fn act_claim_from_value_at_depth(
    value: &serde_json::Value,
    depth: usize,
) -> Result<ActClaim, HttpError> {
    if depth > 10 {
        return Err(HttpError::invalid_request("act delegation chain too deep"));
    }
    let Some(obj) = value.as_object() else {
        return Err(HttpError::invalid_request("malformed prior act claim"));
    };
    let sub = obj
        .get("sub")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| HttpError::invalid_request("malformed prior act claim"))?
        .to_string();
    let iss = obj.get("iss").and_then(|value| value.as_str()).map(ToString::to_string);
    let act = obj
        .get("act")
        .map(|nested| act_claim_from_value_at_depth(nested, depth + 1))
        .transpose()?
        .map(Box::new);
    Ok(ActClaim { sub, iss, act })
}

fn map_core_error(err: sts_core::CoreError) -> HttpError {
    match err.kind {
        sts_core::CoreErrorKind::InvalidRequest => HttpError::invalid_request(err.message),
        sts_core::CoreErrorKind::InvalidClient => HttpError::invalid_client(err.message),
        sts_core::CoreErrorKind::InvalidTarget => HttpError::invalid_target(err.message),
        sts_core::CoreErrorKind::InvalidScope => HttpError::invalid_scope(err.message),
    }
}

fn map_subject_verify_error(err: &VerifyError) -> HttpError {
    match err.kind {
        VerifyErrorKind::InvalidAudience => HttpError::invalid_grant(err.message.clone()),
        VerifyErrorKind::InvalidIssuer => HttpError::invalid_grant(err.message.clone()),
        VerifyErrorKind::InvalidLifetime => HttpError::invalid_grant(err.message.clone()),
        VerifyErrorKind::InvalidToken | VerifyErrorKind::InvalidClaims => {
            HttpError::invalid_grant(err.message.clone())
        }
        _ => HttpError::invalid_request(err.message.clone()),
    }
}

fn map_replay_error(err: sts_replay::ReplayError) -> HttpError {
    match err.kind {
        ReplayErrorKind::InvalidRequest | ReplayErrorKind::ReplayDetected => {
            HttpError::invalid_request(err.message)
        }
        ReplayErrorKind::StoreFull => HttpError::service_unavailable(err.message),
    }
}

fn map_client_assertion_replay_error(err: sts_replay::ReplayError) -> HttpError {
    match err.kind {
        ReplayErrorKind::InvalidRequest => HttpError::invalid_client(err.message),
        ReplayErrorKind::ReplayDetected => {
            HttpError::invalid_client("client_assertion replay detected")
        }
        ReplayErrorKind::StoreFull => HttpError::service_unavailable(err.message),
    }
}

fn map_dpop_error(err: DpopError) -> HttpError {
    HttpError::invalid_dpop_proof(err.message)
}

fn map_dpop_replay_error(err: sts_replay::ReplayError) -> HttpError {
    match err.kind {
        ReplayErrorKind::InvalidRequest | ReplayErrorKind::ReplayDetected => {
            HttpError::invalid_dpop_proof("DPoP proof replay detected")
        }
        ReplayErrorKind::StoreFull => HttpError::service_unavailable(err.message),
    }
}

fn join_scopes(scopes: &BTreeSet<String>) -> String {
    scopes.iter().cloned().collect::<Vec<_>>().join(" ")
}

fn public_cache_headers(max_age: i64) -> HeaderMap {
    let mut headers = security_headers();
    let value = format!("public, max-age={}", max_age.max(0));
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_str(&value)
            .unwrap_or_else(|_| HeaderValue::from_static("public, max-age=0")),
    );
    headers
}

fn token_headers() -> HeaderMap {
    let mut headers = security_headers();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers
}

fn security_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers
}

fn new_jti() -> String {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{Method, Request};
    use http_body_util::BodyExt;
    use rand::{SeedableRng, rngs::StdRng};
    use rsa::RsaPrivateKey;
    use serde_json::Value;
    use sts_config::{
        ConfigSource, ImpersonationPolicyEntry, ImpersonationSelector, TokenExchangeMode,
    };
    use tower::ServiceExt;

    #[derive(Debug, Clone, Serialize)]
    struct SubjectWireClaims {
        iss: String,
        sub: String,
        aud: String,
        scope: String,
        exp: i64,
        iat: i64,
    }

    #[derive(Debug, Clone, Serialize)]
    struct AssertionWireClaims {
        iss: String,
        sub: String,
        aud: String,
        exp: i64,
        iat: i64,
        jti: String,
    }

    fn signer(seed: u64, kid: &str) -> RsaJoseSigner {
        let mut rng = StdRng::seed_from_u64(seed);
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
        RsaJoseSigner::from_generated(&private_key, kid).expect("signer")
    }

    fn test_state() -> (HttpState, RsaJoseSigner, RsaJoseSigner, RsaJoseSigner) {
        let sts_signer = signer(1, "sts-kid");
        let subject_signer = signer(2, "subject-kid");
        let actor_signer = signer(3, "chat-mcp-actor-key-1");
        let client_signer = signer(4, "chat-mcp-key-1");
        let mut config = RuntimeConfig::from_source(&ConfigSource::from_pairs([
            ("IDP_ISSUER", "https://issuer.example/oauth2/default"),
            ("EXPECTED_SUBJECT_AUD", "api://obo"),
            ("ACTOR_IDS", "chat-mcp"),
            ("OBO_STS_ISSUER", "https://sts.example"),
            (
                "TARGET_POLICY_JSON",
                r#"{"api://chat-mcp":{"allowed_scopes":["chat.read","chat.write"],"default_scopes":["chat.read"]}}"#,
            ),
        ]))
        .expect("config");
        config.require_subject_binding = false;
        let state = HttpState::new(
            config,
            sts_signer.clone(),
            subject_signer.public_jwks(),
            actor_signer.public_jwks(),
            client_signer.public_jwks(),
            ReplayPolicy::in_memory(),
        );
        (state, subject_signer, actor_signer, client_signer)
    }

    fn allow_impersonation_anywhere(state: &mut HttpState, client_id: &str) {
        state.config.impersonation_policy.clients.insert(
            client_id.to_string(),
            ImpersonationPolicyEntry {
                targets: ImpersonationSelector::Any,
                subjects: ImpersonationSelector::Any,
            },
        );
    }

    async fn read_json(response: Response) -> Value {
        let bytes = response.into_body().collect().await.expect("body").to_bytes();
        serde_json::from_slice(&bytes).expect("json")
    }

    fn signed_subject_token(signer: &RsaJoseSigner, now: i64) -> String {
        signer
            .sign_json_claims(&SubjectWireClaims {
                iss: "https://issuer.example/oauth2/default".to_string(),
                sub: "user@example.com".to_string(),
                aud: "api://obo".to_string(),
                scope: "chat.read chat.write".to_string(),
                exp: now + 600,
                iat: now,
            })
            .expect("subject token")
    }

    fn signed_assertion(signer: &RsaJoseSigner, now: i64, jti: &str) -> String {
        signer
            .sign_json_claims(&AssertionWireClaims {
                iss: "chat-mcp".to_string(),
                sub: "chat-mcp".to_string(),
                aud: "https://sts.example".to_string(),
                exp: now + 300,
                iat: now,
                jti: jti.to_string(),
            })
            .expect("assertion")
    }

    async fn post_token_form(state: HttpState, body: String) -> Response {
        router(state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/token")
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn metadata_route_advertises_the_public_contract() {
        let (state, _, _, _) = test_state();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/.well-known/oauth-authorization-server")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some("public, max-age=300")
        );
        let body = read_json(response).await;
        assert_eq!(body["issuer"], "https://sts.example");
        assert_eq!(body["token_endpoint"], "https://sts.example/token");
        assert_eq!(body["jwks_uri"], "https://sts.example/jwks");
        assert_eq!(body["response_types_supported"], Value::Array(vec![]));
    }

    #[tokio::test]
    async fn jwks_route_publishes_the_sts_public_key() {
        let (state, _, _, _) = test_state();
        let response = router(state)
            .oneshot(
                Request::builder().method(Method::GET).uri("/jwks").body(Body::empty()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        assert_eq!(body["keys"][0]["kid"], "sts-kid");
        assert_eq!(body["keys"][0]["alg"], "RS256");
    }

    #[tokio::test]
    async fn token_route_mints_a_delegated_bearer_token() {
        let (state, subject_signer, actor_signer, _) = test_state();
        let now = unix_now();
        let subject_token = signed_subject_token(&subject_signer, now);
        let actor_token = signed_assertion(&actor_signer, now, "actor-jti-1");

        let body = serde_urlencoded::to_string([
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", subject_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("actor_token", actor_token.as_str()),
            ("actor_token_type", JWT_TOKEN_TYPE),
            ("audience", "api://chat-mcp"),
            ("scope", "chat.read"),
        ])
        .expect("form");
        let response = post_token_form(state.clone(), body).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        let body = read_json(response).await;
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["issued_token_type"], ACCESS_TOKEN_TYPE);
        assert_eq!(body["scope"], "chat.read");
        let token = body["access_token"].as_str().expect("access token");
        let minted: sts_core::MintedClaims =
            sts_jose::verify_claims_against_jwks(token, &state.signer.public_jwks())
                .expect("minted token verifies");
        assert_eq!(minted.sub, "user@example.com");
        assert_eq!(minted.aud, "api://chat-mcp");
        assert_eq!(minted.client_id, "chat-mcp");
        assert_eq!(minted.act.expect("act").sub, "chat-mcp");
    }

    #[tokio::test]
    async fn token_route_accepts_private_key_jwt_client_auth_with_actor_delegation() {
        let (state, subject_signer, actor_signer, client_signer) = test_state();
        let now = unix_now();
        let subject_token = signed_subject_token(&subject_signer, now);
        let actor_token = signed_assertion(&actor_signer, now, "actor-jti-private-key-jwt");
        let client_assertion = signed_assertion(&client_signer, now, "client-jti-1");

        let body = serde_urlencoded::to_string([
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", subject_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("actor_token", actor_token.as_str()),
            ("actor_token_type", JWT_TOKEN_TYPE),
            ("audience", "api://chat-mcp"),
            ("scope", "chat.read"),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE),
            ("client_assertion", client_assertion.as_str()),
            ("client_id", "chat-mcp"),
        ])
        .expect("form");

        let response = post_token_form(state.clone(), body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        let token = body["access_token"].as_str().expect("access token");
        let minted: sts_core::MintedClaims =
            sts_jose::verify_claims_against_jwks(token, &state.signer.public_jwks())
                .expect("minted token verifies");
        assert_eq!(minted.sub, "user@example.com");
        assert_eq!(minted.client_id, "chat-mcp");
        assert_eq!(minted.act.expect("act").sub, "chat-mcp");
    }

    #[tokio::test]
    async fn token_route_mints_impersonation_token_without_act() {
        let (mut state, subject_signer, _, client_signer) = test_state();
        state.config.token_exchange_mode = TokenExchangeMode::Impersonation;
        allow_impersonation_anywhere(&mut state, "chat-mcp");
        let now = unix_now();
        let subject_token = signed_subject_token(&subject_signer, now);
        let client_assertion = signed_assertion(&client_signer, now, "client-jti-impersonation");

        let body = serde_urlencoded::to_string([
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", subject_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("audience", "api://chat-mcp"),
            ("scope", "chat.read"),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE),
            ("client_assertion", client_assertion.as_str()),
            ("client_id", "chat-mcp"),
        ])
        .expect("form");

        let response = post_token_form(state.clone(), body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_json(response).await;
        let token = body["access_token"].as_str().expect("access token");
        let minted: sts_core::MintedClaims =
            sts_jose::verify_claims_against_jwks(token, &state.signer.public_jwks())
                .expect("minted token verifies");
        assert_eq!(minted.sub, "user@example.com");
        assert_eq!(minted.client_id, "chat-mcp");
        assert!(minted.act.is_none());
    }

    #[tokio::test]
    async fn token_route_rejects_client_assertion_client_id_mismatch() {
        let (state, subject_signer, actor_signer, client_signer) = test_state();
        let now = unix_now();
        let subject_token = signed_subject_token(&subject_signer, now);
        let actor_token = signed_assertion(&actor_signer, now, "actor-jti-mismatch");
        let client_assertion = signed_assertion(&client_signer, now, "client-jti-mismatch");

        let body = serde_urlencoded::to_string([
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", subject_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("actor_token", actor_token.as_str()),
            ("actor_token_type", JWT_TOKEN_TYPE),
            ("audience", "api://chat-mcp"),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE),
            ("client_assertion", client_assertion.as_str()),
            ("client_id", "other-client"),
        ])
        .expect("form");

        let response = post_token_form(state, body).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(response).await;
        assert_eq!(body["error"], "invalid_client");
        assert_eq!(
            body["error_description"],
            "client_id does not match the authenticated client_assertion"
        );
    }

    #[tokio::test]
    async fn token_route_rejects_client_assertion_signed_by_another_client_key() {
        let (mut state, subject_signer, actor_signer, client_signer) = test_state();
        let other_client_signer = signer(5, "other-client-key-1");
        state.config.client_ids.insert("other-client".to_string());
        state.client_jwks = JwksDocument::new(vec![
            client_signer.public_jwks().keys[0].clone(),
            other_client_signer.public_jwks().keys[0].clone(),
        ]);
        let now = unix_now();
        let subject_token = signed_subject_token(&subject_signer, now);
        let actor_token = signed_assertion(&actor_signer, now, "actor-jti-cross-client-kid");
        let client_assertion =
            signed_assertion(&other_client_signer, now, "client-jti-cross-client-kid");

        let body = serde_urlencoded::to_string([
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", subject_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("actor_token", actor_token.as_str()),
            ("actor_token_type", JWT_TOKEN_TYPE),
            ("audience", "api://chat-mcp"),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE),
            ("client_assertion", client_assertion.as_str()),
            ("client_id", "chat-mcp"),
        ])
        .expect("form");

        let response = post_token_form(state, body).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(response).await;
        assert_eq!(body["error"], "invalid_client");
        assert!(
            body["error_description"]
                .as_str()
                .unwrap_or("")
                .contains("signing key does not belong")
        );
    }

    #[tokio::test]
    async fn token_route_rejects_actor_token_signed_by_cross_domain_client_key() {
        let (mut state, subject_signer, actor_signer, _) = test_state();
        let client_domain_signer = signer(6, "chat-mcp-svc-key-1");
        state.config.client_ids.insert("chat-mcp-svc".to_string());
        state.actor_jwks = JwksDocument::new(vec![
            actor_signer.public_jwks().keys[0].clone(),
            client_domain_signer.public_jwks().keys[0].clone(),
        ]);
        let now = unix_now();
        let subject_token = signed_subject_token(&subject_signer, now);
        let actor_token =
            signed_assertion(&client_domain_signer, now, "actor-jti-cross-domain-client-key");

        let body = serde_urlencoded::to_string([
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", subject_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("actor_token", actor_token.as_str()),
            ("actor_token_type", JWT_TOKEN_TYPE),
            ("audience", "api://chat-mcp"),
            ("scope", "chat.read"),
        ])
        .expect("form");

        let response = post_token_form(state, body).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(response).await;
        assert_eq!(body["error"], "invalid_client");
        assert!(
            body["error_description"]
                .as_str()
                .unwrap_or("")
                .contains("signing key does not belong")
        );
    }

    #[tokio::test]
    async fn token_route_rejects_private_key_jwt_delegation_without_actor_token() {
        let (state, subject_signer, _, client_signer) = test_state();
        let now = unix_now();
        let subject_token = signed_subject_token(&subject_signer, now);
        let client_assertion = signed_assertion(&client_signer, now, "client-jti-no-actor");

        let body = serde_urlencoded::to_string([
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", subject_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("audience", "api://chat-mcp"),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE),
            ("client_assertion", client_assertion.as_str()),
            ("client_id", "chat-mcp"),
        ])
        .expect("form");

        let response = post_token_form(state, body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"], "invalid_request");
        assert_eq!(body["error_description"], "actor_token required for delegation");
    }

    #[tokio::test]
    async fn token_route_rejects_missing_actor_token() {
        let (state, subject_signer, _, _) = test_state();
        let subject_token = signed_subject_token(&subject_signer, unix_now());
        let body = serde_urlencoded::to_string([
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", subject_token.as_str()),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("audience", "api://chat-mcp"),
        ])
        .expect("form");
        let response = post_token_form(state, body).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        let body = read_json(response).await;
        assert_eq!(body["error"], "invalid_client");
    }
}
