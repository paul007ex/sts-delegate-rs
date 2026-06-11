use axum::body::Body;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::header::{CACHE_CONTROL, CONTENT_TYPE, PRAGMA};
use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use rand::{SeedableRng, rngs::StdRng};
use rsa::RsaPrivateKey;
use serde::Serialize;
use serde_json::{Value, json};
use sts_config::{ConfigSource, RuntimeConfig, TokenExchangeMode};
use sts_core::{ACCESS_TOKEN_TYPE, JWT_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE};
use sts_http::{HttpState, router};
use sts_jose::{JoseSigner, RsaJoseSigner};
use sts_replay::ReplayPolicy;
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
    let sts_signer = signer(10, "sts-kid");
    let subject_signer = signer(11, "subject-kid");
    let actor_signer = signer(12, "actor-kid");
    let client_signer = signer(13, "client-kid");
    let mut config = RuntimeConfig::from_source(&ConfigSource::from_pairs([
        ("IDP_ISSUER", "https://issuer.example/oauth2/default"),
        ("EXPECTED_SUBJECT_AUD", "api://obo"),
        ("ACTOR_IDS", "chat-mcp"),
        ("CLIENT_IDS", "chat-mcp"),
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

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn signed_subject_token(signer: &RsaJoseSigner, now: i64) -> String {
    signer
        .sign_json_claims(&SubjectWireClaims {
            iss: "https://issuer.example/oauth2/default".to_string(),
            sub: "alice@example.com".to_string(),
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

async fn read_json(response: Response<Body>) -> Value {
    let bytes = response.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&bytes).expect("json")
}

async fn post_token_form(state: HttpState, body: String) -> Response<Body> {
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

fn jwt_segment(token: &str, index: usize) -> Value {
    let segment = token.split('.').nth(index).expect("jwt segment");
    let bytes = URL_SAFE_NO_PAD.decode(segment.as_bytes()).expect("base64url");
    serde_json::from_slice(&bytes).expect("json segment")
}

#[tokio::test]
async fn contract_discovery_and_jwks_match_python_oracle_shape() {
    let (state, _, _, _) = test_state();
    let metadata_response = router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metadata_response.status(), StatusCode::OK);
    assert_eq!(
        metadata_response.headers().get(CACHE_CONTROL).and_then(|value| value.to_str().ok()),
        Some("public, max-age=300")
    );
    let metadata = read_json(metadata_response).await;
    assert_eq!(metadata["issuer"], "https://sts.example");
    assert_eq!(metadata["token_endpoint"], "https://sts.example/token");
    assert_eq!(metadata["jwks_uri"], "https://sts.example/jwks");
    assert_eq!(metadata["response_types_supported"], json!([]));
    assert_eq!(metadata["grant_types_supported"], json!([TOKEN_EXCHANGE_GRANT_TYPE]));
    assert_eq!(metadata["token_endpoint_auth_methods_supported"], json!(["private_key_jwt"]));
    assert_eq!(metadata["token_endpoint_auth_signing_alg_values_supported"], json!(["RS256"]));

    let jwks_response = router(state)
        .oneshot(Request::builder().method(Method::GET).uri("/jwks").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(jwks_response.status(), StatusCode::OK);
    let jwks = read_json(jwks_response).await;
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["kid"], "sts-kid");
    assert_eq!(key["use"], "sig");
    assert_eq!(key["alg"], "RS256");
    for private_member in ["d", "p", "q", "dp", "dq", "qi"] {
        assert!(key.get(private_member).is_none(), "JWKS leaked {private_member}");
    }
}

#[tokio::test]
async fn contract_delegation_token_matches_python_oracle_wire_shape() {
    let (state, subject_signer, actor_signer, _) = test_state();
    let now = unix_now();
    let subject_token = signed_subject_token(&subject_signer, now);
    let actor_token = signed_assertion(&actor_signer, now, "actor-contract-1");
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
        response.headers().get(CACHE_CONTROL).and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response.headers().get(PRAGMA).and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
    let response_body = read_json(response).await;
    assert_eq!(response_body["issued_token_type"], ACCESS_TOKEN_TYPE);
    assert_eq!(response_body["token_type"], "Bearer");
    assert_eq!(response_body["scope"], "chat.read");

    let token = response_body["access_token"].as_str().expect("access token");
    let header = jwt_segment(token, 0);
    let payload = jwt_segment(token, 1);
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["kid"], "sts-kid");
    assert_eq!(payload["iss"], "https://sts.example");
    assert_eq!(payload["sub"], "alice@example.com");
    assert_eq!(payload["aud"], "api://chat-mcp");
    assert_eq!(payload["client_id"], "chat-mcp");
    assert_eq!(payload["act"], json!({"sub": "chat-mcp"}));
    assert!(payload.get("cnf").is_none());
    assert!(payload.get("auth_time").is_none());
    assert!(payload.get("acr").is_none());
    assert!(payload.get("amr").is_none());
}

#[tokio::test]
async fn contract_impersonation_omits_act_claim() {
    let (mut state, subject_signer, _, client_signer) = test_state();
    state.config.token_exchange_mode = TokenExchangeMode::Impersonation;
    state.config.impersonation_policy.allowed_clients.insert("chat-mcp".to_string());
    let now = unix_now();
    let subject_token = signed_subject_token(&subject_signer, now);
    let client_assertion = signed_assertion(&client_signer, now, "client-contract-1");
    let body = serde_urlencoded::to_string([
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("subject_token", subject_token.as_str()),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("audience", "api://chat-mcp"),
        ("scope", "chat.read"),
        ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
        ("client_assertion", client_assertion.as_str()),
        ("client_id", "chat-mcp"),
    ])
    .expect("form");

    let response = post_token_form(state, body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response_body = read_json(response).await;
    let token = response_body["access_token"].as_str().expect("access token");
    let payload = jwt_segment(token, 1);
    assert_eq!(payload["sub"], "alice@example.com");
    assert_eq!(payload["client_id"], "chat-mcp");
    assert!(payload.get("act").is_none(), "impersonation must omit act");
}

#[tokio::test]
async fn contract_token_errors_are_oauth_json_and_no_store() {
    let (state, _, _, _) = test_state();
    let body = serde_urlencoded::to_string([("grant_type", "bad")]).expect("form");
    let response = post_token_form(state, body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(CACHE_CONTROL).and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response.headers().get(PRAGMA).and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
    let body = read_json(response).await;
    assert_eq!(body["error"], "unsupported_grant_type");
    assert!(body["error_description"].as_str().unwrap_or("").contains(TOKEN_EXCHANGE_GRANT_TYPE));
}
