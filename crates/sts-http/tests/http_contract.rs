use axum::body::Body;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, PRAGMA, WWW_AUTHENTICATE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
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

#[derive(Debug, Clone, Serialize)]
struct DpopProofClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
}

fn signer(seed: u64, kid: &str) -> RsaJoseSigner {
    let mut rng = StdRng::seed_from_u64(seed);
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa");
    RsaJoseSigner::from_generated(&private_key, kid).expect("signer")
}

fn test_state() -> (HttpState, RsaJoseSigner, RsaJoseSigner, RsaJoseSigner) {
    let sts_signer = signer(10, "sts-kid");
    let subject_signer = signer(11, "subject-kid");
    let actor_signer = signer(12, "chat-mcp-actor-key-1");
    let client_signer = signer(13, "chat-mcp-key-1");
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

fn path_bearing_state() -> HttpState {
    let (mut state, _, _, _) = test_state();
    state.config.our_issuer = "https://sts.example/tenant1".to_string();
    state
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
    post_token_form_with_dpop_values(state, body, &[]).await
}

async fn post_form_to_uri(state: HttpState, uri: &str, body: String) -> Response<Body> {
    router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn post_token_raw(
    state: HttpState,
    body: impl Into<Body>,
    content_type: Option<&str>,
    extra_headers: &[(&str, &str)],
) -> Response<Body> {
    let mut builder = Request::builder().method(Method::POST).uri("/token");
    if let Some(content_type) = content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
    router(state).oneshot(builder.body(body.into()).unwrap()).await.unwrap()
}

async fn post_token_form_with_dpop_values(
    state: HttpState,
    body: String,
    dpop_values: &[&str],
) -> Response<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/token")
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    for value in dpop_values {
        builder = builder.header("DPoP", *value);
    }
    router(state).oneshot(builder.body(Body::from(body)).unwrap()).await.unwrap()
}

#[tokio::test]
async fn contract_token_rejects_wrong_content_type_and_duplicate_form_params() {
    let (state, _, _, _) = test_state();

    let response = post_token_raw(state.clone(), "{}", Some("application/json"), &[]).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"], "invalid_request");
    assert!(body["error_description"].as_str().unwrap_or("").contains("Content-Type"));

    let duplicate_grant = serde_urlencoded::to_string([
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
    ])
    .expect("form");
    let response = post_token_form(state.clone(), duplicate_grant).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"], "invalid_request");
    assert!(body["error_description"].as_str().unwrap_or("").contains("grant_type"));

    let duplicate_audience = serde_urlencoded::to_string([
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("subject_token", "bad-subject"),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("audience", "api://one"),
        ("audience", "api://two"),
    ])
    .expect("form");
    let response = post_token_form(state, duplicate_audience).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"], "invalid_target");
    assert!(body["error_description"].as_str().unwrap_or("").contains("multiple audience"));
}

#[tokio::test]
async fn contract_authorization_header_client_auth_is_rejected() {
    let (state, _, _, _) = test_state();
    let body = serde_urlencoded::to_string([
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("subject_token", "bad-subject"),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("audience", "api://chat-mcp"),
    ])
    .expect("form");
    let response = post_token_raw(
        state.clone(),
        body,
        Some("application/x-www-form-urlencoded"),
        &[(AUTHORIZATION.as_str(), "Basic abc123")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE).and_then(|value| value.to_str().ok()),
        Some("Basic")
    );
    let body = read_json(response).await;
    assert_eq!(body["error"], "invalid_client");
    assert!(body["error_description"].as_str().unwrap_or("").contains("Authorization header"));

    let mixed = serde_urlencoded::to_string([
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("subject_token", "bad-subject"),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("audience", "api://chat-mcp"),
        ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
        ("client_assertion", "bad-assertion"),
        ("client_id", "chat-mcp"),
    ])
    .expect("form");
    let response = post_token_raw(
        state,
        mixed,
        Some("application/x-www-form-urlencoded"),
        &[(AUTHORIZATION.as_str(), "Bearer abc123")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE).and_then(|value| value.to_str().ok()),
        Some("Bearer")
    );
    let body = read_json(response).await;
    assert_eq!(body["error"], "invalid_client");
}

fn jwt_segment(token: &str, index: usize) -> Value {
    let segment = token.split('.').nth(index).expect("jwt segment");
    let bytes = URL_SAFE_NO_PAD.decode(segment.as_bytes()).expect("base64url");
    serde_json::from_slice(&bytes).expect("json segment")
}

fn dpop_proof(now: i64, jti: &str, htm: &str, htu: &str) -> String {
    let signing_key = SigningKey::from_slice(&[7_u8; 32]).expect("p256 key");
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
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(serde_json::from_value(jwk).expect("jwk"));
    let der = signing_key.to_pkcs8_der().expect("pkcs8 der");
    encode(
        &header,
        &DpopProofClaims {
            jti: jti.to_string(),
            htm: htm.to_string(),
            htu: htu.to_string(),
            iat: now,
        },
        &EncodingKey::from_ec_der(der.as_bytes()),
    )
    .expect("dpop proof")
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
    assert!(
        metadata["dpop_signing_alg_values_supported"]
            .as_array()
            .expect("dpop algs")
            .contains(&json!("ES256"))
    );
    assert!(
        !metadata["dpop_signing_alg_values_supported"]
            .as_array()
            .expect("dpop algs")
            .contains(&json!("HS256"))
    );

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
async fn contract_path_bearing_issuer_advertised_endpoints_are_live() {
    let state = path_bearing_state();
    let app = router(state.clone());

    let metadata_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/.well-known/oauth-authorization-server/tenant1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metadata_response.status(), StatusCode::OK);
    let metadata = read_json(metadata_response).await;
    assert_eq!(metadata["issuer"], "https://sts.example/tenant1");
    assert_eq!(metadata["token_endpoint"], "https://sts.example/tenant1/token");
    assert_eq!(metadata["jwks_uri"], "https://sts.example/tenant1/jwks");

    let jwks_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/tenant1/jwks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks_response.status(), StatusCode::OK);
    assert_eq!(
        jwks_response.headers().get(CACHE_CONTROL).and_then(|value| value.to_str().ok()),
        Some("public, max-age=300")
    );
    let jwks = read_json(jwks_response).await;
    assert_eq!(jwks["keys"][0]["kid"], "sts-kid");

    let token_response =
        post_form_to_uri(state.clone(), "/tenant1/token", "grant_type=x".to_string()).await;
    assert_ne!(token_response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        token_response.headers().get(CACHE_CONTROL).and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        token_response.headers().get(PRAGMA).and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
    let token_error = read_json(token_response).await;
    assert_eq!(token_error["error"], "unsupported_grant_type");

    let root_jwks_response = router(state.clone())
        .oneshot(Request::builder().method(Method::GET).uri("/jwks").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(root_jwks_response.status(), StatusCode::OK);

    let root_token_response = post_form_to_uri(state, "/token", "grant_type=x".to_string()).await;
    assert_ne!(root_token_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn contract_metadata_is_public_and_get_only() {
    let (state, _, _, _) = test_state();

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/.well-known/oauth-authorization-server")
                .header(AUTHORIZATION, "Bearer ignored")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/.well-known/oauth-authorization-server")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=x"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn contract_dpop_delegation_binds_token_and_returns_dpop_type() {
    let (state, subject_signer, actor_signer, _) = test_state();
    let now = unix_now();
    let subject_token = signed_subject_token(&subject_signer, now);
    let actor_token = signed_assertion(&actor_signer, now, "actor-dpop-contract-1");
    let proof = dpop_proof(now, "dpop-contract-1", "POST", "https://sts.example/token?ignored=1");
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

    let response = post_token_form_with_dpop_values(state, body, &[&proof]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response_body = read_json(response).await;
    assert_eq!(response_body["token_type"], "DPoP");
    let token = response_body["access_token"].as_str().expect("access token");
    let payload = jwt_segment(token, 1);
    assert!(payload["cnf"]["jkt"].as_str().is_some_and(|value| !value.is_empty()));
    assert!(payload.get("cnf_jkt").is_none());
}

#[tokio::test]
async fn contract_dpop_replay_reuses_holder_key_and_jti_fail_closed() {
    let (state, subject_signer, actor_signer, _) = test_state();
    let now = unix_now();
    let proof = dpop_proof(now, "dpop-contract-replay", "POST", "https://sts.example/token");

    for actor_jti in ["actor-dpop-replay-1", "actor-dpop-replay-2"] {
        let subject_token = signed_subject_token(&subject_signer, now);
        let actor_token = signed_assertion(&actor_signer, now, actor_jti);
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
        let response = post_token_form_with_dpop_values(state.clone(), body, &[&proof]).await;
        if actor_jti.ends_with("-1") {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = read_json(response).await;
            assert_eq!(body["error"], "invalid_dpop_proof");
            assert!(body["error_description"].as_str().unwrap_or("").contains("replay"));
        }
    }
}

#[tokio::test]
async fn contract_dpop_duplicate_or_malformed_header_is_invalid_dpop_proof() {
    let (state, _, _, _) = test_state();
    let body = serde_urlencoded::to_string([
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("subject_token", "bad-subject"),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("actor_token", "bad-actor"),
        ("actor_token_type", JWT_TOKEN_TYPE),
        ("audience", "api://chat-mcp"),
    ])
    .expect("form");
    let proof = dpop_proof(unix_now(), "dpop-duplicate", "POST", "https://sts.example/token");
    let response =
        post_token_form_with_dpop_values(state.clone(), body.clone(), &[&proof, &proof]).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body_json = read_json(response).await;
    assert_eq!(body_json["error"], "invalid_dpop_proof");

    let response = post_token_form_with_dpop_values(state, body, &["not.a.jwt"]).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body_json = read_json(response).await;
    assert_eq!(body_json["error"], "invalid_dpop_proof");
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
async fn contract_requested_token_type_matches_python_oracle() {
    let (state, subject_signer, actor_signer, _) = test_state();
    let now = unix_now();
    let subject_token = signed_subject_token(&subject_signer, now);

    let access_token_actor = signed_assertion(&actor_signer, now, "actor-rtt-access-token");
    let access_token_body = serde_urlencoded::to_string([
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("subject_token", subject_token.as_str()),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("actor_token", access_token_actor.as_str()),
        ("actor_token_type", JWT_TOKEN_TYPE),
        ("audience", "api://chat-mcp"),
        ("scope", "chat.read"),
        ("requested_token_type", ACCESS_TOKEN_TYPE),
    ])
    .expect("form");
    let response = post_token_form(state.clone(), access_token_body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["issued_token_type"], ACCESS_TOKEN_TYPE);

    let saml_actor = signed_assertion(&actor_signer, now, "actor-rtt-saml");
    let saml_body = serde_urlencoded::to_string([
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("subject_token", subject_token.as_str()),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("actor_token", saml_actor.as_str()),
        ("actor_token_type", JWT_TOKEN_TYPE),
        ("audience", "api://chat-mcp"),
        ("requested_token_type", "urn:ietf:params:oauth:token-type:saml2"),
    ])
    .expect("form");
    let response = post_token_form(state.clone(), saml_body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap_or("")
            .contains("unsupported requested_token_type")
    );

    let jwt_actor = signed_assertion(&actor_signer, now, "actor-rtt-jwt");
    let jwt_body = serde_urlencoded::to_string([
        ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
        ("subject_token", subject_token.as_str()),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("actor_token", jwt_actor.as_str()),
        ("actor_token_type", JWT_TOKEN_TYPE),
        ("audience", "api://chat-mcp"),
        ("requested_token_type", JWT_TOKEN_TYPE),
    ])
    .expect("form");
    let response = post_token_form(state, jwt_body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap_or("")
            .contains("unsupported requested_token_type")
    );
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
async fn contract_dpop_impersonation_binds_token_without_act_claim() {
    let (mut state, subject_signer, _, client_signer) = test_state();
    state.config.token_exchange_mode = TokenExchangeMode::Impersonation;
    state.config.impersonation_policy.allowed_clients.insert("chat-mcp".to_string());
    let now = unix_now();
    let subject_token = signed_subject_token(&subject_signer, now);
    let client_assertion = signed_assertion(&client_signer, now, "client-dpop-contract-1");
    let proof =
        dpop_proof(now, "dpop-impersonation-contract-1", "POST", "https://sts.example/token");
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

    let response = post_token_form_with_dpop_values(state, body, &[&proof]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response_body = read_json(response).await;
    assert_eq!(response_body["token_type"], "DPoP");
    let token = response_body["access_token"].as_str().expect("access token");
    let payload = jwt_segment(token, 1);
    assert_eq!(payload["sub"], "alice@example.com");
    assert_eq!(payload["client_id"], "chat-mcp");
    assert!(payload.get("act").is_none(), "impersonation must omit act");
    assert!(payload["cnf"]["jkt"].as_str().is_some_and(|value| !value.is_empty()));
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
