# sts-delegate-rs v2 Contract Requirements Ledger

Generated: 2026-06-11

This ledger is the canonical alpha contract-freeze artifact for issue #2. It maps the
Python `sts-delegate` oracle, Rust implementation, contract tests, issue trail, and
primary RFCs into atomic product requirements for the Rust v2 line.

## Source Set

- Rust repo instructions: `AGENTS.md`, `CLAUDE.md`
- Rust implementation: `crates/sts-core`, `crates/sts-config`, `crates/sts-verify`,
  `crates/sts-jose`, `crates/sts-dpop`, `crates/sts-replay`, `crates/sts-http`,
  `crates/sts-cli`
- Rust validation scripts: `scripts/oracle_contract_smoke.sh`,
  `scripts/check_architecture_boundaries.py`
- Python oracle tests: `tests/test_integration.py`, `tests/test_impersonation.py`,
  `tests/test_dpop.py`
- Python oracle implementation: `sts_delegate/application/exchange.py`,
  `sts_delegate/domain/payload.py`, `sts_delegate/transport.py`,
  `sts_delegate/dpop.py`, `sts_delegate/client_auth.py`,
  `sts_delegate/application/replay_records.py`
- Rust issues: #1 through #21, with #2 as the active freeze tracker
- Primary specs: RFC 6749, RFC 7523, RFC 7519, RFC 8414, RFC 8693, RFC 9068,
  RFC 9449

## Master Requirements Ledger

| ID | Requirement | Type | Status | Owner | Source(s) | Test proof / gate | Edge cases / related issues |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R-001 | GitHub issues are canonical for product work; `/tmp` logs are monitoring only. | policy | implemented | PM | `AGENTS.md`; issue #2 | issue comments on #2 | Do not close issues from stale log-only evidence. |
| R-002 | The Python repo remains the behavior oracle until Rust parity is proven. | policy | implemented | PM/tests | `README.md:16`; issue #2 | `scripts/oracle_contract_smoke.sh` | Keep alpha allowed, beta/stable blocked until parity matrix. |
| R-003 | Rust v2 must preserve observable endpoints, claims, errors, replay behavior, DPoP, and client auth where intended. | must | partial | PM/all crates | issue #2; `README.md:18` | workspace tests; oracle smoke | Divergences must be explicit issues. |
| R-004 | Requirements must classify source-backed items as must, must-not, policy, non-goal, or open question. | policy | implemented | PM | issue #2; `/tmp/sts-requirements-log.md` | this ledger | Scratch log had duplicate IDs; this file resets numbering. |
| R-005 | Every protocol/security requirement must cite code, test, issue, or RFC evidence. | policy | implemented | PM/security | `AGENTS.md`; RFC source set | this ledger | Vague claims are not freeze-ready. |
| R-006 | Rust code targets Rust 2024. | must | implemented | architecture | `Cargo.toml:14`; `AGENTS.md` | `cargo metadata`; build | Crate manifests inherit workspace package data. |
| R-007 | Product code must forbid unsafe code. | must-not | implemented | architecture/security | `Cargo.toml:29`; crate roots line 1 | `scripts/check_architecture_boundaries.py` | Any future unsafe needs a tracked issue. |
| R-008 | Clippy must deny `dbg!`, `todo!`, `unwrap_used`, and undocumented unsafe blocks. | must-not | implemented | architecture/security | `Cargo.toml:23` | `cargo clippy --workspace --all-targets -- -D warnings` | Tests may use expect, but product unwrap remains barred. |
| R-009 | The workspace must keep explicit crates: core, config, verify, jose, dpop, replay, http, cli. | must | implemented | architecture | `Cargo.toml:1`; `AGENTS.md` | architecture guard | Unexpected crates are a guard failure. |
| R-010 | Rust must not mirror the Python tree one-for-one without a Rust ownership reason. | policy | implemented | architecture | `AGENTS.md`; issue #3 | architecture guard | Python facades are oracle evidence, not crate names. |
| R-011 | Transport dependencies must stay in `sts-http`. | must-not | implemented | architecture | `scripts/check_architecture_boundaries.py:35` | architecture guard | Axum/http/tower outside HTTP fail the guard. |
| R-012 | Network JWKS/discovery dependencies must stay in `sts-verify`. | must-not | implemented | architecture | `scripts/check_architecture_boundaries.py:36` | architecture guard | `reqwest` direct deps outside verify fail. |
| R-013 | Tokio must not bleed into lower crates except the verify network boundary. | must-not | implemented | architecture | `scripts/check_architecture_boundaries.py:37` | architecture guard | Avoid async runtime coupling in policy/crypto crates. |
| R-014 | Workspace normal dependency graph must remain acyclic. | must | implemented | architecture | `scripts/check_architecture_boundaries.py:64` | architecture guard | Cycles fail release checks. |
| R-015 | `sts-core` owns token-exchange policy and claim shaping, not HTTP or crypto. | must | implemented | core | `crates/sts-core/src/lib.rs:3` | `cargo test -p sts-core` | Keep signing out of core. |
| R-016 | `sts-config` owns env parsing and deployment policy loading. | must | implemented | config | `crates/sts-config/src/lib.rs:3` | `cargo test -p sts-config --lib` | No hidden env reads in imports. |
| R-017 | `sts-verify` owns trust anchors, discovery, JWKS fetch, and JWT verification. | must | implemented | verify | `crates/sts-verify/src/lib.rs:3` | `cargo test -p sts-verify --lib` | HTTP composes verification, but does not own it. |
| R-018 | `sts-jose` owns JOSE/JWK/JWKS and signing backend selection. | must | implemented | jose | `crates/sts-jose/src/lib.rs:3` | `cargo test -p sts-jose --lib` | PQC selection must fail closed until real backend. |
| R-019 | `sts-dpop` owns stateless RFC 9449 proof validation and holder-key binding. | must | implemented | dpop | `crates/sts-dpop/src/lib.rs:3` | `cargo test -p sts-dpop --lib` | Replay recording remains in replay/http. |
| R-020 | `sts-replay` owns replay state and fixed-size replay keys. | must | implemented | replay | `crates/sts-replay/src/lib.rs:3` | `cargo test -p sts-replay --lib` | Multi-worker shared store is future work. |
| R-021 | `sts-http` owns route names, response headers, form parsing, and OAuth error rendering. | must | implemented | http | `crates/sts-http/src/lib.rs:3` | HTTP contract tests | HTTP must call lower crates for policy. |
| R-022 | `sts-cli` is currently a thin ops boundary with no hidden runtime behavior. | policy | partial | cli | `crates/sts-cli/src/main.rs:3` | compile only | Full CLI is planned, not shipped. |
| R-023 | The public HTTP surface is `POST /token`, `GET /jwks`, and `GET /.well-known/oauth-authorization-server`. | must | implemented | http | `crates/sts-http/src/lib.rs:104`; Python `transport.py:150` | `contract_discovery_and_jwks_match_python_oracle_shape` | `/exchange` must not return. |
| R-024 | Path-bearing issuers must have live path-aware metadata, token, and JWKS aliases. | must | implemented | http | RFC 8414 Section 3.1; `crates/sts-http/src/lib.rs:110` | `contract_path_bearing_issuer_advertised_endpoints_are_live` | Root aliases remain live during alpha. |
| R-025 | Metadata must use GET; POST to metadata must be method-not-allowed. | must | implemented | http | RFC 8414 Section 3.1; `crates/sts-http/src/lib.rs:108` | `contract_metadata_is_public_and_get_only` | Authorization header does not block metadata. |
| R-026 | Metadata `issuer` must equal configured STS issuer. | must | implemented | http | RFC 8414 Section 3.2; `crates/sts-http/src/lib.rs:300` | `contract_discovery_and_jwks_match_python_oracle_shape` | Exact string equality matters. |
| R-027 | Metadata must advertise `token_endpoint` and `jwks_uri` derived from the STS issuer. | must | implemented | http | RFC 8414 Section 2; `crates/sts-http/src/lib.rs:84` | HTTP contract tests | Path-bearing issuer values must be reachable. |
| R-028 | Metadata must advertise token exchange as the supported grant type. | must | implemented | http | RFC 8693 Section 2.1; `crates/sts-http/src/lib.rs:305` | metadata contract test | No full AS grant claims yet. |
| R-029 | Metadata must advertise only `private_key_jwt` for token endpoint client auth. | policy | implemented | http/client-auth | Python `client_auth.py:1`; `crates/sts-http/src/lib.rs:306` | metadata contract test | Basic/Bearer header auth rejected. |
| R-030 | Metadata must advertise only assertion signing algorithms actually enforced. | must | partial | http/verify | Python `client_auth.py:12`; `crates/sts-http/src/lib.rs:307` | metadata contract test | Current Rust advertises RS256 only. |
| R-031 | Metadata must advertise only DPoP algorithms the verifier accepts. | must | implemented | dpop/http | RFC 9449; `crates/sts-dpop/src/lib.rs:19` | metadata contract test | HS256 and none must not appear. |
| R-032 | `/jwks` must publish public STS signing keys only. | must | implemented | jose/http | `crates/sts-http/src/lib.rs:295`; `crates/sts-jose/src/lib.rs:282` | JWKS contract test | Private JWK members must not leak. |
| R-033 | `/jwks` responses must be public cacheable with max-age. | policy | implemented | http | Python `tests/test_integration.py:612`; `crates/sts-http/src/lib.rs:295` | `contract_discovery_and_jwks_match_python_oracle_shape` | Token responses use no-store instead. |
| R-034 | `/token` must accept only `application/x-www-form-urlencoded`. | must | implemented | http | RFC 8693 Section 2.1; `crates/sts-http/src/lib.rs:316` | `contract_token_rejects_wrong_content_type_and_duplicate_form_params` | JSON/multipart fail 4xx, not 500. |
| R-035 | `/token` must reject duplicate recognized form parameters. | must | implemented | http | RFC 6749 Section 3.1; `crates/sts-http/src/lib.rs:320` | duplicate form test | Duplicate target parameters map to invalid_target. |
| R-036 | Unknown extension request parameters must be ignored unless a recognized gate fails. | policy | implemented | http/core | Python `tests/test_integration.py:206`; issue #17 | `contract_unknown_extension_params_are_ignored` | Fresh actor assertion required when testing around replay. |
| R-037 | `/token` must reject Authorization header client auth and direct callers to private_key_jwt. | policy | implemented | http/client-auth | `crates/sts-http/src/lib.rs:350`; issue #4 | `contract_authorization_header_client_auth_is_rejected` | Preserve WWW-Authenticate scheme. |
| R-038 | `/token` responses and errors must include `Cache-Control: no-store` and `Pragma: no-cache`. | must | implemented | http | RFC 6749 Section 5.1; Python `tests/test_integration.py:550`; `crates/sts-http/src/lib.rs:267` | token/error contract tests | Metadata/JWKS are public-cacheable. |
| R-039 | OAuth error responses must be JSON and include stable `error` and `error_description` when OAuth-shaped. | must | implemented | http | RFC 6749 Section 5.2; `crates/sts-http/src/lib.rs:282` | HTTP contract tests | Service-unavailable may omit OAuth `error`. |
| R-040 | Unexpected internal failures must map to clean `server_error` without leaking internal detail. | must | open | http | Python `tests/test_integration.py:732` | missing Rust test | Add catch-all/panic-safe HTTP test. |
| R-041 | Old `/exchange` route must remain absent. | must-not | implemented | http | Python `tests/test_integration.py:751`; issue #17 | `contract_exchange_route_remains_absent` | `/token` is the only token-exchange route. |
| R-042 | Interactive docs must be off by default if/when served. | policy | open | http/ops | Python `transport.py:78` | missing Rust scope | Rust has no docs UI yet. |
| R-043 | OpenAPI, if shipped, must be curated and drift-checked. | policy | missing | http/docs | Python `transport.py:78` | no Rust OpenAPI | Future issue needed before full HTTP release. |
| R-044 | Metrics, if shipped, must be opt-in and not alter protocol behavior. | policy | missing | http/ops | Python `transport.py:85` | no Rust metrics | Future issue. |
| R-045 | Token exchange grant type must be exactly `urn:ietf:params:oauth:grant-type:token-exchange`. | must | implemented | core/http | RFC 8693 Section 2.1; `crates/sts-core/src/lib.rs:12` | HTTP contract tests | Bad grant returns unsupported_grant_type. |
| R-046 | `subject_token` is required and must not exceed configured max token length. | must | implemented | http/verify | RFC 8693 Section 2.1; `crates/sts-http/src/lib.rs:388` | HTTP unit tests | Oversized input fails before crypto. |
| R-047 | `subject_token_type` is required and only access_token or jwt are accepted for inbound subject tokens. | policy | implemented | http/verify | `crates/sts-http/src/lib.rs:28`; issue #11 | HTTP contract tests | Unsupported type is invalid_request. |
| R-048 | `actor_token_type` is required when `actor_token` is present. | must | implemented | http | RFC 8693 Section 2.1; Python `tests/test_integration.py:220` | HTTP tests | Empty actor token remains present and malformed. |
| R-049 | `actor_token_type` must not be accepted without actor token. | must | implemented | http | RFC 8693 Section 2.1; issue #17 | `contract_actor_token_type_without_actor_token_is_rejected` | Rejected before subject-token verification. |
| R-050 | `requested_token_type` absent means the STS mints its default access_token type. | policy | implemented | core/http | RFC 8693 Section 2.1; issue #11 | requested-token contract test | Default issued_token_type is access_token. |
| R-051 | `requested_token_type=access_token` is accepted. | must | implemented | http | issue #11; Python `tests/test_integration.py:178` | requested-token contract test | Response still JWT-formatted at+jwt token. |
| R-052 | `requested_token_type=jwt` is rejected to avoid acknowledging one type while reporting access_token. | policy | implemented | http | issue #11; Python `tests/test_integration.py:178` | requested-token contract test | Intentional Python parity choice. |
| R-053 | Unsupported requested token types return `invalid_request`. | must | implemented | http | RFC 8693 Section 2.2.2; `crates/sts-http/tests/http_contract.rs:615` | requested-token contract test | SAML2 currently unsupported. |
| R-054 | Exactly one target must be resolved from `audience` and/or `resource`. | policy | implemented | core/http | RFC 8693 Section 2.1.1; `crates/sts-core/src/lib.rs:155` | core tests | Both present must agree. |
| R-055 | `resource` values must be absolute URIs and must not contain fragments. | must | implemented | core | RFC 8693 Section 2.1; `crates/sts-core/src/lib.rs:283` | core tests | Relative resource rejected. |
| R-056 | Unknown targets are denied by default with `invalid_target`. | must | implemented | core/http/config | Python `tests/test_integration.py:170`; `crates/sts-config/src/lib.rs:576` | HTTP/core tests | Empty target policy denies every target. |
| R-057 | Scopes must be downscoped against target allowed scopes. | must | implemented | core | Python `tests/test_integration.py:162`; `crates/sts-core/src/lib.rs:183` | core tests | No remaining scope returns invalid_scope. |
| R-058 | Scope strings are space-delimited and case-sensitive. | must | implemented | core | RFC 8693 Section 2.1; `crates/sts-core/src/lib.rs:303` | core tests | Dedup behavior remains open. |
| R-059 | Default scopes are used when no requested scope is supplied. | policy | implemented | http/config | `crates/sts-http/src/lib.rs`; `crates/sts-config/src/lib.rs:91` | HTTP tests | Empty default scope can deny. |
| R-060 | Subject token must validate before token issuance. | must | implemented | verify/http | RFC 8693 Section 2.1; `crates/sts-verify/src/lib.rs:293` | verify/http tests | Invalid subject maps to invalid_grant. |
| R-061 | Subject token issuer must equal pinned IdP issuer. | must | implemented | verify | Python `tests/test_integration.py:407`; `crates/sts-verify/src/lib.rs:307` | verify tests | Issuer comparison is exact. |
| R-062 | Subject token audience must match configured accepted audiences. | must | implemented | verify | `crates/sts-verify/src/lib.rs:313` | verify/http tests | String or array audiences accepted. |
| R-063 | Subject token must contain usable `sub`; minted token preserves it. | must | implemented | core/http | Python `tests/test_integration.py:127`; `crates/sts-http/src/lib.rs:406` | HTTP contract tests | Missing/empty sub fails invalid_grant. |
| R-064 | Subject token expiration and `nbf` must be enforced with clock skew leeway. | must | implemented | verify | `crates/sts-verify/src/lib.rs:397` | verify tests | Future nbf rejected. |
| R-065 | The minted access token must have header `typ=at+jwt`. | must | implemented | jose/core | RFC 9068 Section 2.1; Python `tests/test_integration.py:139`; `crates/sts-jose/src/lib.rs:356` | HTTP contract tests | Generic assertions keep `typ=JWT`. |
| R-066 | Minted access tokens must be RS256 in the classical default runtime. | must | implemented | jose | `crates/sts-jose/src/lib.rs:351`; issue #5 | JOSE tests | PQC not silently substituted. |
| R-067 | Minted claims must include `iss`, `sub`, `aud`, `scope`, `iat`, `exp`, `jti`, and `client_id`. | must | implemented | core | RFC 9068 Section 2.2; Python `tests/test_integration.py:139`; `crates/sts-core/src/lib.rs:53` | core/http tests | Optional claims omitted if absent. |
| R-068 | Delegation tokens preserve subject in `sub` and carry actor in `act.sub`. | must | implemented | core/http | RFC 8693 Section 1.1/4.1; `crates/sts-core/src/lib.rs:217` | delegation contract test | Actor is not promoted to top-level sub. |
| R-069 | Impersonation tokens preserve subject in `sub` and omit `act`. | must | implemented | core/http | RFC 8693 Section 1.1; issue #12 | impersonation contract tests | Client is stamped in `client_id`. |
| R-070 | Nested incoming `act` chains must be preserved when building delegation `act`. | must | implemented | core | RFC 8693 Section 4.1; `crates/sts-core/src/lib.rs:217` | `build_act_nests_prior_chain` | Full incoming nested-chain verification remains partial. |
| R-071 | `client_id` in delegation mode equals the actor identity. | policy | implemented | core/http | Python `domain/payload.py:39`; HTTP tests | delegation contract test | Multiple actors require correct one. |
| R-072 | `client_id` in impersonation mode equals authenticated private_key_jwt client. | policy | implemented | http/core | issue #12; Python `tests/test_impersonation.py:299` | impersonation contract tests | Actor-token-only cannot impersonate. |
| R-073 | Optional auth-context claims `auth_time`, `acr`, and `amr` are copied when present and omitted when absent. | must | partial | core/http | Python `domain/payload.py:18`; Python `tests/test_integration.py:232` | core omits absent | Rust carry-forward not fully wired. |
| R-074 | Minted token `exp` must be no later than now + configured scoped token TTL. | must | implemented | http/core | `crates/sts-http/src/lib.rs`; Python `domain/payload.py:28` | HTTP tests | TTL defaults to 300. |
| R-075 | Minted token `exp` must not outlive the subject token. | must | implemented | http/core | Python `tests/test_integration.py:678`; Python `domain/payload.py:28` | `contract_delegation_lifetime_is_capped_by_subject_and_actor_exp` | Covers delegation and impersonation subject cap. |
| R-076 | Delegation minted token `exp` must not outlive the actor token. | must | implemented | http/core | Python `tests/test_integration.py:693`; Python `domain/payload.py:28` | `contract_delegation_lifetime_is_capped_by_subject_and_actor_exp` | Actor cap is delegation-specific. |
| R-077 | `expires_in` must reflect actual minted lifetime after any cap. | must | implemented | http | RFC 6749 Section 5.1; Python `tests/test_integration.py:709` | `contract_delegation_lifetime_is_capped_by_subject_and_actor_exp` | Avoids over-stating token validity. |
| R-078 | Minted token `jti` must be a non-empty generated string. | must | implemented | http/core | RFC 7519 Section 4.1.7; `crates/sts-http/src/lib.rs` | HTTP contract tests | Resource server can do replay checks. |
| R-079 | The STS signing JWKS must not include private members. | must-not | implemented | jose/http | `crates/sts-jose/src/lib.rs:88`; Python `tests/test_integration.py:620` | JWKS contract test | Extra-JWKS file loading not yet in Rust. |
| R-080 | Classical signing backend selection accepts blank, `classical`, and `RS256`. | policy | implemented | jose | `crates/sts-jose/src/lib.rs:31` | JOSE tests | Case-insensitive parsing. |
| R-081 | PQC or unknown signing backend selection must fail closed and never instantiate RS256. | must-not | implemented | jose/security | issue #5; `crates/sts-jose/src/lib.rs:426` | JOSE tests | Native PQC remains missing. |
| R-082 | Real PQC support must be first-class when implemented, not marker-only or fallback-only. | must | missing | jose/security | issue #2; repo instructions | no implementation | Future issue needed. |
| R-083 | Client assertion auth uses `private_key_jwt` assertion type. | must | implemented | http/verify | RFC 7523; `crates/sts-http/src/lib.rs:42` | HTTP tests | Wrong/missing assertion type rejected. |
| R-084 | Client assertion `iss` and `sub` must match. | must | implemented | verify | RFC 7523; `crates/sts-verify/src/lib.rs:328` | verify/http tests | Prevent confused identities. |
| R-085 | `client_id` form value must match authenticated client assertion subject. | must | implemented | http | issue #7; `crates/sts-http/tests/http_contract.rs:1337` | client mismatch test | Error is invalid_client. |
| R-086 | Client assertion audience must identify this STS issuer or token endpoint. | must | implemented | verify/http | RFC 7523; `crates/sts-verify/src/lib.rs:334` | verify/http tests | Path-bearing issuer endpoints included. |
| R-087 | Client assertion lifetime must not exceed configured max TTL plus skew. | must | implemented | verify | `crates/sts-verify/src/lib.rs:414` | verify tests | Missing iat uses now-based span. |
| R-088 | Client assertion signing key `kid` must belong to the claimed client identity. | must | implemented | verify/http | issue #7; `crates/sts-verify/src/lib.rs:371` | cross-client-key tests | Longest registered prefix wins. |
| R-089 | Actor assertion signing key `kid` must belong to the claimed actor identity. | must | implemented | verify/http | issue #10; `crates/sts-http/tests/http_contract.rs:1408` | cross-domain actor key test | Uses actor/client registry. |
| R-090 | Actor assertion must be bound to the presented subject token when subject binding is required. | must | implemented | verify/http | Python `tests/test_integration.py:367`; `crates/sts-verify/src/lib.rs:358` | verify tests | Constant-time hash comparison. |
| R-091 | Subject-token hash binding uses SHA-256 base64url over the presented subject token. | policy | implemented | verify | `crates/sts-verify/src/lib.rs:453`; Python `crypto.subject_token_hash` | verify tests | Exact hash format is parity-critical. |
| R-092 | `may_act` authorizes delegation, not impersonation. | must | partial | core/http | RFC 8693 Section 4.4; Python `tests/test_impersonation.py:414` | impersonation tests | Rust delegation may_act parity needs expansion. |
| R-093 | Delegation mode requires actor token. | must | implemented | http | Python `tests/test_impersonation.py:284`; `crates/sts-http/src/lib.rs:426` | HTTP tests | If client auth present, error is invalid_request. |
| R-094 | Impersonation mode requires private_key_jwt client auth. | must | implemented | http | Python `tests/test_impersonation.py:395`; issue #12 | impersonation tests | Actor-token-only cannot impersonate. |
| R-095 | `both` mode dispatches to delegation when actor_token is present. | policy | implemented | http/config | Python `tests/test_impersonation.py:434`; `crates/sts-config/src/lib.rs:75` | HTTP tests | Empty actor_token is present malformed. |
| R-096 | `both` mode dispatches to impersonation when actor_token is absent and client assertion exists. | policy | implemented | http/config | Python `tests/test_impersonation.py:444` | HTTP tests | Missing policy still denies. |
| R-097 | Empty present actor_token must not be treated as absent impersonation. | must-not | implemented | http | Python `tests/test_impersonation.py:458` | `contract_both_mode_dispatches_by_actor_token_presence` | Present-empty remains malformed and mints no token. |
| R-098 | Impersonation policy is deny-by-default when no client entry exists. | must | implemented | config/http | issue #12; Python `tests/test_impersonation.py:316` | impersonation tests | Wrong client is invalid_request. |
| R-099 | Impersonation policy supports per-client target allowlists. | must | implemented | config/http | issue #12; `crates/sts-config/src/lib.rs:114` | impersonation policy tests | Wrong target maps invalid_target. |
| R-100 | Impersonation policy supports per-client subject allowlists. | must | implemented | config/http | issue #12; `crates/sts-config/src/lib.rs:120` | impersonation policy tests | Wrong subject maps invalid_request. |
| R-101 | Impersonation selector `"*"` means any target or subject for that selector only. | policy | implemented | config/http | Python `tests/test_impersonation.py:152`; `crates/sts-config/src/lib.rs:660` | config tests | Missing field is empty set, not star. |
| R-102 | Actor token `jti` must be non-empty and single-use per actor namespace. | must | implemented | replay/http | RFC 7519 Section 4.1.7; Python `application/replay_records.py:22`; `crates/sts-http/src/lib.rs:445` | replay/http tests | Same jti across actors does not collide. |
| R-103 | Client assertion `jti` must be recorded only after late gates pass. | must | partial | replay/http | Python `application/exchange.py:87`; oracle smoke test list | oracle smoke | Add explicit Rust late-failure test. |
| R-104 | DPoP proof `jti` must be single-use per holder key thumbprint. | must | implemented | dpop/replay | RFC 9449 Section 4.3; `crates/sts-replay/src/lib.rs:156` | dpop replay contract test | Replay key is `sha256(jkt || NUL || jti)`. |
| R-105 | Replay store must reject empty jti. | must | implemented | replay | `crates/sts-replay/src/lib.rs:93` | replay tests | Actor/client layers map to OAuth errors. |
| R-106 | Replay store full must fail closed with service_unavailable semantics. | must | implemented | replay/http | `crates/sts-replay/src/lib.rs:114` | replay tests | Retry-After set by HTTP mapping. |
| R-107 | DPoP proof must be a compact JWT and under the local max proof length. | must | implemented | dpop | RFC 9449 Section 11.1; `crates/sts-dpop/src/lib.rs:27` | dpop tests | Oversized proof rejected before signature work. |
| R-108 | DPoP proof must use `typ=dpop+jwt`. | must | implemented | dpop | RFC 9449 Section 4.3; `crates/sts-dpop/src/lib.rs:171` | dpop tests | `JWT` rejected. |
| R-109 | DPoP proof algorithm must be an accepted asymmetric algorithm, not `none` or MAC. | must | implemented | dpop | RFC 9449 Section 4.3; `crates/sts-dpop/src/lib.rs:178` | dpop tests | HS256 rejected. |
| R-110 | DPoP proof header must carry a valid public JWK and no private key material. | must | implemented | dpop | RFC 9449 Section 4.3; `crates/sts-dpop/src/lib.rs:189` | dpop tests | `d`, RSA CRT, and `k` members rejected. |
| R-111 | DPoP proof signature must verify against the embedded public JWK. | must | implemented | dpop | RFC 9449 Section 4.3; `crates/sts-dpop/src/lib.rs:226` | dpop tests | Embedded key mismatch rejected. |
| R-112 | DPoP proof requires non-empty string `jti`, `htm`, `htu`, and finite numeric `iat`. | must | implemented | dpop | RFC 9449 Section 4.3; `crates/sts-dpop/src/lib.rs:243` | dpop tests | Non-string fields rejected cleanly. |
| R-113 | DPoP `htm` comparison is case-insensitive. | policy | implemented | dpop | Python `tests/test_dpop.py:105`; `crates/sts-dpop/src/lib.rs:258` | dpop tests | HTTP method token case ignored. |
| R-114 | DPoP `htu` comparison strips query and fragment and normalizes scheme/host/default port/trailing slash. | policy | implemented | dpop | Python `dpop.py:56`; `crates/sts-dpop/src/lib.rs:265` | dpop tests | Path remains case-sensitive. |
| R-115 | DPoP `iat` must be within clock skew leeway. | must | implemented | dpop | RFC 9449 Section 4.3; `crates/sts-dpop/src/lib.rs:276` | dpop tests | Future and stale outside window reject. |
| R-116 | DPoP replay retention expires at proof `iat + leeway`, not observation time + leeway. | must | implemented | dpop/replay | Python `tests/test_integration.py:289`; `crates/sts-dpop/src/lib.rs:120` | dpop/replay tests | Future-skew proof stays protected. |
| R-117 | DPoP-bound minted tokens must include `cnf: {"jkt": ...}` and return `token_type=DPoP`. | must | implemented | core/http | RFC 9449 Section 6; Python `tests/test_integration.py:256`; `crates/sts-core/src/lib.rs:66` | DPoP contract tests | No top-level `cnf_jkt`. |
| R-118 | Non-DPoP exchanges must return `token_type=Bearer` and omit `cnf`. | must | implemented | core/http | Python `tests/test_integration.py:256`; `crates/sts-core/src/lib.rs:64` | DPoP/delegation contract tests | Library-only path unchanged. |
| R-119 | DPoP duplicate or malformed headers must return `invalid_dpop_proof`. | must | implemented | http/dpop | RFC 9449 Section 5; `crates/sts-http/tests/http_contract.rs:518` | DPoP contract test | Duplicate header does not fall through. |
| R-120 | DPoP `ath` is not a token-endpoint requirement for this STS; resource-server proof checking is out of current scope. | non-goal | implemented | dpop | Python `dpop.py:84`; RFC 9449 | no RS endpoint | Revisit only with resource-server support. |
| R-121 | Runtime config must require IdP issuer and expected subject audience. | must | implemented | config | `crates/sts-config/src/lib.rs:373` | config tests | OKTA_ISSUER is compatibility alias for IDP_ISSUER. |
| R-122 | Runtime config must require at least one actor identity. | must | implemented | config | `crates/sts-config/src/lib.rs:425` | config tests | `GATEWAY_ACTOR_ID` contributes to actor IDs. |
| R-123 | Target policy JSON or file must parse to object entries with string array scopes. | must | implemented | config | `crates/sts-config/src/lib.rs:584` | config tests | Entries beginning `_` are ignored. |
| R-124 | Invalid config values must fail startup/config load before serving traffic. | must | partial | config/http | Python `tests/test_integration.py:597`; `crates/sts-config/src/lib.rs:211` | config tests | HTTP bootstrap still needs product entrypoint. |
| R-125 | Source releases are GitHub tag archives until crates.io publishing is explicitly planned. | policy | implemented | release | `README.md:20`; issue #9 | release audit | `cargo package --workspace` is not the alpha gate. |
| R-126 | Release validation requires fmt, workspace tests, clippy, architecture guard, oracle smoke, and diff check. | policy | implemented | release | issue #2 comments; `README.md:24` | alpha.4 validation | Supply-chain helper CLIs remain optional until installed. |
| R-127 | The requirements ledger must not close #2 until 100+ requirements and 20+ use cases are canonical. | must | implemented | PM | issue #2 | this ledger | Close only after issue update and validation. |
| R-128 | Full Authorization Server features such as authorization endpoint, revocation, introspection, and registration are non-goals for current STS alpha. | non-goal | implemented | PM/http | Python docs; `README.md:3` | no routes | Future AS expansion requires new milestone. |
| R-129 | Full CLI, rotation, canary, and ops helpers are planned v2 product work but not shipped in alpha. | policy | missing | cli/ops | `README.md:14`; `crates/sts-cli/src/main.rs:3` | compile only | Needs dedicated issue. |
| R-130 | Native PQC signing/JWKS/downstream verification is a v2 requirement, but alpha currently only provides fail-closed selection. | must | missing | jose/security | repo instructions; `crates/sts-jose/src/lib.rs:5` | JOSE fail-closed tests | Needs dedicated implementation issue before claim. |
| R-131 | Live tenant validation must use the configured real Okta trial issuer; `example.com`, `issuer.example`, `sts.example`, and `*.example.*` are fixture-only and must not close readiness issues. | must | partial | tests/security | issue #21; Python `run-real-idp-canary.md`; `/Users/Shared/claude/obo-lab/okta.env` | ad hoc live Rust/Python Okta harness | Needs committed canary script before readiness closeout. |
| R-132 | Runtime STS issuer values must reject query components, fragment components, and non-loopback HTTP. | must | open | config/security | issue #13; Python `tests/test_stress.py:920`; Python `infrastructure/config_env.py:47` | missing Rust config test | Decide and test whether Python's loopback HTTP dev exception is preserved. |

## Use Cases

| ID | Actor | Trigger | Preconditions | Main flow | Alternate flow | Failure flow | Expected result | Requirement map |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| UC-01 | MCP server actor | Exchange user token for downstream token | Valid subject token, valid actor assertion, target policy permits target | POST form to `/token`; verify subject; verify actor; downscope; mint at+jwt | DPoP absent means Bearer token | Unknown target returns invalid_target | Delegated token has user `sub`, actor `act.sub`, scoped `aud` | R-023, R-045, R-060, R-068 |
| UC-02 | MCP server actor | Exchange with DPoP sender constraint | UC-01 plus valid DPoP proof | Validate proof; mint token with `cnf.jkt`; record DPoP replay | No proof preserves Bearer path | Replayed proof returns invalid_dpop_proof | Token type is DPoP and token is bound to holder key | R-107 through R-119 |
| UC-03 | Private client | Delegation with private_key_jwt plus actor token | Client assertion and actor assertion both valid | Authenticate client; validate actor; mint delegated token | Actor-token compatibility path may work without client assertion | Missing actor token fails delegation | Delegation still requires actor proof | R-083 through R-093 |
| UC-04 | Private client | Impersonation token exchange | Impersonation mode enabled, client policy permits target/subject | Authenticate client; verify subject; gate impersonation policy; mint without act | DPoP may bind impersonation token | No policy denies invalid_request | Token has subject sub, no act, client_id of client | R-069, R-094 through R-101 |
| UC-05 | Operator | Start service from env config | Required issuer, subject audience, actor IDs, target policy available | Load RuntimeConfig from env/source map | OKTA_ISSUER can supply issuer alias | Missing issuer/audience/actor fails load | Bad config, including unsafe or ambiguous issuer values, fails before useful traffic | R-121 through R-124, R-132 |
| UC-06 | Resource server | Discover STS metadata | STS issuer configured | GET metadata endpoint | Path-bearing issuer uses RFC 8414 inserted path | POST metadata returns 405 | Metadata identifies issuer, token endpoint, JWKS URI, auth methods | R-024 through R-031 |
| UC-07 | Resource server | Fetch signing keys | STS signer initialized | GET `/jwks` | Path alias works for path-bearing issuer | Private key members never appear | Public JWKS can verify minted tokens | R-032, R-033, R-079 |
| UC-08 | Security reviewer | Validate architecture boundary | Rust workspace present | Run architecture guard | Add new crate only with guard update | Transport/network deps in lower crates fail | Dependency direction stays explicit | R-009 through R-014 |
| UC-09 | Release manager | Cut source alpha tag | Clean main, validation green | Run fmt/test/clippy/guards/oracle smoke; tag release | Source-only release allowed | crates.io package failure does not block alpha | GitHub prerelease with caveats | R-125, R-126 |
| UC-10 | Test engineer | Compare Python oracle and Rust | Sibling Python repo or override path exists | Run oracle smoke script | Custom PYTHON_ORACLE_REPO/PYTHON_BIN allowed | Missing oracle repo exits 2 | Focused offline Python and Rust parity tests pass without implying live tenant readiness | R-002, R-126, R-131 |
| UC-11 | Client developer | Send malformed form | `/token` reachable | POST invalid content type or duplicate param | Unknown extension params ignored | Recognized duplicate returns OAuth error | Clean 4xx JSON, not 500 | R-034 through R-040 |
| UC-12 | Tenant operator | Use issuer path `/tenant1` | Real configured Okta trial issuer and STS issuer path are available; synthetic issuer values are fixture-only | Discover at `/.well-known/oauth-authorization-server/tenant1`; call aliases | Root `/token` and `/jwks` remain live in alpha | Advertised endpoint 404 is regression | Multi-tenant issuer metadata is usable and live proof does not rely on `example.com` | R-024, R-027, R-131 |
| UC-13 | Actor service | Reuse actor jti accidentally | First exchange already recorded jti | Second exchange attempts same actor/jti | Different actor may reuse same raw jti | Same actor reuse rejected | Actor replay is per-actor namespace | R-102 |
| UC-14 | DPoP client | Send proof with future-edge iat | `iat` within leeway | Record replay until `iat + leeway` | Normal iat expires at same formula | Reuse before expiry rejected | Future-skew replay gap closed | R-115, R-116 |
| UC-15 | Client | Request `requested_token_type=jwt` | Valid otherwise | POST token exchange with jwt requested type | access_token requested type succeeds | jwt returns invalid_request | Python parity is preserved | R-050 through R-053 |
| UC-16 | Product manager | Decide v2/v1 boundary | Requirements ledger current | Use migration map to split work by crate/lane | Defer full AS/CLI/PQC with explicit issues | No beta claim until blockers closed | Roadmap remains honest | R-127 through R-130 |
| UC-17 | Security engineer | Audit DPoP proof header | Proof arrives with embedded JWK | Reject private members; enforce alg/key match | RSA/EC/OKP accepted when alg compatible | none/HS/private JWK fails | Proof proves holder key only | R-107 through R-112 |
| UC-18 | Integrator | Use path-independent quickstart values | Actor `chat-mcp`, target `api://chat-mcp`, subject aud `api://obo` | Generate subject/actor tokens and exchange | Scope can be narrowed | Drift from docs breaks oracle | Guide flow stays executable | R-023, R-057, R-068 |
| UC-19 | Resource server | Verify at+jwt access token | Has STS JWKS | Verify RS256 signature, `typ=at+jwt`, claims | DPoP token additionally checks cnf at RS | Wrong typ/alg/kid rejected | Minted token is inspectable and verifiable | R-065 through R-067, R-117 |
| UC-20 | Future crypto implementer | Enable native PQC backend | Real backend, JWS/JWK support, tests exist | Select PQC explicitly; publish matching JWKS; sign and verify | Classical remains default unless configured | Missing backend fails closed | PQC is real capability, not silent downgrade | R-080 through R-082, R-130 |
| UC-21 | Operator | Rotate or inspect keys via CLI | Future CLI commands exist | CLI loads config and key custody safely | Dry-run/canary validates outputs | Unsafe key file refuses by default | Ops helpers do not mutate protocol semantics | R-079, R-124, R-129 |
| UC-22 | Auditor | Check issue closure evidence | Issue references implementation and tests | Read issue comments and commit SHA | Comments can defer with explicit caveat | Stale evidence cannot close issue | Issue trail is reviewable | R-001, R-005, R-126 |

## Negative Cases / Must-Not Cases

| ID | Case | Expected behavior | Source(s) | Requirements |
| --- | --- | --- | --- | --- |
| N-01 | JSON body sent to `/token` | `invalid_request`, 4xx | Rust HTTP contract; Python `tests/test_integration.py:438` | R-034 |
| N-02 | Duplicate `grant_type` | `invalid_request` | Rust HTTP contract | R-035 |
| N-03 | Duplicate `audience` | `invalid_target` | Rust HTTP contract | R-035 |
| N-04 | Authorization Basic header at `/token` | `invalid_client`, WWW-Authenticate Basic | Rust HTTP contract | R-037 |
| N-05 | Authorization Bearer mixed with private_key_jwt | `invalid_client`, WWW-Authenticate Bearer | Rust HTTP contract | R-037 |
| N-06 | Wrong grant type | `unsupported_grant_type` | Rust HTTP contract | R-045 |
| N-07 | Unknown target | `invalid_target` | Python integration; Rust HTTP/core | R-056 |
| N-08 | No remaining scopes after downscope | `invalid_scope` | Rust core tests | R-057 |
| N-09 | `requested_token_type=jwt` | `invalid_request` | issue #11; Rust contract | R-052 |
| N-10 | Actor token without actor_token_type | `invalid_request` | Python integration | R-048 |
| N-11 | actor_token_type without actor_token | reject | RFC 8693 | R-049 |
| N-12 | Delegation without actor token | reject | Rust HTTP tests | R-093 |
| N-13 | Impersonation without private_key_jwt | reject | Python impersonation tests | R-094 |
| N-14 | Impersonation with wrong target | `invalid_target` | issue #12 | R-099 |
| N-15 | Impersonation with wrong subject | `invalid_request` | issue #12 | R-100 |
| N-16 | Private key in DPoP JWK | `invalid_dpop_proof` | Rust/Python DPoP tests | R-110 |
| N-17 | DPoP alg `none` or HS256 | `invalid_dpop_proof` | Rust/Python DPoP tests | R-109 |
| N-18 | DPoP signature not made by embedded key | `invalid_dpop_proof` | Python DPoP tests | R-111 |
| N-19 | DPoP stale/future iat outside leeway | `invalid_dpop_proof` | Rust/Python DPoP tests | R-115 |
| N-20 | DPoP replay | `invalid_dpop_proof` | Rust HTTP contract | R-104 |
| N-21 | Actor jti replay by same actor | reject | Python integration; Rust replay | R-102 |
| N-22 | Client assertion signed by another client key | `invalid_client` | issue #7 | R-088 |
| N-23 | Actor assertion signed by cross-domain client key | `invalid_client` | issue #10 | R-089 |
| N-24 | PQC requested with no backend | unsupported algorithm, no RS256 fallback | issue #5 | R-081 |
| N-25 | Private members in `/jwks` | must never publish | Rust HTTP/JWKS tests | R-032, R-079 |
| N-26 | Unexpected internal error leaks detail | must not leak; clean server_error | Python integration | R-040 |
| N-27 | `/exchange` route exists | must stay 404 | Python integration | R-041 |
| N-28 | Transport dependency added to lower crate | architecture guard failure | issue #3 | R-011 |
| N-29 | Unsafe code added silently | architecture/security failure | workspace lints | R-007 |
| N-30 | Full OAuth AS capability claimed in alpha | must not claim | README release shape | R-128 |
| N-31 | STS issuer contains query, fragment, or non-loopback HTTP scheme | reject config load | issue #13; Python stress tests | R-132 |

## Edge Case Register

| ID | Edge case | Required handling | Source(s) | Requirements |
| --- | --- | --- | --- | --- |
| E-01 | Path-bearing issuer with trailing slash | strip trailing slash for route derivation | RFC 8414 Section 3.1; Rust HTTP | R-024 |
| E-02 | Metadata queried with Authorization header | still public OK | Rust HTTP contract | R-025 |
| E-03 | `response_types_supported` has no values | current Rust returns empty array | Rust HTTP metadata | R-026 |
| E-04 | Unknown extension form param | ignore | Python integration | R-036 |
| E-05 | `resource` relative URI | reject invalid_target | Rust core test | R-055 |
| E-06 | `resource` has fragment | reject invalid_target | RFC 8693; Rust core | R-055 |
| E-07 | `audience` and `resource` both set and equal | accept | Rust core test | R-054 |
| E-08 | `audience` and `resource` mismatch | reject invalid_target | Rust core test | R-054 |
| E-09 | Subject `aud` as JSON array | accept if any expected matches | Rust verify | R-062 |
| E-10 | Actor/client registry has overlapping prefixes | longest identity prefix wins | Rust verify test | R-088, R-089 |
| E-11 | Missing impersonation policy selector field | empty set, deny | Rust config | R-098 |
| E-12 | Impersonation selector `"*"` | any for that selector | Rust/Python config tests | R-101 |
| E-13 | Empty present actor_token in both mode | malformed, not impersonation | Python impersonation; Rust HTTP contract | R-097 |
| E-14 | Auth-context absent | omit `auth_time`, `acr`, `amr` | Python integration; Rust core | R-073 |
| E-15 | Subject expires before default TTL | cap minted exp and expires_in | Python integration | R-075, R-077 |
| E-16 | Actor expires before default TTL | cap minted exp | Python integration | R-076 |
| E-17 | DPoP htm lower-case `post` | accept | Rust/Python DPoP | R-113 |
| E-18 | DPoP htu with query/fragment | ignore query/fragment | Python DPoP | R-114 |
| E-19 | DPoP htu with default port | normalize | Rust/Python DPoP | R-114 |
| E-20 | DPoP htu trailing slash | normalize | issue #2 comment; Python DPoP | R-114 |
| E-21 | DPoP non-string htm/htu from transport | clean invalid_dpop_proof | Python DPoP | R-112 |
| E-22 | DPoP oversized compact proof | reject before signature | Rust/Python DPoP | R-107 |
| E-23 | DPoP maximum-length jti | accept exactly max | Python DPoP | R-112 |
| E-24 | DPoP jti over max | reject | Rust/Python DPoP | R-112 |
| E-25 | Replay store sweep before future proof window closes | entry remains | Python integration | R-116 |
| E-26 | Replay store full after sweep | service unavailable | Rust replay | R-106 |
| E-27 | JWKS cache headers differ from token cache headers | public vs no-store | Python/Rust HTTP tests | R-033, R-038 |
| E-28 | Source release package check fails for unpublished path deps | not alpha blocker | README; issue #9 | R-125 |
| E-29 | Missing Python oracle repo for smoke script | exit 2 | script | R-010, R-126 |
| E-30 | Supply-chain helper CLIs absent | report caveat, do not fake audit | release audit notes | R-126 |
| E-31 | Real Okta tenant config absent during live validation | report not configured; do not substitute `example.com` | issue #21 | R-131 |
| E-32 | Loopback HTTP STS issuer in local development | preserve or reject only by explicit #13 decision | Python config policy; issue #13 | R-132 |

## v2 Rust Migration Map

| Boundary | Current Python owner | Rust v2 owner | Keep/remove | Parity risk | Cutover criteria | Rollback boundary |
| --- | --- | --- | --- | --- | --- | --- |
| Token-exchange constants and request shape | `constants.py`, request/service layers | `sts-core`, `sts-http` | keep wire shape | Missing optional params or wrong errors | HTTP contract plus oracle smoke | Revert HTTP parser/core commit |
| Target resolution and downscope | `core.py`, domain modules | `sts-core` | keep semantics, Rust API may differ | Scope/default policy drift | core tests plus Python target tests | Replace core crate version |
| Minted claim assembly | `domain/payload.py` | `sts-core` plus HTTP composition | keep wire claims | exp/auth-context/cnf drift | claim-shape contract tests | Disable Rust endpoint; keep Python |
| Subject verification | `verify.py`, trust modules | `sts-verify` | keep issuer/audience/time gates | JWT library differences | verify tests and oracle tokens | Swap verification call back to Python oracle in tests only |
| Actor/client assertion verification | `verification/*`, `client_auth.py` | `sts-verify`, `sts-http` | keep private_key_jwt policy | kid binding, subject binding, replay order | #7/#10 tests plus oracle smoke | Revert assertion auth slice |
| JOSE signing and JWKS | `signer.py`, `keys.py` | `sts-jose` | keep RS256 default; add PQC later | Key custody/JWKS private leak | JOSE tests, JWKS black-box tests | Revert signer backend change |
| PQC backend | preview/planned Python work | future `sts-jose` backend | add, no fallback | Claiming unsupported PQC | native sign/verify/JWKS/downstream verification tests | Disable PQC feature; classical default |
| DPoP stateless proof validation | `dpop.py` | `sts-dpop` | keep local canonicalization | htu normalization and alg drift | DPoP unit and HTTP contract tests | Feature flag disable DPoP endpoint branch |
| Replay storage | `replay.py`, `application/replay_records.py` | `sts-replay` | keep semantics; store backend can change | late jti preburn, multi-worker | replay tests plus oracle late-failure tests | In-memory store only |
| HTTP routes and errors | `transport.py`, response modules | `sts-http` | keep endpoints; no `/exchange` | status/error/header drift | HTTP contract suite | Route traffic to Python service |
| Runtime config | `config*` modules | `sts-config` | keep env names where stable | startup drift, defaults | config tests and smoke startup | Pin old config values in compatibility adapter |
| CLI/ops | Python scripts/tools | `sts-cli` | add Rust commands later | shipping empty CLI as complete | dedicated CLI issues/tests | Keep Python scripts |
| Release process | Python packaging scripts | Rust release workflow | source alpha now | false crates.io claim | release audit and README caveat | Tag rollback/retraction |

## Bug / Issue Register

| Issue | Classification | Validated / observed problem | Impacted behavior | State | Close / handoff rule |
| --- | --- | --- | --- | --- | --- |
| #1 | tests | Needed Python-oracle smoke runner | Parity harness | closed | Keep runner in release gate. |
| #2 | roadmap | Requirements ledger and use-case count not canonical | Contract freeze | open | Can close after this ledger is committed, validated, and issue-updated. |
| #3 | architecture | Crate boundaries needed executable guard | Dependency direction | closed | Guard remains release gate. |
| #4 | HTTP | Endpoint, metadata, cache/error contract needed freeze tests | `/token`, `/jwks`, metadata | closed | New HTTP drift gets new issue. |
| #5 | security/crypto | Backend selection needed fail-closed PQC behavior | JOSE selection | closed | Native PQC needs new implementation issue. |
| #6 | security | Incoming JWT assertions needed signature/claim checks | Subject/actor/client verification | closed | Extend tests for issuer/audience edge cases. |
| #7 | security | private_key_jwt needed client identity/kid binding | Client auth | closed | New client auth algs need dedicated issue. |
| #8 | DPoP | DPoP proof validation and `cnf.jkt` binding needed wiring | DPoP sender constraint | closed | Add full oracle matrix before beta. |
| #9 | release | Workspace is source-only for alpha, crates.io packaging not current model | Release artifacts | closed | Reopen only when crates.io publishing milestone starts. |
| #10 | security | Actor assertion kid could be cross-domain | Actor auth | closed | Keep cross-domain test. |
| #11 | parity | `requested_token_type=jwt` divergence from Python | Token request | closed | Any future change is intentional divergence issue. |
| #12 | parity/security | Impersonation policy needed Python target/subject shape | Impersonation | closed | Add more both-mode/empty-token parity tests. |
| #13 | config/security | RuntimeConfig accepts query/fragment/non-loopback HTTP STS issuers rejected by Python | Startup config and metadata truth | open | Close only after Rust config tests and final loopback policy decision. |
| Python #210 | bug/parity | Scoped token cannot outlive subject | Token lifetime | implemented in Rust contract | Keep #14 lifetime cap test in release gate. |
| Python #280 | bug/parity | Scoped token cannot outlive actor | Token lifetime | implemented in Rust contract | Keep #14 lifetime cap test in release gate. |
| Python #279 | bug/parity | `expires_in` must reflect capped lifetime | Token response | implemented in Rust contract | Keep #14 lifetime cap test in release gate. |
| Python #580 | bug/parity | Empty actor_token is present malformed | Mode dispatch | implemented in Rust contract | Keep #15 both-mode dispatch test in release gate. |
| Python #602 | bug/parity | DPoP jti/proof anti-DoS and replay key bounds | DPoP/replay | implemented in Rust | Keep DPoP tests. |

## Current Freeze Gaps

- Rust still needs an explicit catch-all clean 500 test for unexpected HTTP failures.
- Rust still needs #13 config issuer validation for query, fragment, and non-loopback HTTP values.
- Native PQC signing/JWKS/downstream verification is missing; only fail-closed selection is shipped.
- CLI/ops helpers are only a crate boundary, not a complete product surface.
- Full Authorization Server features remain non-goals for this STS alpha.

## Executive Conclusion

v1 Python can remain the production behavior oracle while Rust alpha expands. The Rust
line already has meaningful implementation for the core STS path, HTTP surface, JOSE,
verification, DPoP, replay, config, and architecture guards.

v2 must become a Rust-native, contract-tested STS with native crypto backend seams,
explicit PQC support when real backend support lands, and a release process that keeps
source-only alpha claims separate from future package publishing and enterprise-ready
claims.

The biggest risks are not basic routing anymore. They are parity drift in subtle
security paths, over-claiming PQC before real sign/verify/JWKS support exists, and
letting alpha source releases sound like a stable full OAuth authorization server.
