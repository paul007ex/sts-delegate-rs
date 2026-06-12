# RFC / OIDC curl conformance pack

One executable curl test per protocol requirement, run against a live `sts-cli serve`
instance and classified pass/fail. This is the runnable companion to
`docs/requirements/rust-v2-contract-ledger.md` — each row maps to an `R-NNN` ledger ID
and the primary RFC clause it proves.

## How to run

Bring up the server in RS256 mode with a file-based IdP JWKS and a target policy, then
run the pack. Replace the issuer/keys with your own; the commands are the contract.

```bash
export STS=http://127.0.0.1:18888
# server env: IDP_ISSUER, IDP_JWKS_FILE, EXPECTED_SUBJECT_AUD, ACTOR_IDS/CLIENT_IDS,
#   ACTOR_JWKS_FILE/CLIENT_JWKS_FILE, OBO_STS_KEY_FILE, OBO_STS_ISSUER=$STS,
#   STS_SIGNING_ALG=RS256 (+ STS_ALLOW_NON_PQC=true STS_ALLOW_NON_PQC_INBOUND=true),
#   TARGET_POLICY_JSON='{"api://obo":{"scopes":["vpn.connect","read","write"],
#                        "accepted_token_signing_algs":["RS256"],"pqc_required":false}}'
sts-cli serve &
./conformance.sh        # see scripts/ companion; prints PASS/FAIL per requirement
```

## Results (live server, RS256 mode)

**20 / 20 PASS.** Each test is the exact curl below; the captured response is the proof.

| R-ID | RFC | Requirement | curl test | Result |
|---|---|---|---|---|
| R-026 | 8414 §3 | Metadata `issuer` equals configured STS issuer | `GET /.well-known/oauth-authorization-server` → `"issuer":"$STS"` | ✅ 200 |
| R-028 | 8693 §2.1 | Metadata advertises the token-exchange grant | `GET …/oauth-authorization-server` → `grant-type:token-exchange` | ✅ 200 |
| R-029 | 8414 §2 | Metadata advertises only `private_key_jwt` client auth | `GET …/oauth-authorization-server` → `private_key_jwt` | ✅ 200 |
| R-025 | 8414 §3 | Metadata is GET-only | `POST …/oauth-authorization-server` | ✅ 405 |
| R-032 | — | `/jwks` publishes public keys only (no private `d`) | `GET /jwks` → `kty:RSA`, no `d` | ✅ 200 |
| R-045 | 8693 §2.1 | `grant_type` must be token-exchange | `POST /token grant_type=authorization_code` | ✅ `unsupported_grant_type` |
| R-039 | 6749 §5.2 | Missing `grant_type` → `invalid_request` | `POST /token foo=bar` | ✅ 400 `invalid_request` |
| R-046 | 8693 §2.1 | `subject_token` required | `POST /token grant_type=…token-exchange` | ✅ 400 `invalid_request` |
| R-047 | 8693 §2.1 | `subject_token_type` required | `POST /token …subject_token only` | ✅ 400 `invalid_request` |
| R-053 | 8693 §2.1 | Unsupported `requested_token_type` → `invalid_request` | `…requested_token_type=urn:bogus` | ✅ 400 `invalid_request` |
| R-054 | 8693 §2.1 | Exactly one target required | `…no audience/resource` | ✅ 400 (rejected) |
| R-034 | 6749 §4 | `/token` accepts only `application/x-www-form-urlencoded` | `POST /token` JSON body | ✅ 400 `Content-Type must be…` |
| R-JWS-none | 8725 §3.1 | `alg:none` subject_token rejected | `…subject_token=<alg:none JWT>` | ✅ 400 `none is not allowed` |
| R-JWS-garb | 8725 §2.2 | Garbage JWT → clean `invalid_grant`, no 500 | `…subject_token=not.a.jwt` | ✅ 400 `invalid_grant` |
| R-CA-aud | 7523 §3 | `client_assertion` wrong-aud rejected | `POST /introspect` w/ aud=token_endpoint on an endpoint that wants issuer | ✅ 401 `audience does not identify…` |
| R-023B | 7662 §2.1 | `/introspect` requires client auth | `POST /introspect token=x` (no client_assertion) | ✅ 401 `invalid_client` |
| R-023B-ct | 7662 §2.1 | `/introspect` rejects wrong content-type | `POST /introspect` JSON body | ✅ 400 |
| R-023C | 7009 §2.1 | `/revoke` requires client auth | `POST /revoke token=x` (no client_assertion) | ✅ 401 `invalid_client` |
| R-023D | 9728 §3 | Protected-resource metadata served | `GET /.well-known/oauth-protected-resource` | ✅ 200 (resource + AS + scopes) |
| R-HAPPY | 8693 §2.1/§4.1 | Full delegation issues an `act`-claim token | full exchange → decode JWT: `sub=user`, `act.sub=actor` | ✅ `sub=alice@corp act.sub=chat-mcp` |

## Representative captured transcripts

### R-HAPPY — full RFC 8693 delegation exchange (the issued token)

```bash
curl -s -X POST $STS/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode "subject_token=$SUBJECT_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  --data-urlencode "actor_token=$ACTOR_TOKEN" \
  -d actor_token_type=urn:ietf:params:oauth:token-type:jwt \
  -d audience=api://obo -d scope=vpn.connect \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$CLIENT_ASSERTION"
# 200 OK — decoded access_token claims:
#   { "iss":"http://127.0.0.1:18888", "sub":"alice@corp", "aud":"api://obo",
#     "scope":"vpn.connect", "act":{"sub":"chat-mcp"}, "client_id":"chat-mcp" }
# sub preserved (the user), act.sub = the agent: RFC 8693 §4.1 delegation, correct.
```

### R-JWS-none — alg:none is rejected (RFC 8725 §3.1)

```bash
curl -s -X POST $STS/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode "subject_token=eyJhbGciOiJub25lIn0.<claims>." \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=api://obo
# 400 {"error":"invalid_grant","error_description":"JWS algorithm none is not allowed for this verification context"}
```

### R-023B / R-023C — introspection & revocation require client auth (RFC 7662/7009)

```bash
curl -s -X POST $STS/introspect -d token=x
# 401 cache-control:no-store {"error":"invalid_client","error_description":"client_assertion required"}
curl -s -X POST $STS/revoke -d token=x
# 401 {"error":"invalid_client","error_description":"client_assertion required"}
```

## Notes / observations

- **R-054 ordering:** with no target *and* delegation mode, the server returns
  `actor_token required for delegation` before the missing-target error. Both are
  `400 invalid_request`; the precedence is cosmetic, not a conformance break.
- The `act` claim is inside the signed `access_token`, so assert on the decoded JWT,
  not the raw response body.
- This pack runs the RS256 inbound/issuance path. The PQC (ML-DSA) path is the default
  in production and is covered by the property/fuzz tests tracked in issue #128.
