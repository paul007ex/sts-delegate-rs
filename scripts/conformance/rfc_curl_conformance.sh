#!/usr/bin/env bash
# RFC / OIDC conformance pack for sts-delegate-rs — one curl test per requirement,
# run against a live server, classified pass/fail. Maps to docs/requirements ledger R-IDs.
set -u
STS="${STS:-http://127.0.0.1:18888}"
cd "$(dirname "$0")"
SUBJ=$(cat subject_token.txt)
CA=$(python3 mint.py client_assertion "$STS")
ACT=$(python3 mint.py actor_token)
TE="urn:ietf:params:oauth:grant-type:token-exchange"
AT="urn:ietf:params:oauth:token-type:access_token"
JWT_T="urn:ietf:params:oauth:token-type:jwt"
CAT="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
PASS=0; FAIL=0
RESULTS=""

# check(id, rfc, desc, expected_substr, curl-args...)
check() {
  local id="$1" rfc="$2" desc="$3" expect="$4"; shift 4
  local out code body
  out=$(curl -s -w $'\n%{http_code}' "$@")
  code=$(printf '%s' "$out" | tail -1)
  body=$(printf '%s' "$out" | sed '$d')
  local verdict
  if printf '%s' "$body $code" | grep -q "$expect"; then verdict="PASS"; PASS=$((PASS+1)); else verdict="FAIL"; FAIL=$((FAIL+1)); fi
  printf '%-7s %-7s %-9s %s\n' "$id" "$rfc" "$verdict" "$desc"
  printf '         expect=«%s»  got: HTTP %s %s\n' "$expect" "$code" "$(printf '%s' "$body" | head -c 160 | tr '\n' ' ')"
  RESULTS="$RESULTS|$id|$rfc|$verdict|$desc|"
}

echo "================ sts-delegate-rs RFC/OIDC conformance (live: $STS) ================"

# --- Discovery / metadata (RFC 8414) ---
check R-026 "8414" "Metadata issuer equals configured STS issuer" "\"issuer\":\"$STS\"" \
  "$STS/.well-known/oauth-authorization-server"
check R-028 "8693" "Metadata advertises token-exchange grant" "grant-type:token-exchange" \
  "$STS/.well-known/oauth-authorization-server"
check R-029 "8414" "Metadata advertises only private_key_jwt client auth" "private_key_jwt" \
  "$STS/.well-known/oauth-authorization-server"
check R-025 "8414" "Metadata is GET-only (POST not allowed)" "405" \
  -X POST "$STS/.well-known/oauth-authorization-server"
check R-032 "n/a"  "/jwks publishes public keys only (no private 'd')" "\"kty\":\"RSA\"" \
  "$STS/jwks"

# --- Token endpoint grant/param validation (RFC 8693 / 6749 / OAuth 2.1) ---
check R-045 "8693" "grant_type must be token-exchange (wrong rejected)" "unsupported_grant_type" \
  -X POST "$STS/token" -d 'grant_type=authorization_code'
check R-039a "6749" "Missing grant_type -> invalid_request 400" "invalid_request" \
  -X POST "$STS/token" -d 'foo=bar'
check R-046 "8693" "subject_token required" "invalid_request" \
  -X POST "$STS/token" -d "grant_type=$TE"
check R-047 "8693" "subject_token_type required" "invalid_request" \
  -X POST "$STS/token" -d "grant_type=$TE" --data-urlencode "subject_token=$SUBJ"
check R-053 "8693" "Unsupported requested_token_type -> invalid_request" "invalid_request" \
  -X POST "$STS/token" -d "grant_type=$TE" --data-urlencode "subject_token=$SUBJ" \
  -d "subject_token_type=$AT" -d 'requested_token_type=urn:bogus' -d 'audience=api://obo'
check R-054 "8693" "Missing target (no audience/resource) rejected" "invalid_" \
  -X POST "$STS/token" -d "grant_type=$TE" --data-urlencode "subject_token=$SUBJ" \
  -d "subject_token_type=$AT" \
  -d 'client_assertion_type='"$CAT" --data-urlencode "client_assertion=$CA"
check R-034 "6749" "/token rejects non-form content-type" "invalid_" \
  -X POST "$STS/token" -H 'Content-Type: application/json' --data '{"grant_type":"x"}'

# --- Crypto / token verification (RFC 8725 / 7515) ---
check R-JWS-none "8725" "alg:none subject_token rejected" "none is not allowed" \
  -X POST "$STS/token" -d "grant_type=$TE" \
  --data-urlencode "subject_token=eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2lkcC5sb2NhbC50ZXN0L29hdXRoMi9kZWZhdWx0Iiwic3ViIjoidiIsImF1ZCI6ImFwaTovL29ibyIsImV4cCI6OTk5OTk5OTk5OX0." \
  -d "subject_token_type=$AT" -d 'audience=api://obo'
check R-JWS-garb "8725" "Garbage subject_token -> clean invalid_grant (no 500)" "invalid_grant" \
  -X POST "$STS/token" -d "grant_type=$TE" --data-urlencode "subject_token=not.a.jwt" \
  -d "subject_token_type=$AT" -d 'audience=api://obo'

# --- Client auth (RFC 7521/7523) ---
check R-CA-aud "7523" "client_assertion wrong-aud rejected" "audience does not identify" \
  -X POST "$STS/introspect" -d "client_assertion_type=$CAT" \
  --data-urlencode "client_assertion=$(python3 mint.py client_assertion "$STS/token")" -d 'token=x'

# --- Introspection (RFC 7662) ---
check R-023B-auth "7662" "/introspect requires client auth" "invalid_client" \
  -X POST "$STS/introspect" -d 'token=x'
check R-023B-ct "7662" "/introspect rejects wrong content-type" "invalid_" \
  -X POST "$STS/introspect" -H 'Content-Type: application/json' --data '{"token":"x"}'

# --- Revocation (RFC 7009) ---
check R-023C-auth "7009" "/revoke requires client auth" "invalid_client" \
  -X POST "$STS/revoke" -d 'token=x'

# --- Protected-resource metadata (RFC 9728) ---
check R-023D "9728" "/.well-known/oauth-protected-resource served" "resource" \
  "$STS/.well-known/oauth-protected-resource"

# --- Happy path (RFC 8693 delegation) ---
check R-HAPPY "8693" "Full delegation exchange issues act-claim token" "\"act\"" \
  -X POST "$STS/token" -d "grant_type=$TE" \
  --data-urlencode "subject_token=$SUBJ" -d "subject_token_type=$AT" \
  --data-urlencode "actor_token=$ACT" -d "actor_token_type=$JWT_T" \
  -d 'audience=api://obo' -d 'scope=vpn.connect' \
  -d "client_assertion_type=$CAT" --data-urlencode "client_assertion=$CA"

echo "================================================================================"
echo "PASS=$PASS  FAIL=$FAIL"
printf '%s\n' "$RESULTS" > /tmp/sts-live/results.txt
