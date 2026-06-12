# obo-lab Contract Coverage Plan

This page inventories the `obo-lab` adversarial and E2E material for Rust contract
coverage. It addresses issue #59 and keeps live-tenant/MCP proof separate from
deterministic Rust tests.

## Scenario Matrix

| obo-lab source | Useful scenario | Rust status | Next action |
| --- | --- | --- | --- |
| `tests/adversarial_probes.py` | malformed grants, missing fields, broad-token misuse, invalid actor proof | Mostly covered by `sts-http` form, actor, target, replay, and DPoP contract tests | Add narrow tests only for any probe not already represented in the ledger. |
| `tests/flow_e2e.py` | end-to-end subject token to scoped token flow | Covered offline by `crates/sts-http/tests/http_contract.rs` and live by `scripts/live_rust_sts_canary.py` when configured | Keep deterministic tests offline; use live canary only for configured real tenant proof. |
| `tests/fleet_test.py` | multiple MCP servers/tools and audience isolation | Partially covered by target/audience tests | Add a future multi-target contract test if it proves target isolation better than existing single-target cases. |
| `tests/test_sts_gates.py` | STS gate ordering and rejection paths | Covered by ledger rows for signature, audience, actor binding, `may_act`, target, downscope, replay, and late replay burn prevention | Keep as parity reference. |
| `tests/test_stress.py` | edge cases and regression pressure | Covered in part by RFC empty-form, issuer, DPoP, and replay tests | Mine only current gaps into focused issues; avoid synthetic volume without new assertions. |
| `tools/jwt_inspect.py` | safe claim inspection | Rust CLI has redacted `exchange`, `jwks inspect`, and `key inspect` | Future CLI enhancement only if users need standalone JWT inspect. |
| `tools/walk.py` | scripted walkthrough | Rust equivalent is README plus `sts-cli` commands and live canary script | Convert into docs/examples after product docs settle. |

## Already Covered Rust Contract Areas

| Area | Rust proof |
| --- | --- |
| Discovery and JWKS shape | `contract_discovery_and_jwks_match_python_oracle_shape` |
| Path-bearing issuer aliases | `contract_path_bearing_issuer_advertised_endpoints_are_live` |
| Form content type and duplicate recognized parameters | `contract_token_rejects_wrong_content_type_and_duplicate_form_params` |
| OAuth 2.1 empty optional token parameters | `rfc_oauth21_empty_*` tests |
| Unknown extension parameters | `contract_unknown_extension_params_are_ignored` |
| Delegation claim shape | `contract_delegation_token_matches_python_oracle_wire_shape` |
| Prior `act` chain handling | `contract_delegation_preserves_sanitized_nested_prior_act_chain` and related rejection tests |
| `may_act` authorization | `contract_may_act_*` tests |
| Impersonation mode | `contract_impersonation_*` tests |
| DPoP binding and replay | `contract_dpop_*` tests |
| Replay burn ordering | `contract_client_assertion_jti_is_not_burned_by_late_target_failure` |
| Clean error mapping | `contract_token_errors_are_oauth_json_and_no_store` and signing failure test |
| Live real-tenant process proof | `scripts/live_rust_sts_canary.py --require-live` when configured |

## Follow-Up Issues To File Only If Gaps Are Reproduced

| Candidate gap | File only if current Rust tests do not prove it |
| --- | --- |
| Multi-target MCP fleet isolation | Need a black-box test with two configured targets and cross-audience rejection. |
| Standalone JWT inspection CLI | Need user demand beyond current safe decoded output from `exchange`. |
| Live MCP client invocation | Requires configured `.mcp.json`/real tenant proof; not a deterministic Rust unit test. |
| Stress-loop coverage | File only for a concrete edge case missing from the ledger. |

## Live-Proof Rule

`example.com`, `issuer.example`, `sts.example`, and other fixture issuers are valid for
offline tests only. They must not close live-tenant readiness work. Live proof must use
configured real issuer values and redacted logs.
