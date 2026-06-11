#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
rust_repo="$(cd -- "$script_dir/.." && pwd)"
python_oracle_repo="${PYTHON_ORACLE_REPO:-"$rust_repo/../sts-delegate"}"

if [[ ! -d "$python_oracle_repo" ]]; then
  echo "PYTHON_ORACLE_REPO does not exist: $python_oracle_repo" >&2
  exit 2
fi

if [[ -n "${PYTHON_BIN:-}" ]]; then
  python_bin="$PYTHON_BIN"
elif [[ -x "$python_oracle_repo/.venv/bin/python" ]]; then
  python_bin="$python_oracle_repo/.venv/bin/python"
else
  python_bin="python3"
fi

python_tests=(
  "tests/test_integration.py::test_client_assertion_kid_must_belong_to_asserted_client"
  "tests/test_integration.py::test_requested_token_type_validated"
  "tests/test_integration.py::test_http_exchange_rejects_duplicate_form_param"
  "tests/test_integration.py::test_authorization_header_rejected_on_token_endpoint"
  "tests/test_integration.py::test_authorization_header_cannot_be_mixed_with_private_key_jwt"
  "tests/test_integration.py::test_client_assertion_jti_not_preburned_on_late_failure"
  "tests/test_integration.py::test_do_exchange_dpop_binds_cnf_jkt_and_token_type"
  "tests/test_integration.py::test_metadata_is_public_and_get_only"
  "tests/test_integration.py::test_path_bearing_issuer_advertised_endpoints_are_real"
  "tests/test_impersonation.py::test_impersonation_policy_wrong_target"
  "tests/test_impersonation.py::test_impersonation_policy_wrong_subject"
  "tests/test_dpop.py::test_valid_proof_returns_jkt_and_jti"
  "tests/test_dpop.py::test_dpop_replay_key_is_bounded"
)

run() {
  echo "+ $*"
  "$@"
}

status=0
trap 'status=$?; if [[ $status -ne 0 ]]; then echo "oracle_contract_smoke=fail status=$status"; fi' EXIT

echo "python_oracle_repo=$python_oracle_repo"
echo "rust_repo=$rust_repo"
echo "python_bin=$python_bin"

(
  cd "$python_oracle_repo"
  run "$python_bin" -m pytest -q "${python_tests[@]}"
)

(
  cd "$rust_repo"
  run cargo test -p sts-http --test http_contract
  run cargo test -p sts-http --lib
  run cargo test -p sts-dpop --lib
  run cargo test -p sts-replay --lib
)

echo "oracle_contract_smoke=pass"
