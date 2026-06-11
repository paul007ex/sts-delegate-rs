#!/usr/bin/env bash
set -euo pipefail

readonly CARGO_AUDIT_VERSION="${CARGO_AUDIT_VERSION:-0.22.2}"
readonly CARGO_DENY_VERSION="${CARGO_DENY_VERSION:-0.19.8}"
readonly CARGO_GEIGER_VERSION="${CARGO_GEIGER_VERSION:-0.13.0}"
readonly CARGO_VET_VERSION="${CARGO_VET_VERSION:-0.10.2}"

cargo install cargo-audit --version "${CARGO_AUDIT_VERSION}" --locked
cargo install cargo-deny --version "${CARGO_DENY_VERSION}" --locked
cargo install cargo-geiger --version "${CARGO_GEIGER_VERSION}" --locked
cargo install cargo-vet --version "${CARGO_VET_VERSION}" --locked
