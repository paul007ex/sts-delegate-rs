# Repository Guidelines

## Project Structure & Module Organization

`sts-delegate-rs/` is the Rust-native v2 product for the STS. Keep the workspace
small, explicit, and layered. The initial crates are:

- `sts-core` for token-exchange policy and claim shaping
- `sts-dpop` for RFC 9449 DPoP proof validation and holder-key binding
- `sts-verify` for issuer/trust-anchor validation
- `sts-replay` for replay policy and state
- `sts-jose` for JOSE/JWK/JWKS and signing backend selection
- `sts-config` for env parsing and resolved startup config
- `sts-http` for `/token`, `/jwks`, discovery, and error mapping
- `sts-cli` for ops/rotation/canary helpers

Do not mirror the Python tree one-for-one unless the boundary is actually useful in Rust.
Prefer small crates with explicit ownership and clear dependency direction.

## Build, Test, and Development Commands

```bash
rustup update stable
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
python3 scripts/security_audit_loop.py
```

Use `cargo test --workspace` as the baseline. Add focused crate tests when working on a
single lane. Keep the workspace on the latest stable Rust toolchain available in the
environment unless an issue explicitly requires a pinned toolchain.

For substantive security, protocol, JOSE, DPoP, replay, runtime, or release changes,
run the secure Rust audit loop after the focused tests. For background monitoring, run
`python3 scripts/security_audit_loop.py --loop 180`. Normal mode reports
installed/missing supply-chain tools without executing the full release gate. For
release gates, add `--strict-supply-chain`; that mode requires `cargo-audit`,
`cargo-deny`, `cargo-geiger`, and `cargo-vet` to be installed and passing.
Use `scripts/install_supply_chain_tools.sh` to install the pinned local/CI tool
versions.

For live tenant/MCP evidence, run `python3 scripts/real_tenant_endpoint_loop.py`.
Use `--mcp-call-mode fastmcp --require-mcp` when proving Claude/MCP client calls
through the configured `.mcp.json` gateway URLs. Use
`--mcp-url-set obo-lab-direct` only for the owned-server pattern where the MCP
servers validate the real Okta user token directly; keep gateway failures tracked
separately.
This loop must use a configured real Okta issuer such as `CANARY_IDP_ISSUER` or
`OKTA_ISSUER`; `example.com`, `issuer.example`, `sts.example`, and `*.example.*`
are fixture-only and must not be accepted as live proof. Redact bearer tokens,
subject tokens, assertions, private keys, Authorization headers, and raw replay
identifiers from logs and issue comments.

## Coding Style & Naming Conventions

Target Rust 2024. Keep `unsafe` out of the codebase unless an issue explicitly approves
it and the safety contract is documented. Prefer explicit error enums, explicit feature
flags, explicit module boundaries, and small public APIs.

Use protocol terminology consistently:

- `subject` = the user
- `actor` = the party acting for them
- `sts-delegate` = the STS itself
- `resource server` = the downstream consumer of the token

Do not mirror Python file names just because they exist there. Choose Rust module and
crate names that keep the product architecture readable.

## Testing Guidelines

Every change to token issuance, signing, JWKS publication, replay behavior, client auth,
or discovery metadata needs accepted-path and rejected-path tests. Use the Python repo
as the behavior oracle, but port the behavior as Rust contract/integration tests rather
than copying implementation shape.

Keep tests deterministic. Avoid hidden env reads or network access in library imports.

## Commit & Pull Request Guidelines

Use focused commits. Keep the Rust repo issue-driven. Every substantive change should
link to a GitHub issue and update the coordination log in `/tmp`.

If you are making a protocol or security change, cite the RFC section in the issue and
in review notes. Do not rely on memory for OAuth, JOSE, DPoP, JWT, or metadata rules.

## Security & Protocol Invariants

The Rust product must keep delegation honest, preserve `sub` for the user, and carry
`act` for the actor on delegation paths. PQC must be explicit, fail-closed, and
first-class when enabled. The default runtime remains classical unless the relevant
issue says otherwise.

Keep signing, trust-anchor validation, replay policy, and HTTP transport separated.
Keep key custody out of protocol glue.

The secure Rust loop must stay active during product work. It checks formatting,
Clippy, crate boundaries, duplicate dependencies, production panic/placeholder/unsafe
patterns, sensitive logging patterns, and supply-chain tool availability. Strict
mode executes the installed supply-chain tools. Confirmed findings belong in GitHub
issues before they are treated as resolved.

## Agent-Specific Review Rules

Use the Rust-native skills for Rust work:

- `rust-architecture-review-system`
- `rust-contract-test-engineer`
- `rust-crypto-developer`
- `rust-security-code-anti-pattern-audit`
- `sts-delegate-rust-pm`

Use the Rust sts-delegate adapters when the work is repo-specific:

- `sts-delegate-rs-anti-pattern-audit` for Rust STS issue/code/security/parity QA
- `rust-dpop-sender-constraint` for RFC 9449 DPoP and `cnf.jkt` behavior
- `rust-oss-release-auditor` for Rust release, artifact, and supply-chain gates
- `sts-delegate-rs-docs` for Rust contract docs, ADRs, parity matrices, and issue text

GitHub issues are canonical for all work items, bugs, features, and acceptance criteria.
The `/tmp/sts-delegate-rs-coordination-log.md` file is a monitoring trail only.

Work one issue at a time when two changes would touch the same files or boundary. Run
lanes in parallel only when they cannot clobber each other.

Before coding, inspect:

- the current open issue queue
- recent closed issues relevant to the lane
- the live tree and current branch state

If a finding matches an existing issue, update that issue instead of filing a duplicate.
If the issue scope is vague, tighten the scope before touching code.

## Current Workflow

1. Read the active issue.
2. Read the relevant Rust sources, tests, docs, or specs.
3. Append a short status entry to `/tmp/sts-delegate-rs-coordination-log.md`.
4. Make the smallest useful change or file the smallest useful issue.
5. Run the relevant tests or parity checks.
6. Run `python3 scripts/security_audit_loop.py` after substantive code changes.
7. Update the issue thread with evidence and follow-up.
8. Move immediately to the next unblocked issue.
