# Release Security

This page records the current release-trust state and the work needed to complete
issue #46. It does not mark SBOM, provenance, or signing complete until those artifacts
are generated and validated in the release path.

## Current Release Artifacts

| Artifact | Current state | Verification |
| --- | --- | --- |
| GitHub source archive | Shipped by GitHub tag | Verify tag and source review. |
| Hosted `sts-cli` archive | Shipped by `.github/workflows/release.yml` after tag/workflow run | Download archive and `SHA256SUMS`; run `shasum -a 256 -c SHA256SUMS`. |
| Local `sts-cli` archive | Built by `scripts/package_release.sh` | Run script and checksum verification locally. |
| Homebrew formula | Downloads hosted archive and verifies checksum | `brew tap`, `brew install`, `brew test`. |
| Docker image | Local build path only | `docker build` and `scripts/docker_smoke.sh`. No GHCR publication claim. |
| crates.io packages | Out of scope | Workspace crates are `publish = false`. |

## Required Future Trust Artifacts

| Requirement | Target implementation | Validation |
| --- | --- | --- |
| SBOM for CLI archives | Generate CycloneDX or SPDX SBOM for each hosted archive and upload beside checksums. | Verify SBOM references the release archive/crate graph and contains no secrets. |
| SBOM for container image | Generate image SBOM after a registry publication path exists. | Verify image digest and SBOM digest together. |
| Provenance/attestation | Add hosted artifact provenance for release workflow outputs. | Verify attestation against repository, workflow, tag, and commit. |
| Artifact signing | Sign release archives/checksums with Sigstore or another approved signing path. | Document `cosign verify-blob` or equivalent commands. |
| Container signing | Sign published image digest once a registry path exists. | Document `cosign verify` against the image digest. |

## Operator Verification Commands

Current checksums:

```bash
release_tag=v0.1.0
gh release download "$release_tag" \
  --repo paul007ex/sts-delegate-rs \
  --pattern 'sts-cli-*.tar.gz' \
  --pattern SHA256SUMS
shasum -a 256 -c SHA256SUMS
```

Future signed release shape:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/paul007ex/sts-delegate-rs/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature sts-cli.tar.gz.sig \
  sts-cli.tar.gz
```

The exact signing command remains roadmap until the release workflow produces those
artifacts.

## Secret-Handling Rules

- Release workflows must not print bearer tokens, subject tokens, actor assertions,
  client assertions, private JWK members, DPoP proofs, Authorization headers, or real
  tenant secrets.
- Archive contents must not include generated secrets, local `.env` files, canary
  credentials, private keys, or `dist/` leftovers.
- SBOM and provenance files are public artifacts and must contain package/build metadata
  only.

## Open Work For #46

Issue #46 should remain open until at least one implementation PR adds generated SBOMs,
attestation/provenance, and signing to the release workflow. This document supplies the
operator-facing plan and verification language; it is not the implementation.
