# Release Security

This page records the current release-trust state for issue #46. Hosted and local
CLI archives now carry SPDX SBOMs and checksums. Hosted release assets are attested
by GitHub artifact attestations in the release workflow.

## Current Release Artifacts

| Artifact | Current state | Verification |
| --- | --- | --- |
| GitHub source archive | Shipped by GitHub tag | Verify tag and source review. |
| Hosted `sts-cli` archive | Shipped by `.github/workflows/release.yml` after tag/workflow run | Download archive, SPDX SBOM, and `SHA256SUMS`; run checksum and attestation verification. |
| Local `sts-cli` archive | Built by `scripts/package_release.sh` | Run script and checksum verification locally; inspect generated SPDX SBOM. |
| Homebrew formula | Downloads hosted archive and verifies checksum | `brew tap`, `brew install`, `brew test`. |
| Docker image | Local build path only | `docker build` and `scripts/docker_smoke.sh`. No GHCR publication claim. |
| crates.io packages | Out of scope | Workspace crates are `publish = false`. |

## Release Trust Artifacts

| Requirement | Current implementation | Validation |
| --- | --- | --- |
| SBOM for CLI archives | `scripts/package_release.sh` calls `scripts/generate_release_sbom.py` and emits `dist/sts-cli-*.spdx.json` beside each archive. | `shasum -a 256 -c dist/SHA256SUMS`; JSON parse/inspection of the SPDX document. |
| Provenance/attestation | `.github/workflows/release.yml` attests hosted release assets with GitHub artifact attestations. | `gh attestation verify` against the repository and release workflow identity. |
| Artifact signing | Hosted attestations provide Sigstore-backed artifact identity and provenance for uploaded assets. | Verify attestations after downloading the release assets. |
| SBOM for container image | Roadmap until a registry publication path exists. | Verify image digest and SBOM digest together after image publication exists. |
| Container signing | Roadmap until a registry publication path exists. | Document `cosign verify` against the published image digest when GHCR or another registry is added. |

## Operator Verification Commands

Current checksums and SBOMs:

```bash
release_tag=v0.1.0
gh release download "$release_tag" \
  --repo paul007ex/sts-delegate-rs \
  --pattern 'sts-cli-*.tar.gz' \
  --pattern 'sts-cli-*.spdx.json' \
  --pattern SHA256SUMS
shasum -a 256 -c SHA256SUMS
for sbom in sts-cli-*.spdx.json; do python3 -m json.tool "$sbom" >/dev/null; done
```

Hosted artifact attestations:

```bash
gh attestation verify sts-cli-*.tar.gz \
  --repo paul007ex/sts-delegate-rs \
  --cert-identity-regex 'https://github.com/paul007ex/sts-delegate-rs/.github/workflows/release.yml@refs/tags/.*'
gh attestation verify sts-cli-*.spdx.json \
  --repo paul007ex/sts-delegate-rs \
  --cert-identity-regex 'https://github.com/paul007ex/sts-delegate-rs/.github/workflows/release.yml@refs/tags/.*'
```

Local archives cannot prove hosted workflow identity. Use the checksum and SBOM for
local artifact integrity, and use hosted attestations for release provenance.

## Secret-Handling Rules

- Release workflows must not print bearer tokens, subject tokens, actor assertions,
  client assertions, private JWK members, DPoP proofs, Authorization headers, or real
  tenant secrets.
- Archive contents must not include generated secrets, local `.env` files, canary
  credentials, private keys, or `dist/` leftovers.
- SBOM and provenance files are public artifacts and must contain package/build metadata
  only.

## Remaining Work

Container image SBOMs and container signing remain blocked on a real registry
publication path. The current Dockerfile is still a local build path, not a signed
published image.
