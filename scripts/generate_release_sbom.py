#!/usr/bin/env python3
"""Generate an SPDX 2.3 JSON SBOM for a sts-cli release archive."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def spdx_ref(value: str) -> str:
    cleaned = []
    for char in value:
        if char.isalnum() or char in ".-":
            cleaned.append(char)
        else:
            cleaned.append("-")
    return "SPDXRef-" + "".join(cleaned).strip("-")


def cargo_metadata() -> dict[str, Any]:
    completed = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def package_supplier(package: dict[str, Any]) -> str:
    authors = package.get("authors") or []
    if authors:
        return f"Organization: {', '.join(sorted(str(author) for author in authors))}"
    return "NOASSERTION"


def package_entry(package: dict[str, Any]) -> dict[str, Any]:
    name = str(package["name"])
    version = str(package["version"])
    checksum_input = f"{name}@{version}".encode("utf-8")
    checksum = hashlib.sha256(checksum_input).hexdigest()
    return {
        "SPDXID": spdx_ref(f"cargo-{name}-{version}"),
        "name": name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": str(package.get("license") or "NOASSERTION"),
        "licenseDeclared": str(package.get("license") or "NOASSERTION"),
        "copyrightText": "NOASSERTION",
        "supplier": package_supplier(package),
        "checksums": [{"algorithm": "SHA256", "checksumValue": checksum}],
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:cargo/{name}@{version}",
            }
        ],
    }


def build_document(archive: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    archive_sha = sha256_file(archive)
    created = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    workspace = metadata.get("workspace_members") or []
    workspace_ids = set(str(package_id) for package_id in workspace)
    packages = sorted(metadata["packages"], key=lambda package: (package["name"], package["version"]))
    root_ref = spdx_ref(f"release-archive-{archive.name}")
    package_refs = [spdx_ref(f"cargo-{package['name']}-{package['version']}") for package in packages]
    workspace_refs = [
        spdx_ref(f"cargo-{package['name']}-{package['version']}")
        for package in packages
        if str(package["id"]) in workspace_ids
    ]

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"sts-delegate-rs release SBOM for {archive.name}",
        "documentNamespace": f"https://github.com/paul007ex/sts-delegate-rs/sbom/{archive_sha}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: scripts/generate_release_sbom.py"],
        },
        "packages": [
            {
                "SPDXID": root_ref,
                "name": archive.name,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": archive_sha}],
                "supplier": "Organization: paul007ex/sts-delegate-rs",
            },
            *(package_entry(package) for package in packages),
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": root_ref,
            },
            *(
                {
                    "spdxElementId": root_ref,
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": package_ref,
                }
                for package_ref in package_refs
            ),
            *(
                {
                    "spdxElementId": root_ref,
                    "relationshipType": "GENERATED_FROM",
                    "relatedSpdxElement": workspace_ref,
                }
                for workspace_ref in workspace_refs
            ),
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path, help="Release archive path")
    parser.add_argument("--output", required=True, type=Path, help="SPDX JSON output path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    archive = args.archive.resolve()
    output = args.output.resolve()
    if not archive.is_file():
        raise SystemExit(f"archive not found: {archive}")

    document = build_document(archive, cargo_metadata())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"sbom={output}")
    print(f"archive_sha256={sha256_file(archive)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
