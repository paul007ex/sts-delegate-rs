#!/usr/bin/env python3
"""Check the sts-delegate-rs crate dependency boundary."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

WORKSPACE_CRATES = {
    "sts-cli",
    "sts-config",
    "sts-core",
    "sts-dpop",
    "sts-http",
    "sts-jose",
    "sts-replay",
    "sts-verify",
}

ALLOWED_NORMAL_WORKSPACE_DEPS = {
    # `sts-cli` can bootstrap the HTTP runtime and run operator key workflows.
    # Key rotation uses JOSE-owned RSA/JWK generation instead of duplicating
    # private-key handling in the CLI crate.
    "sts-cli": {"sts-dpop", "sts-http", "sts-jose"},
    "sts-config": set(),
    "sts-core": set(),
    "sts-dpop": set(),
    "sts-http": {"sts-config", "sts-core", "sts-dpop", "sts-jose", "sts-replay", "sts-verify"},
    # `sts-jose` owns compact JWS signing and currently has a typed access-token
    # helper for `MintedClaims`. Keep this edge explicit until the JOSE API is fully generic.
    "sts-jose": {"sts-core"},
    "sts-replay": set(),
    "sts-verify": {"sts-jose"},
}

TRANSPORT_ONLY_NORMAL_DEPS = {"axum", "http", "http-body-util", "tower"}
NETWORK_CLIENT_NORMAL_DEPS = {"reqwest"}
ASYNC_RUNTIME_NORMAL_DEPS = {"tokio"}


def run_metadata(repo: Path) -> dict:
    output = subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=repo,
        text=True,
    )
    return json.loads(output)


def normal_dependencies(package: dict) -> set[str]:
    deps: set[str] = set()
    for dep in package["dependencies"]:
        if dep.get("kind") in (None, "normal"):
            deps.add(dep["name"])
    return deps


def workspace_normal_graph(packages: dict[str, dict]) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    for name, package in packages.items():
        graph[name] = normal_dependencies(package) & WORKSPACE_CRATES
    return graph


def find_cycles(graph: dict[str, set[str]]) -> list[str]:
    cycles: list[str] = []
    visiting: list[str] = []
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            cycle = visiting[visiting.index(node) :] + [node]
            cycles.append(" -> ".join(cycle))
            return
        if node in visited:
            return
        visiting.append(node)
        for dep in sorted(graph[node]):
            visit(dep)
        visiting.pop()
        visited.add(node)

    for node in sorted(graph):
        visit(node)
    return cycles


def crate_root(package: dict) -> Path:
    targets = package["targets"]
    for target in targets:
        if "lib" in target["kind"] or "bin" in target["kind"]:
            return Path(target["src_path"])
    raise ValueError(f"no crate root target for {package['name']}")


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    metadata = run_metadata(repo)
    packages = {pkg["name"]: pkg for pkg in metadata["packages"] if pkg["name"] in WORKSPACE_CRATES}
    errors: list[str] = []

    missing = WORKSPACE_CRATES - packages.keys()
    extra = packages.keys() - WORKSPACE_CRATES
    if missing:
        errors.append(f"missing workspace crates from metadata: {sorted(missing)}")
    if extra:
        errors.append(f"unexpected workspace crates in metadata: {sorted(extra)}")

    graph = workspace_normal_graph(packages)
    for crate_name, actual in sorted(graph.items()):
        allowed = ALLOWED_NORMAL_WORKSPACE_DEPS[crate_name]
        unexpected = actual - allowed
        if unexpected:
            errors.append(
                f"{crate_name} has unexpected normal workspace deps: {sorted(unexpected)}; "
                f"allowed={sorted(allowed)}"
            )

    for crate_name, package in sorted(packages.items()):
        direct_deps = normal_dependencies(package)
        if crate_name != "sts-http":
            transport_deps = direct_deps & TRANSPORT_ONLY_NORMAL_DEPS
            if transport_deps:
                errors.append(f"{crate_name} depends on transport-only crates: {sorted(transport_deps)}")
        if crate_name not in {"sts-cli", "sts-verify"}:
            network_deps = direct_deps & NETWORK_CLIENT_NORMAL_DEPS
            if network_deps:
                errors.append(
                    f"{crate_name} depends on network-client crates: {sorted(network_deps)}"
                )
        if crate_name not in {"sts-cli", "sts-http", "sts-verify"}:
            async_deps = direct_deps & ASYNC_RUNTIME_NORMAL_DEPS
            if async_deps:
                errors.append(f"{crate_name} depends directly on async runtime crates: {sorted(async_deps)}")

        root = crate_root(package)
        text = root.read_text(encoding="utf-8")
        if "#![forbid(unsafe_code)]" not in text.splitlines()[:5]:
            errors.append(f"{crate_name} crate root does not forbid unsafe code: {root}")

    for cycle in find_cycles(graph):
        errors.append(f"workspace dependency cycle: {cycle}")

    if errors:
        print("architecture_boundaries=fail")
        for error in errors:
            print(f"- {error}")
        return 1

    for crate_name in sorted(graph):
        deps = ", ".join(sorted(graph[crate_name])) or "(none)"
        print(f"{crate_name}: {deps}")
    print("architecture_boundaries=pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
