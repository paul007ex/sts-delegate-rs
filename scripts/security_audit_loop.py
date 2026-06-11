#!/usr/bin/env python3
"""Run the sts-delegate-rs secure Rust audit loop."""

from __future__ import annotations

import argparse
import datetime as dt
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]

PRODUCTION_PATTERNS = [
    ("placeholder macro", re.compile(r"\b(?:todo!|unimplemented!|dbg!)\s*\(")),
    ("unsafe block", re.compile(r"\bunsafe\s*\{")),
    ("panic surface", re.compile(r"(?:\.unwrap\(\)|\.expect\(|panic!\s*\()")),
]

SECRET_LOG_PATTERN = re.compile(
    r"(?:println!|eprintln!|dbg!|tracing::\w+!|log::\w+!)\s*\(.*"
    r"(?:token|secret|assertion|private_key|authorization)",
    re.IGNORECASE,
)

OPTIONAL_SUPPLY_CHAIN_TOOLS = {
    "cargo-audit": "cargo audit",
    "cargo-deny": "cargo deny check",
    "cargo-geiger": "cargo geiger",
    "cargo-vet": "cargo vet",
}

STRICT_SUPPLY_CHAIN_TIMEOUT_SECONDS = 180

ALLOWED_DUPLICATE_DEPENDENCIES = {
    "untrusted": (
        "aws-lc-rs 1.17 uses untrusted 0.7 via ring-io while rustls-webpki "
        "0.103 uses untrusted 0.9; both are required by the selected AWS-LC "
        "JOSE provider plus rustls verifier stack"
    ),
}


def timestamp() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_command(label: str, command: list[str], timeout: int | None = None) -> bool:
    print(f"check={label} command={' '.join(command)}")
    try:
        completed = subprocess.run(command, cwd=REPO, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"check={label} result=fail reason=timeout seconds={timeout}")
        return False
    if completed.returncode == 0:
        print(f"check={label} result=pass")
        return True
    print(f"check={label} result=fail code={completed.returncode}")
    return False


def check_duplicate_dependencies() -> bool:
    command = ["cargo", "tree", "-d"]
    print(f"check=duplicate-dependencies command={' '.join(command)}")
    completed = subprocess.run(command, cwd=REPO, text=True, check=False, capture_output=True)
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)
    if completed.returncode != 0:
        print(f"check=duplicate-dependencies result=fail code={completed.returncode}")
        return False
    duplicate_names = duplicate_dependency_names(completed.stdout)
    unreviewed = sorted(name for name in duplicate_names if name not in ALLOWED_DUPLICATE_DEPENDENCIES)
    if unreviewed:
        print(
            "check=duplicate-dependencies result=fail reason=unreviewed-duplicates "
            f"crates={','.join(unreviewed)}"
        )
        return False
    for name in sorted(duplicate_names):
        print(
            "check=duplicate-dependencies allowed="
            f"{name} reason={ALLOWED_DUPLICATE_DEPENDENCIES[name]!r}"
        )
    print("check=duplicate-dependencies result=pass")
    return True


def duplicate_dependency_names(tree_output: str) -> set[str]:
    names: set[str] = set()
    for line in tree_output.splitlines():
        if line[:1].isspace():
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+) v\d", line)
        if match:
            names.add(match.group(1))
    return names


def rust_source_files() -> list[Path]:
    return sorted((REPO / "crates").glob("*/src/**/*.rs"))


def production_lines(path: Path) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    pending_cfg_test = False
    skipping_cfg_test_block = False
    cfg_test_depth = 0

    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if skipping_cfg_test_block:
            cfg_test_depth += line.count("{") - line.count("}")
            if cfg_test_depth <= 0:
                skipping_cfg_test_block = False
                cfg_test_depth = 0
            continue

        if stripped == "#[cfg(test)]":
            pending_cfg_test = True
            continue

        if pending_cfg_test:
            if "{" in line:
                skipping_cfg_test_block = True
                cfg_test_depth = line.count("{") - line.count("}")
                if cfg_test_depth <= 0:
                    skipping_cfg_test_block = False
                    cfg_test_depth = 0
            pending_cfg_test = False
            continue

        lines.append((line_number, line))

    return lines


def scan_production_rust() -> bool:
    findings: list[str] = []
    for path in rust_source_files():
        rel = path.relative_to(REPO)
        for line_number, line in production_lines(path):
            for label, pattern in PRODUCTION_PATTERNS:
                if pattern.search(line):
                    findings.append(f"{rel}:{line_number}: {label}: {line.strip()}")
            if SECRET_LOG_PATTERN.search(line):
                findings.append(f"{rel}:{line_number}: possible sensitive logging: {line.strip()}")

    if not findings:
        print("check=production-anti-pattern-scan result=pass")
        return True

    print("check=production-anti-pattern-scan result=fail")
    for finding in findings:
        print(f"- {finding}")
    return False


def strict_supply_chain_commands() -> dict[str, list[str]]:
    cli_manifest = REPO / "crates/sts-cli/Cargo.toml"
    return {
        "cargo-audit": ["cargo", "audit"],
        "cargo-deny": ["cargo", "deny", "check"],
        "cargo-geiger": [
            "cargo",
            "geiger",
            "--manifest-path",
            str(cli_manifest),
            "--all-features",
            "--forbid-only",
            "--locked",
            "--output-format",
            "Ratio",
        ],
        "cargo-vet": ["cargo", "vet"],
    }


def run_supply_chain_tools(strict: bool) -> bool:
    ok = True
    commands = strict_supply_chain_commands()
    for binary, description in OPTIONAL_SUPPLY_CHAIN_TOOLS.items():
        if shutil.which(binary) is None:
            print(f"check={binary} result=missing")
            ok = ok and not strict
            continue
        print(f"check={binary} result=installed command='{description}'")
        if strict:
            ok = run_command(binary, commands[binary], timeout=STRICT_SUPPLY_CHAIN_TIMEOUT_SECONDS) and ok
    return ok


def run_once(args: argparse.Namespace) -> bool:
    print(f"security_audit_loop_start={timestamp()}")
    ok = True
    required_commands = [
        ("fmt", ["cargo", "fmt", "--check"]),
        ("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings"]),
        ("architecture-boundaries", ["scripts/check_architecture_boundaries.py"]),
    ]

    for label, command in required_commands:
        ok = run_command(label, command) and ok

    ok = check_duplicate_dependencies() and ok
    ok = scan_production_rust() and ok
    ok = run_supply_chain_tools(args.strict_supply_chain) and ok

    if args.full:
        full_commands = [
            ("workspace-tests", ["cargo", "test", "--workspace"]),
            ("oracle-contract-smoke", ["scripts/oracle_contract_smoke.sh"]),
        ]
        for label, command in full_commands:
            ok = run_command(label, command) and ok

    print(f"security_audit_loop_result={'pass' if ok else 'fail'}")
    return ok


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loop", type=int, default=0, metavar="SECONDS", help="repeat forever at this interval")
    parser.add_argument("--full", action="store_true", help="also run workspace tests and Python-oracle smoke")
    parser.add_argument(
        "--strict-supply-chain",
        action="store_true",
        help="fail when cargo-audit, cargo-deny, cargo-geiger, or cargo-vet is missing",
    )
    return parser.parse_args()


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)
    args = parse_args()
    if args.loop:
        interval = max(args.loop, 30)
        while True:
            run_once(args)
            print(f"security_audit_loop_sleep={interval}")
            time.sleep(interval)

    return 0 if run_once(args) else 1


if __name__ == "__main__":
    sys.exit(main())
