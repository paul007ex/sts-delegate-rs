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
    "cargo-audit": ["cargo", "audit"],
    "cargo-deny": ["cargo", "deny", "check"],
    "cargo-geiger": ["cargo", "geiger", "--all-features"],
    "cargo-vet": ["cargo", "vet"],
}


def timestamp() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_command(label: str, command: list[str]) -> bool:
    print(f"check={label} command={' '.join(command)}")
    completed = subprocess.run(command, cwd=REPO, text=True, check=False)
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
    if completed.stdout.strip():
        print("check=duplicate-dependencies result=fail reason=duplicates-present")
        return False
    print("check=duplicate-dependencies result=pass")
    return True


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


def run_supply_chain_tools(strict_missing: bool) -> bool:
    ok = True
    for binary, command in OPTIONAL_SUPPLY_CHAIN_TOOLS.items():
        if shutil.which(binary) is None:
            print(f"check={binary} result=missing")
            ok = ok and not strict_missing
            continue
        ok = run_command(binary, command) and ok
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
