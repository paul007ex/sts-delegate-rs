#!/usr/bin/env python3
"""Start a fresh Rust STS and prove live Bearer plus DPoP token exchange safely."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils


REPO = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = Path("/Users/Shared/claude/obo-lab/okta.env")
DEFAULT_SUBJECT_TOKEN_FILE = Path("/Users/Shared/claude/obo-lab/user_access_token.txt")
DEFAULT_STS_PRIVATE_JWK_FILE = Path("/Users/Shared/claude/obo-lab/secrets/obo_sts_private_key.json")
DEFAULT_MCP_CONFIG = Path("/Users/Shared/claude/obo-lab/.mcp.json")
DEFAULT_FASTMCP_PYTHON = Path("/Users/Shared/claude/obo-lab/.venv/bin/python3")

ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
PQC_SIGNING_ALG = "ML-DSA-65"

MCP_TARGET_SPECS = {
    "chat-mcp": ("api://chat-mcp", "chat.read"),
    "databricks-mcp": ("api://databricks-mcp", "databricks.read"),
    "servicenow-mcp": ("api://servicenow-mcp", "servicenow.read"),
}
MCP_TOOL_PROBES = {
    "chat-mcp": ("say", {"message": "hello from sts-delegate-rs PQC canary"}),
    "databricks-mcp": ("run_sql_query", {"sql": "SELECT 1"}),
    "servicenow-mcp": ("list_incidents", {}),
}

TOKEN_FIELD_NAMES = {
    "access_token",
    "actor_token",
    "authorization",
    "client_assertion",
    "dpop",
    "jti",
    "subject_token",
}
PRIVATE_JWK_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"}
JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b")
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
SECRET_QUERY_RE = re.compile(
    r"(?i)([?&](?:access_token|subject_token|actor_token|client_assertion|client_secret|authorization)=)[^&\s]+"
)

FASTMCP_CLIENT_PROGRAM = r"""
from __future__ import annotations

import asyncio
import json
import re
import sys

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport


JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b")


def safe_data_summary(data):
    if not isinstance(data, dict):
        return {"data_type": type(data).__name__}
    summary = {"data_keys": sorted(str(key) for key in data)}
    via_actor = data.get("via_actor")
    if isinstance(via_actor, dict):
        summary["via_actor"] = via_actor.get("sub")
    elif isinstance(via_actor, str) and not JWT_RE.search(via_actor):
        summary["via_actor"] = via_actor[:120]
    for key in ("sub", "aud", "scope", "iss", "actor", "tool"):
        value = data.get(key)
        if isinstance(value, str) and not JWT_RE.search(value):
            summary[key] = value[:160]
    return summary


async def call_one(server: dict) -> dict:
    transport = StreamableHttpTransport(server["url"], headers=server["headers"])
    async with Client(transport) as client:
        tools = await client.list_tools()
        tool_names = sorted(tool.name for tool in tools)
        result = {"tools": tool_names}
        identity_tools = [name for name in ("whoami", "incoming", "outgoing") if name in tool_names]
        identity_results = {}
        for tool_name in identity_tools:
            response = await client.call_tool(tool_name, {})
            identity_results[tool_name] = safe_data_summary(getattr(response, "data", None))
        if identity_results:
            result["identity"] = identity_results
        tool_name = server.get("tool")
        if tool_name:
            response = await client.call_tool(tool_name, server.get("args") or {})
            result["tool"] = tool_name
            result["tool_call"] = safe_data_summary(getattr(response, "data", None))
            result["call_status"] = "ok"
        else:
            result["call_status"] = "no_tool_probe"
        return result


async def main() -> None:
    payload = json.load(sys.stdin)
    results = {}
    for name, server in sorted(payload["servers"].items()):
        try:
            results[name] = {"ok": True, **await call_one(server)}
        except Exception as exc:  # noqa: BLE001 - subprocess output is parsed and redacted by caller.
            results[name] = {"ok": False, "error_type": type(exc).__name__, "message": str(exc)[:300]}
    print(json.dumps(results, sort_keys=True))


asyncio.run(main())
"""


class CanaryError(RuntimeError):
    pass


def timestamp() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_json(value: dict[str, Any]) -> str:
    return b64url(json.dumps(value, separators=(",", ":"), sort_keys=True).encode())


def b64url_uint(value: int, width: int | None = None) -> str:
    length = width or max(1, (value.bit_length() + 7) // 8)
    return b64url(value.to_bytes(length, "big"))


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode())


def sha256_prefix(value: str | bytes, *, length: int = 16) -> str:
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()[:length]


def subject_token_hash(subject_token: str) -> str:
    return b64url(hashlib.sha256(subject_token.encode()).digest())


def redact_string(value: str) -> str:
    redacted = SECRET_QUERY_RE.sub(lambda match: f"{match.group(1)}<redacted>", value)
    redacted = BEARER_RE.sub("Bearer <redacted>", redacted)
    return JWT_RE.sub("<jwt-redacted>", redacted)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for key, item in value.items():
            lowered = key.lower()
            if lowered in TOKEN_FIELD_NAMES or lowered in PRIVATE_JWK_MEMBERS:
                safe[key] = "<redacted>"
            elif any(marker in lowered for marker in ("secret", "password", "private", "assertion")):
                safe[key] = "<redacted>"
            else:
                safe[key] = redact(item)
        return safe
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_string(value)
    return value


def log(event: str, **fields: Any) -> None:
    print(json.dumps({"event": event, **redact(fields)}, sort_keys=True), flush=True)


def self_test_redaction() -> None:
    synthetic_jwt = "headerheaderheaderheader.payloadpayloadpayloadpayload.signaturesignature"
    sample = {
        "authorization": f"Bearer {synthetic_jwt}",
        "url": f"https://tenant.invalid/cb?access_token={synthetic_jwt}",
        "nested": {"client_assertion": synthetic_jwt, "jti": "raw-jti"},
        "private_jwk": {"kty": "RSA", "d": "private-value"},
    }
    rendered = json.dumps(redact(sample), sort_keys=True)
    forbidden = [synthetic_jwt, "raw-jti", "private-value", "Bearer header", "access_token=header"]
    if any(value in rendered for value in forbidden):
        raise CanaryError("redaction self-test failed")


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    return values


def env_value(name: str, env_file: dict[str, str]) -> str | None:
    value = os.environ.get(name) or env_file.get(name)
    if value and value.strip():
        return value.strip()
    return None


def read_env_or_file(name: str, env_file: dict[str, str], default_file: Path | None = None) -> str | None:
    value = env_value(name, env_file)
    if value:
        return value
    path = env_value(f"{name}_FILE", env_file)
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    if default_file and default_file.exists():
        return default_file.read_text(encoding="utf-8").strip()
    return None


def env_path(name: str, env_file: dict[str, str], default: Path) -> Path | None:
    raw = env_value(name, env_file)
    path = Path(raw) if raw else default
    return path if path.exists() else None


def load_json(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise CanaryError(f"{label} must be a JSON object")
    return value


def jwt_claims_unverified(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise CanaryError("token is not a compact JWT")
    claims = json.loads(b64url_decode(parts[1]))
    if not isinstance(claims, dict):
        raise CanaryError("JWT claims are not an object")
    return claims


def jwt_header_unverified(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise CanaryError("token is not a compact JWT")
    header = json.loads(b64url_decode(parts[0]))
    if not isinstance(header, dict):
        raise CanaryError("JWT header is not an object")
    return header


def jwk_int(jwk: dict[str, Any], name: str) -> int:
    value = jwk.get(name)
    if not isinstance(value, str) or not value:
        raise CanaryError(f"private JWK missing {name}")
    return int.from_bytes(b64url_decode(value), "big")


def rsa_private_key_from_jwk(jwk: dict[str, Any]) -> rsa.RSAPrivateKey:
    public = rsa.RSAPublicNumbers(e=jwk_int(jwk, "e"), n=jwk_int(jwk, "n"))
    private = rsa.RSAPrivateNumbers(
        p=jwk_int(jwk, "p"),
        q=jwk_int(jwk, "q"),
        d=jwk_int(jwk, "d"),
        dmp1=jwk_int(jwk, "dp"),
        dmq1=jwk_int(jwk, "dq"),
        iqmp=jwk_int(jwk, "qi"),
        public_numbers=public,
    )
    return private.private_key()


def rsa_private_jwk_from_key(key: rsa.RSAPrivateKey, kid: str) -> dict[str, str]:
    numbers = key.private_numbers()
    public = numbers.public_numbers
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": b64url_uint(public.n),
        "e": b64url_uint(public.e),
        "d": b64url_uint(numbers.d),
        "p": b64url_uint(numbers.p),
        "q": b64url_uint(numbers.q),
        "dp": b64url_uint(numbers.dmp1),
        "dq": b64url_uint(numbers.dmq1),
        "qi": b64url_uint(numbers.iqmp),
    }


def public_jwk_from_private_jwk(jwk: dict[str, Any]) -> dict[str, Any]:
    return {
        "kty": jwk["kty"],
        "kid": jwk["kid"],
        "use": jwk.get("use", "sig"),
        "alg": jwk.get("alg", "RS256"),
        "n": jwk["n"],
        "e": jwk["e"],
    }


def generate_actor_private_jwk(actor_id: str) -> dict[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return rsa_private_jwk_from_key(key, f"{actor_id}-canary-key")


def write_actor_jwks(private_jwks: list[dict[str, Any]], directory: Path) -> Path:
    if not private_jwks:
        raise CanaryError("at least one actor JWK is required")
    path = directory / "actor_jwks.json"
    path.write_text(
        json.dumps({"keys": [public_jwk_from_private_jwk(jwk) for jwk in private_jwks]}, sort_keys=True),
        encoding="utf-8",
    )
    path.chmod(0o600)
    log(
        "actor_jwks_ready",
        key_count=len(private_jwks),
        actor_ids=[str(jwk.get("kid", "")).split("-canary-key")[0] for jwk in private_jwks],
        actor_jwks_file=str(path),
        actor_jwks_file_sha256_prefix=file_sha256_prefix(path),
    )
    return path


def sign_rs256_jwt(private_jwk: dict[str, Any], claims: dict[str, Any]) -> str:
    kid = private_jwk.get("kid")
    if not isinstance(kid, str) or not kid:
        raise CanaryError("private JWK missing kid")
    header = {"alg": "RS256", "kid": kid, "typ": "JWT"}
    signing_input = f"{b64url_json(header)}.{b64url_json(claims)}".encode()
    signature = rsa_private_key_from_jwk(private_jwk).sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return f"{signing_input.decode()}.{b64url(signature)}"


def ec_public_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": b64url_uint(numbers.x, 32),
        "y": b64url_uint(numbers.y, 32),
    }


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return b64url(hashlib.sha256(canonical).digest())


def sign_es256_dpop_proof(
    key: ec.EllipticCurvePrivateKey,
    *,
    htm: str,
    htu: str,
    now: int,
    jti: str,
) -> tuple[str, str]:
    public_jwk = ec_public_jwk(key)
    header = {"alg": "ES256", "jwk": public_jwk, "typ": "dpop+jwt"}
    claims = {"htm": htm, "htu": htu, "iat": now, "jti": jti}
    signing_input = f"{b64url_json(header)}.{b64url_json(claims)}".encode()
    signature_der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signature_der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{signing_input.decode()}.{b64url(signature)}", jwk_thumbprint(public_jwk)


def http_json(method: str, url: str, *, headers: dict[str, str] | None = None, data: bytes | None = None) -> tuple[int, dict[str, Any] | None]:
    request = urllib.request.Request(url, data=data, headers=headers or {"Accept": "application/json"}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read(256_000)
            parsed = json.loads(raw) if raw else None
            return response.status, parsed if isinstance(parsed, dict) else None
    except urllib.error.HTTPError as err:
        raw = err.read(64_000)
        parsed = None
        if raw:
            try:
                parsed_value = json.loads(raw)
                parsed = parsed_value if isinstance(parsed_value, dict) else None
            except json.JSONDecodeError:
                parsed = None
        return err.code, parsed
    except urllib.error.URLError as err:
        raise CanaryError(f"{method} {url} failed: {redact_string(str(err.reason))}") from err


def post_token(token_endpoint: str, form: dict[str, str], *, dpop_proof: str | None = None) -> tuple[int, dict[str, Any] | None]:
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    if dpop_proof:
        headers["DPoP"] = dpop_proof
    encoded = urllib.parse.urlencode(form).encode()
    return http_json("POST", token_endpoint, headers=headers, data=encoded)


def verify_rs256_jwt_against_jwks(token: str, jwks: dict[str, Any]) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise CanaryError("minted token is not a compact JWT")
    header = json.loads(b64url_decode(parts[0]))
    if header.get("alg") != "RS256":
        raise CanaryError("minted token alg is not RS256")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise CanaryError("minted token header missing kid")
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise CanaryError("JWKS keys is not an array")
    key = next((item for item in keys if isinstance(item, dict) and item.get("kid") == kid), None)
    if not key:
        raise CanaryError("minted token kid not found in Rust JWKS")
    public = rsa.RSAPublicNumbers(e=jwk_int(key, "e"), n=jwk_int(key, "n")).public_key()
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        public.verify(b64url_decode(parts[2]), signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise CanaryError("minted token signature did not verify against Rust JWKS") from exc
    return jwt_claims_unverified(token)


def verify_token_with_cli(
    binary: Path,
    *,
    token: str,
    jwks: dict[str, Any],
    directory: Path,
    label: str,
    expected_alg: str,
) -> dict[str, Any]:
    header = jwt_header_unverified(token)
    if header.get("alg") != expected_alg:
        raise CanaryError(f"{label} minted token alg mismatch")
    token_file = directory / f"{label}_access_token.jwt"
    jwks_file = directory / f"{label}_rust_jwks.json"
    token_file.write_text(token, encoding="utf-8")
    jwks_file.write_text(json.dumps(jwks, sort_keys=True), encoding="utf-8")
    token_file.chmod(0o600)
    jwks_file.chmod(0o600)
    output = run_cli(
        binary,
        [
            "token",
            "verify",
            "--token-file",
            str(token_file),
            "--jwks-file",
            str(jwks_file),
        ],
        timeout=60,
    )
    for expected in (
        "token_verify_status=ok",
        "jwt_signature_verified=true",
        f"jwt_header_alg={expected_alg}",
    ):
        if expected not in output:
            raise CanaryError(f"sts-cli token verify output missing {expected}")
    log(
        "token_verify_pass",
        label=label,
        jwt_header_alg=expected_alg,
        token_sha256_prefix=sha256_prefix(token),
        token_len=len(token),
        output_sha256_prefix=sha256_prefix(output),
    )
    return jwt_claims_unverified(token)


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def file_sha256_prefix(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()[:16]


def build_cli(skip_build: bool, *, pqc: bool) -> Path:
    binary = REPO / "target/debug/sts-cli"
    if not skip_build or not binary.exists():
        command = ["cargo", "build", "-p", "sts-cli"]
        if pqc:
            command.extend(["--features", "pqc-openssl-unstable"])
        completed = subprocess.run(
            command,
            cwd=REPO,
            text=True,
            capture_output=True,
            check=False,
            timeout=300,
        )
        if completed.returncode != 0:
            raise CanaryError(f"cargo build failed rc={completed.returncode}: {redact_string(completed.stderr[-500:])}")
    if not binary.exists():
        raise CanaryError("target/debug/sts-cli was not produced")
    log("sts_cli_binary_ready", exe=str(binary), exe_sha256_prefix=file_sha256_prefix(binary))
    if pqc:
        preflight = run_cli(binary, ["pqc", "preflight"], timeout=60)
        if "pqc_openssl_feature_enabled=true" not in preflight or f"{PQC_SIGNING_ALG}_sign_verify=ok" not in preflight:
            raise CanaryError("sts-cli PQC preflight did not prove OpenSSL ML-DSA readiness")
        log("sts_cli_pqc_preflight_pass", output_sha256_prefix=sha256_prefix(preflight))
    return binary


def run_cli(binary: Path, args: list[str], *, timeout: int = 30) -> str:
    completed = subprocess.run(
        [str(binary), *args],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    combined = f"{completed.stdout}\n{completed.stderr}"
    if completed.returncode != 0:
        raise CanaryError(
            f"sts-cli {' '.join(args[:2])} failed rc={completed.returncode}: {redact_string(combined[-500:])}"
        )
    if JWT_RE.search(combined) or BEARER_RE.search(combined):
        raise CanaryError("sts-cli output contained an unredacted token-looking value")
    return completed.stdout


def fastmcp_call_servers(
    servers: dict[str, dict[str, Any]],
    *,
    fastmcp_python: Path,
    timeout: int,
) -> dict[str, dict[str, Any]]:
    if not fastmcp_python.exists():
        raise CanaryError(f"FastMCP Python interpreter missing: {fastmcp_python}")
    completed = subprocess.run(
        [str(fastmcp_python), "-c", FASTMCP_CLIENT_PROGRAM],
        input=json.dumps({"servers": servers}),
        cwd=REPO,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        combined = f"{completed.stdout}\n{completed.stderr}"
        raise CanaryError(
            f"FastMCP client subprocess failed rc={completed.returncode}: {redact_string(combined[-700:])}"
        )
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CanaryError("FastMCP client subprocess returned non-JSON output") from exc
    if not isinstance(parsed, dict):
        raise CanaryError("FastMCP client subprocess returned invalid result shape")
    return {str(name): result for name, result in parsed.items() if isinstance(result, dict)}


def mcp_servers_from_config(config_path: Path) -> dict[str, str]:
    if not config_path.exists():
        raise CanaryError(f"MCP config missing: {config_path}")
    data = json.loads(config_path.read_text(encoding="utf-8"))
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        raise CanaryError("MCP config has no mcpServers object")
    urls: dict[str, str] = {}
    for name, server in sorted(servers.items()):
        if not isinstance(server, dict):
            continue
        url = server.get("url")
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            urls[str(name)] = url
    if not urls:
        raise CanaryError("MCP config has no HTTP server URLs")
    return urls


def run_fastmcp_proof(
    *,
    mcp_config: Path,
    fastmcp_python: Path,
    minted_tokens: dict[str, str],
    require_mcp: bool,
) -> None:
    if not mcp_config.exists():
        log("mcp_not_configured", config=str(mcp_config), missing=["mcp config"])
        if require_mcp:
            raise CanaryError(f"MCP config missing: {mcp_config}")
        return
    urls = mcp_servers_from_config(mcp_config)
    servers: dict[str, dict[str, Any]] = {}
    for name, token in sorted(minted_tokens.items()):
        url = urls.get(name)
        if not url:
            continue
        tool_name, tool_args = MCP_TOOL_PROBES.get(name, (None, {}))
        servers[name] = {
            "url": url,
            "headers": {"Authorization": f"Bearer {token}"},
            "tool": tool_name,
            "args": tool_args,
        }
    if not servers:
        log("mcp_not_configured", config=str(mcp_config), missing=["matching configured MCP server URLs"])
        if require_mcp:
            raise CanaryError("no configured MCP server URL matched minted token targets")
        return
    results = fastmcp_call_servers(servers, fastmcp_python=fastmcp_python, timeout=60)
    failures = [f"{name}:{result.get('error_type', 'error')}" for name, result in results.items() if not result.get("ok")]
    log(
        "mcp_fastmcp_calls_checked",
        config=str(mcp_config),
        servers={name: {"url": servers[name]["url"], "token_sha256_prefix": sha256_prefix(minted_tokens[name])} for name in servers},
        results=results,
    )
    if require_mcp and failures:
        raise CanaryError(f"MCP proof failed: {', '.join(failures)}")


def process_command(pid: int) -> str | None:
    try:
        completed = subprocess.run(
            ["/bin/ps", "-p", str(pid), "-o", "comm="],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
    except Exception:
        return None
    command = completed.stdout.strip()
    return command or None


def wait_ready(process: subprocess.Popen[str], issuer: str) -> dict[str, Any]:
    metadata_url = metadata_url_for_issuer(issuer)
    deadline = time.time() + 45
    last_error = "not ready"
    while time.time() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read()[-1000:] if process.stderr else ""
            raise CanaryError(f"sts-cli serve exited early rc={process.returncode}: {redact_string(stderr)}")
        try:
            status, metadata = http_json("GET", metadata_url)
            if status == 200 and isinstance(metadata, dict):
                jwks_uri = metadata.get("jwks_uri")
                token_endpoint = metadata.get("token_endpoint")
                if not isinstance(jwks_uri, str) or not isinstance(token_endpoint, str):
                    raise CanaryError("metadata missing token_endpoint or jwks_uri")
                jwks_status, jwks = http_json("GET", jwks_uri)
                if jwks_status == 200 and isinstance(jwks, dict):
                    log(
                        "rust_sts_ready",
                        metadata_status=status,
                        jwks_status=jwks_status,
                        key_count=len(jwks.get("keys", [])) if isinstance(jwks.get("keys"), list) else 0,
                    )
                    return {"metadata": metadata, "jwks": jwks}
                last_error = f"jwks_status={jwks_status}"
        except Exception as exc:
            last_error = str(exc)
        time.sleep(0.25)
    raise CanaryError(f"Rust STS did not become ready: {redact_string(last_error)}")


def metadata_url_for_issuer(issuer: str) -> str:
    parsed = urllib.parse.urlsplit(issuer)
    path = parsed.path.rstrip("/")
    base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    return f"{base}/.well-known/oauth-authorization-server{path}"


def fetch_idp_jwks_file(issuer: str, directory: Path) -> Path:
    discovery_url = f"{issuer}/.well-known/openid-configuration"
    discovery_status, discovery = http_json("GET", discovery_url)
    if discovery_status != 200 or not isinstance(discovery, dict):
        raise CanaryError(f"Okta discovery failed status={discovery_status}")
    if str(discovery.get("issuer", "")).rstrip("/") != issuer.rstrip("/"):
        raise CanaryError("Okta discovery issuer mismatch")
    jwks_uri = discovery.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise CanaryError("Okta discovery missing jwks_uri")
    jwks_status, jwks = http_json("GET", jwks_uri)
    if jwks_status != 200 or not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise CanaryError(f"Okta JWKS failed status={jwks_status}")
    for key in jwks.get("keys", []):
        if isinstance(key, dict) and PRIVATE_JWK_MEMBERS & key.keys():
            raise CanaryError("Okta JWKS exposed private key members")
    path = directory / "idp_jwks.json"
    path.write_text(json.dumps(jwks, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)
    log(
        "idp_jwks_ready",
        discovery_status=discovery_status,
        jwks_status=jwks_status,
        key_count=len(jwks.get("keys", [])),
        jwks_file=str(path),
        jwks_file_sha256_prefix=file_sha256_prefix(path),
    )
    return path


def checked_config(args: argparse.Namespace, env_file: dict[str, str]) -> dict[str, Any] | None:
    missing: list[str] = []
    issuer = env_value("CANARY_IDP_ISSUER", env_file) or env_value("OKTA_ISSUER", env_file) or env_value("IDP_ISSUER", env_file)
    expected_aud = env_value("CANARY_EXPECTED_SUBJECT_AUD", env_file) or env_value("EXPECTED_SUBJECT_AUD", env_file)
    subject_token = read_env_or_file("CANARY_SUBJECT_TOKEN", env_file, args.subject_token_file)
    sts_private_jwk_file = env_path("OBO_STS_KEY_FILE", env_file, args.sts_private_jwk_file)

    if not issuer:
        missing.append("CANARY_IDP_ISSUER or OKTA_ISSUER or IDP_ISSUER")
    if not expected_aud:
        missing.append("CANARY_EXPECTED_SUBJECT_AUD or EXPECTED_SUBJECT_AUD")
    if not subject_token:
        missing.append("CANARY_SUBJECT_TOKEN/_FILE or user_access_token.txt")
    if not sts_private_jwk_file:
        missing.append("OBO_STS_KEY_FILE or obo_sts_private_key.json")
    if missing:
        log("live_rust_sts_canary_not_configured", missing=missing)
        return None

    subject_claims = jwt_claims_unverified(subject_token)
    exp = subject_claims.get("exp")
    if isinstance(exp, (int, float)) and exp <= time.time() + 60:
        log("live_rust_sts_canary_not_configured", missing=["subject token is expired or expires within 60 seconds"])
        return None

    actor_id = (
        env_value("CANARY_ACTOR_ID", env_file)
        or env_value("GATEWAY_ACTOR_ID", env_file)
        or (env_value("ACTOR_IDS", env_file) or "chat-mcp").split(",")[0].strip()
    )
    target_audience = env_value("CANARY_TARGET_AUDIENCE", env_file) or args.target_audience
    target_scope = env_value("CANARY_TARGET_SCOPE", env_file) or args.target_scope
    return {
        "issuer": issuer.rstrip("/"),
        "expected_aud": expected_aud,
        "subject_token": subject_token,
        "subject_claims": subject_claims,
        "sts_private_jwk_file": sts_private_jwk_file,
        "actor_id": actor_id,
        "target_audience": target_audience,
        "target_scope": target_scope,
    }


def actor_assertion(private_jwk: dict[str, Any], actor_id: str, audience: str, subject_token: str) -> str:
    now = int(time.time())
    claims = {
        "iss": actor_id,
        "sub": actor_id,
        "aud": audience,
        "iat": now,
        "exp": now + 180,
        "jti": secrets.token_urlsafe(24),
        "sub_tok_hash": subject_token_hash(subject_token),
    }
    return sign_rs256_jwt(private_jwk, claims)


def exchange_form(subject_token: str, actor_token: str, target_audience: str, target_scope: str) -> dict[str, str]:
    return {
        "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
        "subject_token": subject_token,
        "subject_token_type": ACCESS_TOKEN_TYPE,
        "actor_token": actor_token,
        "actor_token_type": JWT_TOKEN_TYPE,
        "audience": target_audience,
        "scope": target_scope,
    }


def canary_targets(config: dict[str, Any], *, prove_mcp: bool) -> dict[str, tuple[str, str]]:
    targets = {str(config["actor_id"]): (str(config["target_audience"]), str(config["target_scope"]))}
    if prove_mcp:
        targets.update(MCP_TARGET_SPECS)
    return targets


def target_policy_for(targets: dict[str, tuple[str, str]], *, pqc: bool) -> dict[str, Any]:
    policy: dict[str, Any] = {}
    for _actor_id, (audience, scope) in sorted(targets.items()):
        entry: dict[str, Any] = {
            "allowed_scopes": [scope],
            "default_scopes": [scope],
        }
        if pqc:
            entry["accepted_token_signing_algs"] = [PQC_SIGNING_ALG]
            entry["pqc_required"] = True
        policy[audience] = entry
    return policy


def validate_exchange_claims(
    *,
    label: str,
    response: dict[str, Any],
    claims: dict[str, Any],
    expected_token_type: str,
    subject_claims: dict[str, Any],
    actor_id: str,
    target_audience: str,
    target_scope: str,
    expected_jkt: str | None = None,
) -> None:
    if response.get("token_type") != expected_token_type:
        raise CanaryError(f"{label} token_type mismatch")
    if response.get("issued_token_type") != ACCESS_TOKEN_TYPE:
        raise CanaryError(f"{label} issued_token_type mismatch")
    if response.get("signing_alg_selected") not in (None, "RS256", PQC_SIGNING_ALG):
        raise CanaryError(f"{label} signing_alg_selected is unexpected")
    if claims.get("sub") != subject_claims.get("sub"):
        raise CanaryError(f"{label} did not preserve subject")
    act = claims.get("act")
    if not isinstance(act, dict) or act.get("sub") != actor_id:
        raise CanaryError(f"{label} missing act.sub")
    if claims.get("aud") != target_audience:
        raise CanaryError(f"{label} target audience mismatch")
    if claims.get("scope") != target_scope:
        raise CanaryError(f"{label} scope mismatch")
    if expected_jkt is not None:
        cnf = claims.get("cnf")
        if not isinstance(cnf, dict) or cnf.get("jkt") != expected_jkt:
            raise CanaryError(f"{label} cnf.jkt mismatch")


def safe_claim_event(response: dict[str, Any], claims: dict[str, Any], *, dpop_jkt: str | None = None) -> dict[str, Any]:
    header = jwt_header_unverified(str(response.get("access_token", "")))
    event = {
        "status": 200,
        "token_type": response.get("token_type"),
        "issued_token_type": response.get("issued_token_type"),
        "signing_alg_selected": response.get("signing_alg_selected"),
        "pqc_fallback": response.get("pqc_fallback"),
        "jwt_header_alg": header.get("alg"),
        "jwt_header_kid": header.get("kid"),
        "access_token_sha256_prefix": sha256_prefix(str(response.get("access_token", ""))),
        "access_token_len": len(str(response.get("access_token", ""))),
        "iss": claims.get("iss"),
        "sub_sha256_prefix": sha256_prefix(str(claims.get("sub", ""))),
        "jti_sha256_prefix": sha256_prefix(str(claims.get("jti", ""))) if claims.get("jti") else None,
        "act_sub": claims.get("act", {}).get("sub") if isinstance(claims.get("act"), dict) else None,
        "aud": claims.get("aud"),
        "scope": claims.get("scope"),
        "exp": claims.get("exp"),
    }
    if dpop_jkt:
        event["cnf_jkt_sha256_prefix"] = sha256_prefix(dpop_jkt)
    return event


def run_live(args: argparse.Namespace) -> bool:
    env_file = parse_env_file(args.env_file)
    config = checked_config(args, env_file)
    if config is None:
        return not args.require_live

    binary = build_cli(args.skip_build, pqc=args.pqc)
    port = free_loopback_port()
    issuer = f"http://127.0.0.1:{port}/tenant1"
    targets = canary_targets(config, prove_mcp=args.prove_mcp)
    actor_ids = sorted(targets)
    target_policy = target_policy_for(targets, pqc=args.pqc)
    with tempfile.TemporaryDirectory(prefix="sts-rust-canary-") as raw_tmpdir:
        tmpdir = Path(raw_tmpdir)
        sts_private_jwk_file = Path(config["sts_private_jwk_file"])
        if args.pqc:
            sts_private_jwk_file = tmpdir / "sts_mldsa_private.json"
            sts_public_jwks_file = tmpdir / "sts_mldsa_public.jwks.json"
            key_output = run_cli(
                binary,
                [
                    "pqc",
                    "key",
                    "generate",
                    "--alg",
                    PQC_SIGNING_ALG,
                    "--out",
                    str(sts_private_jwk_file),
                    "--public-jwks-out",
                    str(sts_public_jwks_file),
                ],
                timeout=60,
            )
            for expected in ("pqc_key_status=generated", f"alg={PQC_SIGNING_ALG}", "private_key_mode=0600"):
                if expected not in key_output:
                    raise CanaryError(f"sts-cli PQC key generation output missing {expected}")
            log(
                "sts_pqc_key_ready",
                alg=PQC_SIGNING_ALG,
                private_key_file=str(sts_private_jwk_file),
                public_jwks_file=str(sts_public_jwks_file),
                output_sha256_prefix=sha256_prefix(key_output),
            )

        idp_jwks_file = fetch_idp_jwks_file(config["issuer"], tmpdir)
        actor_jwks_by_id = {actor_id: generate_actor_private_jwk(actor_id) for actor_id in actor_ids}
        actor_jwks_file = write_actor_jwks(list(actor_jwks_by_id.values()), tmpdir)
        process_env = os.environ.copy()
        process_env.update(
            {
                "IDP_ISSUER": config["issuer"],
                "EXPECTED_SUBJECT_AUD": config["expected_aud"],
                "ACTOR_IDS": ",".join(actor_ids),
                "OBO_STS_ISSUER": issuer,
                "STS_HTTP_ADDR": f"127.0.0.1:{port}",
                "OBO_STS_KEY_FILE": str(sts_private_jwk_file),
                "IDP_JWKS_FILE": str(idp_jwks_file),
                "ACTOR_JWKS_FILE": str(actor_jwks_file),
                "CLIENT_JWKS_FILE": str(actor_jwks_file),
                "TARGET_POLICY_JSON": json.dumps(target_policy, separators=(",", ":")),
                "STS_TOKEN_EXCHANGE_MODE": "delegation",
                "REQUIRE_SUBJECT_BINDING": "true",
                "SUBJECT_SCOPE_BOUND_REQUIRED": "false",
            }
        )
        if args.pqc:
            process_env.update(
                {
                    "STS_SIGNING_ALG": PQC_SIGNING_ALG,
                    "STS_PQC_PREFERRED": "true",
                    "STS_ALLOW_NON_PQC": "false",
                    "STS_PQC_PREFERRED_ALGS": PQC_SIGNING_ALG,
                }
            )

        process = subprocess.Popen(
            [str(binary), "serve"],
            cwd=REPO,
            env=process_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        log(
            "rust_sts_process_started",
            pid=process.pid,
            cwd=str(REPO),
            exe=str(binary),
            ps_command=process_command(process.pid),
            exe_sha256_prefix=file_sha256_prefix(binary),
            issuer=issuer,
        )
        try:
            ready = wait_ready(process, issuer)
            metadata = ready["metadata"]
            jwks = ready["jwks"]
            token_endpoint = metadata["token_endpoint"]
            subject_token = config["subject_token"]
            primary_actor_jwk = actor_jwks_by_id[str(config["actor_id"])]
            expected_alg = PQC_SIGNING_ALG if args.pqc else "RS256"

            bearer_actor = actor_assertion(primary_actor_jwk, config["actor_id"], issuer, subject_token)
            bearer_status, bearer_body = post_token(
                token_endpoint,
                exchange_form(subject_token, bearer_actor, config["target_audience"], config["target_scope"]),
            )
            if bearer_status != 200 or not isinstance(bearer_body, dict) or not isinstance(bearer_body.get("access_token"), str):
                raise CanaryError(f"Bearer exchange failed status={bearer_status} body={redact(bearer_body)}")
            if args.pqc:
                if bearer_body.get("signing_alg_selected") != PQC_SIGNING_ALG or bearer_body.get("pqc_fallback") is not False:
                    raise CanaryError("Bearer PQC exchange did not use fail-closed ML-DSA signing")
                bearer_claims = verify_token_with_cli(
                    binary,
                    token=str(bearer_body["access_token"]),
                    jwks=jwks,
                    directory=tmpdir,
                    label="bearer",
                    expected_alg=expected_alg,
                )
            else:
                bearer_claims = verify_rs256_jwt_against_jwks(str(bearer_body["access_token"]), jwks)
            validate_exchange_claims(
                label="bearer",
                response=bearer_body,
                claims=bearer_claims,
                expected_token_type="Bearer",
                subject_claims=config["subject_claims"],
                actor_id=config["actor_id"],
                target_audience=config["target_audience"],
                target_scope=config["target_scope"],
            )
            log("bearer_exchange_pass", **safe_claim_event(bearer_body, bearer_claims))

            dpop_key = ec.generate_private_key(ec.SECP256R1())
            dpop_proof, dpop_jkt = sign_es256_dpop_proof(
                dpop_key,
                htm="POST",
                htu=token_endpoint,
                now=int(time.time()),
                jti=secrets.token_urlsafe(24),
            )
            dpop_actor = actor_assertion(primary_actor_jwk, config["actor_id"], issuer, subject_token)
            dpop_status, dpop_body = post_token(
                token_endpoint,
                exchange_form(subject_token, dpop_actor, config["target_audience"], config["target_scope"]),
                dpop_proof=dpop_proof,
            )
            if dpop_status != 200 or not isinstance(dpop_body, dict) or not isinstance(dpop_body.get("access_token"), str):
                raise CanaryError(f"DPoP exchange failed status={dpop_status} body={redact(dpop_body)}")
            if args.pqc:
                if dpop_body.get("signing_alg_selected") != PQC_SIGNING_ALG or dpop_body.get("pqc_fallback") is not False:
                    raise CanaryError("DPoP PQC exchange did not use fail-closed ML-DSA signing")
                dpop_claims = verify_token_with_cli(
                    binary,
                    token=str(dpop_body["access_token"]),
                    jwks=jwks,
                    directory=tmpdir,
                    label="dpop",
                    expected_alg=expected_alg,
                )
            else:
                dpop_claims = verify_rs256_jwt_against_jwks(str(dpop_body["access_token"]), jwks)
            validate_exchange_claims(
                label="dpop",
                response=dpop_body,
                claims=dpop_claims,
                expected_token_type="DPoP",
                subject_claims=config["subject_claims"],
                actor_id=config["actor_id"],
                target_audience=config["target_audience"],
                target_scope=config["target_scope"],
                expected_jkt=dpop_jkt,
            )
            log("dpop_exchange_pass", **safe_claim_event(dpop_body, dpop_claims, dpop_jkt=dpop_jkt))

            replay_actor = actor_assertion(primary_actor_jwk, config["actor_id"], issuer, subject_token)
            replay_status, replay_body = post_token(
                token_endpoint,
                exchange_form(subject_token, replay_actor, config["target_audience"], config["target_scope"]),
                dpop_proof=dpop_proof,
            )
            if replay_status != 400 or not isinstance(replay_body, dict) or replay_body.get("error") != "invalid_dpop_proof":
                raise CanaryError(f"DPoP replay was not rejected status={replay_status} body={redact(replay_body)}")
            log("dpop_replay_rejected", status=replay_status, error=replay_body.get("error"))

            cli_subject_file = tmpdir / "cli_subject_token.txt"
            cli_actor_file = tmpdir / "cli_actor_token.jwt"
            cli_jwks_file = tmpdir / "cli_rust_jwks.json"
            cli_dpop_key_file = tmpdir / "cli_dpop_holder_private_jwk.json"
            cli_subject_file.write_text(subject_token, encoding="utf-8")
            cli_actor = actor_assertion(primary_actor_jwk, config["actor_id"], issuer, subject_token)
            cli_actor_file.write_text(cli_actor, encoding="utf-8")
            cli_jwks_file.write_text(json.dumps(jwks, sort_keys=True), encoding="utf-8")
            for path in (cli_subject_file, cli_actor_file, cli_jwks_file):
                path.chmod(0o600)

            key_output = run_cli(
                binary,
                ["dpop", "key", "generate", "--out", str(cli_dpop_key_file)],
            )
            if "dpop_key_status=generated" not in key_output or "jkt_sha256_prefix=" not in key_output:
                raise CanaryError("sts-cli dpop key generate did not report safe key status")

            cli_output = run_cli(
                binary,
                [
                    "exchange",
                    "--token-endpoint",
                    token_endpoint,
                    "--subject-token-file",
                    str(cli_subject_file),
                    "--actor-token-file",
                    str(cli_actor_file),
                    "--audience",
                    config["target_audience"],
                    "--scope",
                    config["target_scope"],
                    "--dpop-key-file",
                    str(cli_dpop_key_file),
                    "--jwks-file",
                    str(cli_jwks_file),
                ],
            )
            for expected in (
                "exchange_status=ok",
                "token_type=DPoP",
                "jwt_signature_verified=true",
                "dpop_cnf_jkt_matches_holder=true",
                "claims.cnf_jkt_sha256_prefix=",
            ):
                if expected not in cli_output:
                    raise CanaryError(f"sts-cli DPoP exchange output missing {expected}")
            if f"jwt_header_alg={expected_alg}" not in cli_output:
                raise CanaryError(f"sts-cli DPoP exchange output did not verify {expected_alg}")
            log(
                "cli_dpop_exchange_pass",
                output_sha256_prefix=sha256_prefix(cli_output),
                key_output_sha256_prefix=sha256_prefix(key_output),
            )

            if args.prove_mcp:
                mcp_tokens: dict[str, str] = {}
                for actor_id, (target_audience, target_scope) in sorted(MCP_TARGET_SPECS.items()):
                    actor_jwk = actor_jwks_by_id[actor_id]
                    actor_token = actor_assertion(actor_jwk, actor_id, issuer, subject_token)
                    status, body = post_token(
                        token_endpoint,
                        exchange_form(subject_token, actor_token, target_audience, target_scope),
                    )
                    if status != 200 or not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
                        raise CanaryError(f"MCP token exchange for {actor_id} failed status={status} body={redact(body)}")
                    if args.pqc and (body.get("signing_alg_selected") != PQC_SIGNING_ALG or body.get("pqc_fallback") is not False):
                        raise CanaryError(f"MCP token exchange for {actor_id} did not use fail-closed ML-DSA signing")
                    if args.pqc:
                        claims = verify_token_with_cli(
                            binary,
                            token=str(body["access_token"]),
                            jwks=jwks,
                            directory=tmpdir,
                            label=f"mcp_{actor_id}",
                            expected_alg=expected_alg,
                        )
                    else:
                        claims = verify_rs256_jwt_against_jwks(str(body["access_token"]), jwks)
                    validate_exchange_claims(
                        label=f"mcp_{actor_id}",
                        response=body,
                        claims=claims,
                        expected_token_type="Bearer",
                        subject_claims=config["subject_claims"],
                        actor_id=actor_id,
                        target_audience=target_audience,
                        target_scope=target_scope,
                    )
                    mcp_tokens[actor_id] = str(body["access_token"])
                    log("mcp_token_exchange_pass", server=actor_id, **safe_claim_event(body, claims))
                run_fastmcp_proof(
                    mcp_config=args.mcp_config,
                    fastmcp_python=args.fastmcp_python,
                    minted_tokens=mcp_tokens,
                    require_mcp=args.require_mcp,
                )
            log("live_rust_sts_canary_result", result="pass")
            return True
        except Exception as exc:
            log("live_rust_sts_canary_result", result="fail", error_type=type(exc).__name__, message=str(exc))
            return False
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE)
    parser.add_argument("--subject-token-file", type=Path, default=DEFAULT_SUBJECT_TOKEN_FILE)
    parser.add_argument("--sts-private-jwk-file", type=Path, default=DEFAULT_STS_PRIVATE_JWK_FILE)
    parser.add_argument("--target-audience", default="api://chat-mcp")
    parser.add_argument("--target-scope", default="chat.read")
    parser.add_argument("--require-live", action="store_true", help="fail instead of reporting not_configured")
    parser.add_argument("--skip-build", action="store_true", help="reuse existing target/debug/sts-cli")
    parser.add_argument("--pqc", action="store_true", help="run the live canary with ML-DSA STS signing")
    parser.add_argument("--prove-mcp", action="store_true", help="mint per-MCP-server tokens and call configured MCP servers")
    parser.add_argument("--mcp-config", type=Path, default=DEFAULT_MCP_CONFIG)
    parser.add_argument("--fastmcp-python", type=Path, default=DEFAULT_FASTMCP_PYTHON)
    parser.add_argument("--require-mcp", action="store_true", help="fail if configured MCP calls do not pass")
    parser.add_argument("--self-test-redaction", action="store_true")
    return parser.parse_args()


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)
    args = parse_args()
    log("live_rust_sts_canary_start", timestamp=timestamp())
    try:
        self_test_redaction()
        if args.self_test_redaction:
            log("redaction_self_test", result="pass")
            return 0
        return 0 if run_live(args) else 1
    except Exception as exc:
        log("live_rust_sts_canary_result", result="fail", error_type=type(exc).__name__, message=str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
