#!/usr/bin/env python3
"""Run redacted real-tenant endpoint checks for sts-delegate-rs coordination."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
DEFAULT_OBO_ENV = Path("/Users/Shared/claude/obo-lab/okta.env")
DEFAULT_MCP_CONFIG = Path("/Users/Shared/claude/obo-lab/.mcp.json")
DEFAULT_FASTMCP_PYTHON = Path("/Users/Shared/claude/obo-lab/.venv/bin/python3")

EXAMPLE_HOST_FRAGMENTS = ("example.com", "example.test", "example.org", "issuer.example", "sts.example")
PRIVATE_JWK_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "oth"}
TOKEN_FIELD_NAMES = {"authorization", "access_token", "subject_token", "actor_token", "client_assertion"}
OBO_LAB_DIRECT_MCP_URLS = {
    "chat-mcp": "http://127.0.0.1:8103/mcp",
    "databricks-mcp": "http://127.0.0.1:8101/mcp",
    "servicenow-mcp": "http://127.0.0.1:8102/mcp",
}
SECRET_QUERY_RE = re.compile(
    r"(?i)([?&](?:access_token|subject_token|actor_token|client_assertion|client_secret|authorization)=)[^&\s]+"
)
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b")
MCP_TOOL_PROBES = {
    "chat-mcp": ("say", {"message": "hello from sts-delegate-rs canary"}),
    "databricks-mcp": ("run_sql_query", {"sql": "SELECT 1"}),
    "servicenow-mcp": ("list_incidents", {}),
}

FASTMCP_CLIENT_PROGRAM = r"""
from __future__ import annotations

import asyncio
import json
import sys

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport


async def call_one(server: dict) -> dict:
    transport = StreamableHttpTransport(server["url"], headers=server["headers"])
    async with Client(transport) as client:
        tools = await client.list_tools()
        tool_names = sorted(tool.name for tool in tools)
        tool_name = server.get("tool")
        result = {"tools": tool_names, "tool": tool_name, "call_status": "not_configured"}
        if tool_name:
            response = await client.call_tool(tool_name, server.get("args") or {})
            data = getattr(response, "data", None)
            if isinstance(data, dict):
                via_actor = data.get("via_actor")
                result["data_keys"] = sorted(str(key) for key in data)
                result["via_actor"] = via_actor.get("sub") if isinstance(via_actor, dict) else via_actor
            else:
                result["data_type"] = type(data).__name__
            result["call_status"] = "ok"
        return result


async def main() -> None:
    payload = json.load(sys.stdin)
    results = {}
    for name, server in sorted(payload["servers"].items()):
        try:
            results[name] = {"ok": True, **await call_one(server)}
        except Exception as exc:  # noqa: BLE001 - subprocess returns sanitized diagnostics.
            results[name] = {
                "ok": False,
                "error_type": type(exc).__name__,
                "message": str(exc)[:300],
            }
    print(json.dumps(results, sort_keys=True))


asyncio.run(main())
"""


class CanaryError(RuntimeError):
    pass


def timestamp() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def log(event: str, **fields: Any) -> None:
    print(json.dumps({"event": event, **redact(fields)}, sort_keys=True), flush=True)


def redact_string(value: str) -> str:
    redacted = SECRET_QUERY_RE.sub(lambda match: f"{match.group(1)}<redacted>", value)
    redacted = BEARER_RE.sub("Bearer <redacted>", redacted)
    return JWT_RE.sub("<jwt-redacted>", redacted)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for key, item in value.items():
            lowered = key.lower()
            if lowered in TOKEN_FIELD_NAMES or any(
                marker in lowered for marker in ("secret", "password", "private", "assertion")
            ):
                safe[key] = "<redacted>"
            else:
                safe[key] = redact(item)
        return safe
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_string(value)
    return value


def self_test_redaction() -> None:
    synthetic_jwt = "headerheaderheaderheader.payloadpayloadpayloadpayload.signaturesignature"
    sample = {
        "message": f"Authorization: Bearer {synthetic_jwt} failed",
        "url": f"https://tenant.invalid/cb?access_token={synthetic_jwt}&ok=1",
        "nested": [{"client_assertion": synthetic_jwt}],
    }
    rendered = json.dumps(redact(sample), sort_keys=True)
    if synthetic_jwt in rendered or "access_token=header" in rendered:
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
    return os.environ.get(name) or env_file.get(name)


def read_env_or_file(name: str, env_file: dict[str, str]) -> str | None:
    raw = env_value(name, env_file)
    if raw:
        return raw.strip()
    path = env_value(f"{name}_FILE", env_file)
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return None


def reject_example_url(url: str, label: str, *, allow_loopback: bool = False) -> None:
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    if not parsed.scheme or not host:
        raise CanaryError(f"{label} must be an absolute URL")
    if allow_loopback and host in {"127.0.0.1", "localhost", "::1"}:
        return
    if parsed.scheme != "https":
        raise CanaryError(f"{label} must use https for real-tenant proof")
    if any(fragment in host for fragment in EXAMPLE_HOST_FRAGMENTS) or host.endswith(".example"):
        raise CanaryError(f"{label} must not use an example-domain issuer")


def http_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 8.0,
) -> tuple[int, dict[str, Any] | None, str]:
    data = None
    request_headers = {"Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    if body is not None:
        data = json.dumps(body).encode()
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(256_000)
            content_type = response.headers.get("content-type", "")
            parsed = json.loads(raw) if raw and "json" in content_type.lower() else None
            return response.status, parsed, content_type
    except urllib.error.HTTPError as err:
        raw = err.read(4096)
        parsed = None
        if raw and "json" in (err.headers.get("content-type", "").lower()):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = None
        return err.code, parsed, err.headers.get("content-type", "")
    except urllib.error.URLError as err:
        raise CanaryError(f"{method} {url} failed: {err.reason}") from err


def unverified_jwt_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise CanaryError("bearer token is not a JWT")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload.encode()))
    if not isinstance(claims, dict):
        raise CanaryError("bearer token claims are not an object")
    return claims


def bearer_from_headers(headers: dict[str, Any]) -> str | None:
    authorization = headers.get("Authorization") or headers.get("authorization")
    if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
        return None
    return authorization[len("Bearer ") :].strip()


def token_seconds_remaining(claims: dict[str, Any]) -> int | None:
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        return None
    return int(exp - time.time())


def check_okta(env_file: dict[str, str]) -> dict[str, Any]:
    issuer = env_value("CANARY_IDP_ISSUER", env_file) or env_value("OKTA_ISSUER", env_file) or env_value(
        "IDP_ISSUER", env_file
    )
    if not issuer:
        log("okta_not_configured", missing=["CANARY_IDP_ISSUER or OKTA_ISSUER or IDP_ISSUER"])
        return {"configured": False}
    issuer = issuer.rstrip("/")
    reject_example_url(issuer, "Okta issuer")
    discovery_url = f"{issuer}/.well-known/openid-configuration"
    status, document, _content_type = http_json("GET", discovery_url)
    if status != 200 or not isinstance(document, dict):
        raise CanaryError(f"Okta discovery failed status={status}")
    if document.get("issuer", "").rstrip("/") != issuer:
        raise CanaryError("Okta discovery issuer does not match configured issuer")
    jwks_uri = document.get("jwks_uri")
    if not isinstance(jwks_uri, str):
        raise CanaryError("Okta discovery missing jwks_uri")
    reject_example_url(jwks_uri, "Okta jwks_uri")
    jwks_status, jwks, _ = http_json("GET", jwks_uri)
    if jwks_status != 200 or not isinstance(jwks, dict) or not jwks.get("keys"):
        raise CanaryError(f"Okta JWKS failed status={jwks_status}")
    for key in jwks.get("keys", []):
        if isinstance(key, dict) and PRIVATE_JWK_MEMBERS & key.keys():
            raise CanaryError("Okta JWKS exposed private JWK members")
    log(
        "okta_endpoints_ok",
        issuer=issuer,
        discovery_status=status,
        jwks_status=jwks_status,
        jwks_keys=len(jwks.get("keys", [])),
    )
    return {"configured": True, "issuer": issuer, "jwks_uri": jwks_uri}


def mcp_rpc(url: str, authorization: str, method: str, params: dict[str, Any] | None = None) -> int:
    status, _body, _content_type = http_json(
        "POST",
        url,
        headers={
            "Authorization": authorization,
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-06-18",
        },
        body={"jsonrpc": "2.0", "id": f"canary-{method}", "method": method, "params": params or {}},
        timeout=10,
    )
    return status


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
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip().splitlines()[-1:] or ["<no stderr>"]
        raise CanaryError(f"FastMCP client subprocess failed rc={completed.returncode}: {stderr[0][:240]}")
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CanaryError("FastMCP client subprocess returned non-JSON output") from exc
    if not isinstance(parsed, dict):
        raise CanaryError("FastMCP client subprocess returned invalid result shape")
    return {str(name): result for name, result in parsed.items() if isinstance(result, dict)}


def check_mcp(
    config_path: Path,
    okta_issuer: str | None,
    require_mcp: bool,
    *,
    call_mode: str,
    fastmcp_python: Path,
    url_set: str,
) -> dict[str, Any]:
    if not config_path.exists():
        event = "mcp_not_configured"
        log(event, config=str(config_path), missing=["mcp config"])
        if require_mcp:
            raise CanaryError(f"MCP config missing: {config_path}")
        return {"configured": False}

    data = json.loads(config_path.read_text(encoding="utf-8"))
    servers = data.get("mcpServers")
    if not isinstance(servers, dict) or not servers:
        log("mcp_not_configured", config=str(config_path), missing=["mcpServers"])
        if require_mcp:
            raise CanaryError("MCP config has no mcpServers")
        return {"configured": False}

    checked: list[dict[str, Any]] = []
    mcp_servers: dict[str, dict[str, Any]] = {}
    for name, server in sorted(servers.items()):
        if not isinstance(server, dict):
            continue
        url = server.get("url")
        headers = server.get("headers", {})
        if not isinstance(url, str) or not isinstance(headers, dict):
            continue
        configured_url = url
        if url_set == "obo-lab-direct":
            url = OBO_LAB_DIRECT_MCP_URLS.get(name, url)
        token = bearer_from_headers(headers)
        if not token:
            raise CanaryError(f"MCP server {name} missing bearer Authorization header")
        claims = unverified_jwt_claims(token)
        token_issuer = str(claims.get("iss", "")).rstrip("/")
        reject_example_url(token_issuer, f"MCP bearer issuer for {name}")
        if okta_issuer and token_issuer != okta_issuer.rstrip("/"):
            raise CanaryError(f"MCP bearer issuer for {name} does not match configured Okta issuer")
        authorization = headers.get("Authorization") or headers.get("authorization")
        if not isinstance(authorization, str):
            raise CanaryError(f"MCP server {name} missing string Authorization header")
        tool_name, tool_args = MCP_TOOL_PROBES.get(name, (None, {}))
        mcp_servers[name] = {
            "url": url,
            "headers": {"Authorization": authorization},
            "tool": tool_name,
            "args": tool_args,
        }
        entry = {
            "name": name,
            "url": url,
            "token_issuer": token_issuer,
            "token_subject_present": bool(claims.get("sub")),
            "token_seconds_remaining": token_seconds_remaining(claims),
        }
        if configured_url != url:
            entry["configured_url"] = configured_url
        checked.append(entry)

    if not checked:
        log("mcp_not_configured", config=str(config_path), missing=["valid mcpServers"])
        if require_mcp:
            raise CanaryError("MCP config has no valid mcpServers entries")
        return {"configured": False}

    fastmcp_results: dict[str, dict[str, Any]] = {}
    use_fastmcp = call_mode == "fastmcp" or (call_mode == "auto" and fastmcp_python.exists())
    if use_fastmcp:
        fastmcp_results = fastmcp_call_servers(mcp_servers, fastmcp_python=fastmcp_python, timeout=45)

    failures: list[str] = []
    for entry in checked:
        name = str(entry["name"])
        authorization = mcp_servers[name]["headers"]["Authorization"]
        url = str(mcp_servers[name]["url"])
        if fastmcp_results:
            result = fastmcp_results.get(name, {"ok": False, "error_type": "missing_result"})
            safe_result = redact(result)
            entry["client"] = "fastmcp"
            entry["tool"] = mcp_servers[name].get("tool")
            entry["fastmcp"] = safe_result
            if not bool(result.get("ok")):
                failures.append(f"{name}: {result.get('error_type', 'error')}")
            continue
        try:
            initialize_status = mcp_rpc(
                url,
                authorization,
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "sts-delegate-rs-canary", "version": "0"},
                },
            )
            tools_status = mcp_rpc(url, authorization, "tools/list")
        except CanaryError:
            if require_mcp:
                raise
            initialize_status = 0
            tools_status = 0
        entry["client"] = "raw-jsonrpc"
        entry["initialize_status"] = initialize_status
        entry["tools_list_status"] = tools_status
        if require_mcp and initialize_status >= 400 and tools_status >= 400:
            failures.append(f"{name}: raw initialize/tools rejected")
    log("mcp_endpoints_checked", servers=checked)
    if require_mcp and failures:
        raise CanaryError(f"MCP endpoint proof failed: {', '.join(failures)}")
    return {"configured": True, "servers": checked}


def check_sts(env_file: dict[str, str]) -> dict[str, Any]:
    base = env_value("CANARY_STS_BASE_URL", env_file)
    if not base:
        log("sts_not_configured", missing=["CANARY_STS_BASE_URL"])
        return {"configured": False}
    base = base.rstrip("/")
    reject_example_url(base, "STS base URL", allow_loopback=True)
    metadata_status, metadata, _ = http_json("GET", f"{base}/.well-known/oauth-authorization-server")
    if metadata_status != 200 or not isinstance(metadata, dict):
        raise CanaryError(f"STS metadata failed status={metadata_status}")
    jwks_uri = metadata.get("jwks_uri")
    if not isinstance(jwks_uri, str):
        raise CanaryError("STS metadata missing jwks_uri")
    jwks_status, jwks, _ = http_json("GET", jwks_uri)
    if jwks_status != 200 or not isinstance(jwks, dict) or not jwks.get("keys"):
        raise CanaryError(f"STS JWKS failed status={jwks_status}")
    token_form = read_env_or_file("CANARY_STS_TOKEN_FORM_JSON", env_file)
    token_status = "not_configured"
    if token_form:
        token_endpoint = metadata.get("token_endpoint")
        if not isinstance(token_endpoint, str):
            raise CanaryError("STS metadata missing token_endpoint")
        form = json.loads(token_form)
        if not isinstance(form, dict):
            raise CanaryError("CANARY_STS_TOKEN_FORM_JSON must be a JSON object")
        encoded = urllib.parse.urlencode({str(k): str(v) for k, v in form.items()}).encode()
        request = urllib.request.Request(
            token_endpoint,
            data=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                token_status = response.status
                response.read(64_000)
        except urllib.error.HTTPError as err:
            token_status = err.code
            err.read(4096)
    log("sts_endpoints_checked", base=base, metadata_status=metadata_status, jwks_status=jwks_status, token_status=token_status)
    return {"configured": True}


def run_once(args: argparse.Namespace) -> bool:
    log("real_tenant_endpoint_loop_start", timestamp=timestamp())
    env_file = parse_env_file(args.env_file)
    try:
        okta = check_okta(env_file)
        check_mcp(
            args.mcp_config,
            okta.get("issuer") if okta.get("configured") else None,
            args.require_mcp,
            call_mode=args.mcp_call_mode,
            fastmcp_python=args.fastmcp_python,
            url_set=args.mcp_url_set,
        )
        check_sts(env_file)
    except Exception as exc:
        log("real_tenant_endpoint_loop_result", result="fail", error_type=type(exc).__name__, message=str(exc))
        return False
    log("real_tenant_endpoint_loop_result", result="pass")
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loop", type=int, default=0, metavar="SECONDS", help="repeat forever at this interval")
    parser.add_argument("--env-file", type=Path, default=DEFAULT_OBO_ENV)
    parser.add_argument("--mcp-config", type=Path, default=DEFAULT_MCP_CONFIG)
    parser.add_argument("--require-mcp", action="store_true", help="fail when configured MCP endpoints are unreachable")
    parser.add_argument(
        "--mcp-call-mode",
        choices=("auto", "raw", "fastmcp"),
        default="auto",
        help="MCP endpoint proof mode; auto uses FastMCP when available",
    )
    parser.add_argument(
        "--mcp-url-set",
        choices=("configured", "obo-lab-direct"),
        default="configured",
        help="use configured .mcp.json URLs or known direct obo-lab backend URLs",
    )
    parser.add_argument("--fastmcp-python", type=Path, default=DEFAULT_FASTMCP_PYTHON)
    parser.add_argument("--self-test-redaction", action="store_true", help="run the local log-redaction self-test")
    return parser.parse_args()


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)
    args = parse_args()
    if args.self_test_redaction:
        self_test_redaction()
        log("redaction_self_test", result="pass")
        return 0
    if args.loop:
        interval = max(args.loop, 30)
        while True:
            run_once(args)
            log("real_tenant_endpoint_loop_sleep", seconds=interval)
            time.sleep(interval)
    return 0 if run_once(args) else 1


if __name__ == "__main__":
    sys.exit(main())
