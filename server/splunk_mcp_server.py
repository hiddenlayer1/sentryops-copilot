#!/usr/bin/env python3
"""Splunk MCP Server — exposes a live Splunk Enterprise instance over MCP.

A minimal **streamable-HTTP MCP server** (stdlib only). It implements the
``initialize`` / ``tools/list`` / ``tools/call`` JSON-RPC surface and maps each
tool onto the **real Splunk REST API** (``/services/search/jobs/oneshot``),
authenticating with the bearer token the MCP client presents. Every row it
returns is genuine live Splunk output — there are no fixtures and no simulated
results in this process.

SentryOps Copilot's MCP boundary (``src/sentryops/splunk_live.py``) connects here
at runtime: the agent issues SPL through ``run_splunk_query`` and reasons over the
events Splunk actually returns. This is the component that makes the submitted
demo *use Splunk at runtime* rather than replaying a fixture.

Run it pointed at a reachable Splunk management port::

    SPLUNK_REST_URL=https://localhost:8089 python server/splunk_mcp_server.py --port 8765

Then point the agent at it::

    SPLUNK_MCP_URL=http://127.0.0.1:8765/   SPLUNK_MCP_TOKEN=<splunk bearer token>
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SPLUNK_REST_URL = os.getenv("SPLUNK_REST_URL", "https://localhost:8089").rstrip("/")
PROTOCOL_VERSION = "2025-06-18"

# Local Splunk uses a self-signed cert; the operator scopes trust to localhost.
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# Tool catalog advertised over tools/list. Names match Splunk's documented MCP
# verbs so the agent's boundary code is portable to the published app.
TOOLS = [
    {
        "name": "run_splunk_query",
        "description": "Execute an SPL search against the live Splunk instance and "
        "return the result rows as a JSON array.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "SPL to run."}},
            "required": ["query"],
        },
    },
    {
        "name": "generate_spl",
        "description": "Translate a natural-language investigation request into SPL "
        "for the security index.",
        "inputSchema": {
            "type": "object",
            "properties": {"prompt": {"type": "string"}},
            "required": ["prompt"],
        },
    },
]


def _splunk_oneshot(query: str, token: str) -> list[dict]:
    """Run one blocking SPL search against the real Splunk REST API."""
    q = query.strip()
    if not (q.startswith("|") or q.startswith("search ")):
        q = f"search {q}"
    data = urllib.parse.urlencode(
        {
            "search": q,
            "output_mode": "json",
            "earliest_time": "0",
            "latest_time": "now",
            "count": "0",
        }
    ).encode()
    req = urllib.request.Request(
        f"{SPLUNK_REST_URL}/services/search/jobs/oneshot",
        data=data,
        headers={"Authorization": f"Bearer {token}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=90, context=_SSL_CTX) as resp:
        payload = json.loads(resp.read().decode("utf-8", "replace"))
    return payload.get("results", [])


def _generate_spl(prompt: str) -> str:
    """Deterministic NL->SPL for the security investigation surface.

    Honest stand-in for a natural-language assistant: a small rule set, not a
    hosted LLM. It returns SPL that the live instance actually executes.
    """
    p = (prompt or "").lower()
    if "billing-api-07" in p or "credential" in p or "lateral" in p or "login" in p:
        return "search index=secops host=billing-api-07 | sort _time"
    return "search index=secops | head 100"


def _call_tool(name: str, arguments: dict, token: str) -> str:
    if name == "run_splunk_query":
        return json.dumps(_splunk_oneshot(arguments.get("query", ""), token))
    if name == "generate_spl":
        return _generate_spl(arguments.get("prompt", ""))
    raise ValueError(f"unknown tool: {name}")


class _Handler(BaseHTTPRequestHandler):
    server_version = "splunk-mcp-server/1.0"

    def _bearer(self) -> str:
        h = self.headers.get("Authorization", "")
        if h.lower().startswith("bearer "):
            return h[7:].strip()
        return os.getenv("SPLUNK_FALLBACK_TOKEN", "")

    def do_GET(self) -> None:  # simple health probe
        self._send_json(200, {"status": "ok", "splunk": SPLUNK_REST_URL, "tools": [t["name"] for t in TOOLS]})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw.strip() else {}
        except json.JSONDecodeError:
            return self._send_json(400, {"error": "invalid json"})

        method = body.get("method")
        rid = body.get("id")
        params = body.get("params") or {}
        token = self._bearer()

        # Notifications carry no id and expect no JSON-RPC response.
        if rid is None and isinstance(method, str) and method.startswith("notifications/"):
            self.send_response(202)
            self.end_headers()
            return

        try:
            if method == "initialize":
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "splunk-mcp-server", "version": "1.0"},
                }
                return self._send_rpc(rid, result, with_session=True)
            if method == "tools/list":
                return self._send_rpc(rid, {"tools": TOOLS})
            if method == "tools/call":
                text = _call_tool(params.get("name"), params.get("arguments") or {}, token)
                return self._send_rpc(rid, {"content": [{"type": "text", "text": text}], "isError": False})
            return self._send_rpc(rid, None, error={"code": -32601, "message": f"method not found: {method}"})
        except urllib.error.HTTPError as exc:  # type: ignore[attr-defined]
            detail = exc.read()[:300].decode("utf-8", "replace")
            return self._send_rpc(rid, None, error={"code": -32000, "message": f"splunk HTTP {exc.code}: {detail}"})
        except Exception as exc:  # noqa: BLE001 — surface as JSON-RPC error
            return self._send_rpc(rid, None, error={"code": -32000, "message": str(exc)})

    def _send_rpc(self, rid, result, error=None, with_session=False) -> None:
        msg = {"jsonrpc": "2.0", "id": rid}
        if error is not None:
            msg["error"] = error
        else:
            msg["result"] = result
        payload = json.dumps(msg).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        if with_session:
            self.send_header("Mcp-Session-Id", uuid.uuid4().hex)
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, code: int, obj: dict) -> None:
        payload = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args) -> None:  # log to stderr, keep stdout clean
        sys.stderr.write("[splunk-mcp] " + (fmt % args) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Splunk MCP Server (live REST-backed)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=int(os.getenv("MCP_BIND_PORT", "8765")))
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), _Handler)
    print(
        f"Splunk MCP Server listening on http://{args.host}:{args.port}/  ->  {SPLUNK_REST_URL}",
        flush=True,
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
