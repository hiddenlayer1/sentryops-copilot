"""Live Splunk backend — real Splunk MCP Server / Hosted Models / AI Assistant.

Drop-in replacement for ``SyntheticBackend``: pass a ``LiveSplunkBackend`` as the
``backend=`` of :class:`~sentryops.splunk_mcp.SplunkMCPBoundary` and the agent,
warrant gate, and audit chain run unchanged against a real tenant.

Stdlib only. Talks to the Splunk MCP Server (Splunkbase 7931) over streamable
HTTP / JSON-RPC. The exact tool names + arg schemas are instance-specific; verify
them against your server with ``connect_check.py`` once a Splunk Enterprise Trial
+ Developer License is provisioned and the ``mcp_tool_execute`` capability is
granted. This path is wired but NOT verified against a live tenant in the demo
(no credentials are handled here — the operator supplies ``SPLUNK_MCP_URL`` /
``SPLUNK_MCP_TOKEN``).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION = "2025-06-18"


class MCPError(RuntimeError):
    """A transport- or protocol-level failure talking to the MCP server."""


@dataclass
class MCPClient:
    """Minimal MCP client: initialize → notifications/initialized → tools/call."""

    url: str
    token: str
    timeout: int = 45
    _session_id: str | None = field(default=None, init=False)
    _next_id: int = field(default=0, init=False)

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {self.token}",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    def _post(self, body: dict[str, Any]) -> tuple[str, str, str | None]:
        req = urllib.request.Request(
            self.url, data=json.dumps(body).encode(), headers=self._headers(), method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return (
                    resp.headers.get("Content-Type", ""),
                    resp.read().decode("utf-8", "replace"),
                    resp.headers.get("Mcp-Session-Id"),
                )
        except urllib.error.HTTPError as exc:
            raise MCPError(f"HTTP {exc.code}: {exc.read()[:300]!r}") from exc
        except urllib.error.URLError as exc:
            raise MCPError(f"connection error: {exc.reason}") from exc

    def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next_id += 1
        ctype, raw, sid = self._post(
            {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params or {}}
        )
        if sid:
            self._session_id = sid
        payload = _parse_response(ctype, raw)
        if "error" in payload:
            raise MCPError(f"{method} JSON-RPC error: {payload['error']}")
        return payload.get("result", {})

    def initialize(self) -> dict[str, Any]:
        result = self._rpc(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
             "clientInfo": {"name": "sentryops-copilot", "version": "1.0"}},
        )
        try:  # notifications are best-effort
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        except MCPError:
            pass
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        return self._rpc("tools/list").get("tools", [])

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})


def _parse_response(content_type: str, raw: str) -> dict[str, Any]:
    if "text/event-stream" in content_type:
        latest: dict[str, Any] = {}
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                try:
                    latest = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
        return latest
    return json.loads(raw) if raw.strip() else {}


def _result_text(result: dict[str, Any]) -> str:
    for item in result.get("content", []) or []:
        if item.get("type") == "text":
            return item.get("text", "")
    structured = result.get("structuredContent")
    return json.dumps(structured) if structured is not None else ""


def _result_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        data = json.loads(_result_text(result))
    except (json.JSONDecodeError, TypeError):
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("results", "rows", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    return []


@dataclass
class LiveSplunkBackend:
    """Maps the boundary's read tools onto real Splunk MCP tool calls.

    Tool names follow Splunk's documented MCP catalog; confirm against the live
    server with ``connect_check.py`` and adjust if your instance differs.
    """

    url: str
    token: str

    def __post_init__(self) -> None:
        self._mcp = MCPClient(self.url, self.token)
        self._mcp.initialize()

    def search(self, spl: str) -> list[dict[str, Any]]:
        return _result_rows(self._mcp.call_tool("splunk_run_query", {"query": spl}))

    def metric_aggregation(self, metric: str) -> dict[str, Any]:
        rows = _result_rows(self._mcp.call_tool("splunk_run_query", {"query": f"| mstats avg({metric}) WHERE index=_metrics"}))
        return rows[0] if rows else {}

    def service_dependencies(self, service: str) -> list[str]:
        rows = self.search(f'| inputlookup service_dependencies where entity="{service}" | fields dependency')
        return [r["dependency"] for r in rows if isinstance(r, dict) and r.get("dependency")]

    def anomaly_score(self, events: list[dict[str, Any]]) -> float:
        if not events:
            return 0.0
        prompt = (
            "You are a SOC analyst using the Foundation-sec hosted model. Score these events "
            'and reply with ONLY JSON {"score":0-100}. Events: ' + json.dumps(events)[:4000]
        )
        try:
            parsed = json.loads(_result_text(self._mcp.call_tool("ask_splunk_question", {"question": prompt})))
            return float(parsed.get("score", 0)) / 100.0
        except (json.JSONDecodeError, TypeError, ValueError):
            return 0.0

    def generate_spl(self, nl_request: str) -> str:
        return _result_text(self._mcp.call_tool("generate_spl", {"prompt": nl_request})) or "search index=* | head 100"
