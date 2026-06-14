"""Validate the live Splunk MCP path against a real tenant.

    SPLUNK_MCP_URL=... SPLUNK_MCP_TOKEN=... python connect_check.py

Connects, lists the server's real tool catalog, and runs one trivial query so you
can confirm the tool names in `splunk_live.py` match your instance before a real
submission run. Does nothing (and needs no Splunk) for the synthetic demo.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from sentryops.splunk_live import LiveSplunkBackend, MCPClient  # noqa: E402


def main() -> int:
    url, token = os.getenv("SPLUNK_MCP_URL"), os.getenv("SPLUNK_MCP_TOKEN")
    if not url or not token:
        print("Set SPLUNK_MCP_URL and SPLUNK_MCP_TOKEN first (see .env.example).")
        return 2
    client = MCPClient(url, token)
    client.initialize()
    tools = client.list_tools()
    print(f"Connected. Server exposes {len(tools)} tools:")
    for t in tools:
        print(f"  - {t.get('name')}")
    backend = LiveSplunkBackend(url, token)
    rows = backend.search("| makeresults | eval ok=1")
    print(f"\nSample query returned {len(rows)} row(s). Live path is reachable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
