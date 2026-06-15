# SentryOps Copilot

**Autonomous Splunk security-ops triage with a *structural* human-in-the-loop gate.**

An agent triages a Splunk alert end to end — natural-language → SPL, correlation
and service-map lookup over a **live Splunk MCP Server**, and an anomaly score
computed *in Splunk* with SPL — then *proposes* a remediation. It can never
execute one on its own. Execution at the MCP boundary requires a **warrant**: an
HMAC-SHA256 signature over the exact action, minted only by a human operator. The
agent process doesn't hold the operator key, so a prompt injection can't make it
self-approve. The constraint is cryptographic, not a UI button.

> Most "human in the loop" agents enforce the gate in the UI, where it can be
> skipped or configured away. SentryOps enforces it at the tool boundary, where
> it's a check the agent literally cannot pass without a human.

## Runs against a real Splunk MCP Server at runtime

This is not a fixture replay. With a Splunk instance reachable, the agent drives a
**real Splunk MCP Server** (`server/splunk_mcp_server.py` — a stdlib,
streamable-HTTP MCP server) that executes every tool call as live SPL against
Splunk and returns the real indexed events:

| Agent step | Live MCP call |
|:--|:--|
| NL alert → SPL | `generate_spl` |
| pull correlated events | `run_splunk_query` → real indexed events |
| resolve service dependencies | `run_splunk_query` + `inputlookup` |
| anomaly confidence | `run_splunk_query` + z-score SPL (computed in Splunk) |

The same agent, warrant gate, and audit chain also run **fully offline** on a
bundled synthetic incident (no Splunk required), so the security properties are
reproducible anywhere. Primary track: **Security**. Bonus: **Best Use of the
Splunk MCP Server**.

## Quickstart

**Live path — real Splunk at runtime:**

```bash
# 1. Point the MCP server at your Splunk management port and start it
SPLUNK_REST_URL=https://localhost:8089 python server/splunk_mcp_server.py --port 8765

# 2. Confirm the agent sees the live tool catalog + a real query round-trips
SPLUNK_MCP_URL=http://127.0.0.1:8765/mcp SPLUNK_MCP_TOKEN=<splunk token> python connect_check.py

# 3. Run the end-to-end agent against live Splunk
SPLUNK_MCP_URL=http://127.0.0.1:8765/mcp SPLUNK_MCP_TOKEN=<splunk token> python demo/run_demo.py
```

**Offline path — zero install, stdlib only:**

```bash
python demo/run_demo.py        # bundled synthetic incident, no Splunk needed
python tests/test_gate.py      # security-property tests (also runs under pytest)
# open ui/approval_gate.html in a browser for the operator surface
```

Either way the demo prints the full flow: triage → the agent's self-approval
attempt being **denied** → a human minting a warrant → the approved action
executing → the audit chain verifying, then failing after tampering.

## The two properties, proven by tests

`tests/test_gate.py` (7 tests, all green):

- **No unapproved action** — `execute_remediation` refuses without a valid,
  action-bound warrant; a warrant for action A can't authorize action B; a
  tampered signature is rejected; 40 injection-style self-approval attempts are
  all denied.
- **No fabricated finding** — with zero evidence the orchestrator returns
  `insufficient_evidence` instead of inventing a finding (the constraint lives in
  the tool's `evidence_count`, not a prompt).
- **Tamper-evident audit** — editing any historical audit entry breaks chain
  verification.

## Why it complements Splunk

Splunk is the system of record for ops telemetry. SentryOps turns the **Splunk MCP
Server into a safe system of _action_**: an agent acts on Splunk signals while a
provable, cryptographic approval gate and a tamper-evident trail sit at the tool
boundary. It builds *on* the MCP Server rather than replacing anything Splunk
ships. The anomaly score is computed in Splunk via SPL; a production deployment
can swap the deterministic `generate_spl` rule for the Splunk AI Assistant, and
the z-score for a Splunk hosted model, **without touching the gate**.

## Layout

```
server/splunk_mcp_server.py  live Splunk MCP Server (stdlib; runs SPL via REST)
src/sentryops/
  warrant.py        signed approval warrants  (mint = operator, verify = boundary)
  audit.py          HMAC-chained tamper-evident trail
  splunk_mcp.py     the MCP boundary: structured tools + gated write tool + SyntheticBackend
  splunk_live.py    LiveSplunkBackend — real Splunk MCP Server client
  orchestrator.py   autonomous triage loop (holds no operator key)
  operator.py       human approval side (mints warrants)
  fixtures/         synthetic incident — no real hosts, customers, or schemas
ui/approval_gate.html   operator approval surface (Web Crypto HMAC, matches Python)
demo/run_demo.py        end-to-end narrated demo (live or synthetic)
tests/test_gate.py      security-property tests
connect_check.py        validates the live Splunk MCP path against your server
architecture_diagram.md required architecture diagram
```

## How the live path works

The boundary is backend-pluggable. Offline it uses `SyntheticBackend` (bundled
fixtures). With `SPLUNK_MCP_URL` + `SPLUNK_MCP_TOKEN` set, `demo/run_demo.py`
selects `LiveSplunkBackend` — a stdlib MCP client (`src/sentryops/splunk_live.py`)
that speaks JSON-RPC to the Splunk MCP Server and calls `run_splunk_query` /
`generate_spl`. The MCP server forwards the bearer token to Splunk and runs the
SPL via `/services/search/jobs/oneshot`. **No agent, warrant, or audit code
changes** between offline and live — only the source of the read data:

```python
from sentryops.splunk_live import LiveSplunkBackend
boundary = SplunkMCPBoundary(fixtures={}, audit=audit, _operator_key=key,
                             clock=clock, backend=LiveSplunkBackend(url, token))
```

## License

MIT — see [LICENSE](LICENSE). Built for the Splunk Agentic Ops Hackathon; all
incident data is synthetic.
