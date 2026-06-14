# SentryOps Copilot

**Autonomous Splunk security-ops triage with a *structural* human-in-the-loop gate.**

An agent triages a Splunk alert end to end — natural-language → SPL via the
**Splunk AI Assistant**, correlation via the **Splunk MCP Server**, anomaly
scoring via **Splunk Hosted Models** — and *proposes* a remediation. It can never
execute one on its own. Execution at the MCP boundary requires a **warrant**: an
HMAC-SHA256 signature over the exact action, minted only by a human operator. The
agent process doesn't hold the operator key, so a prompt injection can't make it
self-approve. The constraint is cryptographic, not a UI button.

> Most "human in the loop" agents enforce the gate in the UI, where it can be
> skipped or configured away. SentryOps enforces it at the tool boundary, where
> it's a check the agent literally cannot pass without a human.

## Why it complements Splunk

Splunk is the system of record for ops telemetry. SentryOps turns the **Splunk
MCP Server into a safe system of _action_**: it lets an agent act on Splunk
signals while keeping a provable approval gate and a tamper-evident trail that
exports straight back into Splunk. It showcases three Splunk AI surfaces at once
rather than replacing any of them.

| Splunk surface | Used for | Bonus track |
|:--|:--|:--|
| **Splunk MCP Server** | search · metric aggregation · service map | Best Use of Splunk MCP Server |
| **Splunk Hosted Models** | anomaly scoring over raw events | Best Use of Splunk Hosted Models |
| **Splunk AI Assistant / Dev Tools** | NL → SPL, live dashboard scaffolding | Best Use of Splunk Developer Tools |

Primary track: **Security**.

## Quickstart (zero install — stdlib only)

```bash
# 1. Run the end-to-end demo on the bundled synthetic incident
python demo/run_demo.py

# 2. Run the security-property test suite (also works under pytest)
python tests/test_gate.py

# 3. Open the operator approval surface
#    open ui/approval_gate.html in a browser
```

The demo prints the full flow: triage → the agent's self-approval attempt being
**denied** → a human minting a warrant → the approved action executing → the
audit chain verifying, then failing after tampering.

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

## Layout

```
src/sentryops/
  warrant.py        signed approval warrants  (mint = operator, verify = boundary)
  audit.py          HMAC-chained tamper-evident trail
  splunk_mcp.py     the MCP boundary: structured tools + gated write tool + SyntheticBackend
  splunk_live.py    LiveSplunkBackend — real Splunk MCP Server client (optional)
  orchestrator.py   autonomous triage loop (holds no operator key)
  operator.py       human approval side (mints warrants)
  fixtures/         synthetic incident — no real hosts, customers, or schemas
ui/approval_gate.html   operator approval surface (Web Crypto HMAC, matches Python)
demo/run_demo.py        end-to-end narrated demo
tests/test_gate.py      security-property tests
connect_check.py        validates the live Splunk MCP path against your tenant
architecture_diagram.md required architecture diagram
```

## Production integration (real Splunk MCP Server)

The boundary is backend-pluggable. The demo uses `SyntheticBackend` (bundled
fixtures, zero setup). For a real tenant, pass `LiveSplunkBackend` — a stdlib MCP
client (`src/sentryops/splunk_live.py`) that talks to the **Splunk MCP Server**
(Splunkbase 7931) over JSON-RPC, with `splunk_run_query`, `ask_splunk_question`
(Hosted Models), and `generate_spl` (AI Assistant) mapped to the same five tools
the agent already calls. **No agent, warrant, or audit code changes** between
demo and tenant:

```python
from sentryops.splunk_live import LiveSplunkBackend
boundary = SplunkMCPBoundary(fixtures={}, audit=audit, _operator_key=key,
                             clock=clock, backend=LiveSplunkBackend(url, token))
```

Validate the live path against your instance:

```bash
cp .env.example .env   # set SPLUNK_MCP_URL + SPLUNK_MCP_TOKEN
python connect_check.py    # lists the server's real tools + runs a probe query
```

The live path is wired but not exercised in the demo (no credentials handled
here); `connect_check.py` confirms tool names against your server.

## License

MIT — see [LICENSE](LICENSE). Built as a self-contained demo for the Splunk
Agentic Ops Hackathon; uses only synthetic data.
