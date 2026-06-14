"""End-to-end SentryOps Copilot demo on the bundled synthetic incident.

Run from the repo root:

    python demo/run_demo.py

It prints the full agentic flow: AI-Assistant SPL generation, MCP search, Hosted
Model scoring, a traceable finding, the autonomous-execution attempt being
*denied*, a human operator minting a warrant, the approved action executing, and
the tamper-evident audit trail verifying — then failing after tampering.

Stdlib only; no Splunk tenant required. This is the script the 3-minute demo
video walks through.
"""
from __future__ import annotations

import json
import sys
from itertools import count
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentryops import AuditChain, Operator, Orchestrator, SplunkMCPBoundary  # noqa: E402

# Demo-only shared secret between the operator UI and the MCP boundary. In
# production this is an operator-held signing key never exposed to the agent.
DEMO_OPERATOR_KEY = b"DEMO-OPERATOR-KEY-not-for-production"
DEMO_CHAIN_KEY = b"DEMO-AUDIT-CHAIN-KEY"


def synthetic_clock():
    counter = count(1)
    return lambda: f"2026-06-14T17:00:{next(counter):02d}Z"


def banner(text: str) -> None:
    print(f"\n{'='*68}\n  {text}\n{'='*68}")


def main() -> int:
    fixtures = json.loads(
        (ROOT / "src" / "sentryops" / "fixtures" / "synthetic_incident.json").read_text("utf-8")
    )
    clock = synthetic_clock()
    audit = AuditChain(chain_key=DEMO_CHAIN_KEY)
    boundary = SplunkMCPBoundary(
        fixtures=fixtures, audit=audit, _operator_key=DEMO_OPERATOR_KEY, clock=clock
    )
    orchestrator = Orchestrator(boundary=boundary)
    operator = Operator(operator_id="ops.alice", _operator_key=DEMO_OPERATOR_KEY, clock=clock)

    banner("1 · Autonomous triage  (Splunk AI Assistant + MCP Server + Hosted Models)")
    result = orchestrator.triage(fixtures["alert"])
    for note in result.notes:
        print(f"   • {note}")
    print(f"\n   STATUS: {result.status}")
    print("   FINDING:")
    print("   " + json.dumps(result.finding, indent=2).replace("\n", "\n   "))

    banner("2 · Agent tries to self-approve  (simulated prompt injection)")
    denied = orchestrator.attempt_autonomous_execution(result.proposed_action)
    print(f"   RESULT: {denied['status'].upper()}")
    print(f"   {denied['reason']}")
    print("   → The boundary holds the operator key. The agent cannot forge a warrant.")

    banner("3 · Human operator reviews and approves  (mints a signed warrant)")
    warrant = operator.approve(result.proposed_action)
    print(f"   Operator '{warrant.operator_id}' approved {warrant.action_id}")
    print(f"   warrant.signature = {warrant.signature[:32]}…  (HMAC-SHA256, bound to this action)")

    banner("4 · Approved action executes through the MCP boundary")
    executed = orchestrator.execute_with_warrant(result.proposed_action, warrant)
    print(f"   {executed['status'].upper()}: {executed['action']['kind']} on "
          f"{executed['action']['target']}  (operator {executed['operator_id']})")

    banner("5 · Tamper-evident audit trail")
    print(f"   chain length: {len(audit.entries)} entries")
    print(f"   chain verifies: {audit.verify()}")
    print("   Now tamper with a historical entry's payload …")
    audit.entries[1].payload["spl"] = "search index=* | DELETE EVERYTHING"
    print(f"   chain verifies after tamper: {audit.verify()}  ← break is detected")

    banner("RESULT")
    ok = (
        denied["status"] == "denied"
        and executed["status"] == "executed"
        and not audit.verify()  # tampered above
    )
    print(f"   Structural gate held, approved action executed, tampering detected: {ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
