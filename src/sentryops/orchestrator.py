"""The autonomous triage orchestrator.

The orchestrator reasons over Splunk signals and assembles a finding, then
*proposes* a remediation. It deliberately holds no operator key, so it cannot
execute the remediation it proposes — that requires a human-minted warrant.

In production the ``reason_*`` steps are an LLM planning loop (Claude Code over
the MCP tool protocol). Here they are deterministic so the demo and tests are
reproducible; the control flow — and the boundary contract — is identical.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .splunk_mcp import ApprovalRequired, SplunkMCPBoundary
from .warrant import Warrant


@dataclass
class TriageResult:
    finding: dict[str, Any] | None
    proposed_action: dict[str, Any] | None
    status: str  # "awaiting_approval" | "insufficient_evidence"
    notes: list[str] = field(default_factory=list)


@dataclass
class Orchestrator:
    boundary: SplunkMCPBoundary

    def triage(self, alert: dict[str, Any]) -> TriageResult:
        notes: list[str] = []

        # 1. Splunk AI Assistant: natural-language alert -> SPL
        spl = self.boundary.generate_spl(alert["description"]).data
        notes.append(f"AI Assistant generated SPL: {spl}")

        # 2. Splunk MCP Server: pull correlated events
        search = self.boundary.search(spl)
        notes.append(f"MCP search returned {search.evidence_count} events")

        # Constraint: cannot fabricate a finding with no evidence. Structural —
        # this is gated on the tool's evidence_count, not the model's judgement.
        if not search.evidence_available:
            return TriageResult(None, None, "insufficient_evidence", notes)

        # 3. Context: metrics + service dependency graph
        deps = self.boundary.service_dependencies(alert.get("service", "")).data
        notes.append(f"Service map resolved {len(deps)} downstream dependencies")

        # 4. Splunk Hosted Model: anomaly confidence over the raw events
        score = self.boundary.anomaly_score(search.data).data["confidence"]
        notes.append(f"Hosted Model anomaly confidence: {score:.2f}")

        # 5. Assemble a traceable finding
        finding = {
            "finding_id": alert["alert_id"],
            "summary": f"Correlated {search.evidence_count} events on {alert.get('service','?')}; "
            f"anomaly confidence {score:.2f}.",
            "confidence": score,
            "evidence_count": search.evidence_count,
            "downstream_dependencies": deps,
            "recommended_action": alert.get("recommended_action", "isolate_host"),
            "target": alert.get("service", "unknown"),
        }

        # 6. Propose — but do NOT execute. Execution needs an operator warrant.
        action = self.boundary.propose_remediation(finding)
        notes.append(f"Proposed remediation {action['action_id']} (awaiting operator warrant)")
        return TriageResult(finding, action, "awaiting_approval", notes)

    def attempt_autonomous_execution(self, action: dict[str, Any]) -> dict[str, Any]:
        """Simulate a compromised / prompt-injected agent trying to self-approve.

        The boundary rejects it because the orchestrator cannot produce a valid
        warrant. Used by the demo and the test suite to prove the gate holds.
        """
        try:
            return self.boundary.execute_remediation(action, warrant=None)
        except ApprovalRequired as exc:
            return {"status": "denied", "reason": str(exc)}

    def execute_with_warrant(self, action: dict[str, Any], warrant: Warrant) -> dict[str, Any]:
        """Execute an operator-approved action by passing through the warrant."""
        return self.boundary.execute_remediation(action, warrant)
