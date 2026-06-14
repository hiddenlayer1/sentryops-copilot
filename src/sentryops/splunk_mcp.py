"""The Splunk MCP boundary — the agent's only interface to the world.

The boundary exposes structured tools over a pluggable **backend**:

* ``SyntheticBackend`` (default) serves the bundled fixtures so the demo and
  tests run with zero external setup.
* ``LiveSplunkBackend`` (see ``splunk_live.py``) talks to a real Splunk MCP
  Server / Hosted Models / AI Assistant. Selecting it changes **no** agent,
  warrant, or audit code — only where the read data comes from.

Two boundary properties matter for judging, and hold regardless of backend:

1. **No fabricated findings.** Every read tool returns an ``evidence_count``.
   The orchestrator is contractually forbidden from emitting a finding when
   ``evidence_count == 0`` — the constraint lives in the tool schema, not a
   prompt.
2. **No unapproved actions.** ``execute_remediation`` verifies a signed
   :class:`~sentryops.warrant.Warrant` before doing anything. The boundary
   holds the operator key; the orchestrator does not.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .audit import AuditChain
from .warrant import Warrant, verify_warrant


class ApprovalRequired(Exception):
    """Raised when execute_remediation is called without a valid warrant."""


class Backend(Protocol):
    """Where read data comes from. Implemented by Synthetic + Live backends."""

    def search(self, spl: str) -> list[dict[str, Any]]: ...
    def metric_aggregation(self, metric: str) -> dict[str, Any]: ...
    def service_dependencies(self, service: str) -> list[str]: ...
    def anomaly_score(self, events: list[dict[str, Any]]) -> float: ...
    def generate_spl(self, nl_request: str) -> str: ...


@dataclass
class SyntheticBackend:
    """Deterministic backend over the bundled synthetic incident fixtures."""

    fixtures: dict[str, Any]

    def search(self, spl: str) -> list[dict[str, Any]]:
        return self.fixtures.get("events", [])

    def metric_aggregation(self, metric: str) -> dict[str, Any]:
        return self.fixtures.get("metrics", {}).get(metric, {})

    def service_dependencies(self, service: str) -> list[str]:
        return self.fixtures.get("service_map", {}).get(service, [])

    def anomaly_score(self, events: list[dict[str, Any]]) -> float:
        return self.fixtures.get("hosted_model_score", 0.0) if events else 0.0

    def generate_spl(self, nl_request: str) -> str:
        return self.fixtures.get("spl_for", {}).get(nl_request, "search index=* | head 100")


@dataclass
class ToolResult:
    """Structured response. ``evidence_count`` is load-bearing, not cosmetic."""

    tool: str
    data: Any
    evidence_count: int

    @property
    def evidence_available(self) -> bool:
        return self.evidence_count > 0


@dataclass
class SplunkMCPBoundary:
    """The structured surface the orchestrator is allowed to touch.

    ``_operator_key`` is private to the boundary (and shared only with the human
    operator's approval UI). It is never passed to the orchestrator, which is
    why a prompt injection cannot make the agent mint its own warrant.
    """

    fixtures: dict[str, Any]
    audit: AuditChain
    _operator_key: bytes
    clock: Callable[[], str]
    backend: Backend | None = None
    executed: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._backend: Backend = self.backend or SyntheticBackend(self.fixtures)

    # ---- Splunk MCP Server: read tools --------------------------------------
    def search(self, spl: str) -> ToolResult:
        events = self._backend.search(spl)
        self.audit.append("mcp.search", {"spl": spl, "hits": len(events)}, self.clock())
        return ToolResult("splunk.search", events, evidence_count=len(events))

    def metric_aggregation(self, metric: str) -> ToolResult:
        agg = self._backend.metric_aggregation(metric)
        n = len(agg) if isinstance(agg, dict) else 0
        self.audit.append("mcp.metrics", {"metric": metric, "buckets": n}, self.clock())
        return ToolResult("splunk.metrics", agg, evidence_count=n)

    def service_dependencies(self, service: str) -> ToolResult:
        deps = self._backend.service_dependencies(service)
        self.audit.append("mcp.service_map", {"service": service, "deps": len(deps)}, self.clock())
        return ToolResult("splunk.service_map", deps, evidence_count=len(deps))

    # ---- Splunk Hosted Models -----------------------------------------------
    def anomaly_score(self, events: list[dict[str, Any]]) -> ToolResult:
        """Stand-in for a Splunk Hosted Model scoring endpoint.

        The agent does NOT compute the score itself; it submits events and
        reasons over the returned confidence.
        """
        score = self._backend.anomaly_score(events)
        self.audit.append("hosted_model.score", {"n": len(events), "score": score}, self.clock())
        return ToolResult("splunk.hosted_model", {"confidence": score}, evidence_count=1 if events else 0)

    # ---- Splunk AI Assistant ------------------------------------------------
    def generate_spl(self, nl_request: str) -> ToolResult:
        """Stand-in for the Splunk AI Assistant natural-language → SPL tool."""
        spl = self._backend.generate_spl(nl_request)
        self.audit.append("ai_assistant.spl", {"request": nl_request, "spl": spl}, self.clock())
        return ToolResult("splunk.ai_assistant", spl, evidence_count=1)

    # ---- The gated write tool ----------------------------------------------
    def propose_remediation(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Build an action proposal. This does NOT execute anything."""
        action = {
            "action_id": f"act-{finding.get('finding_id', 'unknown')}",
            "kind": finding.get("recommended_action", "isolate_host"),
            "target": finding.get("target", "unknown"),
            "reason": finding.get("summary", ""),
        }
        self.audit.append("remediation.proposed", action, self.clock())
        return action

    def execute_remediation(self, action: dict[str, Any], warrant: Warrant | None) -> dict[str, Any]:
        """The only state-changing tool. Refuses to act without a valid warrant.

        This is the structural human-in-the-loop gate. There is no ``force`` flag
        and no prompt that bypasses it — verification is a cryptographic check.
        """
        if not verify_warrant(self._operator_key, action, warrant):
            self.audit.append(
                "remediation.denied",
                {"action_id": action.get("action_id"), "reason": "missing_or_invalid_warrant"},
                self.clock(),
            )
            raise ApprovalRequired(
                f"Action {action.get('action_id')} requires a valid operator warrant."
            )
        self.executed.append(action)
        self.audit.append(
            "remediation.executed",
            {"action_id": action.get("action_id"), "operator_id": warrant.operator_id},
            self.clock(),
        )
        return {"status": "executed", "action": action, "operator_id": warrant.operator_id}
