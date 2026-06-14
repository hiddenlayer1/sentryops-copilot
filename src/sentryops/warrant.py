"""Signed approval warrants — the structural human-in-the-loop primitive.

The core safety property of SentryOps Copilot: an autonomous agent can *propose*
a remediation, but it can never *execute* one. Execution at the Splunk MCP
boundary requires a **warrant** — an HMAC-SHA256 signature over the exact action
payload, minted only by a human operator who holds the operator key.

Why this beats a UI "Are you sure?" button: the gate is not a screen the agent
renders, it is a cryptographic check the boundary performs. The orchestrator
process does not hold the operator key, so it cannot forge a warrant no matter
what a prompt injection tells it to do. The constraint is architectural, not
behavioural.

Stdlib only (hmac, hashlib, json) — no third-party crypto needed for the demo.
"""
from __future__ import annotations

import hmac
import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Any


def canonical(payload: dict[str, Any]) -> bytes:
    """Deterministic byte encoding of a payload, identical on mint and verify."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class Warrant:
    """A single-use authorization to execute one specific action."""

    action_id: str
    operator_id: str
    issued_at: str
    nonce: str
    signature: str  # hex HMAC-SHA256

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _signing_material(action: dict[str, Any], operator_id: str, issued_at: str, nonce: str) -> bytes:
    """Bind the signature to the exact action plus issuance context.

    A warrant minted for action A cannot authorize action B because B produces
    different signing material and therefore a different signature.
    """
    return canonical(
        {
            "action": action,
            "operator_id": operator_id,
            "issued_at": issued_at,
            "nonce": nonce,
        }
    )


def mint_warrant(
    operator_key: bytes,
    action: dict[str, Any],
    *,
    operator_id: str,
    issued_at: str,
    nonce: str,
) -> Warrant:
    """Operator side. Only callers holding ``operator_key`` can produce a valid warrant."""
    sig = hmac.new(
        operator_key,
        _signing_material(action, operator_id, issued_at, nonce),
        hashlib.sha256,
    ).hexdigest()
    return Warrant(
        action_id=str(action.get("action_id", "")),
        operator_id=operator_id,
        issued_at=issued_at,
        nonce=nonce,
        signature=sig,
    )


def verify_warrant(operator_key: bytes, action: dict[str, Any], warrant: Warrant) -> bool:
    """Boundary side. Constant-time comparison against a recomputed signature.

    Returns False if the warrant is missing, was minted for a different action,
    or was tampered with. There is no code path that accepts an unsigned action.
    """
    if warrant is None:
        return False
    expected = hmac.new(
        operator_key,
        _signing_material(action, warrant.operator_id, warrant.issued_at, warrant.nonce),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, warrant.signature)
