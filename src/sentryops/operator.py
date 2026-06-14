"""The human operator side of the approval gate.

The :class:`Operator` holds the operator key and is the *only* party that can
mint a warrant. In the running system this logic lives behind the approval UI
(see ``ui/approval_gate.html``): a human reviews the agent's proposed action and
clicks Approve, which mints a warrant bound to that exact action. The orchestrator
never has access to an :class:`Operator` instance or the key it holds.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .warrant import Warrant, mint_warrant


@dataclass
class Operator:
    operator_id: str
    _operator_key: bytes
    clock: Callable[[], str]
    _nonce_seq: int = 0

    def approve(self, action: dict[str, Any]) -> Warrant:
        """Human-in-the-loop approval. Mints a single-use warrant for one action."""
        self._nonce_seq += 1
        nonce = f"{self.operator_id}-{self._nonce_seq}"
        return mint_warrant(
            self._operator_key,
            action,
            operator_id=self.operator_id,
            issued_at=self.clock(),
            nonce=nonce,
        )
