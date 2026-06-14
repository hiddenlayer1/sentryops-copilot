"""Tamper-evident audit trail — every boundary action is HMAC-chained.

Each entry's hash covers the previous entry's hash plus the current entry body,
so altering any historical entry invalidates every entry after it. This is what
makes a finding *traceable*: a judge (or an auditor) can replay the chain and
confirm that no step was inserted, removed, or edited after the fact.
"""
from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass, field
from typing import Any

from .warrant import canonical

_GENESIS = "0" * 64


@dataclass
class AuditEntry:
    seq: int
    ts: str
    kind: str
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


@dataclass
class AuditChain:
    """Append-only, hash-linked log keyed by a chain secret."""

    chain_key: bytes
    entries: list[AuditEntry] = field(default_factory=list)

    @property
    def head(self) -> str:
        return self.entries[-1].entry_hash if self.entries else _GENESIS

    def _hash(self, seq: int, ts: str, kind: str, payload: dict[str, Any], prev_hash: str) -> str:
        body = canonical(
            {"seq": seq, "ts": ts, "kind": kind, "payload": payload, "prev_hash": prev_hash}
        )
        return hmac.new(self.chain_key, body, hashlib.sha256).hexdigest()

    def append(self, kind: str, payload: dict[str, Any], ts: str) -> AuditEntry:
        seq = len(self.entries)
        prev = self.head
        entry = AuditEntry(
            seq=seq,
            ts=ts,
            kind=kind,
            payload=payload,
            prev_hash=prev,
            entry_hash=self._hash(seq, ts, kind, payload, prev),
        )
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        """Recompute the whole chain; returns False if any link is broken."""
        prev = _GENESIS
        for e in self.entries:
            if e.prev_hash != prev:
                return False
            if self._hash(e.seq, e.ts, e.kind, e.payload, e.prev_hash) != e.entry_hash:
                return False
            prev = e.entry_hash
        return True
