from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .models import AdmissionReceipt

ZERO_HASH = "0" * 64


def _hash_entry(core: dict) -> str:
    raw = json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


class LedgerStore:
    """Append-only hash chain over decision receipts."""

    def __init__(self, path: str | None = None):
        self.path = Path(path or os.getenv("LEDGER_FILE", "data/ledger.ndjson"))
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        entries = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entries.append(json.loads(line))
        return entries

    def append(self, receipt: AdmissionReceipt) -> dict:
        entries = self._entries()
        previous = entries[-1]["entry_hash"] if entries else ZERO_HASH
        core = {
            "sequence": len(entries) + 1,
            "decision_hash": receipt.decision_hash,
            "decision": receipt.decision.value,
            "policy_version": receipt.policy_version,
            "previous_entry_hash": previous,
        }
        entry = {**core, "entry_hash": _hash_entry(core)}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
        return entry

    def verify(self) -> dict:
        entries = self._entries()
        previous = ZERO_HASH
        for expected_seq, entry in enumerate(entries, start=1):
            core = {
                "sequence": entry.get("sequence"),
                "decision_hash": entry.get("decision_hash"),
                "decision": entry.get("decision"),
                "policy_version": entry.get("policy_version"),
                "previous_entry_hash": entry.get("previous_entry_hash"),
            }
            if core["sequence"] != expected_seq:
                return {"verified": False, "entries": len(entries), "failure": "sequence", "at": expected_seq}
            if core["previous_entry_hash"] != previous:
                return {"verified": False, "entries": len(entries), "failure": "chain", "at": expected_seq}
            if entry.get("entry_hash") != _hash_entry(core):
                return {"verified": False, "entries": len(entries), "failure": "hash", "at": expected_seq}
            previous = entry["entry_hash"]
        return {"verified": True, "entries": len(entries), "head": previous}

    def tail(self, limit: int = 25) -> list[dict]:
        return self._entries()[-max(1, min(limit, 250)):]
