from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .models import AdmissionReceipt, AdmissionRequest, Decision, Evidence, RuleResult

SCHEMA_VERSION = "3lockbox-receipt/1.1"


def canonical_decision_payload(policy_version: str, decision: Decision, request: AdmissionRequest, evidence: Evidence, rules: list[RuleResult]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "policy_version": policy_version,
        "decision": decision.value,
        "input": request.model_dump(mode="json"),
        "evidence": evidence.model_dump(mode="json"),
        "rules": [r.model_dump(mode="json") for r in rules],
    }


def compute_decision_hash(policy_version: str, decision: Decision, request: AdmissionRequest, evidence: Evidence, rules: list[RuleResult]) -> str:
    payload = canonical_decision_payload(policy_version, decision, request, evidence, rules)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def build_receipt(policy_version: str, decision: Decision, request: AdmissionRequest, evidence: Evidence, rules: list[RuleResult]) -> AdmissionReceipt:
    decision_hash = compute_decision_hash(policy_version, decision, request, evidence, rules)
    return AdmissionReceipt(
        schema_version=SCHEMA_VERSION,
        policy_version=policy_version,
        decision=decision,
        decision_hash=decision_hash,
        input=request,
        evidence=evidence,
        rules=rules,
        observed_at=datetime.now(timezone.utc).isoformat(),
        source="IP2Location.io",
    )


class ReceiptStore:
    def __init__(self, root: str | None = None):
        self.root = Path(root or os.getenv("RECEIPT_DIR", "data/receipts"))
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, receipt: AdmissionReceipt) -> Path:
        path = self.root / f"{receipt.decision_hash}.json"
        path.write_text(receipt.model_dump_json(indent=2), encoding="utf-8")
        return path

    def load(self, decision_hash: str) -> AdmissionReceipt:
        if not decision_hash or any(c not in "0123456789abcdef" for c in decision_hash.lower()):
            raise FileNotFoundError(decision_hash)
        path = self.root / f"{decision_hash}.json"
        return AdmissionReceipt.model_validate_json(path.read_text(encoding="utf-8"))
