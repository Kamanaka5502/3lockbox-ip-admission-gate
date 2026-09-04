import hashlib,json,os
from datetime import datetime,timezone
from pathlib import Path
from .models import AdmissionReceipt,AdmissionRequest,Decision,Evidence,RuleResult
SCHEMA_VERSION="3lockbox-receipt/1.0"

def canonical_decision_payload(policy_version,decision,request,evidence,rules):
    return {"schema_version":SCHEMA_VERSION,"policy_version":policy_version,"decision":decision.value,"input":request.model_dump(mode="json"),"evidence":evidence.model_dump(mode="json"),"rules":[r.model_dump(mode="json") for r in rules]}

def compute_decision_hash(policy_version,decision,request,evidence,rules):
    b=json.dumps(canonical_decision_payload(policy_version,decision,request,evidence,rules),sort_keys=True,separators=(",",":"),ensure_ascii=False).encode(); return hashlib.sha256(b).hexdigest()

def build_receipt(policy_version,decision,request,evidence,rules):
    h=compute_decision_hash(policy_version,decision,request,evidence,rules)
    return AdmissionReceipt(policy_version=policy_version,decision=decision,decision_hash=h,input=request,evidence=evidence,rules=rules,observed_at=datetime.now(timezone.utc).isoformat())

class ReceiptStore:
    def __init__(self,root=None): self.root=Path(root or os.getenv("RECEIPT_DIR","data/receipts")); self.root.mkdir(parents=True,exist_ok=True)
    def save(self,receipt):
        p=self.root/f"{receipt.decision_hash}.json"; p.write_text(receipt.model_dump_json(indent=2),encoding="utf-8"); return p
    def load(self,h):
        if not h or any(c not in "0123456789abcdef" for c in h.lower()): raise FileNotFoundError(h)
        return AdmissionReceipt.model_validate_json((self.root/f"{h}.json").read_text(encoding="utf-8"))
