import json

from app.ledger import LedgerStore
from app.models import AdmissionRequest, Evidence
from app.policy import POLICY_VERSION, evaluate
from app.receipts import build_receipt


def receipt(ip="8.8.8.8"):
    req = AdmissionRequest(ip=ip, expected_country="US")
    ev = Evidence(ip=ip, country_code="US", asn="15169")
    decision, rules = evaluate(req, ev)
    return build_receipt(POLICY_VERSION, decision, req, ev, rules)


def test_ledger_chain_verifies(tmp_path):
    ledger = LedgerStore(str(tmp_path / "ledger.ndjson"))
    ledger.append(receipt())
    ledger.append(receipt("1.1.1.1"))
    result = ledger.verify()
    assert result["verified"] is True
    assert result["entries"] == 2


def test_ledger_detects_tamper(tmp_path):
    path = tmp_path / "ledger.ndjson"
    ledger = LedgerStore(str(path))
    ledger.append(receipt())
    entry = json.loads(path.read_text().strip())
    entry["decision"] = "REFUSE"
    path.write_text(json.dumps(entry) + "\n")
    assert ledger.verify()["verified"] is False
