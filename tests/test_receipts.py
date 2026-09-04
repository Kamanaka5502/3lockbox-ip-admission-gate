from app.models import AdmissionRequest,Evidence
from app.policy import POLICY_VERSION,evaluate
from app.receipts import build_receipt,compute_decision_hash

def test_hash_deterministic():
    q=AdmissionRequest(ip="8.8.8.8",expected_country="US"); e=Evidence(ip="8.8.8.8",country_code="US",asn="15169"); d,r=evaluate(q,e); assert compute_decision_hash(POLICY_VERSION,d,q,e,r)==compute_decision_hash(POLICY_VERSION,d,q,e,r)
def test_receipt_hash_stable():
    q=AdmissionRequest(ip="8.8.8.8",expected_country="US"); e=Evidence(ip="8.8.8.8",country_code="US",asn="15169"); d,r=evaluate(q,e); assert build_receipt(POLICY_VERSION,d,q,e,r).decision_hash==build_receipt(POLICY_VERSION,d,q,e,r).decision_hash
