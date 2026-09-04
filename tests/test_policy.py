from app.models import AdmissionRequest, Decision, Evidence
from app.policy import evaluate


def evidence(**kwargs):
    base = {"ip": "8.8.8.8", "country_code": "US", "asn": "15169", "usage_type": "ISP"}
    base.update(kwargs)
    return Evidence(**base)


def test_admit_clean_evidence():
    req = AdmissionRequest(ip="8.8.8.8", expected_country="US")
    decision, rules = evaluate(req, evidence())
    assert decision == Decision.ADMIT
    assert rules == []


def test_refuse_denied_country():
    req = AdmissionRequest(ip="8.8.8.8", deny_countries=["US"])
    decision, rules = evaluate(req, evidence())
    assert decision == Decision.REFUSE
    assert any(r.rule_id == "COUNTRY_DENY" for r in rules)


def test_review_expected_country_mismatch():
    req = AdmissionRequest(ip="8.8.8.8", expected_country="CA")
    decision, rules = evaluate(req, evidence())
    assert decision == Decision.REVIEW
    assert any(r.rule_id == "EXPECTED_COUNTRY_MISMATCH" for r in rules)


def test_refuse_denied_asn():
    req = AdmissionRequest(ip="8.8.8.8", deny_asns=["AS15169"])
    decision, rules = evaluate(req, evidence())
    assert decision == Decision.REFUSE
    assert any(r.rule_id == "ASN_DENY" for r in rules)


def test_review_datacenter():
    req = AdmissionRequest(ip="8.8.8.8", block_datacenter=True)
    decision, rules = evaluate(req, evidence(usage_type="DCH"))
    assert decision == Decision.REVIEW
    assert any(r.rule_id == "DATACENTER_REVIEW" for r in rules)


def test_proxy_refuse():
    req = AdmissionRequest(ip="8.8.8.8", deny_proxy=True)
    decision, rules = evaluate(req, evidence(is_proxy=True, proxy_type="DCH"))
    assert decision == Decision.REFUSE
    assert any(r.rule_id == "PROXY_DENY" for r in rules)


def test_vpn_refuse():
    decision, _ = evaluate(AdmissionRequest(ip="8.8.8.8", deny_vpn=True), evidence(is_vpn=True))
    assert decision == Decision.REFUSE


def test_tor_refuse():
    decision, _ = evaluate(AdmissionRequest(ip="8.8.8.8", deny_tor=True), evidence(is_tor=True))
    assert decision == Decision.REFUSE


def test_fraud_score_refuse():
    decision, _ = evaluate(AdmissionRequest(ip="8.8.8.8", max_fraud_score=10), evidence(fraud_score=42))
    assert decision == Decision.REFUSE
