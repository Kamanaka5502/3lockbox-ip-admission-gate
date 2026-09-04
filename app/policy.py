from __future__ import annotations

from .models import AdmissionRequest, Decision, Evidence, RuleResult

POLICY_VERSION = "3lockbox-ip-policy/1.1"
DATACENTER_USAGE_TYPES = {"DCH", "CDN", "SES"}


def evaluate(request: AdmissionRequest, evidence: Evidence) -> tuple[Decision, list[RuleResult]]:
    rules: list[RuleResult] = []
    country = (evidence.country_code or "").upper()
    asn = (evidence.asn or "").upper().replace("AS", "")
    usage = (evidence.usage_type or "").upper()
    threat = (evidence.threat or "").strip()

    if not country:
        rules.append(RuleResult(rule_id="EVIDENCE_COUNTRY_MISSING", severity="REVIEW", message="Country evidence is missing; execution cannot be admitted cleanly."))
    if request.deny_countries and country in request.deny_countries:
        rules.append(RuleResult(rule_id="COUNTRY_DENY", severity="REFUSE", message="Observed country is explicitly denied.", observed=country))
    if request.allow_countries and country not in request.allow_countries:
        rules.append(RuleResult(rule_id="COUNTRY_NOT_ALLOWED", severity="REFUSE", message="Observed country is outside the explicit allow set.", observed=country or None))
    if request.expected_country and country and country != request.expected_country:
        rules.append(RuleResult(rule_id="EXPECTED_COUNTRY_MISMATCH", severity="REVIEW", message="Observed country does not match the expected country.", observed={"expected": request.expected_country, "observed": country}))
    if request.deny_asns and asn and asn in request.deny_asns:
        rules.append(RuleResult(rule_id="ASN_DENY", severity="REFUSE", message="Observed ASN is explicitly denied.", observed=asn))
    if request.block_datacenter and (usage in DATACENTER_USAGE_TYPES or evidence.is_data_center is True):
        rules.append(RuleResult(rule_id="DATACENTER_REVIEW", severity="REVIEW", message="IP appears to originate from hosting/data-center infrastructure.", observed={"usage_type": usage or None, "is_data_center": evidence.is_data_center}))
    if request.deny_proxy and evidence.is_proxy is True:
        rules.append(RuleResult(rule_id="PROXY_DENY", severity="REFUSE", message="IP2Location identifies the address as a proxy.", observed={"is_proxy": True, "proxy_type": evidence.proxy_type}))
    if request.deny_vpn and evidence.is_vpn is True:
        rules.append(RuleResult(rule_id="VPN_DENY", severity="REFUSE", message="IP2Location identifies the address as VPN infrastructure.", observed=True))
    if request.deny_tor and evidence.is_tor is True:
        rules.append(RuleResult(rule_id="TOR_DENY", severity="REFUSE", message="IP2Location identifies the address as a Tor exit/node.", observed=True))
    if request.max_fraud_score is not None and evidence.fraud_score is not None and evidence.fraud_score > request.max_fraud_score:
        rules.append(RuleResult(rule_id="FRAUD_SCORE_DENY", severity="REFUSE", message="Observed fraud score exceeds the configured admission ceiling.", observed={"score": evidence.fraud_score, "maximum": request.max_fraud_score}))
    if threat and threat != "-":
        rules.append(RuleResult(rule_id="THREAT_SIGNAL_REVIEW", severity="REVIEW", message="IP2Location returned a non-empty threat signal.", observed=threat))

    severities = {rule.severity for rule in rules}
    if "REFUSE" in severities:
        return Decision.REFUSE, rules
    if "REVIEW" in severities:
        return Decision.REVIEW, rules
    return Decision.ADMIT, rules
