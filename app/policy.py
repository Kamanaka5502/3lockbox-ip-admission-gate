from .models import AdmissionRequest,Decision,Evidence,RuleResult
POLICY_VERSION="3lockbox-ip-policy/1.0"
DATACENTER_USAGE_TYPES={"DCH","CDN","SES"}

def evaluate(request:AdmissionRequest,evidence:Evidence):
    rules=[]; country=(evidence.country_code or "").upper(); asn=(evidence.asn or "").upper().replace("AS",""); usage=(evidence.usage_type or "").upper()
    if not country: rules.append(RuleResult(rule_id="EVIDENCE_COUNTRY_MISSING",severity="REVIEW",message="Country evidence is missing; execution cannot be admitted cleanly."))
    if request.deny_countries and country in request.deny_countries: rules.append(RuleResult(rule_id="COUNTRY_DENY",severity="REFUSE",message="Observed country is explicitly denied.",observed=country))
    if request.allow_countries and country not in request.allow_countries: rules.append(RuleResult(rule_id="COUNTRY_NOT_ALLOWED",severity="REFUSE",message="Observed country is outside the explicit allow set.",observed=country or None))
    if request.expected_country and country and country!=request.expected_country: rules.append(RuleResult(rule_id="EXPECTED_COUNTRY_MISMATCH",severity="REVIEW",message="Observed country does not match the expected country.",observed={"expected":request.expected_country,"observed":country}))
    if request.deny_asns and asn and asn in request.deny_asns: rules.append(RuleResult(rule_id="ASN_DENY",severity="REFUSE",message="Observed ASN is explicitly denied.",observed=asn))
    if request.block_datacenter and usage in DATACENTER_USAGE_TYPES: rules.append(RuleResult(rule_id="DATACENTER_REVIEW",severity="REVIEW",message="IP appears to originate from hosting/data-center infrastructure.",observed=usage))
    sev={r.severity for r in rules}
    return (Decision.REFUSE if "REFUSE" in sev else Decision.REVIEW if "REVIEW" in sev else Decision.ADMIT),rules
