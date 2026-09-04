from app.models import AdmissionRequest,Decision,Evidence
from app.policy import evaluate

def ev(**kw):
    d={"ip":"8.8.8.8","country_code":"US","asn":"15169","usage_type":"ISP"}; d.update(kw); return Evidence(**d)
def test_admit():
    d,r=evaluate(AdmissionRequest(ip="8.8.8.8",expected_country="US"),ev()); assert d==Decision.ADMIT and r==[]
def test_country_refuse():
    d,r=evaluate(AdmissionRequest(ip="8.8.8.8",deny_countries=["US"]),ev()); assert d==Decision.REFUSE
def test_country_review():
    d,r=evaluate(AdmissionRequest(ip="8.8.8.8",expected_country="CA"),ev()); assert d==Decision.REVIEW
def test_asn_refuse():
    d,r=evaluate(AdmissionRequest(ip="8.8.8.8",deny_asns=["AS15169"]),ev()); assert d==Decision.REFUSE
def test_dc_review():
    d,r=evaluate(AdmissionRequest(ip="8.8.8.8",block_datacenter=True),ev(usage_type="DCH")); assert d==Decision.REVIEW
