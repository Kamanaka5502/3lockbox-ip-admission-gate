from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, field_validator

class Decision(str, Enum):
    ADMIT = "ADMIT"
    REVIEW = "REVIEW"
    REFUSE = "REFUSE"

class AdmissionRequest(BaseModel):
    ip: str
    expected_country: str | None = None
    allow_countries: list[str] = Field(default_factory=list)
    deny_countries: list[str] = Field(default_factory=list)
    deny_asns: list[str] = Field(default_factory=list)
    block_datacenter: bool = False
    deny_proxy: bool = False
    deny_vpn: bool = False
    deny_tor: bool = False
    max_fraud_score: int | None = Field(default=None, ge=0, le=99)

    @field_validator("expected_country")
    @classmethod
    def normalize_expected_country(cls, value):
        return value.upper() if value else value

    @field_validator("allow_countries", "deny_countries")
    @classmethod
    def normalize_countries(cls, values):
        return sorted({v.upper() for v in values if v})

    @field_validator("deny_asns")
    @classmethod
    def normalize_asns(cls, values):
        normalized = set()
        for value in values:
            v = str(value).upper().strip()
            if v.startswith("AS"):
                v = v[2:]
            if v:
                normalized.add(v)
        return sorted(normalized)

class Evidence(BaseModel):
    ip: str
    country_code: str | None = None
    country_name: str | None = None
    region_name: str | None = None
    city_name: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: str | None = None
    as_name: str | None = None
    isp: str | None = None
    domain: str | None = None
    usage_type: str | None = None
    is_proxy: bool | None = None
    fraud_score: int | None = None
    proxy_type: str | None = None
    threat: str | None = None
    is_vpn: bool | None = None
    is_tor: bool | None = None
    is_data_center: bool | None = None
    source: str = "IP2Location.io"

class RuleResult(BaseModel):
    rule_id: str
    severity: str
    message: str
    observed: Any = None

class AdmissionReceipt(BaseModel):
    schema_version: str = "3lockbox-receipt/1.1"
    policy_version: str
    decision: Decision
    decision_hash: str
    input: AdmissionRequest
    evidence: Evidence
    rules: list[RuleResult]
    observed_at: str
    source: str = "IP2Location.io"
