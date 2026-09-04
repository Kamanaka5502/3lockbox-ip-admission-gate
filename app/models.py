from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, field_validator

class Decision(str, Enum):
    ADMIT="ADMIT"; REVIEW="REVIEW"; REFUSE="REFUSE"

class AdmissionRequest(BaseModel):
    ip:str
    expected_country:str|None=None
    allow_countries:list[str]=Field(default_factory=list)
    deny_countries:list[str]=Field(default_factory=list)
    deny_asns:list[str]=Field(default_factory=list)
    block_datacenter:bool=False
    @field_validator("expected_country")
    @classmethod
    def norm_expected(cls,v): return v.upper() if v else v
    @field_validator("allow_countries","deny_countries")
    @classmethod
    def norm_countries(cls,v): return sorted({x.upper() for x in v if x})
    @field_validator("deny_asns")
    @classmethod
    def norm_asns(cls,v): return sorted({str(x).upper().strip().removeprefix("AS") for x in v if str(x).strip()})

class Evidence(BaseModel):
    ip:str
    country_code:str|None=None
    country_name:str|None=None
    region_name:str|None=None
    city_name:str|None=None
    latitude:float|None=None
    longitude:float|None=None
    asn:str|None=None
    as_name:str|None=None
    isp:str|None=None
    domain:str|None=None
    usage_type:str|None=None
    is_proxy:bool|None=None
    fraud_score:int|None=None
    source:str="IP2Location.io"

class RuleResult(BaseModel):
    rule_id:str; severity:str; message:str; observed:Any=None

class AdmissionReceipt(BaseModel):
    schema_version:str="3lockbox-receipt/1.0"
    policy_version:str
    decision:Decision
    decision_hash:str
    input:AdmissionRequest
    evidence:Evidence
    rules:list[RuleResult]
    observed_at:str
    source:str="IP2Location.io"
