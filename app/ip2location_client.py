import os, ipaddress, httpx
from .models import Evidence

class IP2LocationError(RuntimeError): pass

class IP2LocationClient:
    def __init__(self,api_key=None,base_url=None):
        self.api_key=api_key if api_key is not None else os.getenv("IP2LOCATION_API_KEY","").strip()
        self.base_url=base_url or os.getenv("IP2LOCATION_BASE_URL","https://api.ip2location.io/")
    @staticmethod
    def validate_public_ip(ip):
        try: parsed=ipaddress.ip_address(ip)
        except ValueError as exc: raise IP2LocationError(f"Invalid IP address: {ip}") from exc
        if not parsed.is_global: raise IP2LocationError("3LOCKBOX refuses lookup for non-global addresses.")
        return parsed
    async def lookup(self,ip):
        parsed=self.validate_public_ip(ip)
        params={"ip":str(parsed),"format":"json"}
        if self.api_key: params["key"]=self.api_key
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                r=await client.get(self.base_url,params=params); r.raise_for_status(); p=r.json()
        except (httpx.HTTPError,ValueError) as exc: raise IP2LocationError(f"IP2Location.io lookup failed: {exc}") from exc
        if isinstance(p,dict) and p.get("error"): raise IP2LocationError(f"IP2Location.io returned an error: {p['error']}")
        ai=p.get("as_info") or {}
        asn=p.get("asn") or ai.get("as_number")
        if asn is not None: asn=str(asn).upper().replace("AS","")
        return Evidence(ip=str(parsed),country_code=p.get("country_code"),country_name=p.get("country_name"),region_name=p.get("region_name"),city_name=p.get("city_name"),latitude=p.get("latitude"),longitude=p.get("longitude"),asn=asn,as_name=p.get("as") or ai.get("as_name"),isp=p.get("isp"),domain=p.get("domain"),usage_type=p.get("usage_type") or ai.get("as_usage_type"),is_proxy=p.get("is_proxy"),fraud_score=p.get("fraud_score"))
