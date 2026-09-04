from __future__ import annotations

import ipaddress
import os
import httpx
from .models import Evidence

class IP2LocationError(RuntimeError):
    pass

class IP2LocationClient:
    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key if api_key is not None else os.getenv("IP2LOCATION_API_KEY", "").strip()
        self.base_url = base_url or os.getenv("IP2LOCATION_BASE_URL", "https://api.ip2location.io/")

    @staticmethod
    def validate_public_ip(ip: str) -> ipaddress._BaseAddress:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise IP2LocationError(f"Invalid IP address: {ip}") from exc
        if not parsed.is_global:
            raise IP2LocationError("3LOCKBOX refuses lookup for non-global addresses (private, loopback, link-local, multicast, reserved, or unspecified).")
        return parsed

    async def lookup(self, ip: str) -> Evidence:
        parsed = self.validate_public_ip(ip)
        params = {"ip": str(parsed), "format": "json"}
        if self.api_key:
            params["key"] = self.api_key
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.get(self.base_url, params=params)
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise IP2LocationError(f"IP2Location.io lookup failed: {exc}") from exc
        if isinstance(payload, dict) and payload.get("error"):
            raise IP2LocationError(f"IP2Location.io returned an error: {payload['error']}")

        as_info = payload.get("as_info") or {}
        proxy = payload.get("proxy") or {}
        asn = payload.get("asn") or as_info.get("as_number")
        if asn is not None:
            asn = str(asn).upper().replace("AS", "")

        return Evidence(
            ip=str(parsed),
            country_code=payload.get("country_code"),
            country_name=payload.get("country_name"),
            region_name=payload.get("region_name"),
            city_name=payload.get("city_name"),
            latitude=payload.get("latitude"),
            longitude=payload.get("longitude"),
            asn=asn,
            as_name=payload.get("as") or as_info.get("as_name"),
            isp=payload.get("isp"),
            domain=payload.get("domain"),
            usage_type=payload.get("usage_type") or as_info.get("as_usage_type"),
            is_proxy=payload.get("is_proxy"),
            fraud_score=payload.get("fraud_score"),
            proxy_type=proxy.get("proxy_type"),
            threat=proxy.get("threat"),
            is_vpn=proxy.get("is_vpn"),
            is_tor=proxy.get("is_tor"),
            is_data_center=proxy.get("is_data_center"),
        )
