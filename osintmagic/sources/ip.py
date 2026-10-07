"""IP recon (keyless).

Four independent sources: ip-api.com (geolocation/ISP/ASN), ipinfo.io
(org/hostname), RDAP (network + abuse contact), and reverse-DNS PTR.
"""
from __future__ import annotations

import json

from ..http_client import HttpError, get
from ..models import Finding, SourceResult
from ..registry import source
from .base import DataSource


@source(category="ip", name="ip-api.com")
class IpApiSource(DataSource):
    def check(self, target: str) -> SourceResult:
        url = (
            "http://ip-api.com/json/"
            f"{target}?fields=status,message,country,regionName,city,zip,lat,lon,"
            "isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        )
        try:
            data = json.loads(get(url, timeout=10).text)
        except (HttpError, json.JSONDecodeError) as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        if data.get("status") != "success":
            return SourceResult(
                source=self.name, category=self.category,
                error=data.get("message") or "unknown ip-api error",
            )
        detail = {"type": "geolocation", **{k: v for k, v in data.items() if v not in (None, "") and k != "status"}}
        return SourceResult(
            source=self.name, category=self.category,
            findings=[Finding(source=self.name, category=self.category, status="found", detail=detail)],
        )


@source(category="ip", name="ipinfo.io")
class IpInfoSource(DataSource):
    def check(self, target: str) -> SourceResult:
        url = f"https://ipinfo.io/{target}/json"
        try:
            resp = get(url, timeout=10)
            if resp.status_code >= 400:
                return SourceResult(source=self.name, category=self.category, error=f"http {resp.status_code}")
            data = json.loads(resp.text)
        except (HttpError, json.JSONDecodeError) as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        detail = {"type": "geolocation", **{k: v for k, v in data.items() if v not in (None, "") and k not in ("readme",)}}
        return SourceResult(
            source=self.name, category=self.category,
            findings=[Finding(source=self.name, category=self.category, status="found", detail=detail)],
        )


@source(category="ip", name="RDAP / IP")
class RdapIpSource(DataSource):
    def check(self, target: str) -> SourceResult:
        url = f"https://rdap.org/ip/{target}"
        try:
            resp = get(url, timeout=15)
            if resp.status_code >= 400:
                return SourceResult(source=self.name, category=self.category, error=f"http {resp.status_code}")
            data = json.loads(resp.text)
        except (HttpError, json.JSONDecodeError) as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        detail: dict = {
            "type": "network",
            "name": data.get("name"),
            "handle": data.get("handle"),
            "range": f"{data.get('startAddress')} - {data.get('endAddress')}",
        }
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "abuse" in roles and "abuse_email" not in detail:
                for item in (entity.get("vcardArray") or [None, []])[1]:
                    if isinstance(item, list) and item and item[0] == "email" and len(item) > 3:
                        detail["abuse_email"] = str(item[3])
            if "registrant" in roles and "owner" not in detail:
                for item in (entity.get("vcardArray") or [None, []])[1]:
                    if isinstance(item, list) and item and item[0] == "fn" and len(item) > 3:
                        detail["owner"] = str(item[3])

        return SourceResult(
            source=self.name, category=self.category,
            findings=[Finding(source=self.name, category=self.category, status="found", detail=detail)],
        )


@source(category="ip", name="Reverse DNS")
class ReverseDnsSource(DataSource):
    def check(self, target: str) -> SourceResult:
        try:
            import dns.resolver
            import dns.reversename
        except ImportError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        try:
            rev = dns.reversename.from_address(target)
            answers = dns.resolver.resolve(rev, "PTR", lifetime=8)
            names = sorted(str(a) for a in answers)
        except Exception as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc) or "no PTR record")

        return SourceResult(
            source=self.name, category=self.category,
            findings=[
                Finding(source=self.name, category=self.category, status="info", detail={"type": "PTR", "value": n})
                for n in names
            ],
        )
