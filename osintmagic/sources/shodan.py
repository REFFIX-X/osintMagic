"""Shodan host intelligence (requires optional Shodan API key)."""
from __future__ import annotations

import json

from ..http_client import HttpError, get
from ..keys import get_key
from ..models import Finding, SourceResult
from ..registry import source
from .base import DataSource


@source(category="ip", name="Shodan host")
class ShodanHostSource(DataSource):
    key_name = "SHODAN_API_KEY"

    def check(self, target: str) -> SourceResult:
        key = get_key(self.key_name)
        if not key:
            return SourceResult(source=self.name, category=self.category, error="no Shodan API key")
        try:
            resp = get(f"https://api.shodan.io/shodan/host/{target}", params={"key": key}, timeout=15)
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        if resp.status_code != 200:
            return SourceResult(source=self.name, category=self.category, error=f"http {resp.status_code}")
        try:
            data = json.loads(resp.text)
        except json.JSONDecodeError:
            return SourceResult(source=self.name, category=self.category, error="non-JSON response")

        detail = {
            "type": "shodan",
            "ports": data.get("ports"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "os": data.get("os"),
            "vulns": data.get("vulns"),
        }
        return SourceResult(
            source=self.name, category=self.category,
            findings=[Finding(source=self.name, category=self.category, status="found", detail=detail)],
        )
