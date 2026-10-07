"""VirusTotal domain reputation (requires optional VirusTotal API key)."""
from __future__ import annotations

import json

from ..http_client import HttpError, get
from ..keys import get_key
from ..models import Finding, SourceResult
from ..registry import source
from .base import DataSource


@source(category="domain", name="VirusTotal")
class VirusTotalDomainSource(DataSource):
    key_name = "VIRUSTOTAL_API_KEY"

    def check(self, target: str) -> SourceResult:
        key = get_key(self.key_name)
        if not key:
            return SourceResult(source=self.name, category=self.category, error="no VirusTotal API key")
        try:
            resp = get(
                f"https://www.virustotal.com/api/v3/domains/{target}",
                headers={"x-apikey": key},
                timeout=15,
            )
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        if resp.status_code == 404:
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found", detail={"type": "reputation"})],
            )
        if resp.status_code == 401:
            return SourceResult(source=self.name, category=self.category, error="invalid VirusTotal API key")
        if resp.status_code != 200:
            return SourceResult(source=self.name, category=self.category, error=f"http {resp.status_code}")

        try:
            data = json.loads(resp.text)
            attrs = data["data"]["attributes"]
        except (json.JSONDecodeError, KeyError):
            return SourceResult(source=self.name, category=self.category, error="unexpected response")

        stats = attrs.get("last_analysis_stats", {})
        detail = {
            "type": "reputation",
            "reputation": attrs.get("reputation"),
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "harmless": stats.get("harmless"),
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
        }
        return SourceResult(
            source=self.name, category=self.category,
            findings=[Finding(source=self.name, category=self.category, status="found", detail=detail)],
        )
