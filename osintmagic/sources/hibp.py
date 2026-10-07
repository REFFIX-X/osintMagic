"""HaveIBeenPwned breach lookup (requires optional HIBP API key)."""
from __future__ import annotations

import json

from ..http_client import HttpError, get
from ..keys import get_key
from ..models import Finding, SourceResult
from ..registry import source
from .base import DataSource


@source(category="email", name="HIBP breach")
class HibpBreachSource(DataSource):
    key_name = "HIBP_API_KEY"

    def check(self, target: str) -> SourceResult:
        key = get_key(self.key_name)
        if not key:
            return SourceResult(source=self.name, category=self.category, error="no HIBP API key")
        try:
            resp = get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
                params={"truncateResponse": "false"},
                headers={"hibp-api-key": key},
                timeout=15,
            )
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        if resp.status_code == 404:
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found", detail={"type": "breach"})],
            )
        if resp.status_code == 401:
            return SourceResult(source=self.name, category=self.category, error="invalid HIBP API key")
        if resp.status_code != 200:
            return SourceResult(source=self.name, category=self.category, error=f"http {resp.status_code}")

        try:
            breaches = json.loads(resp.text)
        except json.JSONDecodeError:
            return SourceResult(source=self.name, category=self.category, error="non-JSON response")

        findings = [
            Finding(
                source=self.name, category=self.category, status="found",
                detail={
                    "type": "breach",
                    "name": b.get("Name"),
                    "title": b.get("Title"),
                    "domain": b.get("Domain"),
                    "date": b.get("BreachDate"),
                    "classes": b.get("DataClasses"),
                },
            )
            for b in breaches
        ]
        return SourceResult(source=self.name, category=self.category, findings=findings)
