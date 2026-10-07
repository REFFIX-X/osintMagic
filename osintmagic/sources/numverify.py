"""numverify phone validation (requires optional numverify access key)."""
from __future__ import annotations

import json
import re

from ..http_client import HttpError, get
from ..keys import get_key
from ..models import Finding, SourceResult
from ..registry import source
from .base import DataSource


@source(category="phone", name="numverify")
class NumverifySource(DataSource):
    key_name = "NUMVERIFY_ACCESS_KEY"

    def check(self, target: str) -> SourceResult:
        key = get_key(self.key_name)
        if not key:
            return SourceResult(source=self.name, category=self.category, error="no numverify access key")
        digits = re.sub(r"\D", "", target)
        try:
            resp = get(
                "http://apilayer.net/api/validate",
                params={"access_key": key, "number": digits, "format": 1},
                timeout=15,
            )
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        try:
            data = json.loads(resp.text)
        except json.JSONDecodeError:
            return SourceResult(source=self.name, category=self.category, error="non-JSON response")

        if not data.get("valid"):
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found",
                                  detail={"type": "numverify", "reason": data.get("error") or "invalid number"})],
            )
        detail = {
            "type": "numverify",
            "country": data.get("country_name"),
            "location": data.get("location"),
            "carrier": data.get("carrier"),
            "line_type": data.get("line_type"),
        }
        return SourceResult(
            source=self.name, category=self.category,
            findings=[Finding(source=self.name, category=self.category, status="found", detail=detail)],
        )
