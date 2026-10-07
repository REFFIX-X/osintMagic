"""Data-driven username enumeration (Sherlock-style).

Each site is a JSON entry in ``data/username_sites.json``. Adding a site is a
JSON edit — no code changes. Detection strategies mirror Sherlock: status_code
(404/410 = not found), message (regex on body), or response_url (redirect).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..http_client import HttpError, get
from ..models import Finding, SourceResult
from ..registry import register, source
from .base import DataSource

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "username_sites.json"


def _load_sites() -> list[dict]:
    with open(_DATA_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


class UsernameSiteSource(DataSource):
    category = "username"

    def __init__(self, site: dict):
        self.name = site["name"]
        self.site = site

    def check(self, target: str) -> SourceResult:
        site = self.site
        url = site["url_user"].replace("{}", target)
        try:
            resp = get(
                url,
                impersonate=site.get("impersonate", False),
                timeout=site.get("timeout", 10),
            )
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        status, detail = self._classify(resp, site)
        finding_url = url if status == "found" else None
        return SourceResult(
            source=self.name,
            category=self.category,
            findings=[
                Finding(
                    source=self.name,
                    category=self.category,
                    status=status,
                    url=finding_url,
                    detail=detail,
                )
            ],
        )

    def _classify(self, resp, site) -> tuple[str, dict]:
        error_type = site.get("errorType", "status_code")

        if error_type == "status_code":
            error_codes = set(site.get("errorCodes") or [site.get("errorCode", 404)])
            if resp.status_code in error_codes:
                return "not_found", {"reason": f"http {resp.status_code}"}
            if 200 <= resp.status_code < 400:
                return "found", {}
            return "error", {"http_status": resp.status_code}

        if error_type == "message":
            error_msg = site.get("errorMsg")
            if error_msg and re.search(error_msg, resp.text, re.IGNORECASE):
                return "not_found", {"reason": "error message matched"}
            if 200 <= resp.status_code < 400:
                return "found", {}
            return "error", {"http_status": resp.status_code}

        if error_type == "response_url":
            bad_urls = set(site.get("errorUrl") or [])
            if resp.url in bad_urls:
                return "not_found", {"reason": "redirected to error url"}
            if 200 <= resp.status_code < 400:
                return "found", {}
            return "error", {"http_status": resp.status_code}

        return "error", {"reason": f"unknown errorType: {error_type}"}


for _site in _load_sites():
    register(UsernameSiteSource(_site))


@source(category="username", name="Maigret (deep)")
class MaigretSource(DataSource):
    """Deep username scan across maigret's 2000+ sites (vendored, keyless)."""

    deep = True

    def check(self, target: str) -> SourceResult:
        from ..backends import run_maigret

        result = run_maigret(target)
        if not result["available"]:
            return SourceResult(source=self.name, category=self.category, error=result["reason"])
        if result["reason"]:
            return SourceResult(source=self.name, category=self.category, error=result["reason"])
        findings = []
        for row in result["rows"]:
            status = row.get("status")
            if row.get("exists"):
                findings.append(
                    Finding(source=self.name, category=self.category, status="found",
                            url=row.get("url"),
                            detail={"type": "username", "site": row.get("site"),
                                    "ids": row.get("ids")})
                )
            elif status in ("Available", None):
                continue  # only surface hits for the deep scan
            else:
                findings.append(
                    Finding(source=self.name, category=self.category, status="error",
                            detail={"type": "username", "site": row.get("site"), "status": status})
                )
        return SourceResult(source=self.name, category=self.category, findings=findings)
