"""Data-driven email -> account probing (holehe-style).

Each probe is a JSON entry in ``data/email_sites.json``. Two detection modes:

* ``regex`` — classify the response body with ``exists_re`` / ``not_exists_re``.
* ``cookie`` — an account exists iff the response sets a named cookie (used by
  Google's keyless ``gxlu`` check).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..http_client import HttpError, get, post
from ..models import Finding, SourceResult
from ..registry import register, source
from .base import DataSource

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "email_sites.json"


def _load_sites() -> list[dict]:
    with open(_DATA_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _fill(template, target: str):
    if isinstance(template, dict):
        return {k: (v.replace("{}", target) if isinstance(v, str) else v) for k, v in template.items()}
    if isinstance(template, str):
        return template.replace("{}", target)
    return template


class EmailSiteSource(DataSource):
    category = "email"

    def __init__(self, site: dict):
        self.name = site["name"]
        self.site = site

    def check(self, target: str) -> SourceResult:
        site = self.site
        url = site["url"]
        params = _fill(site.get("params", {}), target)
        method = site.get("method", "GET").upper()
        try:
            if method == "POST":
                json_body = _fill(site.get("json"), target) if site.get("json") else None
                data_body = _fill(site.get("data"), target) if site.get("data") else None
                resp = post(
                    url,
                    params=params,
                    json=json_body,
                    data=data_body,
                    impersonate=site.get("impersonate", False),
                    timeout=site.get("timeout", 10),
                )
            else:
                resp = get(
                    url,
                    params=params,
                    impersonate=site.get("impersonate", False),
                    timeout=site.get("timeout", 10),
                )
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        status, detail = self._classify(resp, site)
        return SourceResult(
            source=self.name,
            category=self.category,
            findings=[
                Finding(source=self.name, category=self.category, status=status, detail=detail)
            ],
        )

    def _classify(self, resp, site) -> tuple[str, dict]:
        detect = site.get("detect", "regex")
        if detect == "cookie":
            cookie = site.get("cookie_name", "")
            set_cookie = resp.headers.get("set-cookie", "")
            if cookie and f"{cookie}=" in set_cookie:
                return "found", {"reason": "account cookie present"}
            return "not_found", {"reason": "no account cookie"}

        exists_re = site.get("exists_re")
        not_exists_re = site.get("not_exists_re")
        if exists_re and re.search(exists_re, resp.text):
            return "found", {}
        if not_exists_re and re.search(not_exists_re, resp.text):
            return "not_found", {}
        return "error", {"reason": "inconclusive response", "http_status": resp.status_code}


for _site in _load_sites():
    register(EmailSiteSource(_site))


@source(category="email", name="Holehe (deep)")
class HoleheSource(DataSource):
    """Deep email scan across holehe's 120+ sites (vendored, keyless)."""

    deep = True

    def check(self, target: str) -> SourceResult:
        from ..backends import run_holehe

        result = run_holehe(target)
        if not result["available"]:
            return SourceResult(source=self.name, category=self.category, error=result["reason"])
        findings = []
        for row in result["rows"]:
            if row.get("rate_limited"):
                status = "error"
                detail = {"type": "rate_limited"}
            elif row.get("exists"):
                status = "found"
                detail = {}
            else:
                status = "not_found"
                detail = {}
            findings.append(
                Finding(source=self.name, category=self.category, status=status,
                        detail={"type": "email_account", "site": row.get("domain") or row.get("site"),
                                **detail})
            )
        if not findings:
            return SourceResult(source=self.name, category=self.category, error="no results")
        return SourceResult(source=self.name, category=self.category, findings=findings)
