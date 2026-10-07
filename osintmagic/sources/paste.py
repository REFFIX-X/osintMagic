"""Paste-site / code-drop leak lookups (keyless, best-effort).

Pastebin's Scraping API requires a paid PRO account and the free psbdmp.ws
service is defunct, so this searches paste sites indirectly through search
engines and scans any retrieved paste bodies for credential patterns. Results
are best-effort and low-confidence.
"""
from __future__ import annotations

import re

from ..http_client import HttpError, get
from ..models import Finding, SourceResult
from ..registry import register
from .base import DataSource
from .search import search_all

_PASTE_SITES = (
    "pastebin.com", "gist.github.com", "paste.ee", "dpaste.com", "dpaste.org",
    "hastebin.com", "rentry.co", "controlc.com", "paste.mozilla.org", "ideone.com",
)

_CREDENTIAL_PATTERNS = {
    "email:password": re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+[\s:;|,]+[\S]{6,}", re.IGNORECASE),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(r"ghp_[0-9A-Za-z]{36}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "connection_string": re.compile(r"(?:mongodb|postgres|postgresql|mysql|redis)://[^\s\"']+"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "firebase_url": re.compile(r"[a-z0-9-]+\.firebaseio\.com"),
    "generic_api_key": re.compile(r"(?:api[_-]?key|secret|access[_-]?token)\s*[:=]\s*[\"']?[\w-]{20,}", re.IGNORECASE),
    "bitcoin_address": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"),
}


def scan_for_credentials(text: str) -> dict[str, int]:
    """Return ``{pattern_name: match_count}`` for credential-like strings."""
    found: dict[str, int] = {}
    for name, pattern in _CREDENTIAL_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            found[name] = len(matches)
    return found


class PasteSearchSource(DataSource):
    """Search paste sites for a target and scan retrieved pastes for secrets."""

    on_demand = True

    def __init__(self, category: str):
        self.category = category
        self.name = "Paste / Code Leaks"

    def check(self, target: str) -> SourceResult:
        findings: list[Finding] = []
        seen: set[str] = set()
        errors = 0

        from concurrent.futures import ThreadPoolExecutor, as_completed

        def run_site(site):
            try:
                return site, search_all(f'site:{site} "{target}"')
            except HttpError:
                return site, None

        with ThreadPoolExecutor(max_workers=6) as ex:
            futures = {ex.submit(run_site, site): site for site in _PASTE_SITES}
            for fut in as_completed(futures):
                site, results = fut.result()
                if results is None:
                    errors += 1
                    continue
                for url, title in results:
                    if url in seen:
                        continue
                    seen.add(url)
                    finding = Finding(
                        source=self.name, category=self.category, status="found",
                        url=url, detail={"type": "paste", "site": site, "title": title},
                        confidence=0.5,
                    )
                    secrets = self._scan_paste(url)
                    if secrets:
                        finding.detail["credentials"] = secrets
                        finding.confidence = 0.9
                    findings.append(finding)

        if not findings:
            detail = {"type": "paste"}
            if errors:
                detail["note"] = f"{errors} search request(s) failed (engine may be blocking)"
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found", detail=detail)],
            )
        return SourceResult(source=self.name, category=self.category, findings=findings)

    def _scan_paste(self, url: str) -> dict[str, int]:
        # Only pastebin exposes a predictable raw endpoint; skip others.
        if "pastebin.com/" not in url:
            return {}
        paste_id = url.rstrip("/").split("/")[-1]
        if not paste_id or len(paste_id) > 16:
            return {}
        try:
            resp = get(f"https://pastebin.com/raw/{paste_id}", timeout=8)
        except HttpError:
            return {}
        return scan_for_credentials(resp.text)


for _category in ("email", "domain", "username"):
    register(PasteSearchSource(_category))
