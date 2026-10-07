"""Focused leak/paste scan (keyless, search-engine based).

Aggregates paste-site dorks, stealer-log / combolist mentions and credential
scanning for a single target. Registered for email, username, domain and phone
so the "Leaks" view (and the Dossier) surface a consolidated breach/leak picture.
"""
from __future__ import annotations

from ..http_client import HttpError
from ..models import Finding, SourceResult
from ..registry import register
from .base import DataSource
from .paste import scan_for_credentials
from .search import search_all

_LEAK_QUERIES = (
    '"{target}" password OR leak OR dump OR combo',
    '"{target}" infostealer OR stealer OR "stealer logs"',
    '"{target}" credentials OR database OR breach',
    '"{target}" doxbin OR paste',
)


class LeaksSource(DataSource):
    name = "Leak / paste mentions"
    deep = False
    on_demand = True

    def __init__(self, category: str):
        self.category = category

    def check(self, target: str) -> SourceResult:
        findings: list[Finding] = []
        seen: set[str] = set()

        from concurrent.futures import ThreadPoolExecutor, as_completed

        def run_query(template):
            try:
                return search_all(template.replace("{target}", target))
            except HttpError:
                return []

        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = [ex.submit(run_query, t) for t in _LEAK_QUERIES]
            for fut in as_completed(futures):
                for url, title in fut.result():
                    if url in seen:
                        continue
                    seen.add(url)
                    finding = Finding(
                        source=self.name, category=self.category, status="found",
                        url=url, detail={"type": "leak", "title": title}, confidence=0.5,
                    )
                    secrets = self._scan_raw(url)
                    if secrets:
                        finding.detail["credentials"] = secrets
                        finding.confidence = 0.9
                    findings.append(finding)

        if not findings:
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found",
                                  detail={"type": "leak"})],
            )
        return SourceResult(source=self.name, category=self.category, findings=findings)

    def _scan_raw(self, url: str) -> dict[str, int]:
        # Only pastebin has a predictable raw endpoint.
        if "pastebin.com/" not in url:
            return {}
        paste_id = url.rstrip("/").split("/")[-1]
        if not paste_id or len(paste_id) > 16:
            return {}
        from ..http_client import get
        try:
            resp = get(f"https://pastebin.com/raw/{paste_id}", timeout=8)
        except HttpError:
            return {}
        return scan_for_credentials(resp.text)


for _category in ("email", "username", "domain", "phone"):
    register(LeaksSource(_category))
