"""Person search — best-effort keyless search-engine scraping.

Search engines are rate-limited and frequently block automated clients, so
these findings carry a low confidence and are labelled as such in the UI.
Candidate username/email generation and dork strings live in
``osintmagic.utils.permutations``; the person *view* orchestrates feeding
generated candidates back through the username engine.
"""
from __future__ import annotations

from ..http_client import HttpError, get
from ..models import Finding, SourceResult
from ..registry import source
from .base import DataSource
from .search import _extract_bing, _extract_ddg

_LOW_CONFIDENCE = 0.4


def _findings(results: list[tuple[str, str]], source_name: str = "search") -> list[Finding]:
    out = []
    for url, title in results:
        if not url.startswith(("http://", "https://")):
            continue
        out.append(
            Finding(
                source=source_name,
                category="person",
                status="found",
                url=url,
                detail={"title": title, "type": "search"},
                confidence=_LOW_CONFIDENCE,
            )
        )
    return out


@source(category="person", name="DuckDuckGo")
class DuckDuckGoSource(DataSource):
    def check(self, target: str) -> SourceResult:
        try:
            resp = get("https://html.duckduckgo.com/html/", params={"q": target}, timeout=8)
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))
        findings = _findings(_extract_ddg(resp.text), self.name)
        if not findings:
            return SourceResult(
                source=self.name, category=self.category,
                error="no results (engine may have blocked the request)",
            )
        return SourceResult(source=self.name, category=self.category, findings=findings)


@source(category="person", name="Bing")
class BingSource(DataSource):
    def check(self, target: str) -> SourceResult:
        try:
            resp = get("https://www.bing.com/search", params={"q": target}, timeout=8)
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))
        findings = _findings(_extract_bing(resp.text), self.name)
        if not findings:
            return SourceResult(
                source=self.name, category=self.category,
                error="no results (engine may have blocked the request)",
            )
        return SourceResult(source=self.name, category=self.category, findings=findings)
