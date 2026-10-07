"""Dark-web / breach-mention search (clearnet proxy, keyless).

Real .onion monitoring requires commercial services (Recorded Future, Flashpoint,
etc.) and an isolated Tor environment — out of scope here. This source instead
surfaces *clearnet* references to breach/leak/ransomware claims about a target
via search engines, clearly labelled as a low-confidence proxy, not dark-web
access.
"""
from __future__ import annotations

from ..http_client import HttpError
from ..models import Finding, SourceResult
from ..registry import source
from .base import DataSource
from .search import search_all

_QUERIES = (
    '"{target}" breach OR leak OR dumped',
    '"{target}" ransomware leak site',
    '"{target}" stealer logs OR infostealer',
    '"{target}" credentials exposed',
)


@source(category="domain", name="Dark Web / Breach Mentions")
class DarkwebMentionSource(DataSource):
    def check(self, target: str) -> SourceResult:
        findings: list[Finding] = []
        seen: set[str] = set()
        errors = 0
        for template in _QUERIES:
            try:
                results = search_all(template.replace("{target}", target))
            except HttpError:
                errors += 1
                continue
            for url, title in results:
                if url in seen:
                    continue
                seen.add(url)
                findings.append(
                    Finding(
                        source=self.name, category=self.category, status="found",
                        url=url, detail={"type": "darkweb_mention", "title": title},
                        confidence=0.35,
                    )
                )
        if not findings:
            note = "no clearnet mentions (real .onion monitoring needs a commercial service)"
            if errors:
                note += f"; {errors} search request(s) failed"
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found",
                                   detail={"type": "darkweb_mention", "note": note})],
            )
        return SourceResult(source=self.name, category=self.category, findings=findings)
