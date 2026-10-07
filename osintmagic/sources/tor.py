"""Dark-web access (optional, TorBot-style) + Ahmia search.

``TorCrawlSource`` crawls a ``.onion`` URL through a local Tor SOCKS5 proxy when
one is reachable; otherwise it no-ops with a clear "Tor not running" message.
``AhmiaSearchSource`` searches the Ahmia .onion index from the clearnet. Passive
and keyless (Tor itself is free) — but note OPSEC: only browse the dark web from
an isolated environment, never with organizational identity.
"""
from __future__ import annotations

import re

from ..http_client import HttpError, get
from ..models import Finding, SourceResult
from ..registry import source
from .base import DataSource

TOR_HOST = "127.0.0.1"
TOR_PORT = 9050
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_ONION_RE = re.compile(r"https?://[a-z0-9-]+\.onion[^\s\"'<>]*", re.IGNORECASE)


def tor_available() -> bool:
    import socket

    try:
        with socket.create_connection((TOR_HOST, TOR_PORT), timeout=3):
            return True
    except OSError:
        return False


def _tor_get(url: str, timeout: float = 20):
    import httpx

    proxy = f"socks5://{TOR_HOST}:{TOR_PORT}"
    with httpx.Client(proxy=proxy, timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url)
    return resp


@source(category="darkweb", name="Tor .onion Crawl")
class TorCrawlSource(DataSource):
    """Fetch a .onion page and list its outbound .onion links via Tor."""

    def check(self, target: str) -> SourceResult:
        url = target.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        if not tor_available():
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="info",
                                  detail={"type": "tor", "value": f"Tor daemon not running at {TOR_HOST}:{TOR_PORT}"})],
            )

        try:
            resp = _tor_get(url)
        except Exception as exc:
            return SourceResult(source=self.name, category=self.category, error=f"fetch failed: {exc}")

        title_match = _TITLE_RE.search(resp.text)
        title = title_match.group(1).strip() if title_match else url
        links = sorted(set(_ONION_RE.findall(resp.text)))
        findings = [
            Finding(source=self.name, category=self.category, status="found", url=url,
                    detail={"type": "tor_page", "title": title, "http_status": resp.status_code})
        ]
        for link in links[:50]:
            findings.append(Finding(source=self.name, category=self.category, status="info",
                                    url=link, detail={"type": "tor_link"}, confidence=0.5))
        return SourceResult(source=self.name, category=self.category, findings=findings)


@source(category="darkweb", name="Ahmia Search")
class AhmiaSearchSource(DataSource):
    """Search the Ahmia .onion index (clearnet endpoint) for a keyword/domain."""

    def check(self, target: str) -> SourceResult:
        url = "https://ahmia.fi/search/"
        try:
            resp = get(url, params={"q": target.strip()}, timeout=15)
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        # Ahmia result links are to .onion hosts.
        onions = sorted(set(_ONION_RE.findall(resp.text)))
        if not onions:
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found",
                                  detail={"type": "ahmia", "note": "no .onion results (or Ahmia blocked the request)"})],
            )
        findings = [
            Finding(source=self.name, category=self.category, status="found", url=o,
                    detail={"type": "ahmia"}, confidence=0.4)
            for o in onions[:50]
        ]
        return SourceResult(source=self.name, category=self.category, findings=findings)
