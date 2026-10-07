"""Shared search-engine scraping (DuckDuckGo, Bing, Mojeek, Brave).

Search engines rate-limit and sometimes block automated clients, so callers
should treat results as best-effort and label them low-confidence. ``search``
queries one engine; ``search_all`` fans out to several and deduplicates.
"""
from __future__ import annotations

import concurrent.futures
import re
from urllib.parse import unquote

from ..http_client import HttpError, get


def _clean_title(raw: str) -> str:
    return re.sub(r"<[^>]+>", "", raw).strip()


def _extract_ddg(html: str) -> list[tuple[str, str]]:
    results = []
    for m in re.finditer(
        r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', html, re.DOTALL
    ):
        href = m.group(1)
        if "uddg=" in href:
            href = unquote(href.split("uddg=", 1)[1].split("&", 1)[0])
        results.append((href, _clean_title(m.group(2))))
    return results


def _extract_bing(html: str) -> list[tuple[str, str]]:
    results = []
    for m in re.finditer(
        r'<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', html, re.DOTALL
    ):
        href = m.group(1)
        if "bing.com/ck/" in href or href.startswith("/"):
            continue  # Bing's click-tracking redirect, not the real result URL
        results.append((href, _clean_title(m.group(2))))
    return results


def _extract_mojeek(html: str) -> list[tuple[str, str]]:
    results = []
    for m in re.finditer(
        r'<a[^>]+class="ob"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', html, re.DOTALL
    ):
        results.append((m.group(1), _clean_title(m.group(2))))
    return results


def _extract_brave(html: str) -> list[tuple[str, str]]:
    results = []
    for m in re.finditer(
        r'<a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a>', html, re.DOTALL
    ):
        href, title = m.group(1), _clean_title(m.group(2))
        if not title or "brave.com" in href:
            continue
        results.append((href, title))
    return results


_ENGINES = {
    "ddg": ("https://html.duckduckgo.com/html/", _extract_ddg),
    "bing": ("https://www.bing.com/search", _extract_bing),
    "mojeek": ("https://www.mojeek.com/search", _extract_mojeek),
    "brave": ("https://search.brave.com/search", _extract_brave),
}


def search(query: str, engine: str = "ddg", timeout: float = 8) -> list[tuple[str, str]]:
    """Return ``(url, title)`` pairs for a query. Raises HttpError on failure."""
    url, extractor = _ENGINES[engine]
    resp = get(url, params={"q": query}, timeout=timeout)
    return extractor(resp.text)


def search_all(query: str, engines=("ddg", "bing", "mojeek", "brave"), timeout: float = 8) -> list[tuple[str, str]]:
    """Query several engines concurrently and return deduplicated ``(url, title)`` pairs.

    A failing engine is skipped (search engines block bots unpredictably), so
    the result is the union of whichever engines responded. If *every* engine
    fails and nothing was found, ``HttpError`` is raised so callers can report a
    genuine failure rather than an empty "not found".
    """
    seen: dict[str, str] = {}
    failures = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(engines)) as ex:
        fut_map = {ex.submit(search, query, engine=e, timeout=timeout): e for e in engines}
        for fut in concurrent.futures.as_completed(fut_map):
            try:
                results = fut.result()
            except HttpError:
                failures += 1
                continue
            for url, title in results:
                if url.startswith(("http://", "https://")) and url not in seen:
                    seen[url] = title
    if failures == len(engines) and not seen:
        raise HttpError(f"all {failures} search engines failed")
    return [(url, title) for url, title in seen.items()]
