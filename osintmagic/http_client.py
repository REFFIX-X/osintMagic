"""Shared HTTP transport.

Two backends are available:

* ``httpx`` (default) — plain HTTP/1.1 + HTTP/2.
* ``curl_cffi`` — TLS/HTTP2 fingerprint impersonation (``impersonate="chrome"``),
  used for sources that front with Cloudflare or otherwise block default
  clients.

Both backends funnel into the same small :class:`HttpResponse` so sources stay
backend-agnostic and tests can monkeypatch ``get``/``post`` with fixtures.
"""
from __future__ import annotations

import json
import os
import random
import time
from dataclasses import dataclass
from typing import Any

import httpx

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

DEFAULT_TIMEOUT = 10.0

# In-memory GET cache (TTL 30s) to dedupe identical requests across sources,
# e.g. WafCdn + TechFingerprint both fetching the domain root.
_CACHE: dict[str, tuple[float, HttpResponse]] = {}
_CACHE_TTL = 30.0
_CACHE_MAX = 256


@dataclass
class HttpResponse:
    status_code: int
    text: str
    url: str
    headers: dict[str, str]


class HttpError(Exception):
    """Raised when a request cannot be completed (DNS, timeout, TLS, ...)."""


def proxy_url() -> str | None:
    """Outbound proxy from ``OSINTMAGIC_PROXY`` (http:// or socks5://)."""
    value = os.environ.get("OSINTMAGIC_PROXY", "").strip()
    return value or None


def _headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    h = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if extra:
        h.update(extra)
    return h


def _to_response(r: Any) -> HttpResponse:
    headers: dict[str, str] = {}
    items = (
        r.headers.multi_items()
        if hasattr(r.headers, "multi_items")
        else r.headers.items()
    )
    for k, v in items:
        k = k.lower()
        headers[k] = f"{headers[k]}\n{v}" if k in headers else v
    return HttpResponse(
        status_code=r.status_code,
        text=r.text,
        url=str(r.url),
        headers=headers,
    )


_client: httpx.Client | None = None
_client_proxy: str | None = None


def _cache_key(method: str, url: str, params: dict[str, Any] | None) -> str:
    return f"{method} {url} {json.dumps(params or {}, sort_keys=True)}"


def _cache_get(key: str) -> HttpResponse | None:
    if key in _CACHE:
        ts, resp = _CACHE[key]
        if time.time() - ts < _CACHE_TTL:
            return resp
        del _CACHE[key]
    return None


def _cache_put(key: str, resp: HttpResponse) -> None:
    if len(_CACHE) >= _CACHE_MAX:
        oldest = min(_CACHE, key=lambda k: _CACHE[k][0])
        del _CACHE[oldest]
    _CACHE[key] = (time.time(), resp)


def clear_cache() -> None:
    _CACHE.clear()


def _get_client() -> httpx.Client:
    """Shared, connection-pooling client (recreated only when the proxy changes)."""
    global _client, _client_proxy
    proxy = proxy_url()
    if _client is None or _client_proxy != proxy:
        if _client is not None:
            _client.close()
        _client = httpx.Client(timeout=DEFAULT_TIMEOUT, follow_redirects=True, proxy=proxy)
        _client_proxy = proxy
    return _client


def get(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    impersonate: bool = False,
    allow_redirects: bool = True,
) -> HttpResponse:
    if impersonate:
        return _curl_cffi_request(
            "GET", url, params=params, headers=headers, timeout=timeout,
            allow_redirects=allow_redirects,
        )
    key = _cache_key("GET", url, params)
    cached = _cache_get(key)
    if cached is not None:
        return cached
    try:
        resp = _to_response(_get_client().get(
            url, params=params, headers=_headers(headers),
            timeout=timeout, follow_redirects=allow_redirects,
        ))
        _cache_put(key, resp)
        return resp
    except httpx.HTTPError as exc:  # includes ConnectError / ReadTimeout / ...
        raise HttpError(str(exc)) from exc


def post(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    json: Any = None,
    data: Any = None,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    impersonate: bool = False,
    allow_redirects: bool = True,
) -> HttpResponse:
    if impersonate:
        return _curl_cffi_request(
            "POST", url, params=params, json=json, data=data, headers=headers,
            timeout=timeout, allow_redirects=allow_redirects,
        )
    try:
        resp = _get_client().post(
            url, params=params, json=json, data=data, headers=_headers(headers),
            timeout=timeout, follow_redirects=allow_redirects,
        )
        return _to_response(resp)
    except httpx.HTTPError as exc:
        raise HttpError(str(exc)) from exc


def _curl_cffi_request(
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    json: Any = None,
    data: Any = None,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    allow_redirects: bool = True,
) -> HttpResponse:
    try:
        from curl_cffi import requests as cf
    except ImportError as exc:  # pragma: no cover - depends on optional dep
        raise HttpError("curl_cffi is not installed") from exc
    try:
        r = cf.request(
            method,
            url,
            params=params,
            json=json,
            data=data,
            headers=_headers(headers),
            timeout=timeout,
            impersonate="chrome",
            allow_redirects=allow_redirects,
            proxy=proxy_url(),
        )
        return _to_response(r)
    except Exception as exc:  # curl_cffi raises a broad set of exceptions
        raise HttpError(str(exc)) from exc
