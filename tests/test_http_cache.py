"""Tests for the HTTP response cache."""
import osintmagic.http_client as hc


def test_cache_dedupes_identical_get(monkeypatch):
    hc.clear_cache()
    calls = []

    class FakeClient:
        def get(self, url, *, params=None, headers=None, timeout=None, follow_redirects=None):
            calls.append(url)
            return _FakeResp(url)

    class _FakeResp:
        def __init__(self, url):
            self.status_code = 200
            self.text = "body"
            self.url = url
            self.headers = {}
        @property
        def headers(self):
            return self._h
        @headers.setter
        def headers(self, v):
            self._h = v

    # Use the real httpx-free path: monkeypatch _get_client and _to_response.
    monkeypatch.setattr(hc, "_get_client", lambda: FakeClient())

    def fake_to_response(r):
        return hc.HttpResponse(status_code=r.status_code, text=r.text, url=r.url, headers={})

    monkeypatch.setattr(hc, "_to_response", fake_to_response)

    r1 = hc.get("https://example.com/")
    r2 = hc.get("https://example.com/")
    r3 = hc.get("https://example.com/?x=1")

    assert r1.text == "body"
    assert calls == ["https://example.com/", "https://example.com/?x=1"]  # second identical was cached


def test_clear_cache(monkeypatch):
    hc.clear_cache()
    assert hc._CACHE == {}


def test_cache_key_distinguishes_params():
    assert hc._cache_key("GET", "https://x", {"a": 1}) != hc._cache_key("GET", "https://x", {"a": 2})
    assert hc._cache_key("GET", "https://x", {"a": 1, "b": 2}) == hc._cache_key("GET", "https://x", {"b": 2, "a": 1})
