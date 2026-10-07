"""Tests for exporters and the proxy env wiring."""
import os

from osintmagic.models import Finding, ScanResult, SourceResult


def _scan_result() -> ScanResult:
    r = ScanResult(target="example.com", kind="domain")
    r.results = [
        SourceResult("DNS Records", "domain", findings=[
            Finding("DNS Records", "domain", "info", detail={"type": "A", "value": "1.2.3.4"}),
            Finding("DNS Records", "domain", "info", detail={"type": "MX", "value": "0 ."}),
        ]),
        SourceResult("crt.sh", "domain", findings=[
            Finding("crt.sh", "domain", "found", url="https://www.example.com",
                    detail={"type": "subdomain", "provider": "crt.sh"}),
        ]),
    ]
    return r


def test_json_export_roundtrip():
    from osintmagic.exporters.json_export import to_json_bytes
    import json
    payload = json.loads(to_json_bytes(_scan_result()))
    assert payload["target"] == "example.com"
    assert payload["stats"]["found"] == 1
    assert len(payload["results"]) == 2


def test_csv_export_has_rows():
    from osintmagic.exporters.csv_export import to_csv_bytes
    text = to_csv_bytes(_scan_result()).decode("utf-8-sig")
    assert "example.com" in text
    assert "subdomain" in text
    assert "1.2.3.4" in text


def test_html_export_is_self_contained():
    from osintmagic.exporters.html_export import to_html_bytes
    html = to_html_bytes(_scan_result()).decode("utf-8")
    assert "<!DOCTYPE html>" in html
    assert "example.com" in html
    assert "A: 1.2.3.4" in html or "1.2.3.4" in html


def test_proxy_url_reads_env(monkeypatch):
    import osintmagic.http_client as hc
    monkeypatch.setenv("OSINTMAGIC_PROXY", "socks5://127.0.0.1:9050")
    assert hc.proxy_url() == "socks5://127.0.0.1:9050"
    monkeypatch.delenv("OSINTMAGIC_PROXY")
    assert hc.proxy_url() is None
