"""Tests for infrastructure enrichment (subdomain -> IP -> ASN/geo)."""
from osintmagic.dossier import _subdomain_hosts, enrich_infrastructure
from osintmagic.models import Finding, ScanResult, SourceResult


def _result_with_subdomains():
    result = ScanResult(target="example.com", kind="dossier")
    result.results = [
        SourceResult("crt.sh", "domain", findings=[
            Finding("crt.sh", "domain", "found", url="https://www.example.com", detail={"type": "subdomain"}),
            Finding("crt.sh", "domain", "found", url="https://api.example.com", detail={"type": "subdomain"}),
            Finding("crt.sh", "domain", "info", url="https://example.com", detail={"type": "tech", "name": "nginx"}),
        ]),
    ]
    return result


def test_subdomain_hosts_extraction():
    hosts = _subdomain_hosts(_result_with_subdomains())
    assert hosts == ["api.example.com", "www.example.com"]


def test_enrich_infrastructure_no_subdomains():
    result = ScanResult(target="x", kind="dossier")
    result.results = [SourceResult("dns", "domain", findings=[
        Finding("dns", "domain", "info", detail={"type": "A", "value": "1.2.3.4"}),
    ])]
    infra = enrich_infrastructure(result)
    assert infra == {"rows": [], "asns": {}, "countries": {}, "total_subdomains": 0}


def test_enrich_infrastructure_resolves_and_geo(monkeypatch):
    # Monkeypatch the two network helpers to avoid real DNS + ipinfo calls.
    import osintmagic.dossier as dossier

    monkeypatch.setattr(dossier, "_resolve_host", lambda host: ["203.0.113.10"])
    monkeypatch.setattr(dossier, "_ipinfo", lambda ip: {
        "ip": ip, "org": "AS64500 Example Org", "city": "Testville",
        "region": "TestRegion", "country": "US", "loc": "37.77,-122.42",
    })

    infra = enrich_infrastructure(_result_with_subdomains())
    assert infra["total_subdomains"] == 2
    assert infra["asns"] == {"AS64500": 2}
    assert infra["countries"] == {"US": 2}
    rows = infra["rows"]
    assert len(rows) == 2
    assert rows[0]["lat"] == 37.77 and rows[0]["lon"] == -122.42
    assert rows[0]["org"] == "AS64500 Example Org"
