from osintmagic.models import Finding, ScanResult, SourceResult


def _f(**detail):
    return Finding(source="S", category="c", status="info", detail=detail)


def test_label_type_and_value():
    assert _f(type="A", value="1.2.3.4").label() == "A: 1.2.3.4"


def test_label_type_only():
    assert _f(type="Email auth posture").label() == "Email auth posture"


def test_label_uses_name_and_provider():
    assert _f(type="tech", name="WordPress").label() == "tech: WordPress"
    assert _f(type="waf_cdn", provider="Cloudflare").label() == "waf_cdn: Cloudflare"


def test_label_falls_back_to_source():
    assert Finding(source="DNS Records", category="c", status="info").label() == "DNS Records"


def test_extras_excludes_label_fields():
    f = _f(type="bucket", provider="s3", access="private", ownership="unconfirmed")
    assert f.extras() == {"access": "private", "ownership": "unconfirmed"}


def test_scan_stats_counts_all_statuses():
    result = ScanResult(target="t", kind="k")
    result.results = [
        SourceResult("s1", "k", findings=[
            Finding("s1", "k", "found"),
            Finding("s1", "k", "not_found"),
        ]),
        SourceResult("s2", "k", findings=[Finding("s2", "k", "info")], error=None),
    ]
    stats = result.stats()
    assert stats["found"] == 1
    assert stats["not_found"] == 1
    assert stats["info"] == 1
    assert stats["sources"] == 2
