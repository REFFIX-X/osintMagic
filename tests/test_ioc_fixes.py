"""Regression tests for IOC-extraction and STIX fixes."""
from osintmagic.utils.iocs import defang, extract_iocs, to_stix


def test_domain_not_dropped_when_inside_email():
    iocs = extract_iocs("contact bob@attack.com — see attack.com")
    assert "attack.com" in iocs["domain"]


def test_url_trailing_punctuation_stripped():
    iocs = extract_iocs("visit https://example.com/path, then leave.")
    assert "https://example.com/path" in iocs["url"]


def test_hash_not_all_digits():
    iocs = extract_iocs("account number 1234567890123456789012345678901234567890")
    assert iocs["hash"] == []


def test_hash_recognizes_sha256():
    iocs = extract_iocs("sha256 deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    assert iocs["hash"] == ["deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]


def test_stix_hash_algo_by_length():
    from osintmagic.models import Finding, ScanResult, SourceResult
    r = ScanResult(target="t", kind="k")
    r.results = [SourceResult("s", "k", findings=[
        Finding("s", "k", "found", detail={"type": "x", "value": "a" * 32}),
    ])]
    bundle = to_stix(r)
    patterns = [o["pattern"] for o in bundle["objects"] if "file:hashes" in o["pattern"]]
    assert patterns, "hash indicator missing"
    assert "MD5" in patterns[0]
    assert all(o["valid_from"] for o in bundle["objects"])


def test_stix_valid_from_is_real_timestamp():
    from osintmagic.models import Finding, ScanResult, SourceResult
    r = ScanResult(target="t", kind="k")
    r.results = [SourceResult("s", "k", findings=[
        Finding("s", "k", "found", detail={"type": "x", "value": "1.2.3.4"}),
    ])]
    for o in to_stix(r)["objects"]:
        assert o["valid_from"].endswith("Z")
