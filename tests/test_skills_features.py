"""Tests for features added from the OSINT skill set."""
from collections import Counter

from osintmagic.email_headers import analyze_headers
from osintmagic.sources.brand import TyposquatSource
from osintmagic.sources.domain import _is_internal
from osintmagic.sources.paste import scan_for_credentials
from osintmagic.utils.iocs import defang, extract_iocs, result_to_iocs, to_stix
from osintmagic.utils.permutations import domain_permutations, levenshtein, similarity


# --- typosquat engine ---------------------------------------------------------

def test_domain_permutations_cover_core_techniques():
    pairs = dict((d, f) for d, f in domain_permutations("example.com"))
    fuzzers = set(pairs.values())
    for technique in ("omission", "transposition", "homoglyph", "tld-swap", "insertion", "replacement"):
        assert technique in fuzzers
    assert "exmple.com" in pairs          # omission
    assert "exmaple.com" in pairs         # transposition
    assert "example.net" in pairs         # tld-swap


def test_domain_permutations_exclude_original():
    assert all(d != "example.com" for d, _ in domain_permutations("example.com"))


def test_levenshtein_and_similarity():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("abc", "abc") == 0
    assert similarity("micr0soft.com", "microsoft.com") > 0.8
    assert similarity("example.com", "unrelated.org") < 0.5


def test_brand_risk_scoring():
    src = TyposquatSource()
    score, factors = src._score("homoglyph", ["1.2.3.4"], ["mail.evil.com"], {"9.9.9.9"})
    assert score >= 50
    assert any("MX" in f for f in factors)


# --- subdomain internal detection --------------------------------------------

def test_is_internal():
    assert _is_internal("10.0.0.5")
    assert _is_internal("192.168.1.1")
    assert not _is_internal("8.8.8.8")


# --- email headers ------------------------------------------------------------

_SAMPLE_HEADERS = """\
Received: from mail.attacker.example (mail.attacker.example [203.0.113.45])
\tby mx.victim.com with SMTP id abc123
Received: from relay.isp.example (relay.isp.example [198.51.100.9])
\tby mail.attacker.example with SMTP id xyz789
From: "CEO Name" <ceo@examp1e-corp.com>
Reply-To: payments.urgent@gmail.com
Return-Path: <bounce@mail-server.xyz>
Subject: Urgent: Invoice Payment Required
Date: Mon, 15 Jan 2024 09:23:45 +0000
Authentication-Results: mx.victim.com; spf=fail; dkim=none; dmarc=fail
Message-ID: <1234@mail-server.xyz>
"""


def test_email_header_analysis():
    result = analyze_headers(_SAMPLE_HEADERS)
    labels = {f.detail.get("type"): f.detail.get("value") for r in result.results for f in r.findings}
    assert labels.get("From/Reply-To mismatch")            # reply-to differs from from
    assert labels.get("Received hops") == 2
    assert labels.get("Mech SPF") == "fail"
    assert result.target == "Urgent: Invoice Payment Required"


def test_email_header_analysis_handles_junk():
    result = analyze_headers("not really an email header block")
    assert result.results[0].findings  # never empty


# --- paste scanning -----------------------------------------------------------

def test_scan_for_credentials():
    text = "user@corp.com:Passw0rd!  AKIAABCDEFGHIJKLMNOP  -----BEGIN RSA PRIVATE KEY-----"
    found = scan_for_credentials(text)
    assert "email:password" in found
    assert "aws_access_key" in found
    assert "private_key" in found


def test_scan_for_credentials_clean():
    assert scan_for_credentials("just some ordinary prose with no secrets") == {}


# --- IOC utilities ------------------------------------------------------------

def test_extract_iocs():
    text = "C2 at 185.220.101.42 and evil-domain.com, see https://bad.example/path and admin@evil.com hash a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
    iocs = extract_iocs(text)
    assert "185.220.101.42" in iocs["ipv4"]
    assert "evil-domain.com" in iocs["domain"]
    assert any("bad.example" in u for u in iocs["url"])
    assert "admin@evil.com" in iocs["email"]
    assert any(len(h) == 32 for h in iocs["hash"])


def test_defang():
    assert defang("https://evil.com/path") == "hxxps://evil[.]com/path"
    assert defang("user@evil.com") == "user[@]evil[.]com"


def test_result_to_iocs_and_stix():
    from osintmagic.models import Finding, ScanResult, SourceResult
    result = ScanResult(target="example.com", kind="domain")
    result.results = [SourceResult("s", "domain", findings=[
        Finding("s", "domain", "found", url="https://relay.evil.com/x"),
    ])]
    stix = to_stix(result)
    assert stix["type"] == "bundle"
    assert any(o["type"] == "indicator" for o in stix["objects"])
    assert any("relay.evil.com" in o["name"] for o in stix["objects"])
