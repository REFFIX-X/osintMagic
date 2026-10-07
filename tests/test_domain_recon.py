"""Pure-logic tests for the recon sources added from the OSINT skill."""
from osintmagic.sources.domain import _auth_assessment, _bucket_names, _detect_tech, _detect_waf_cdn
from osintmagic.utils.permutations import domain_dorks


def test_bucket_names_include_domain_derived_variants():
    names = _bucket_names("example.com")
    assert "example" in names
    assert "example-com" in names
    assert "example-backup" in names
    assert "example-com-dev" in names
    assert len(names) == len(set(names))  # deduped


def test_bucket_names_for_subdomain_uses_first_label():
    names = _bucket_names("shop.example.com")
    assert "shop" in names
    assert "shop-example-com" in names


def test_detect_waf_cdn_cloudflare():
    assert _detect_waf_cdn({"cf-ray": "abc123"}) == ["Cloudflare"]
    assert _detect_waf_cdn({"x-vercel-id": "x"}) == ["Vercel"]


def test_detect_waf_cdn_from_server_header():
    assert "nginx" in _detect_waf_cdn({"server": "nginx/1.25.3"})
    assert "Cloudflare" in _detect_waf_cdn({"server": "cloudflare"})


def test_detect_waf_cdn_none():
    assert _detect_waf_cdn({"content-type": "text/html"}) == []


def test_detect_tech_body_markers():
    assert "WordPress" in _detect_tech({}, '<link href="/wp-content/themes/x.css">')
    assert "Next.js" in _detect_tech({}, "window.__NEXT_DATA__ = {}")
    assert "Shopify" in _detect_tech({}, "//cdn.shopify.com/s/files/x.js")


def test_detect_tech_headers():
    assert "ASP.NET" in _detect_tech({"x-aspnet-version": "4.0"}, "")
    assert "Drupal" in _detect_tech({"x-drupal-cache": "HIT"}, "")


def test_detect_tech_none():
    assert _detect_tech({"content-type": "text/html"}, "<html><body>hi</body></html>") == []


def test_auth_assessment():
    assert "present" in _auth_assessment(True, True)
    assert "DMARC missing" in _auth_assessment(True, False)
    assert "no SPF or DMARC" in _auth_assessment(False, False)


def test_domain_dorks():
    dorks = domain_dorks("example.com")
    assert any(d == "site:example.com" for d in dorks)
    assert any("filetype:pdf" in d for d in dorks)
    assert any("inurl:admin" in d for d in dorks)
    assert any("pastebin.com" in d for d in dorks)
