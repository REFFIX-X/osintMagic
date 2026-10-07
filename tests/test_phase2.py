"""Tests for Phase 2 additions (phone, people-search, Instagram)."""
import json

from osintmagic.http_client import HttpResponse
from osintmagic.utils.permutations import people_search_links, phone_dorks
from osintmagic.utils.validate import is_phone


def test_is_phone():
    assert is_phone("+1 202 555 0100")
    assert is_phone("202-555-0100")
    assert not is_phone("not a phone")
    assert not is_phone("123")


def test_phone_dorks():
    dorks = phone_dorks("+1 202 555 0100")
    assert any("202" in d for d in dorks)
    assert any("site:facebook.com" in d for d in dorks)


def test_people_search_links():
    links = people_search_links("Jane", "Doe", "Jane Doe")
    labels = [label for label, _ in links]
    urls = [url for _, url in links]
    assert "FamilyTreeNow" in labels
    assert any("jane" in u.lower() for u in urls)
    assert all(u.startswith("http") for u in urls)


def _ig_resp(status=200, body=""):
    return HttpResponse(status_code=status, text=body, url="https://i.instagram.com/api/v1/users/web_profile_info/?username=x", headers={})


def test_instagram_not_found(monkeypatch):
    import osintmagic.sources.instagram as ig

    monkeypatch.setattr(ig, "get", lambda *a, **k: _ig_resp(404))
    sr = ig.InstagramSource().check("nonexistent_user_zzq")
    assert sr.findings[0].status == "not_found"


def test_instagram_found(monkeypatch):
    import osintmagic.sources.instagram as ig

    body = json.dumps({
        "data": {"user": {
            "username": "test", "full_name": "Test User", "biography": "bio",
            "external_url": "https://example.com", "is_private": False,
            "is_verified": True, "category_name": "Public Figure",
            "edge_followed_by": {"count": 100}, "edge_follow": {"count": 50},
            "edge_owner_to_timeline_media": {"count": 10},
            "profile_pic_url": "https://x/pic.jpg",
        }}
    })
    monkeypatch.setattr(ig, "get", lambda *a, **k: _ig_resp(200, body))
    sr = ig.InstagramSource().check("test")
    f = sr.findings[0]
    assert f.status == "found"
    assert f.detail["full_name"] == "Test User"
    assert f.detail["followers"] == 100
    assert f.url == "https://www.instagram.com/test/"


def test_instagram_rate_limited(monkeypatch):
    import osintmagic.sources.instagram as ig

    monkeypatch.setattr(ig, "get", lambda *a, **k: _ig_resp(429, "<html>blocked</html>"))
    sr = ig.InstagramSource().check("test")
    assert sr.error  # non-JSON -> error
