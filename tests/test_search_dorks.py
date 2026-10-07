"""Tests for search-engine fan-out and dork generation."""
import osintmagic.sources.search as search_mod
from osintmagic.utils.permutations import domain_dorks, email_dorks, username_dorks


def test_domain_dorks_cover_intents():
    dorks = domain_dorks("example.com")
    joined = " ".join(dorks)
    assert any("filetype:pdf" in d for d in dorks)
    assert any("inurl:admin" in d for d in dorks)
    assert any("index of" in d for d in dorks)
    assert any("github.com" in d for d in dorks)
    assert any("pastebin.com" in d for d in dorks)
    assert len(dorks) >= 15


def test_username_and_email_dorks():
    assert any("github.com" in d for d in username_dorks("johndoe"))
    assert any("pastebin.com" in d for d in email_dorks("jane@doe.com"))


def test_search_all_dedup_and_skip_failing(monkeypatch):
    calls = []
    def fake_search(query, engine="ddg", timeout=12):
        calls.append(engine)
        if engine == "brave":
            raise search_mod.HttpError("blocked")
        if engine == "ddg":
            return [("https://a.example", "A"), ("https://shared.example", "Shared")]
        return [("https://shared.example", "Shared dup"), ("https://b.example", "B")]

    monkeypatch.setattr(search_mod, "search", fake_search)
    results = search_mod.search_all("q")
    urls = [u for u, _ in results]
    assert urls.count("https://shared.example") == 1  # deduped
    assert "https://a.example" in urls
    assert "https://b.example" in urls
    assert "brave" in calls  # attempted but failed gracefully


def test_search_raises_on_unknown_engine():
    import pytest
    with pytest.raises(KeyError):
        search_mod.search("q", engine="doesnotexist")
