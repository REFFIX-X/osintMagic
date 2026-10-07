"""Tests for key storage and active-source filtering."""
import osintmagic.keys as keys
from osintmagic import get_sources


def test_key_set_get_clear(tmp_path, monkeypatch):
    monkeypatch.setattr(keys, "_PATH", tmp_path / "keys.json")
    assert keys.get_key("HIBP_API_KEY") is None
    keys.set_key("HIBP_API_KEY", "  secret123  ")
    assert keys.get_key("HIBP_API_KEY") == "secret123"
    keys.set_key("HIBP_API_KEY", "")
    assert keys.get_key("HIBP_API_KEY") is None


def test_keyed_source_filtered_by_key(monkeypatch):
    # No keys -> HIBP excluded from the email category.
    monkeypatch.setattr(keys, "has_key", lambda name: False)
    email_names = [s.name for s in get_sources("email")]
    assert "HIBP breach" not in email_names

    # Key present -> HIBP included.
    monkeypatch.setattr(keys, "has_key", lambda name: name == "HIBP_API_KEY")
    email_names = [s.name for s in get_sources("email")]
    assert "HIBP breach" in email_names


def test_keyed_source_reports_no_key(monkeypatch):
    monkeypatch.setattr(keys, "has_key", lambda name: False)
    # Instantiate the source directly (bypasses registry filtering).
    from osintmagic.sources.hibp import HibpBreachSource
    sr = HibpBreachSource().check("x@example.com")
    assert sr.error == "no HIBP API key"
