"""Tests for the target-hub candidate resolution (pure logic)."""
from ui.hub import candidates


def _record(seed, seed_type, entities):
    return {"seed": seed, "type": seed_type, "entities": entities}


def test_candidates_seed_is_type():
    r = _record("johndoe", "username", {})
    assert candidates(r, "username") == ["johndoe"]


def test_candidates_from_discovered_entities():
    r = _record("jane@doe.com", "email", {
        "domain:doe.com": {"type": "domain", "value": "doe.com", "source": "s"},
        "username:jane": {"type": "username", "value": "jane", "source": "s"},
    })
    assert "doe.com" in candidates(r, "domain")
    assert "jane" in candidates(r, "username")


def test_candidates_derives_email_domain_and_localpart():
    r = _record("jane@doe.com", "email", {})
    # email -> domain and email -> username localpart derivations
    assert "doe.com" in candidates(r, "domain")
    assert "jane" in candidates(r, "username")


def test_candidates_dedupes_and_orders():
    r = _record("example.com", "domain", {
        "domain:example.com": {"type": "domain", "value": "example.com", "source": "s"},
    })
    assert candidates(r, "domain") == ["example.com"]


def test_candidates_empty_record():
    assert candidates(None, "domain") == []
