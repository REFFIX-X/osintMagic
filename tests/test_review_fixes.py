"""Regression tests for defects found in the full-code review."""
from osintmagic.engine import run_scan
from osintmagic.models import Finding, ScanResult, SourceResult


# --- engine: duplicate source instances must not crash -----------------------

def test_engine_handles_duplicate_source_instances():
    class Ok:
        name = "ok"
        category = "test"
        deep = False

        def check(self, target):
            return SourceResult(source="ok", category="test", findings=[
                Finding("ok", "test", "found")])

    src = Ok()
    result = run_scan([src, src], "t", kind="test")   # same object twice
    assert len(result.results) == 2


# --- phone: the "phone_info" discriminator must survive ----------------------

def test_phone_detail_type_not_clobbered():
    from osintmagic.sources.phone import PhoneInfoSource
    sr = PhoneInfoSource().check("+1 650 253 0000")
    if sr.error:
        return  # libphonenumber unavailable in this env
    d = sr.findings[0].detail
    assert d["type"] == "phone_info"          # not overwritten by number type
    assert "number_type" in d


# --- dossier: mixed-case finding types must classify as infrastructure -------

def test_dossier_classifies_uppercase_infra_types():
    from osintmagic.dossier import PHASES, classify_finding
    for t in ("AXFR", "DNSSEC", "SRV", "PTR", "CT issuers"):
        f = Finding("Zone Transfer (AXFR)", "domain", "info", detail={"type": t})
        assert classify_finding(f) == PHASES[0], t


# --- targets: re-runs union edges instead of dropping them -------------------

def test_targets_union_edges(monkeypatch, tmp_path):
    import osintmagic.targets as targets

    monkeypatch.setattr(targets, "_DIR", tmp_path)
    seed = "unioned"
    # pre-seed a stored edge, then merge a graph that lacks it
    targets.save_target(seed, {
        "seed": seed, "type": "username", "entities": {},
        "edges": [{"src": "a", "dst": "b", "label": "old"}],
        "iocs": {"domain": ["keep.com"]}, "history": [],
    })

    from osintmagic.graph import Edge, Entity, GraphResult

    class FakeGraph(GraphResult):
        pass

    g = GraphResult(seed=seed, depth=1)
    g.add_entity(Entity("username", seed, "s"))
    g.edges.append(Edge("username:" + seed, "domain:x.com", "new"))

    monkeypatch.setattr(targets, "build_graph", lambda *a, **k: g)
    record, _ = targets.run_and_merge(seed, depth=1)

    labels = {e["label"] for e in record["edges"]}
    assert "old" in labels and "new" in labels      # both preserved
    assert "keep.com" in record["iocs"]["domain"]   # iocs unioned


# --- search: all-engines-failed raises ---------------------------------------

def test_search_all_raises_when_all_fail(monkeypatch):
    import osintmagic.sources.search as search
    import pytest

    def boom(query, engine="ddg", timeout=12):
        raise search.HttpError("blocked")

    monkeypatch.setattr(search, "search", boom)
    with pytest.raises(search.HttpError):
        search.search_all("q")


# --- instagram: {"data": null} must not crash --------------------------------

def test_instagram_null_data(monkeypatch):
    import json
    import osintmagic.sources.instagram as ig
    from osintmagic.http_client import HttpResponse

    monkeypatch.setattr(ig, "get", lambda *a, **k: HttpResponse(
        status_code=200, text=json.dumps({"data": None}), url="https://x", headers={}))
    sr = ig.InstagramSource().check("ghost")
    assert sr.error  # degrades cleanly, no AttributeError


# --- views: leak/darkweb must build a ScanResult, not pass a SourceResult ----

def test_leaks_source_is_source_result(monkeypatch):
    import osintmagic.sources.leaks as leaks
    monkeypatch.setattr(leaks, "search_all", lambda *a, **k: [])
    assert isinstance(leaks.LeaksSource("domain").check("x"), SourceResult)
