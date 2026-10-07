"""Tests for the entity graph + pivoting (pure logic, no network)."""
import osintmagic.graph as graph
from osintmagic.graph import (
    Edge,
    Entity,
    GraphResult,
    build_graph,
    classify_seed,
    classify_value,
    node_id,
)


def test_classify_seed():
    assert classify_seed("jane@doe.com") == "email"
    assert classify_seed("example.com") == "domain"
    assert classify_seed("+1 650 253 0000") == "phone"
    assert classify_seed("Jane Doe") == "name"
    assert classify_seed("johndoe") == "username"
    assert classify_seed("https://example.com/x") == "url"


def test_classify_value():
    assert classify_value("admin@example.com") == "email"
    assert classify_value("evil.com") == "domain"
    assert classify_value("8.8.8.8") == "ip"
    assert classify_value("johndoe") == "username"
    assert classify_value("not a real value!!") is None
    assert classify_value("") is None


def test_node_id():
    assert node_id("email", "a@b.com") == "email:a@b.com"


def test_graph_result_dedup():
    g = GraphResult(seed="x", depth=1)
    g.add_entity(Entity("email", "a@b.com", "s"))
    g.add_entity(Entity("email", "a@b.com", "other"))  # duplicate value -> same id
    assert len(g.nodes) == 1
    g.add_edge("email:a@b.com", "email:c@d.com", "linked")
    g.add_edge("email:a@b.com", "email:c@d.com", "linked")  # duplicate edge
    assert len(g.edges) == 1
    g.add_edge("email:a@b.com", "email:a@b.com", "self")  # self-loop dropped
    assert len(g.edges) == 1


def test_extract_entities():
    entities = graph._extract_entities("contact admin@example.com and see evil.com", "s", 0.5)
    types = {e.etype for e in entities}
    assert "email" in types
    assert "domain" in types


def test_pivot_name():
    entities, edges = graph._pivot_name("Jane Doe", False)
    values = {e.value for e in entities}
    assert "janedoe" in values                       # candidate username
    assert "janedoe@gmail.com" in values             # candidate email (first generated)
    labels = {e.label for e in edges}
    assert "candidate username" in labels
    assert "candidate email" in labels


def _fake_pivoters():
    return {
        "username": lambda v, deep, log=None: (
            [Entity("username", v + "_alt", "fake", 0.5)],
            [Edge(node_id("username", v), node_id("username", v + "_alt"), "variant")],
        ),
        "email": lambda v, deep, log=None: ([], []),
    }


def test_build_graph_depth_and_cap(monkeypatch):
    monkeypatch.setattr(graph, "_PIVOTERS", _fake_pivoters())
    # depth 1: seed -> one alt
    g = build_graph("johndoe", depth=1)
    assert len(g.nodes) == 2
    assert len(g.edges) == 1

    # depth 2: seed -> alt -> alt_alt (variant rule applies to the alt too)
    g2 = build_graph("johndoe", depth=2)
    assert len(g2.nodes) == 3
    assert len(g2.edges) == 2


def test_build_graph_respects_max_entities(monkeypatch):
    # A pivot that fans out widely.
    monkeypatch.setattr(graph, "_PIVOTERS", {
        "username": lambda v, deep: (
            [Entity("username", f"{v}_{i}", "fake", 0.5) for i in range(50)],
            [],
        ),
    })
    g = build_graph("seed", depth=1, max_entities=10)
    assert len(g.nodes) <= 10


def test_pivot_url_extracts_emails(monkeypatch):
    import osintmagic.http_client as hc
    from osintmagic.graph import _pivot_url

    html = "<html><body>contact admin@example.com or see evil-corp.com</body></html>"
    monkeypatch.setattr(hc, "get", lambda *a, **k: hc.HttpResponse(200, html, "https://profile.example/x", {}))
    entities, edges = _pivot_url(Entity("profile", "https://profile.example/x", "s"))
    values = {e.value for e in entities}
    assert "admin@example.com" in values
    assert "evil-corp.com" in values
    assert any(e.label == "exposed on page" for e in edges)


def test_exporters_roundtrip():
    from osintmagic.exporters.graph_export import to_csv_bytes, to_json_bytes
    g = GraphResult(seed="x", depth=1)
    g.add_entity(Entity("email", "a@b.com", "s"))
    g.add_entity(Entity("username", "joe", "s"))
    g.add_edge(node_id("email", "a@b.com"), node_id("username", "joe"), "candidate username")
    import json as _json
    payload = _json.loads(to_json_bytes(g))
    assert len(payload["nodes"]) == 2
    assert len(payload["edges"]) == 1
    csv = to_csv_bytes(g).decode("utf-8-sig")
    assert "candidate username" in csv
