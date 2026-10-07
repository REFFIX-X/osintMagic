"""Tests for the watchlist diff logic."""
from osintmagic.watchlist import diff, snapshot


def _graph(nodes, edges=()):
    class G:
        seed = "x"
        nodes = {}
        edges = []
        def __init__(self, nodes, edges):
            from osintmagic.graph import Entity, Edge, node_id
            for etype, value in nodes:
                e = Entity(etype, value, "s")
                self.nodes[node_id(etype, value)] = e
            for s, d, l in edges:
                self.edges.append(Edge(s, d, l))
    return G(nodes, edges)


def test_diff_new_and_removed():
    old = snapshot(_graph([("username", "a"), ("email", "a@b.com")]))
    new = snapshot(_graph([("username", "a"), ("email", "a@b.com"), ("domain", "b.com")]))
    d = diff(old, new)
    assert "domain:b.com" in d["new_entities"]
    assert d["removed_entities"] == []


def test_diff_removed():
    old = snapshot(_graph([("username", "a"), ("username", "gone")]))
    new = snapshot(_graph([("username", "a")]))
    d = diff(old, new)
    assert "username:gone" in d["removed_entities"]
    assert d["new_entities"] == []


def test_diff_none_old_is_all_new():
    new = snapshot(_graph([("username", "a")]))
    d = diff(None, new)
    assert d["new_entities"] == ["username:a"]
