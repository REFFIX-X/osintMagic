"""Watchlist: monitor targets over time.

Snapshots a target's discovered entity graph, persists it to a local JSON file,
and diffs a fresh scan against the last snapshot to surface what's NEW.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .graph import node_id

_STORE = Path.home() / ".osintmagic" / "watchlist.json"


def _load() -> dict:
    if not _STORE.exists():
        return {}
    try:
        return json.loads(_STORE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    _STORE.parent.mkdir(parents=True, exist_ok=True)
    _STORE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def snapshot(graph) -> dict:
    return {
        "seed": graph.seed,
        "at": time.time(),
        "entities": sorted(node_id(e.etype, e.value) for e in graph.nodes.values()),
        "edges": sorted((e.src, e.dst, e.label) for e in graph.edges),
    }


def list_targets() -> list[dict]:
    out = []
    for name, snap in _load().items():
        out.append({
            "name": name,
            "seed": snap.get("seed"),
            "at": snap.get("at"),
            "entities": len(snap.get("entities", [])),
        })
    return sorted(out, key=lambda r: r["name"])


def save_target(name: str, graph) -> None:
    data = _load()
    data[name] = snapshot(graph)
    _save(data)


def remove_target(name: str) -> None:
    data = _load()
    data.pop(name, None)
    _save(data)


def diff(old: dict | None, new: dict) -> dict:
    old_ents = set(old.get("entities", [])) if old else set()
    new_ents = set(new.get("entities", []))
    old_edges = {tuple(e) for e in (old.get("edges", []) if old else [])}
    new_edges = {tuple(e) for e in new.get("edges", [])}
    return {
        "new_entities": sorted(new_ents - old_ents),
        "removed_entities": sorted(old_ents - new_ents),
        "new_edges": sorted(new_edges - old_edges),
    }


def rescan_target(name: str, graph) -> dict:
    data = _load()
    old = data.get(name)
    new = snapshot(graph)
    data[name] = new
    _save(data)
    return diff(old, new)
