"""Per-target OSINT persistence.

A "target" is a person / organization / entity identified by a seed. Everything
discovered for it — the entity graph, indicators, and a run history — is
accumulated and persisted to ``~/.osintmagic/targets/`` so re-runs add to (and
never lose) what you already know.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from .graph import build_graph, classify_seed
from .utils.iocs import extract_iocs

_DIR = Path.home() / ".osintmagic" / "targets"


def _slug(seed: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", seed.lower()).strip("-")[:64] or "target"


def _path(seed: str) -> Path:
    return _DIR / f"{_slug(seed)}.json"


def list_targets() -> list[dict]:
    out = []
    if not _DIR.exists():
        return out
    for p in sorted(_DIR.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        out.append({
            "seed": data.get("seed"),
            "type": data.get("type"),
            "entities": len(data.get("entities", {})),
            "updated": data.get("updated"),
        })
    return sorted(out, key=lambda r: r["seed"])


def load_target(seed: str) -> dict | None:
    p = _path(seed)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def save_target(seed: str, record: dict) -> None:
    _DIR.mkdir(parents=True, exist_ok=True)
    record["updated"] = time.time()
    _path(seed).write_text(json.dumps(record, indent=2), encoding="utf-8")


def _graph_iocs(graph) -> dict[str, list[str]]:
    text = " ".join(e.value for e in graph.nodes.values())
    return extract_iocs(text)


def run_and_merge(seed: str, depth: int = 2, max_entities: int = 80, log=None, progress=None) -> tuple[dict, list[str]]:
    """Run full OSINT on a seed, merge into the persisted target, return (record, new_entity_ids)."""
    graph = build_graph(seed, depth=depth, max_entities=max_entities, log=log, progress=progress)

    existing = load_target(seed) or {}
    old_ids = set(existing.get("entities", {}).keys())
    new_ids = [nid for nid in graph.nodes if nid not in old_ids]

    # Union of entities (old kept, new added).
    entities = dict(existing.get("entities", {}))
    for nid, e in graph.nodes.items():
        entities[nid] = {"type": e.etype, "value": e.value, "source": e.source}

    # Union of edges too — a re-run at lower depth must not drop known links.
    edge_map: dict[tuple, dict] = {
        (x["src"], x["dst"], x["label"]): x for x in existing.get("edges", [])
    }
    for e in graph.edges:
        edge_map.setdefault((e.src, e.dst, e.label), {"src": e.src, "dst": e.dst, "label": e.label})
    edges = list(edge_map.values())

    # Union of IOCs across runs.
    old_iocs = existing.get("iocs", {})
    new_iocs = _graph_iocs(graph)
    iocs = {k: sorted(set(old_iocs.get(k, [])) | set(new_iocs.get(k, [])))
            for k in set(old_iocs) | set(new_iocs)}

    record = {
        "seed": seed,
        "type": classify_seed(seed),
        "entities": entities,
        "edges": edges,
        "iocs": iocs,
        "history": existing.get("history", []) + [{
            "at": time.time(),
            "new_entities": new_ids,
        }],
    }
    save_target(seed, record)
    return record, new_ids
