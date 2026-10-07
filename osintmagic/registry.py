"""Source catalog.

Sources register themselves at import time. ``get_sources(category)`` returns
instantiated sources so the engine and UI can iterate the catalog without
knowing the concrete classes. Adding a source is a single registration — no
UI or engine changes.
"""
from __future__ import annotations

from typing import Any

_REGISTRY: list[Any] = []


def source(category: str, name: str):
    """Class decorator: registers a no-arg-constructed instance of ``cls``."""

    def deco(cls):
        cls.category = category
        cls.name = name
        _REGISTRY.append(cls())
        return cls

    return deco


def register(instance: Any) -> Any:
    """Register an already-constructed source instance (data-driven sources)."""
    _REGISTRY.append(instance)
    return instance


def get_sources(category: str | None = None, active: bool = True) -> list[Any]:
    sources = _REGISTRY if category is None else [
        s for s in _REGISTRY if getattr(s, "category", None) == category
    ]
    if active:
        from . import keys
        sources = [
            s for s in sources
            if not getattr(s, "on_demand", False)
            and (not getattr(s, "key_name", None) or keys.has_key(s.key_name))
        ]
    return list(sources)


def all_sources() -> list[Any]:
    return list(_REGISTRY)
