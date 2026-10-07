"""Target hub: session state + target-scoped candidate resolution.

The single source of truth for the active target. Views call ``candidates`` to
derive their input from the target's seed and its *discovered* entities, which
is what makes the modules feel connected.
"""
from __future__ import annotations

import streamlit as st

from osintmagic import targets
from osintmagic.utils.validate import is_domain, is_username

_SS_TARGET = "active_target"


def get_target() -> str | None:
    return st.session_state.get(_SS_TARGET)


def set_target(seed: str) -> None:
    st.session_state[_SS_TARGET] = seed


def record() -> dict | None:
    seed = get_target()
    return targets.load_target(seed) if seed else None


def candidates(record: dict | None, etype: str) -> list[str]:
    """Values usable by a module of ``etype``, derived from the target."""
    if not record:
        return []
    seed = record.get("seed", "")
    seed_type = record.get("type", "")
    entities = record.get("entities", {})

    out: list[str] = []
    if seed_type == etype and seed:
        out.append(seed)

    for data in entities.values():
        if data.get("type") == etype:
            out.append(data["value"])

    # Light derivations across types.
    emails = [d["value"] for d in entities.values() if d.get("type") == "email"]
    if etype == "domain":
        for e in emails:
            if "@" in e and is_domain(e.split("@", 1)[1]):
                out.append(e.split("@", 1)[1])
        if seed_type == "email" and "@" in seed and is_domain(seed.split("@", 1)[1]):
            out.append(seed.split("@", 1)[1])
    if etype == "username":
        for e in emails:
            lp = e.split("@", 1)[0]
            if is_username(lp):
                out.append(lp)
        if seed_type == "email":
            lp = seed.split("@", 1)[0]
            if is_username(lp):
                out.append(lp)

    seen: set[str] = set()
    result: list[str] = []
    for v in out:
        v = v.strip()
        if v and v not in seen:
            seen.add(v)
            result.append(v)
    return result


def scoped_run(target: str, record: dict | None, etype: str, kind: str, label: str,
               sources=None, deepable: bool = False, fast_limit: int | None = None) -> str | None:
    """Render a target-scoped candidate picker + run. Returns the picked value.

    ``fast_limit`` (e.g. 15) adds a default-on "fast pass" that runs only the top
    sites; ``deepable`` adds a "deep scan" (vendored tools) toggle.
    """
    from .components import run_and_render

    cands = candidates(record, etype)
    if not cands:
        st.info(f"No {label.lower()} discovered for this target yet — run Overview or Graph first.")
        return None

    st.caption(f"Scoped to “{target}” — input comes from this target's data.")
    pick = st.selectbox(label, cands, key=f"pick_{kind}")

    srcs = list(sources) if sources is not None else []
    non_deep = [s for s in srcs if not s.deep]
    deep_srcs = [s for s in srcs if s.deep]

    deep = False
    fast = False
    if deepable and deep_srcs:
        deep = st.checkbox("Deep scan (slower)", key=f"deep_{kind}")
    if fast_limit and non_deep and not deep:
        fast = st.checkbox(f"Fast pass (top {fast_limit} sites)", value=True, key=f"fast_{kind}")

    if deep:
        chosen = deep_srcs
    elif fast:
        chosen = non_deep[:fast_limit]
    else:
        chosen = non_deep

    if st.button(f"Run {label.lower()} scan", key=f"run_{kind}"):
        run_and_render(chosen, pick, kind)
    return pick
