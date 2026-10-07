"""Overview dashboard — the connected-dots landing for a target."""
from __future__ import annotations

import streamlit as st

from osintmagic import targets
from osintmagic.exporters.graph_export import (
    NODE_COLORS,
    to_csv_bytes,
    to_graphviz_dot,
    to_json_bytes,
    to_pyvis_html,
)
from osintmagic.graph import GraphResult

from ..components import make_live_log


def _record_to_graph(record: dict) -> GraphResult:
    from osintmagic.graph import Edge, Entity

    g = GraphResult(seed=record.get("seed", ""), depth=0)
    for nid, data in (record.get("entities") or {}).items():
        g.nodes[nid] = Entity(data["type"], data["value"], data.get("source", ""))
    for e in (record.get("edges") or []):
        g.edges.append(Edge(e["src"], e["dst"], e["label"]))
    return g


def render(target: str, record: dict | None) -> None:
    st.subheader("Overview")

    if not record:
        st.info("Run the first scan to build this target's picture.")
        if st.button("Run full OSINT", key="ov_first"):
            log = make_live_log()
            targets.run_and_merge(target, depth=2, log=log)
            st.rerun()
        return

    counts: dict[str, int] = {}
    for d in record.get("entities", {}).values():
        counts[d["type"]] = counts.get(d["type"], 0) + 1
    chips = "".join(
        f'<span class="om-entity-chip" style="color:{NODE_COLORS.get(t, "#727072")};'
        f'border-color:{NODE_COLORS.get(t, "#727072")}55;background:{NODE_COLORS.get(t, "#727072")}1a">'
        f'{t} {n}</span>'
        for t, n in sorted(counts.items())
    )
    st.markdown(chips, unsafe_allow_html=True)

    c1, c2 = st.columns([1, 1])
    with c1:
        if st.button("Run full OSINT (deepen)", key="ov_run"):
            log = make_live_log()
            _, new = targets.run_and_merge(target, depth=2, log=log)
            st.success(f"{len(new)} new entities found.")
            st.rerun()
    with c2:
        if st.button("Delete target", key="ov_del"):
            from pathlib import Path

            from .. import hub
            Path(targets._path(target)).unlink(missing_ok=True)
            st.session_state.pop(hub._SS_TARGET, None)
            st.rerun()

    graph = _record_to_graph(record)
    html = to_pyvis_html(graph)
    if html:
        st.components.v1.html(html, height=560, scrolling=True)
    else:
        st.graphviz_chart(to_graphviz_dot(graph))

    iocs = record.get("iocs") or {}
    if any(iocs.values()):
        st.markdown("**Indicators**")
        st.markdown(
            '<div class="om-code">'
            + "<br>".join(f"{k}: {v}" for k, vals in iocs.items() for v in vals[:10])
            + "</div>",
            unsafe_allow_html=True,
        )

    history = record.get("history") or []
    if len(history) > 1:
        st.caption(f"{len(history)} runs recorded — new entities accumulate.")

    c1, c2 = st.columns(2)
    with c1:
        st.download_button("Download graph JSON", to_json_bytes(graph),
                           file_name=f"osintmagic_{target}_graph.json", mime="application/json")
    with c2:
        st.download_button("Download graph CSV", to_csv_bytes(graph),
                           file_name=f"osintmagic_{target}_graph.csv", mime="text/csv")
