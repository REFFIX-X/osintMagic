"""Graph (target-scoped)."""
from __future__ import annotations

import streamlit as st

from osintmagic.exporters.graph_export import (
    to_csv_bytes,
    to_graphviz_dot,
    to_json_bytes,
    to_pyvis_html,
)
from osintmagic.graph import build_graph

from ..components import make_live_log


def render(target: str, record: dict | None) -> None:
    st.subheader("Graph")
    st.caption("Pivot from this target across every source into a connected entity graph.")

    depth = st.slider("Pivot depth", 1, 3, 2, key="g_depth")
    deep = st.checkbox("Deep tools (holehe / maigret / amass — slower)", key="g_deep")

    if st.button("Build graph", key="g_build"):
        log = make_live_log()
        log(f"▶ building graph from “{target}” (depth {depth})")
        graph = build_graph(target, depth=depth, deep=deep, max_entities=80, log=log)
        log(f"✔ {len(graph.nodes)} entities, {len(graph.edges)} links")

        html = to_pyvis_html(graph)
        if html:
            st.components.v1.html(html, height=600, scrolling=True)
        else:
            st.graphviz_chart(to_graphviz_dot(graph))

        c1, c2 = st.columns(2)
        with c1:
            st.download_button("JSON", to_json_bytes(graph),
                               file_name=f"osintmagic_{target}_graph.json", mime="application/json")
        with c2:
            st.download_button("CSV", to_csv_bytes(graph),
                               file_name=f"osintmagic_{target}_graph.csv", mime="text/csv")
