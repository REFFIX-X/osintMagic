"""Leaks & pastes (target-scoped)."""
from __future__ import annotations

import streamlit as st

from osintmagic.engine import run_scan
from osintmagic.sources.leaks import LeaksSource

from .. import hub
from ..components import download_buttons, render_result


def render(target: str, record: dict | None) -> None:
    st.subheader("Leaks & pastes")
    st.caption("Paste/leak mentions + credential-pattern scanning.")

    options: dict[str, tuple[str, str]] = {}
    for etype in ("domain", "email", "username", "phone"):
        for v in hub.candidates(record, etype):
            options[f"{v} · {etype}"] = (v, etype)
    if not options:
        st.info("No entities discovered yet — run Overview first.")
        return

    label = st.selectbox("Entity", list(options.keys()), key="leak_pick")
    val, etype = options[label]
    if st.button("Search for leaks", key="leak_run"):
        result = run_scan([LeaksSource(etype)], val, kind="leaks")
        render_result(result)
        download_buttons(result, f"osintmagic_leaks_{etype}_{val}")
