"""Dossier (target-scoped)."""
from __future__ import annotations

import streamlit as st

from osintmagic.dossier import build_dossier

from .. import hub
from ..components import download_buttons, make_live_log, render_result


def render(target: str, record: dict | None) -> None:
    st.subheader("Dossier")
    st.caption("Full external-recon workflow, correlated into phases with IOC + STIX export.")

    domains = hub.candidates(record, "domain")
    dom = domains[0] if domains else target
    st.caption(f"Target domain: {dom}")

    if st.button("Build dossier", key="dossier_build"):
        log = make_live_log()
        log(f"▶ dossier scan of “{dom}”")
        result = build_dossier(dom, log=log)
        log(f"✔ done in {result.duration:.1f}s")
        render_result(result)
        download_buttons(result, f"osintmagic_dossier_{dom}")
