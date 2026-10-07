"""Dark web (target-scoped)."""
from __future__ import annotations

import streamlit as st

from osintmagic.engine import run_scan
from osintmagic.sources.tor import AhmiaSearchSource, TorCrawlSource

from .. import hub
from ..components import download_buttons, render_result


def render(target: str, record: dict | None) -> None:
    st.subheader("Dark web")
    st.warning("OPSEC: browse .onion only from an isolated environment, never with organizational identity.")

    domains = hub.candidates(record, "domain")
    q = domains[0] if domains else target

    if st.button("Search Ahmia", key="ahmia_run"):
        result = run_scan([AhmiaSearchSource()], q, kind="ahmia")
        render_result(result)
        download_buttons(result, f"osintmagic_ahmia_{q}")

    url = st.text_input(".onion URL (optional)", key="tor_url", placeholder="http://xxxx.onion")
    if st.button("Crawl .onion", key="tor_run") and url.strip():
        result = run_scan([TorCrawlSource()], url.strip(), kind="tor")
        render_result(result)
        download_buttons(result, "osintmagic_tor_crawl")
