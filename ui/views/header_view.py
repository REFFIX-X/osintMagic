"""Email header analysis (target-agnostic tool)."""
from __future__ import annotations

import streamlit as st

from osintmagic.email_headers import analyze_headers

from ..components import download_buttons, render_result


def render(target: str, record: dict | None) -> None:
    st.subheader("Email header analysis")
    st.caption("Paste raw headers to trace the delivery chain and read SPF/DKIM/DMARC.")

    with st.form("header_form"):
        raw = st.text_area("Raw email headers", height=240, key="hdr_input",
                           placeholder="Delivered-To: you@example.com\nReceived: from ...\nFrom: ...")
        submitted = st.form_submit_button("Analyze headers")

    if submitted:
        if not raw.strip():
            st.error("Paste some headers first.")
            return
        result = analyze_headers(raw)
        render_result(result)
        download_buttons(result, "osintmagic_email_headers")
