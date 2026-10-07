"""IP recon (target-scoped)."""
from __future__ import annotations

import streamlit as st

from osintmagic import get_sources

from .. import hub


def render(target: str, record: dict | None) -> None:
    st.subheader("IP recon")
    st.caption("Geolocation, ISP/ASN, RDAP network info, reverse DNS.")
    hub.scoped_run(target, record, "ip", "ip", "IP", get_sources("ip"))
