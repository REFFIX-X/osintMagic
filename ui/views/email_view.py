"""Email search (target-scoped)."""
from __future__ import annotations

import streamlit as st

from osintmagic import get_sources

from .. import hub


def render(target: str, record: dict | None) -> None:
    st.subheader("Email search")
    st.caption("Probe whether an address is registered; deep scan adds holehe.")
    hub.scoped_run(target, record, "email", "email", "Email",
                   get_sources("email"), deepable=True)
