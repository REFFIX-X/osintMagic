"""Typosquat / brand-impersonation (target-scoped)."""
from __future__ import annotations

import streamlit as st

from osintmagic import get_sources

from .. import hub


def render(target: str, record: dict | None) -> None:
    st.subheader("Typosquat / brand impersonation")
    st.caption("Generate lookalike domains and resolve the registered ones, risk-scored.")
    hub.scoped_run(target, record, "domain", "brand", "Domain", get_sources("brand"))
