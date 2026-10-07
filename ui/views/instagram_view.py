"""Instagram public-profile (target-scoped)."""
from __future__ import annotations

import streamlit as st

from osintmagic import get_sources

from .. import hub


def render(target: str, record: dict | None) -> None:
    st.subheader("Instagram")
    st.caption("Public profile fields via Instagram's public endpoint (no login).")
    hub.scoped_run(target, record, "username", "instagram", "Username", get_sources("instagram"))
