"""Username search (target-scoped)."""
from __future__ import annotations

import streamlit as st

from osintmagic import get_sources

from .. import hub


def render(target: str, record: dict | None) -> None:
    st.subheader("Username search")
    st.caption("Check a handle across social, developer and media platforms.")
    hub.scoped_run(target, record, "username", "username", "Username",
                   get_sources("username"), deepable=True, fast_limit=15)
