"""Phone lookup — intelligent freeform input, target-scoped + standalone."""
from __future__ import annotations

import html as _html

import streamlit as st

from osintmagic import get_sources
from osintmagic.utils.permutations import phone_dorks
from osintmagic.utils.phone import normalize_phone, phone_directories

from .. import hub
from ..components import run_and_render


def render(target: str, record: dict | None) -> None:
    st.subheader("Phone lookup")
    st.caption(
        "Intelligent parsing — accepts +45 61608441, 004561608441, or “Denmark 61608441”. "
        "Runs number info, Facebook-breach check, carrier + SMS gateway, and dorks."
    )

    discovered = hub.candidates(record, "phone")
    if discovered:
        st.caption("Discovered for this target: " + ", ".join(discovered))

    with st.form("phone_form"):
        raw = st.text_input(
            "Phone number", key="phone_input",
            placeholder="+45 61608441 · 004561608441 · Denmark 61608441",
            value=discovered[0] if discovered else "",
        )
        submitted = st.form_submit_button("Lookup phone")

    if submitted:
        value = raw.strip()
        if not value:
            st.error("Enter a phone number.")
            return

        norm = normalize_phone(value)
        if not norm:
            st.error(
                "Couldn't parse that number. Include a country code (+45), an international "
                "prefix (0045), or a country name (Denmark)."
            )
            return

        e164 = norm["e164"]
        st.success(f"Detected: {e164} ({norm['country'] or norm['region'] or 'unknown'})")

        run_and_render(get_sources("phone"), e164, "phone")

        st.subheader("Reverse-lookup directories")
        st.markdown(
            "".join(
                f'<a class="om-link" href="{_html.escape(url)}" target="_blank" rel="noopener">'
                f'<span class="om-chip">{_html.escape(label)}</span></a> '
                for label, url in phone_directories(e164)
            ),
            unsafe_allow_html=True,
        )

        st.subheader("Google dorks")
        st.markdown(
            '<div class="om-code">'
            + "<br>".join(_html.escape(d) for d in phone_dorks(e164))
            + "</div>",
            unsafe_allow_html=True,
        )
