"""Domain recon (target-scoped)."""
from __future__ import annotations

import html as _html

import streamlit as st

from osintmagic import get_sources
from osintmagic.utils.permutations import domain_dorks

from .. import hub


def render(target: str, record: dict | None) -> None:
    st.subheader("Domain recon")
    st.caption("Subdomains, DNS + email-auth posture, whois, zone transfer, buckets, WAF/CDN, tech, DNSSEC/SRV.")
    pick = hub.scoped_run(target, record, "domain", "domain", "Domain",
                          get_sources("domain"), deepable=True)
    if pick:
        st.subheader("Google dorks")
        st.markdown(
            '<div class="om-code">'
            + "<br>".join(_html.escape(d) for d in domain_dorks(pick))
            + "</div>",
            unsafe_allow_html=True,
        )
