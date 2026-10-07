"""API keys settings (optional — everything stays keyless by default)."""
from __future__ import annotations

import streamlit as st

from osintmagic import keys


def render() -> None:
    st.header("API keys")
    st.caption(
        "Keyless by default. Add a key to unlock the corresponding source "
        "(HIBP breach lookup, Shodan, VirusTotal, GitHub, numverify)."
    )
    st.warning("Keys are stored locally in `~/.osintmagic/keys.json` — never commit them.")

    with st.form("keys_form"):
        hibp = st.text_input(keys.KEY_LABELS["HIBP_API_KEY"], type="password",
                             value=keys.get_key("HIBP_API_KEY") or "", key="k_hibp")
        shodan = st.text_input(keys.KEY_LABELS["SHODAN_API_KEY"], type="password",
                               value=keys.get_key("SHODAN_API_KEY") or "", key="k_shodan")
        vt = st.text_input(keys.KEY_LABELS["VIRUSTOTAL_API_KEY"], type="password",
                           value=keys.get_key("VIRUSTOTAL_API_KEY") or "", key="k_vt")
        gh = st.text_input(keys.KEY_LABELS["GITHUB_TOKEN"], type="password",
                           value=keys.get_key("GITHUB_TOKEN") or "", key="k_gh")
        nv = st.text_input(keys.KEY_LABELS["NUMVERIFY_ACCESS_KEY"], type="password",
                           value=keys.get_key("NUMVERIFY_ACCESS_KEY") or "", key="k_nv")
        saved = st.form_submit_button("Save keys")

    if saved:
        keys.set_key("HIBP_API_KEY", hibp)
        keys.set_key("SHODAN_API_KEY", shodan)
        keys.set_key("VIRUSTOTAL_API_KEY", vt)
        keys.set_key("GITHUB_TOKEN", gh)
        keys.set_key("NUMVERIFY_ACCESS_KEY", nv)
        st.success("Saved. Keyed sources are now active where applicable.")
        st.rerun()

    st.markdown("**Active keys**")
    active = keys.key_names()
    if not active:
        st.info("No keys configured — all scans are keyless.")
    else:
        for name in active:
            st.markdown(f"• {keys.KEY_LABELS.get(name, name)}")

    if st.button("Clear all keys", key="clear_keys"):
        keys.clear_all()
        st.success("All keys cleared.")
        st.rerun()
