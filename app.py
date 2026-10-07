"""osintMagic — Streamlit entry point (target-hub UI)."""
from __future__ import annotations

import html as _html
import os

import streamlit as st

st.set_page_config(page_title="osintMagic", layout="wide", initial_sidebar_state="expanded")

from osintmagic import targets
from osintmagic.exporters.graph_export import NODE_COLORS
from ui import hub
from ui.theme import apply_theme
from ui.views import (
    darkweb_view,
    domain_view,
    dossier_view,
    email_view,
    graph_view,
    header_view,
    instagram_view,
    ip_view,
    leaks_view,
    overview_view,
    person_view,
    phone_view,
    settings_view,
    typosquat_view,
    username_view,
)

apply_theme()

# --- sidebar: target hub + proxy -------------------------------------------
st.sidebar.title("osintMagic")
st.sidebar.caption("Target hub")

with st.sidebar.form("new_target"):
    new_seed = st.text_input("New target", placeholder="email / username / domain / phone / name")
    created = st.form_submit_button("Create & scan")
if created and new_seed.strip():
    hub.set_target(new_seed.strip())
    st.session_state["pending_scan"] = new_seed.strip()
    st.rerun()

st.sidebar.markdown("**Targets**")
for t in targets.list_targets():
    active = t["seed"] == hub.get_target()
    label = ("● " if active else "○ ") + t["seed"]
    if st.sidebar.button(label, key=f"tgt_{t['seed']}"):
        hub.set_target(t["seed"])
        st.rerun()

proxy = st.sidebar.text_input(
    "Proxy (optional)", key="proxy_input",
    placeholder="socks5://127.0.0.1:9050 or http://127.0.0.1:8080",
)
if proxy.strip():
    os.environ["OSINTMAGIC_PROXY"] = proxy.strip()
else:
    os.environ.pop("OSINTMAGIC_PROXY", None)

if st.sidebar.checkbox("Settings (API keys)", key="show_settings"):
    settings_view.render()
    st.stop()

# --- main -------------------------------------------------------------------
target = hub.get_target()

if not target:
    st.markdown(
        '<div class="om-hero"><h1>osintMagic</h1>'
        '<div class="om-sub">Create a target to begin an investigation — one seed, every module.</div></div>',
        unsafe_allow_html=True,
    )
    with st.form("hero_target"):
        hseed = st.text_input("Target", placeholder="email / username / domain / phone / name")
        hsubmit = st.form_submit_button("Begin investigation")
    if hsubmit and hseed.strip():
        hub.set_target(hseed.strip())
        st.session_state["pending_scan"] = hseed.strip()
        st.rerun()
    st.stop()

# --- first scan: stream a live log so the analyst sees exactly what runs -----
pending = st.session_state.pop("pending_scan", None)
if pending and pending == target:
    from ui.components import make_live_log

    st.subheader(f"Scanning “{target}”…")
    log = make_live_log()
    log(f"▶ starting full OSINT for target “{target}” (depth 1)")
    bar = st.progress(0.0)
    rec, new_ids = targets.run_and_merge(
        target, depth=1, log=log,
        progress=lambda done, total: bar.progress(min(done / total, 1.0)),
    )
    bar.empty()
    log(f"✔ scan complete — {len(rec['entities'])} entities, {len(rec['edges'])} links, {len(new_ids)} new")
    st.success(f"Target “{target}” created — {len(rec['entities'])} entities discovered. Deepen anytime from Overview.")

record = hub.record()

counts: dict[str, int] = {}
for d in (record or {}).get("entities", {}).values():
    counts[d["type"]] = counts.get(d["type"], 0) + 1
chips = "".join(
    f'<span class="om-entity-chip" style="color:{NODE_COLORS.get(t, "#727072")};'
    f'border-color:{NODE_COLORS.get(t, "#727072")}55;background:{NODE_COLORS.get(t, "#727072")}1a">'
    f'{t} {n}</span>'
    for t, n in sorted(counts.items())
)
seed_type = (record or {}).get("type", "")
st.markdown(
    f'<div class="om-header"><div class="om-seed">{_html.escape(target)}</div>'
    f'<div class="om-typed">{_html.escape(seed_type)}</div>{chips}</div>',
    unsafe_allow_html=True,
)

tabs = st.tabs([
    "Overview", "Graph", "Username", "Email", "Email headers", "Phone",
    "Instagram", "Person", "Domain", "Typosquat", "IP", "Leaks", "Dark web", "Dossier",
])
with tabs[0]:
    overview_view.render(target, record)
with tabs[1]:
    graph_view.render(target, record)
with tabs[2]:
    username_view.render(target, record)
with tabs[3]:
    email_view.render(target, record)
with tabs[4]:
    header_view.render(target, record)
with tabs[5]:
    phone_view.render(target, record)
with tabs[6]:
    instagram_view.render(target, record)
with tabs[7]:
    person_view.render(target, record)
with tabs[8]:
    domain_view.render(target, record)
with tabs[9]:
    typosquat_view.render(target, record)
with tabs[10]:
    ip_view.render(target, record)
with tabs[11]:
    leaks_view.render(target, record)
with tabs[12]:
    darkweb_view.render(target, record)
with tabs[13]:
    dossier_view.render(target, record)
