"""Person search (target-scoped)."""
from __future__ import annotations

import html as _html

import streamlit as st

from osintmagic import get_sources
from osintmagic.engine import run_scan
from osintmagic.models import ScanResult, SourceResult
from osintmagic.utils.permutations import (
    dork_queries,
    email_candidates,
    name_candidates,
    people_search_links,
)

from .. import hub
from ..components import download_buttons, render_result, run_and_render

_SS_USERS = "person_users"
_SS_EMAILS = "person_emails"
_SS_DORKS = "person_dorks"
_SS_NAME = "person_full_name"


def _chips(items: list[str]) -> str:
    return "".join(f'<span class="om-chip">{_html.escape(i)}</span>' for i in items)


def _merge_candidate_results(name: str, pairs: list[tuple[str, ScanResult]]) -> ScanResult:
    merged = ScanResult(target=name, kind="person_profiles")
    started = None
    for cand, r in pairs:
        if started is None:
            started = r.started_at
        merged.duration += r.duration
        for sr in r.results:
            merged.results.append(SourceResult(
                source=f"{cand} · {sr.source}", category=sr.category,
                findings=sr.findings, error=sr.error,
            ))
    merged.started_at = started or merged.started_at
    return merged


def _generate(target: str, name: str) -> None:
    parts = [p for p in name.strip().split() if p]
    if len(parts) < 2:
        for key in (_SS_USERS, _SS_EMAILS, _SS_DORKS, _SS_NAME):
            st.session_state.pop(f"{key}::{target}", None)
        st.warning("Enter a first and last name.")
        return
    first, last = parts[0], parts[-1]
    middle = " ".join(parts[1:-1]) if len(parts) > 2 else ""
    st.session_state[f"{_SS_USERS}::{target}"] = name_candidates(first, last, middle)
    st.session_state[f"{_SS_EMAILS}::{target}"] = email_candidates(first, last, middle)
    st.session_state[f"{_SS_DORKS}::{target}"] = dork_queries(name.strip())
    st.session_state[f"{_SS_NAME}::{target}"] = name.strip()


def render(target: str, record: dict | None) -> None:
    st.subheader("Person search")
    st.caption("Candidate usernames/emails, dorks, and people-search links from a name.")

    names = hub.candidates(record, "name")
    if record and record.get("type") == "name" and target not in names:
        names.insert(0, target)
    if not names:
        st.info("This target isn't a person name — create a name target for person search.")
        return

    with st.form("person_form"):
        name = st.selectbox("Name", names, key="person_pick")
        submitted = st.form_submit_button("Generate candidates")

    if submitted:
        _generate(target, name)

    users = st.session_state.get(f"{_SS_USERS}::{target}")
    if not users:
        st.info("Generate candidates to continue.")
        return

    st.markdown(_chips(users[:24]), unsafe_allow_html=True)
    st.markdown("**Candidate emails**")
    st.markdown(_chips(st.session_state[f"{_SS_EMAILS}::{target}"][:20]), unsafe_allow_html=True)
    st.markdown("**Google dorks**")
    st.markdown('<div class="om-code">' + "<br>".join(_html.escape(d) for d in st.session_state[f"{_SS_DORKS}::{target}"]) + "</div>", unsafe_allow_html=True)

    _name = st.session_state[f"{_SS_NAME}::{target}"]
    _parts = [p for p in _name.split() if p]
    st.markdown("**People search**")
    st.markdown(
        "".join(
            f'<a class="om-link" href="{_html.escape(url)}" target="_blank" rel="noopener">'
            f'<span class="om-chip">{_html.escape(label)}</span></a> '
            for label, url in people_search_links(_parts[0], _parts[-1], _name)
        ),
        unsafe_allow_html=True,
    )

    if st.button("Search the web", key="person_web"):
        run_and_render(get_sources("person"), _name, "person")

    n = st.slider("Top candidate usernames to scan", 1, 10, 3, key="person_n")
    if st.button("Scan candidate usernames", key="person_profiles"):
        progress = st.progress(0.0)
        pairs = []
        for i, cand in enumerate(users[:n]):
            pairs.append((cand, run_scan(get_sources("username"), cand, kind="username")))
            progress.progress((i + 1) / n)
        progress.empty()
        merged = _merge_candidate_results(_name, pairs)
        render_result(merged)
        download_buttons(merged, f"osintmagic_person_{_name.replace(' ', '_')}")
