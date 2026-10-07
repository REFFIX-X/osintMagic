"""Shared Streamlit components: stat tiles, result cards, export buttons."""
from __future__ import annotations

import html as _html
import json

import streamlit as st

from osintmagic.engine import run_scan
from osintmagic.exporters import csv_export, html_export, json_export
from osintmagic.models import ScanResult
from osintmagic.utils import iocs

from .theme import PALETTE

_STATUS_COLOR = {"found": "green", "not_found": "dim", "error": "red", "info": "blue"}


def _esc(value) -> str:
    return _html.escape(str(value))


def _badge(status: str) -> str:
    color = PALETTE[_STATUS_COLOR.get(status, "purple")]
    return (
        f'<span class="om-badge" style="color:{color};border-color:{color}55;background:{color}1a">'
        f'{_esc(status.replace("_", " "))}</span>'
    )


def stat_tiles(stats: dict) -> None:
    items = [
        ("Found", stats["found"], "green"),
        ("Not found", stats["not_found"], "dim"),
        ("Errors", stats["error"], "red"),
        ("Info", stats["info"], "blue"),
    ]
    cells = "".join(
        f'<div class="om-tile"><div class="om-num" style="color:{PALETTE[c]}">{n}</div>'
        f'<div class="om-lbl">{label}</div></div>'
        for label, n, c in items
    )
    st.markdown(f'<div class="om-tiles">{cells}</div>', unsafe_allow_html=True)


def _finding_html(f) -> str:
    badge = _badge(f.status)

    if f.status == "found" and f.url:
        body = f'<a class="om-link" href="{_esc(f.url)}" target="_blank" rel="noopener">{_esc(f.url)}</a>'
    elif f.url:
        body = _esc(f.url)
    else:
        body = _esc(f.label())

    extras = dict(f.extras())
    if f.confidence < 1.0:
        extras["confidence"] = f.confidence
    detail = _esc(", ".join(f"{k}: {v}" for k, v in extras.items())) if extras else ""

    return (
        f'<div class="om-card">{badge} <span class="om-body">{body}</span>'
        + (f'<div class="om-detail">{detail}</div>' if detail else "")
        + "</div>"
    )


def render_result(result: ScanResult) -> None:
    parts = [
        f'<div class="om-meta">Scanned {len(result.results)} sources in {result.duration:.1f}s</div>',
    ]
    for r in result.results:
        parts.append(f'<div class="om-group-title">{_esc(r.source)}</div>')
        if r.error:
            parts.append(f'<div class="om-card">{_badge("error")} {_esc(r.error)}</div>')
            continue
        if not r.findings:
            parts.append(f'<div class="om-card">{_badge("info")} no data</div>')
            continue
        for f in r.findings:
            parts.append(_finding_html(f))
    st.markdown("".join(parts), unsafe_allow_html=True)


def download_buttons(result: ScanResult, prefix: str) -> None:
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.download_button(
            "Download JSON", json_export.to_json_bytes(result),
            file_name=f"{prefix}.json", mime="application/json",
        )
    with c2:
        st.download_button(
            "Download CSV", csv_export.to_csv_bytes(result),
            file_name=f"{prefix}.csv", mime="text/csv",
        )
    with c3:
        st.download_button(
            "Download HTML report", html_export.to_html_bytes(result),
            file_name=f"{prefix}.html", mime="text/html",
        )
    with c4:
        st.download_button(
            "Download STIX (IOCs)", json.dumps(iocs.to_stix(result), indent=2).encode("utf-8"),
            file_name=f"{prefix}_stix.json", mime="application/json",
        )


def make_live_log():
    """Return a ``log(msg)`` callable that streams into a scrollable live panel."""
    lines: list[str] = []
    box = st.empty()

    def log(msg: str) -> None:
        lines.append(msg)
        html = (
            '<div class="om-log">'
            + "<br>".join(_esc(l) for l in lines[-200:])
            + "</div>"
        )
        box.markdown(html, unsafe_allow_html=True)

    return log


def run_with_log(sources, target: str, kind: str):
    """Run a scan with a live progress bar + live output log.

    Returns the ``ScanResult``. The log panel stays on screen after the scan.
    """
    log = make_live_log()
    log(f"▶ {kind} scan of “{target}” across {len(sources)} sources")
    progress_bar = st.progress(0.0)
    result = run_scan(
        sources, target, kind=kind,
        progress=lambda done, total: progress_bar.progress(done / total if total else 1.0),
        log=log,
    )
    stats = result.stats()
    log(f"✔ done in {result.duration:.1f}s — {stats['found']} found, {stats['error']} errors, {stats['info']} info")
    return result


def run_and_render(sources, target: str, kind: str) -> None:
    """Run a scan with a live progress bar + log, then render + expose exports."""
    if not sources:
        st.warning("No sources registered for this category.")
        return
    result = run_with_log(sources, target, kind)
    render_result(result)
    download_buttons(result, f"osintmagic_{kind}_{target}")
