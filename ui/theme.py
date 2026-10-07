"""Monokai Pro palette + a single injected CSS block.

The base colors are set in ``.streamlit/config.toml``; this module supplies the
full palette as named constants and styles the custom ``.om-*`` components so
result cards read as one designed system.
"""
from __future__ import annotations

PALETTE = {
    "bg": "#2D2A2E",
    "panel": "#221F22",
    "fg": "#FCFCFA",
    "dim": "#727072",
    "red": "#FF6188",
    "orange": "#FC9867",
    "yellow": "#FFD866",
    "green": "#A9DC76",
    "blue": "#78DCE8",
    "purple": "#AB9DF2",
}

_CSS = """
<style>
/* osintMagic components */
.om-tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 8px 0 20px; }
.om-tile { background: #221F22; border: 1px solid #3a373b; border-radius: 8px; padding: 14px 16px; }
.om-num { font-size: 28px; font-weight: 700; font-family: inherit; }
.om-lbl { color: #727072; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; margin-top: 2px; }
.om-meta { color: #727072; font-size: 13px; margin: 0 0 8px; }
.om-group-title { color: #78DCE8; font-size: 13px; font-weight: 700; margin: 18px 0 6px; text-transform: uppercase; letter-spacing: .05em; }
.om-card { background: #221F22; border: 1px solid #3a373b; border-radius: 6px; padding: 8px 12px; margin-bottom: 6px; }
.om-badge { display: inline-block; padding: 1px 8px; border-radius: 4px; border: 1px solid; font-size: 10px; text-transform: uppercase; letter-spacing: .05em; margin-right: 8px; vertical-align: middle; }
.om-body { vertical-align: middle; word-break: break-all; }
.om-link { color: #78DCE8; text-decoration: none; }
.om-link:hover { text-decoration: underline; }
.om-detail { color: #727072; font-size: 12px; margin: 4px 0 0 0; word-break: break-all; }
.om-chip { display: inline-block; background: #2D2A2E; border: 1px solid #3a373b; color: #FCFCFA; border-radius: 4px; padding: 2px 8px; margin: 2px 4px 2px 0; font-size: 12px; font-family: inherit; }
.om-code { background: #221F22; border: 1px solid #3a373b; border-radius: 6px; padding: 10px 12px; color: #FFD866; font-family: inherit; font-size: 12px; overflow-x: auto; }
.om-log { background: #1b191c; border: 1px solid #3a373b; border-radius: 6px; padding: 8px 12px; font-family: inherit; font-size: 12px; color: #A9DC76; line-height: 1.5; max-height: 320px; overflow-y: auto; white-space: pre-wrap; }
/* target header band — the one memorable element */
.om-header { background: #221F22; border: 1px solid #3a373b; border-left: 4px solid #AB9DF2; border-radius: 8px; padding: 18px 20px; margin: 0 0 14px; }
.om-header .om-seed { font-size: 26px; font-weight: 700; color: #FCFCFA; letter-spacing: .01em; }
.om-header .om-typed { color: #78DCE8; font-size: 12px; margin: 2px 0 10px; }
.om-entity-chip { display: inline-block; border: 1px solid; border-radius: 20px; padding: 2px 10px; margin: 2px 6px 2px 0; font-size: 12px; font-family: inherit; }
/* hero landing (no target) */
.om-hero { text-align: center; padding: 48px 20px 8px; }
.om-hero h1 { font-size: 34px; margin: 0 0 6px; color: #FCFCFA; }
.om-hero .om-sub { color: #727072; font-size: 15px; margin-bottom: 8px; }
/* tighten default spacing */
section.main > div { padding-top: 0.5rem; }
</style>
"""


def apply_theme() -> None:
    import streamlit as st

    st.markdown(_CSS, unsafe_allow_html=True)
