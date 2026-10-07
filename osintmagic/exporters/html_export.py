"""Standalone, self-contained HTML report (Osintgram-style).

Inline Monokai Pro CSS, summary tiles and findings grouped by source. No
server or styling dependency — open the file in any browser.
"""
from __future__ import annotations

import html as _html
import time
from datetime import datetime

from ..models import ScanResult

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

_STATUS_COLOR = {
    "found": "green",
    "not_found": "dim",
    "error": "red",
    "info": "blue",
}


def _esc(value) -> str:
    return _html.escape(str(value))


def _status_badge(status: str) -> str:
    color = PALETTE[_STATUS_COLOR.get(status, "purple")]
    return f'<span class="badge" style="background:{color}22;color:{color};border-color:{color}55">{_esc(status)}</span>'


def to_html_bytes(result: ScanResult) -> bytes:
    stats = result.stats()
    when = datetime.fromtimestamp(result.started_at or time.time()).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    tiles = "".join(
        f'<div class="tile"><div class="num" style="color:{PALETTE[key]}">{value}</div>'
        f'<div class="lbl">{label}</div></div>'
        for key, value, label in (
            ("green", stats["found"], "Found"),
            ("dim", stats["not_found"], "Not found"),
            ("red", stats["error"], "Errors"),
            ("blue", stats["info"], "Info"),
        )
    )

    sections = []
    for r in result.results:
        rows = []
        if r.error:
            rows.append(
                f'<tr><td colspan="2"><span class="badge" style="background:{PALETTE["red"]}22;'
                f'color:{PALETTE["red"]}">{_esc("error")}</span> {_esc(r.error)}</td></tr>'
            )
        for f in r.findings:
            extras = f.extras()
            detail = ", ".join(f"{k}: {v}" for k, v in extras.items()) if extras else ""
            url = f'<a class="url" href="{_esc(f.url)}">{_esc(f.url)}</a>' if f.url else ""
            title = f.url or f.label()
            rows.append(
                f'<tr><td>{_status_badge(f.status)}</td>'
                f'<td><div class="title">{_esc(title)}</div>'
                f'{url}<div class="detail">{_esc(detail)}</div></td></tr>'
            )
        sections.append(
            f'<div class="group"><h2>{_esc(r.source)}</h2><table><tbody>{"".join(rows)}</tbody></table></div>'
        )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>osintMagic — {_esc(result.target)}</title>
<style>
:root {{
  --bg: {PALETTE["bg"]}; --panel: {PALETTE["panel"]}; --fg: {PALETTE["fg"]};
  --dim: {PALETTE["dim"]}; --green: {PALETTE["green"]}; --red: {PALETTE["red"]};
  --blue: {PALETTE["blue"]}; --purple: {PALETTE["purple"]};
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; padding: 40px 24px; background: var(--bg); color: var(--fg);
  font-family: "JetBrains Mono", "Fira Code", Consolas, monospace; font-size: 14px; }}
.container {{ max-width: 960px; margin: 0 auto; }}
h1 {{ font-size: 24px; margin: 0 0 4px; color: var(--purple); }}
.meta {{ color: var(--dim); margin-bottom: 24px; }}
.tiles {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 28px; }}
.tile {{ background: var(--panel); border: 1px solid #3a373b; border-radius: 8px; padding: 14px 16px; }}
.num {{ font-size: 28px; font-weight: 700; }}
.lbl {{ color: var(--dim); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }}
.group {{ background: var(--panel); border: 1px solid #3a373b; border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; }}
.group h2 {{ font-size: 14px; color: var(--blue); margin: 0 0 8px; }}
table {{ width: 100%; border-collapse: collapse; }}
td {{ padding: 8px 6px; border-top: 1px solid #3a373b; vertical-align: top; }}
tr:first-child td {{ border-top: none; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; border: 1px solid; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }}
.title {{ font-weight: 600; word-break: break-all; }}
.url {{ color: var(--blue); text-decoration: none; word-break: break-all; }}
.url:hover {{ text-decoration: underline; }}
.detail {{ color: var(--dim); font-size: 12px; margin-top: 2px; word-break: break-all; }}
@media (max-width: 640px) {{ .tiles {{ grid-template-columns: repeat(2, 1fr); }} }}
</style>
</head>
<body>
<div class="container">
  <h1>osintMagic report</h1>
  <div class="meta">Target: <strong>{_esc(result.target)}</strong> · Kind: {_esc(result.kind)} · {_esc(when)} · {stats["sources"]} sources · {stats["duration"]}s</div>
  <div class="tiles">{tiles}</div>
  {"".join(sections)}
</div>
</body>
</html>
"""
    return doc.encode("utf-8")
