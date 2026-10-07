"""Entity-graph exporters: pyvis HTML, Gephi-friendly JSON, and CSV."""
from __future__ import annotations

import csv
import io
import json

from ..graph import GraphResult

NODE_COLORS = {
    "username": "#AB9DF2",  # purple
    "email": "#78DCE8",     # blue
    "domain": "#A9DC76",    # green
    "phone": "#FC9867",     # orange
    "name": "#FFD866",      # yellow
    "url": "#78DCE8",
    "ip": "#A9DC76",
    "profile": "#FF6188",   # red
}


def _short(value: str, limit: int = 38) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def to_pyvis_html(graph: GraphResult) -> str | None:
    """Return a self-contained interactive graph HTML, or None if pyvis is absent."""
    try:
        from pyvis.network import Network
    except ImportError:
        return None

    net = Network(
        height="640px", width="100%", bgcolor="#2D2A2E",
        font_color="#FCFCFA", directed=True,
    )
    for nid, e in graph.nodes.items():
        net.add_node(
            nid,
            label=_short(e.value),
            title=f"{e.etype}: {e.value}\nsource: {e.source}",
            color=NODE_COLORS.get(e.etype, "#727072"),
        )
    for edge in graph.edges:
        net.add_edge(edge.src, edge.dst, title=edge.label, label=edge.label)
    try:
        return net.generate_html()
    except Exception:
        try:
            import os
            import tempfile
            path = os.path.join(tempfile.mkdtemp(), "graph.html")
            net.write_html(path)
            with open(path, encoding="utf-8") as fh:
                return fh.read()
        except Exception:
            return None


def to_json_bytes(graph: GraphResult) -> bytes:
    payload = {
        "seed": graph.seed,
        "depth": graph.depth,
        "nodes": [
            {"id": nid, "type": e.etype, "value": e.value, "source": e.source, "confidence": e.confidence}
            for nid, e in graph.nodes.items()
        ],
        "edges": [
            {"src": e.src, "dst": e.dst, "label": e.label}
            for e in graph.edges
        ],
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def to_csv_bytes(graph: GraphResult) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["src_type", "src", "relationship", "dst_type", "dst"])
    for edge in graph.edges:
        src_e = graph.nodes.get(edge.src)
        dst_e = graph.nodes.get(edge.dst)
        writer.writerow([
            src_e.etype if src_e else "",
            src_e.value if src_e else edge.src,
            edge.label,
            dst_e.etype if dst_e else "",
            dst_e.value if dst_e else edge.dst,
        ])
    return buf.getvalue().encode("utf-8-sig")


def _dot_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def to_graphviz_dot(graph: GraphResult) -> str:
    """Fallback DOT for st.graphviz_chart when pyvis HTML is unavailable."""
    lines = ["digraph G {", '  bgcolor="#2D2A2E";', '  node [fontcolor="#FCFCFA"];']
    for nid, e in graph.nodes.items():
        color = NODE_COLORS.get(e.etype, "#727072")
        label = _dot_escape(_short(e.value))
        lines.append(f'  "{nid}" [label="{label}", color="{color}", fontcolor="{color}"];')
    for edge in graph.edges:
        label = _dot_escape(edge.label)
        lines.append(f'  "{edge.src}" -> "{edge.dst}" [label="{label}", fontcolor="#727072", color="#3a373b"];')
    lines.append("}")
    return "\n".join(lines)
