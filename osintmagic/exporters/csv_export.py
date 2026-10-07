"""Flattened CSV export (one row per finding)."""
from __future__ import annotations

import csv
import io
import json

from ..models import ScanResult


def to_csv_bytes(result: ScanResult) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["target", "kind", "source", "category", "status", "url", "confidence", "detail"])

    for r in result.results:
        for f in r.findings:
            writer.writerow([
                result.target,
                result.kind,
                f.source,
                f.category,
                f.status,
                f.url or "",
                f.confidence,
                json.dumps(f.detail, ensure_ascii=False),
            ])
        if r.error:
            writer.writerow([result.target, result.kind, r.source, r.category, "error", "", "", r.error])

    return buf.getvalue().encode("utf-8-sig")
