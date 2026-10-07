"""Core data model for osintMagic scans.

Every source returns a ``SourceResult`` which holds one or more ``Finding``
objects. A full ``ScanResult`` aggregates the results of all sources for a
single target and can be serialized for export.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

_PRIMARY_FIELDS = ("value", "name", "provider", "result")


@dataclass
class Finding:
    source: str
    category: str
    status: str  # found | not_found | error | info
    url: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

    def label(self) -> str:
        """Human-readable primary label for this finding, e.g. ``A: 1.2.3.4``."""
        d = self.detail or {}
        primary = next((d[k] for k in _PRIMARY_FIELDS if d.get(k)), None)
        kind = d.get("type")
        if kind and primary:
            return f"{kind}: {primary}"
        if kind:
            return kind
        return str(primary) if primary else self.source

    def extras(self) -> dict[str, Any]:
        """Detail fields not already shown as the label."""
        skip = {"type", *_PRIMARY_FIELDS}
        return {k: v for k, v in (self.detail or {}).items() if k not in skip}


@dataclass
class SourceResult:
    source: str
    category: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


@dataclass
class ScanResult:
    target: str
    kind: str
    results: list[SourceResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    duration: float = 0.0

    def stats(self) -> dict[str, Any]:
        found = not_found = error = info = 0
        for r in self.results:
            for f in r.findings:
                if f.status == "found":
                    found += 1
                elif f.status == "not_found":
                    not_found += 1
                elif f.status == "error":
                    error += 1
                elif f.status == "info":
                    info += 1
        return {
            "target": self.target,
            "kind": self.kind,
            "sources": len(self.results),
            "found": found,
            "not_found": not_found,
            "error": error,
            "info": info,
            "duration": round(self.duration, 2),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "kind": self.kind,
            "started_at": self.started_at,
            "duration": self.duration,
            "stats": self.stats(),
            "results": [
                {
                    "source": r.source,
                    "category": r.category,
                    "error": r.error,
                    "findings": [
                        {
                            "source": f.source,
                            "category": f.category,
                            "status": f.status,
                            "url": f.url,
                            "detail": f.detail,
                            "confidence": f.confidence,
                        }
                        for f in r.findings
                    ],
                }
                for r in self.results
            ],
        }
