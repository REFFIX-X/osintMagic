"""osintMagic — a keyless OSINT suite (username, email, domain, IP, person)."""
from __future__ import annotations

from . import sources  # noqa: F401  (triggers source registration)
from .engine import run_scan
from .models import Finding, ScanResult, SourceResult
from .registry import all_sources, get_sources

__all__ = [
    "Finding",
    "ScanResult",
    "SourceResult",
    "all_sources",
    "get_sources",
    "run_scan",
]

__version__ = "0.1.0"
