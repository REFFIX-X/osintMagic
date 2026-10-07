"""JSON export of a full ScanResult."""
from __future__ import annotations

import json

from ..models import ScanResult


def to_json_bytes(result: ScanResult) -> bytes:
    return json.dumps(result.to_dict(), indent=2).encode("utf-8")
