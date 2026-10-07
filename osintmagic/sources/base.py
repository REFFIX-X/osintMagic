"""Base class for all data sources."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import SourceResult


class DataSource(ABC):
    category: str = ""
    name: str = ""
    deep: bool = False  # vendored/slow "deep scan" sources, excluded from fast scans
    key_name: str | None = None  # if set, the source is skipped unless this key exists
    on_demand: bool = False  # if True, excluded from automatic scans (run via a dedicated tab)

    @abstractmethod
    def check(self, target: str) -> SourceResult:
        """Run the source against ``target`` and return its findings."""
        raise NotImplementedError
