"""Concurrent scan orchestrator.

Runs a list of sources against a target using a bounded thread pool. Each
source's exceptions are captured into its ``SourceResult.error`` so a single
failing source never aborts the scan. An optional ``progress(completed, total)``
callback lets the UI render a live progress bar.
"""
from __future__ import annotations

import concurrent.futures
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from .models import ScanResult, SourceResult

ProgressFn = Callable[[int, int], None]


def run_scan(
    sources,
    target: str,
    *,
    kind: str | None = None,
    progress: ProgressFn | None = None,
    log=None,
    max_workers: int = 12,
    timeout: float | None = None,
) -> ScanResult:
    if not sources:
        return ScanResult(target=target, kind=kind or "unknown")

    result = ScanResult(target=target, kind=kind or sources[0].category)
    started = time.time()

    completed: dict[int, SourceResult] = {}
    workers = min(max_workers, len(sources))

    ex = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {ex.submit(s.check, target): i for i, s in enumerate(sources)}
        done, not_done = concurrent.futures.wait(futures, timeout=timeout)
        for fut in not_done:  # exceeded the global cap — mark as timed out
            fut.cancel()
            i = futures[fut]
            completed[i] = SourceResult(
                source=sources[i].name, category=sources[i].category, error="timeout"
            )
        for fut in done:
            i = futures[fut]
            src = sources[i]
            try:
                sr = fut.result()
            except Exception as exc:  # never let one source kill the scan
                sr = SourceResult(source=src.name, category=src.category, error=str(exc))
            completed[i] = sr
            if log:
                if sr.error:
                    log(f"[{len(completed)}/{len(sources)}] {src.name} → error: {sr.error}")
                else:
                    found = sum(1 for f in sr.findings if f.status == "found")
                    log(f"[{len(completed)}/{len(sources)}] {src.name} → {len(sr.findings)} finding(s), {found} hit(s)")
            if progress:
                progress(len(completed), len(sources))
    finally:
        ex.shutdown(wait=False, cancel_futures=True)

    result.results = [completed[i] for i in range(len(sources))]
    result.duration = time.time() - started
    return result
