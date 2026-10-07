from osintmagic.engine import run_scan
from osintmagic.models import Finding, SourceResult


def test_run_scan_empty():
    result = run_scan([], "target", kind="username")
    assert result.target == "target"
    assert result.results == []


def test_run_scan_captures_source_exception():
    class Boom:
        name = "boom"
        category = "test"

        def check(self, target):
            raise RuntimeError("kaboom")

    result = run_scan([Boom()], "target", kind="test")
    assert len(result.results) == 1
    assert result.results[0].error == "kaboom"


def test_run_scan_preserves_order_and_progress():
    class Ok:
        def __init__(self, name):
            self.name = name
            self.category = "test"

        def check(self, target):
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="found")],
            )

    sources = [Ok(f"s{i}") for i in range(5)]
    ticks = []
    result = run_scan(sources, "target", kind="test", progress=lambda d, t: ticks.append((d, t)))
    assert [r.source for r in result.results] == ["s0", "s1", "s2", "s3", "s4"]
    assert ticks[-1] == (5, 5)
    assert result.stats()["found"] == 5
