# Contributing to osintMagic

Thanks for your interest. Contributions are welcome — bug reports, new sources,
documentation, and fixes.

## Ground rules

- Keep the tool **keyless by default**. A new source must work without an API key,
  or be gated behind the optional key tier (`DataSource.key_name`).
- Query **public data only**. No authentication bypass, no brute-forcing
  credentials, no accessing private profiles.
- Be honest in results: rate-limits and blocked sources must be reported as such,
  never faked or silently dropped.

## Setup

```bash
git clone https://github.com/REFFIX-X/osintMagic.git
cd osintMagic
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Before you open a PR

```bash
python -m pytest -q                       # must pass, no network needed
python -m ruff check osintmagic ui app.py --select F,E9
```

- Add or update tests for your change.
- Keep the existing code style (type hints, small modules, no unnecessary deps).

## Adding a source

Subclass `osintmagic.sources.base.DataSource`, implement `check(target)`, and
decorate it with `@source(category=..., name=...)`. It is auto-registered.

```python
from ..models import Finding, SourceResult
from ..registry import source
from .base import DataSource

@source(category="domain", name="My Source")
class MySource(DataSource):
    def check(self, target: str) -> SourceResult:
        return SourceResult(
            source=self.name, category=self.category,
            findings=[Finding(source=self.name, category=self.category, status="info",
                              detail={"type": "my_type", "value": target})],
        )
```

- Set `key_name="MY_API_KEY"` to make it key-gated (excluded unless the key exists).
- Set `on_demand=True` to exclude it from automatic scans (run only from a tab).
- Set `deep=True` for slow/vendored sources excluded from fast scans.

Data-driven sources (username sites, email probes) live in
`osintmagic/data/*.json` — add entries there instead of writing code.

## Reporting bugs

Open an issue with: what you ran, what you expected, what happened, and the
per-source log line if available. Never paste real API keys.

By contributing you agree to the [LICENSE](LICENSE) and to use this software
lawfully (see [DISCLAIMER.md](DISCLAIMER.md)).
