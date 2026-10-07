"""Local API-key storage (optional, user-level).

Keys are stored in ``~/.osintmagic/keys.json`` and never committed. Everything
stays keyless by default — a source that declares ``key_name`` is only included
in scans when its key is present (see ``registry.get_sources(active=True)``).
"""
from __future__ import annotations

import json
from pathlib import Path

_PATH = Path.home() / ".osintmagic" / "keys.json"


def _load() -> dict:
    if not _PATH.exists():
        return {}
    try:
        return json.loads(_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    _PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def get_key(name: str) -> str | None:
    return _load().get(name)


def has_key(name: str) -> bool:
    return bool(get_key(name))


def set_key(name: str, value: str) -> None:
    data = _load()
    if value.strip():
        data[name] = value.strip()
    else:
        data.pop(name, None)
    _save(data)


def clear_all() -> None:
    _save({})


def key_names() -> list[str]:
    return sorted(_load().keys())


# Canonical key names used by keyed sources.
KEY_LABELS = {
    "HIBP_API_KEY": "HIBP API key",
    "SHODAN_API_KEY": "Shodan API key",
    "VIRUSTOTAL_API_KEY": "VirusTotal API key",
    "GITHUB_TOKEN": "GitHub token",
    "NUMVERIFY_ACCESS_KEY": "numverify access key",
}
