"""Adapters to vendored keyless OSINT tools (holehe, maigret).

Each adapter returns a normalized ``{"available": bool, "rows": [...], "reason": str}``
so the sources can feed the existing engine/UI/exporters without depending on
the tool's own output format. A missing or failed dependency degrades to
``available=False`` with a reason, never a crash.
"""
from __future__ import annotations

import contextlib
import glob
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace


def _holehe_available() -> bool:
    try:
        import holehe  # noqa: F401
        return True
    except Exception:
        return False


def run_holehe(email: str, timeout: float = 15.0) -> dict:
    """Check an email across holehe's 120+ sites (concurrent, keyless)."""
    if not _holehe_available():
        return {"available": False, "rows": [], "reason": "holehe not installed"}

    from holehe import core

    args = SimpleNamespace(nopasswordrecovery=True, onlyused=False)
    modules = core.import_submodules("holehe.modules")
    websites = core.get_functions(modules, args)
    out: list[dict] = []

    async def _run() -> None:
        import httpx
        import trio

        client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        try:
            async with trio.open_nursery() as nursery:
                for website in websites:
                    nursery.start_soon(core.launch_module, website, email, client, out)
        finally:
            await client.aclose()

    import trio

    # holehe modules are chatty; keep their prints out of our app output.
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        trio.run(_run)

    rows = []
    for item in out:
        rows.append({
            "site": item.get("name"),
            "domain": item.get("domain"),
            "exists": bool(item.get("exists")),
            "rate_limited": bool(item.get("rateLimit")),
            "email_recovery": item.get("emailrecovery"),
            "phone": item.get("phoneNumber"),
            "others": item.get("others"),
        })
    return {"available": True, "rows": rows, "reason": None}


def run_maigret(username: str, timeout: float = 120.0) -> dict:
    """Search a username across maigret's 2000+ sites via its CLI (JSON report)."""
    try:
        import maigret  # noqa: F401
    except Exception:
        return {"available": False, "rows": [], "reason": "maigret not installed"}

    tmpdir = tempfile.mkdtemp(prefix="mg_")
    cmd = [
        sys.executable, "-m", "maigret", username,
        "-J", "simple", "--no-color",
        "-fo", tmpdir, "--timeout", "10",
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return {"available": True, "rows": [], "reason": "maigret timed out"}

    reports = glob.glob(f"{tmpdir}/report_*_simple.json")
    rows: list[dict] = []
    if reports:
        # The main report is the largest; maigret also writes small sub-reports
        # for discovered IDs (e.g. a steam_id), which we must skip.
        report_file = max(reports, key=os.path.getsize)
        try:
            with open(report_file, encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        for site, entry in data.items():
            if not isinstance(entry, dict):
                continue
            status = entry.get("status")
            status_val = status.get("status") if isinstance(status, dict) else None
            rows.append({
                "site": site,
                "status": status_val,
                "exists": status_val == "Claimed",
                "url": entry.get("url_user") or (status.get("url") if isinstance(status, dict) else None),
                "http_status": entry.get("http_status"),
                "ids": (status.get("ids") if isinstance(status, dict) else None),
            })
    shutil.rmtree(tmpdir, ignore_errors=True)
    return {"available": True, "rows": rows, "reason": None}


def run_amass(domain: str, timeout: float = 120.0) -> dict:
    """Passive subdomain enumeration via the OWASP Amass binary (if installed).

    Amass is a Go binary and is *not* pip-installable, so this adapter simply
    checks PATH and no-ops with a clear reason when it is absent.
    """
    if not shutil.which("amass"):
        return {"available": False, "rows": [], "reason": "amass binary not found on PATH (install owasp-amass/amass)"}

    tmpdir = tempfile.mkdtemp(prefix="amass_")
    out_file = os.path.join(tmpdir, "amass.json")
    cmd = ["amass", "enum", "-passive", "-d", domain, "-json", out_file]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return {"available": True, "rows": [], "reason": "amass timed out"}

    rows: list[dict] = []
    if os.path.exists(out_file):
        with open(out_file, encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            name = rec.get("name") or rec.get("hostname")
            if name:
                rows.append({"site": name, "exists": True, "url": f"https://{name}", "status": "Claimed", "ids": rec.get("addresses")})
    shutil.rmtree(tmpdir, ignore_errors=True)
    return {"available": True, "rows": rows, "reason": None}
