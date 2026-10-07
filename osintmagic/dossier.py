"""Unified OSINT dossier: run every applicable source and correlate the result.

Follows the four-phase structure of the OSINT-gathering skill: network &
infrastructure, credentials & leaks, technology, and other. Each finding is
classified into a phase so the UI can render a consolidated report.
"""
from __future__ import annotations

from .engine import run_scan
from .models import Finding, ScanResult
from .registry import get_sources
from .utils.iocs import result_to_iocs

_SCAN_TIMEOUT = 120.0


PHASES = (
    "Network & Infrastructure",
    "Credentials & Leaks",
    "Technology",
    "Other",
)

_INFRA_TYPES = {
    "subdomain", "bucket", "waf_cdn", "axfr", "dnssec", "srv", "wildcard dns",
    "ct wildcard certs", "ct recent certs (90d)", "ct issuers", "whois",
    "email auth posture", "geolocation", "network", "ptr",
}
_INFRA_SOURCES = {
    "crt.sh", "certspotter", "wayback machine", "dns records", "rdap / whois",
    "zone transfer (axfr)", "cloud buckets", "waf / cdn", "subdomain brute-force",
    "dnssec / srv", "amass (deep)",
}
_CRED_TYPES = {"paste", "credentials", "darkweb_mention", "leak"}
_TECH_TYPES = {"tech"}
_TECH_SOURCES = {"tech fingerprint"}


def classify_finding(finding: Finding) -> str:
    d = finding.detail or {}
    kind = str(d.get("type", "")).lower()
    source = finding.source.lower()
    if kind in _INFRA_TYPES or source in _INFRA_SOURCES:
        return PHASES[0]
    if kind in _CRED_TYPES or "paste" in source or "leak" in source or "dark web" in source:
        return PHASES[1]
    if kind in _TECH_TYPES or source in _TECH_SOURCES:
        return PHASES[2]
    return PHASES[3]


def build_dossier(target: str, *, include_brand: bool = True, log=None) -> ScanResult:
    """Run domain + brand (+ paste/darkweb, which live in domain) for a target."""
    sources = list(get_sources("domain"))
    if include_brand:
        sources += list(get_sources("brand"))
    return run_scan(sources, target, kind="dossier", log=log, timeout=_SCAN_TIMEOUT)


def phase_summary(result: ScanResult) -> dict[str, dict]:
    """Return per-phase counts (found / total) for a dossier result."""
    summary: dict[str, dict] = {phase: {"found": 0, "total": 0} for phase in PHASES}
    for source_result in result.results:
        for finding in source_result.findings:
            phase = classify_finding(finding)
            summary[phase]["total"] += 1
            if finding.status == "found":
                summary[phase]["found"] += 1
    return summary


def dossier_iocs(result: ScanResult) -> dict[str, list[str]]:
    return result_to_iocs(result)


def _subdomain_hosts(result: ScanResult) -> list[str]:
    from urllib.parse import urlparse

    hosts: set[str] = set()
    for source_result in result.results:
        for finding in source_result.findings:
            if (finding.detail or {}).get("type") != "subdomain":
                continue
            host = urlparse(finding.url).hostname if finding.url else None
            if host:
                hosts.add(host.rstrip(".").lower())
    return sorted(hosts)


def _resolve_host(host: str) -> list[str]:
    try:
        import dns.resolver
        return [str(r) for r in dns.resolver.resolve(host, "A", lifetime=4)]
    except Exception:
        return []


def _ipinfo(ip: str) -> dict:
    import json

    from .http_client import HttpError, get

    try:
        return json.loads(get(f"https://ipinfo.io/{ip}/json", timeout=8).text)
    except (HttpError, json.JSONDecodeError):
        return {}


def enrich_infrastructure(result: ScanResult, limit: int = 40) -> dict:
    """Resolve discovered subdomains to IPs and enrich each with ASN/org/geo.

    Returns ``{"rows": [...], "asns": Counter, "countries": Counter, "total_subdomains": int}``
    where each row carries ``host, ip, org, city, region, country, lat, lon``.
    """
    from collections import Counter
    from concurrent.futures import ThreadPoolExecutor

    hosts = _subdomain_hosts(result)[:limit]
    if not hosts:
        return {"rows": [], "asns": {}, "countries": {}, "total_subdomains": 0}

    # Resolve hosts -> IPs concurrently.
    host_ips: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=20) as ex:
        for host, ips in zip(hosts, ex.map(_resolve_host, hosts)):
            if ips:
                host_ips[host] = ips

    # Enrich each unique IP.
    unique_ips = sorted({ip for ips in host_ips.values() for ip in ips})
    ip_data: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=12) as ex:
        for ip, data in zip(unique_ips, ex.map(_ipinfo, unique_ips)):
            if data.get("ip"):
                ip_data[ip] = data

    rows: list[dict] = []
    asns: Counter = Counter()
    countries: Counter = Counter()
    for host, ips in host_ips.items():
        for ip in ips:
            data = ip_data.get(ip, {})
            org = data.get("org")
            if org:
                asns[org.split(" ", 1)[0]] += 1
            if data.get("country"):
                countries[data["country"]] += 1
            lat = lon = None
            loc = data.get("loc")
            if loc and "," in loc:
                lat_str, lon_str = loc.split(",", 1)
                try:
                    lat, lon = float(lat_str), float(lon_str)
                except ValueError:
                    lat = lon = None
            rows.append({
                "host": host, "ip": ip, "org": org, "city": data.get("city"),
                "region": data.get("region"), "country": data.get("country"),
                "lat": lat, "lon": lon,
            })

    return {
        "rows": rows,
        "asns": dict(asns.most_common()),
        "countries": dict(countries.most_common()),
        "total_subdomains": len(hosts),
    }
