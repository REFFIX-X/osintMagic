"""Indicator-of-compromise (IOC) extraction, defanging and STIX-shaped export."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..models import ScanResult

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'()]+")
_HASH_RE = re.compile(r"\b(?=[a-fA-F0-9]*[a-fA-F])(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_DOMAIN_RE = re.compile(r"\b(?:(?!\d+\.\d+\.\d+\.\d+)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)

_TRAILING_PUNCT = ".,;:!?"


def _strip_trailing(value: str) -> str:
    return value.rstrip(_TRAILING_PUNCT)


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Extract IPs, domains, URLs, emails and hashes from free text."""
    urls = list(dict.fromkeys(_strip_trailing(u) for u in _URL_RE.findall(text)))
    emails = list(dict.fromkeys(_EMAIL_RE.findall(text)))
    ips = [ip for ip in dict.fromkeys(_IPV4_RE.findall(text))]
    hashes = list(dict.fromkeys(_HASH_RE.findall(text)))

    # Domains: exclude exact email/URL tokens (not substring matches, so a domain
    # that also appears inside an email is still kept as a standalone IOC).
    consumed = {c.lower() for c in urls + emails}
    domains = list(dict.fromkeys(d.lower() for d in _DOMAIN_RE.findall(text) if d.lower() not in consumed))

    return {"ipv4": ips, "domain": domains, "url": urls, "email": emails, "hash": hashes}


def defang(value: str) -> str:
    """Defang a URL/domain/email so it cannot be clicked accidentally."""
    out = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    out = out.replace(".", "[.]").replace("@", "[@]")
    return out


def result_to_iocs(result: ScanResult) -> dict[str, list[str]]:
    """Collect IOCs from a finished scan: URLs on findings plus every text field."""
    pieces: list[str] = []
    for source_result in result.results:
        for finding in source_result.findings:
            if finding.url:
                pieces.append(finding.url)
            pieces.extend(str(v) for v in finding.detail.values())
    return extract_iocs("\n".join(pieces))


_HASH_ALGO = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


def to_stix(result: ScanResult) -> dict:
    """Build a minimal STIX 2.1 bundle of the indicators found in a scan."""
    iocs = result_to_iocs(result)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    objects: list[dict] = []

    def pattern_for(kind: str, value: str) -> str:
        if kind == "ipv4":
            return f"[ipv4-addr:value = '{value}']"
        if kind == "domain":
            return f"[domain-name:value = '{value}']"
        if kind == "url":
            return f"[url:value = '{value}']"
        if kind == "email":
            return f"[email-addr:value = '{value}']"
        algo = _HASH_ALGO.get(len(value), "SHA-256")
        return f"[file:hashes.'{algo}' = '{value}']"

    for kind, values in iocs.items():
        for value in values:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "name": f"{kind}: {value}",
                "indicator_types": ["unknown"],
                "pattern": pattern_for(kind, value),
                "pattern_type": "stix",
                "valid_from": now,
            })
    return {
        "type": "bundle",
        "id": f"bundle--osintmagic-{result.kind}-{abs(hash(result.target)) % 10**10}",
        "objects": objects,
    }
