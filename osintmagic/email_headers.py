"""Email header analysis for phishing / authentication triage.

Takes raw headers (an .eml, or the "Show original" / "Internet headers" text)
and reports the delivery chain, From/Reply-To/Return-Path alignment, SPF/DKIM/
DMARC results, embedded URLs and lookalike sender domains. Fully offline.
"""
from __future__ import annotations

import email
import email.policy
import email.utils
import re

from .models import Finding, ScanResult, SourceResult
from .utils.permutations import similarity

_CATEGORY = "email_headers"
_URL_RE = re.compile(r"https?://[^\s<>\"'()]+")
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)

_KEY_FIELDS = ("From", "Reply-To", "Return-Path", "Subject", "Date", "Message-ID", "X-Mailer", "X-Originating-IP")


def _addr_domain(value: str | None) -> str:
    if not value:
        return ""
    addr = email.utils.parseaddr(value)[1]
    return addr.split("@")[-1].lower() if "@" in addr else ""


def analyze_headers(raw: str) -> ScanResult:
    msg = email.message_from_string(raw, policy=email.policy.default)
    findings: list[Finding] = []

    def add(kind: str, value, status: str = "info", confidence: float = 1.0) -> None:
        findings.append(Finding(_CATEGORY, _CATEGORY, status, detail={"type": kind, "value": value}, confidence=confidence))

    for field in _KEY_FIELDS:
        value = msg.get(field)
        if value:
            add(field, str(value).strip())

    # --- authentication results -------------------------------------------------
    auth_text = " ".join(msg.get_all("Authentication-Results") or []) or str(msg.get("Received-SPF") or "")
    for mech, result in _AUTH_RE.findall(auth_text):
        status = "found" if result.lower() == "pass" else "info"
        add(f"Mech {mech.upper()}", result.lower(), status=status)

    # --- alignment --------------------------------------------------------------
    from_dom = _addr_domain(msg.get("From"))
    reply_dom = _addr_domain(msg.get("Reply-To"))
    rp_dom = _addr_domain(msg.get("Return-Path"))
    if reply_dom and from_dom and reply_dom != from_dom:
        add("From/Reply-To mismatch", f"{from_dom} != {reply_dom}", status="found", confidence=0.7)
    if rp_dom and from_dom and rp_dom != from_dom:
        add("Return-Path differs", f"{from_dom} vs {rp_dom}", status="info", confidence=0.6)
        ratio = similarity(from_dom, rp_dom)
        if 0.6 <= ratio < 1.0:
            add("Possible lookalike sender", f"{rp_dom} ~ {from_dom} ({ratio:.0%} similar)",
                status="found", confidence=0.75)

    # --- delivery chain ---------------------------------------------------------
    received = msg.get_all("Received") or []
    if received:
        add("Received hops", len(received))
        add("First hop", " ".join(str(received[-1]).split()))

    # --- embedded URLs ----------------------------------------------------------
    body = ""
    if not msg.is_multipart():
        body = str(msg.get_payload())
    else:
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    body += part.get_content()
                except Exception:
                    pass
    for url in dict.fromkeys(_URL_RE.findall(body)):
        findings.append(Finding(_CATEGORY, _CATEGORY, "info", url=url, detail={"type": "URL in body"}, confidence=0.6))

    if not findings:
        findings.append(Finding(_CATEGORY, _CATEGORY, "error", detail={"type": "parse", "value": "no header fields recognised"}))

    result = ScanResult(target=str(msg.get("Subject") or "(no subject)"), kind=_CATEGORY)
    result.results = [SourceResult("Header analysis", _CATEGORY, findings)]
    return result
