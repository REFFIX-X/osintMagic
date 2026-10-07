"""Typosquatting / brand-impersonation detection (dnstwist-style, keyless).

Generates lookalike domains and resolves them to find *registered* candidates,
scored by impersonation risk. Pure-Python permutations (no dnstwist dependency)
and DNS resolution via dnspython.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from ..models import Finding, SourceResult
from ..registry import source
from ..utils.permutations import domain_permutations
from .base import DataSource

# Lower rank = evaluated first when capping the candidate list.
_FUZZER_PRIORITY = {
    "homoglyph": 0, "transposition": 1, "omission": 2, "replacement": 3,
    "hyphenation": 4, "tld-swap": 5, "addition": 6, "repetition": 7,
    "vowel-swap": 8, "bitsquatting": 9, "subdomain": 10, "insertion": 11,
}

_FUZZER_RISK = {
    "homoglyph": 25, "addition": 15, "replacement": 10, "transposition": 10,
    "omission": 8, "tld-swap": 8, "hyphenation": 8, "bitsquatting": 6,
}


@source(category="brand", name="Typosquat Domains")
class TyposquatSource(DataSource):
    """Resolve lookalike domains and score them for impersonation risk."""

    MAX_CANDIDATES = 120
    WORKERS = 30

    def check(self, target: str) -> SourceResult:
        domain = target.lower().rstrip(".")
        import importlib.util
        if importlib.util.find_spec("dns.resolver") is None:
            return SourceResult(source=self.name, category=self.category, error="dnspython not installed")

        legit_ips = set(self._resolve_a(domain))
        candidates = domain_permutations(domain)
        candidates.sort(key=lambda kv: _FUZZER_PRIORITY.get(kv[1], 99))
        candidates = candidates[: self.MAX_CANDIDATES]

        findings: list[Finding] = []
        with ThreadPoolExecutor(max_workers=self.WORKERS) as ex:
            resolved = ex.map(lambda kv: self._resolve(kv[0]), candidates)
            for (cand, fuzzer), (a_records, mx_records) in zip(candidates, resolved):
                if not a_records and not mx_records:
                    continue  # not registered
                score, factors = self._score(fuzzer, a_records, mx_records, legit_ips)
                findings.append(
                    Finding(
                        source=self.name,
                        category=self.category,
                        status="found",
                        url=f"http://{cand}",
                        detail={
                            "type": "typosquat",
                            "fuzzer": fuzzer,
                            "ip": a_records or None,
                            "mx": mx_records or None,
                            "risk": score,
                            "factors": factors,
                        },
                        confidence=round(score / 100, 2),
                    )
                )

        findings.sort(key=lambda f: f.detail["risk"], reverse=True)
        if not findings:
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found", detail={"type": "typosquat"})],
            )
        return SourceResult(source=self.name, category=self.category, findings=findings)

    def _resolve_a(self, domain: str) -> list[str]:
        try:
            import dns.resolver
            return [str(r) for r in dns.resolver.resolve(domain, "A", lifetime=3)]
        except Exception:
            return []

    def _resolve(self, domain: str) -> tuple[list[str], list[str]]:
        try:
            import dns.resolver
        except ImportError:
            return [], []
        a_records: list[str] = []
        mx_records: list[str] = []
        try:
            a_records = [str(r) for r in dns.resolver.resolve(domain, "A", lifetime=3)]
        except Exception:
            pass
        try:
            mx_records = [str(r.exchange).rstrip(".") for r in dns.resolver.resolve(domain, "MX", lifetime=3)]
        except Exception:
            pass
        return a_records, mx_records

    def _score(self, fuzzer: str, a_records: list[str], mx_records: list[str], legit_ips: set[str]) -> tuple[int, list[str]]:
        score = _FUZZER_RISK.get(fuzzer, 5)
        factors: list[str] = []
        if fuzzer == "homoglyph":
            factors.append("visually identical")
        if mx_records:
            score += 20
            factors.append("MX records (email-capable)")
        if a_records and legit_ips and not set(a_records).intersection(legit_ips):
            score += 10
            factors.append("hosted elsewhere than the real domain")
        if not a_records and mx_records:
            factors.append("mail-only (possible phishing)")
        return min(score, 100), factors
