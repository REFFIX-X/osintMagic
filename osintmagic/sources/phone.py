"""Phone number footprinting (keyless).

Foundation is Google's libphonenumber (parse/validate/carrier/region/timezone,
offline). Adds keyless public lookups: haveibeenzuckered (Facebook 2019 breach
by phone) and freecarrierlookup (carrier + email-to-SMS gateway), plus Google
dorks. No paid Twilio/Truecaller.
"""
from __future__ import annotations

import json

from ..http_client import HttpError, get
from ..models import Finding, SourceResult
from ..registry import source
from ..utils.phone import dk_enrichment
from .base import DataSource
from .search import search_all

_NUMBER_TYPE = {
    0: "fixed line", 1: "mobile", 2: "fixed line or mobile", 3: "toll free",
    4: "premium rate", 5: "shared cost", 6: "VoIP", 7: "personal number",
    8: "pager", 9: "UAN", 10: "voicemail", 99: "unknown",
}


@source(category="phone", name="Number Info")
class PhoneInfoSource(DataSource):
    """Offline libphonenumber analysis: E.164, region, carrier, type, timezone."""

    def check(self, target: str) -> SourceResult:
        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder, timezone
        except ImportError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        try:
            number = phonenumbers.parse(target, None)
        except Exception as exc:
            return SourceResult(source=self.name, category=self.category, error=f"unparseable: {exc}")

        if not phonenumbers.is_possible_number(number):
            return SourceResult(source=self.name, category=self.category, error="not a possible number")

        national = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL)
        region_code = geocoder.region_code_for_number(number)
        detail = {
            "type": "phone_info",
            "e164": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
            "national": national,
            "international": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "country": region_code,
            "region": geocoder.description_for_number(number, "en"),
            "carrier": carrier.name_for_number(number, "en"),
            "number_type": _NUMBER_TYPE.get(phonenumbers.number_type(number), "unknown"),
            "timezone": timezone.time_zones_for_number(number),
            "valid": phonenumbers.is_valid_number(number),
        }
        if region_code == "DK":
            detail.update(dk_enrichment(national))
        return SourceResult(
            source=self.name, category=self.category,
            findings=[Finding(source=self.name, category=self.category, status="found", detail=detail)],
        )


@source(category="phone", name="Facebook breach (haveibeenzuckered)")
class HaveIBeenZuckeredSource(DataSource):
    """Check the phone against the 2019 Facebook 533M leak (keyless API)."""

    def check(self, target: str) -> SourceResult:
        import re
        digits = re.sub(r"\D", "", target)
        url = f"https://haveibeenzuckered.com/api/check?phone={digits}"
        try:
            data = json.loads(get(url, timeout=15).text)
        except (HttpError, json.JSONDecodeError) as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        if data.get("found"):
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="found",
                                  detail={"type": "facebook_breach", "phone": data.get("phone"),
                                          "display_phone": data.get("display_phone")}, confidence=0.9)],
            )
        return SourceResult(
            source=self.name, category=self.category,
            findings=[Finding(source=self.name, category=self.category, status="not_found",
                              detail={"type": "facebook_breach"})],
        )


@source(category="phone", name="Carrier lookup (freecarrierlookup)")
class FreeCarrierLookupSource(DataSource):
    """Carrier + email-to-SMS gateway via freecarrierlookup.com (keyless)."""

    def check(self, target: str) -> SourceResult:
        import re
        digits = re.sub(r"\D", "", target)
        url = f"https://www.freecarrierlookup.com/phone/{digits}"
        try:
            resp = get(url, timeout=15)
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        carrier = re.search(r'Carrier[^<]*</[^>]*>\s*<[^>]*>([^<]+)', resp.text)
        gateway = re.search(r'([a-z0-9._-]+@[a-z0-9._-]+\.[a-z]+)', resp.text)
        if not carrier and not gateway:
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found",
                                  detail={"type": "carrier"})],
            )
        return SourceResult(
            source=self.name, category=self.category,
            findings=[Finding(source=self.name, category=self.category, status="found",
                              detail={"type": "carrier",
                                      "carrier": carrier.group(1).strip() if carrier else None,
                                      "sms_gateway": gateway.group(1) if gateway else None})],
        )


@source(category="phone", name="Reverse search")
class PhoneReverseSearchSource(DataSource):
    """Keyless reverse lookup: search the number across engines + DK/EU directories."""

    def check(self, target: str) -> SourceResult:
        import re

        digits = re.sub(r"\D", "", target)
        queries = [
            f'"{digits}"',
            f'"{target}"',
            f'site:krak.dk OR site:degulesider.dk OR site:118.dk "{digits}"',
            f'site:proff.dk OR site:cvrapi.dk OR site:virk.dk "{digits}"',
        ]
        findings: list[Finding] = []
        seen: set[str] = set()
        for q in queries:
            try:
                results = search_all(q)
            except HttpError:
                continue
            for url, title in results:
                if url in seen:
                    continue
                seen.add(url)
                findings.append(
                    Finding(source=self.name, category=self.category, status="found",
                            url=url, detail={"type": "reverse_search", "title": title},
                            confidence=0.4)
                )
        if not findings:
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found",
                                  detail={"type": "reverse_search"})],
            )
        return SourceResult(source=self.name, category=self.category, findings=findings)
