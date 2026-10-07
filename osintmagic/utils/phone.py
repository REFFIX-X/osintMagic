"""Intelligent phone-number parsing/normalization + static regional enrichment.

Handles freeform input such as ``+45 61608441``, ``004561608441`` or
``Denmark 61608441``, returning a canonical E.164 number plus the detected
country region, so the phone module can run without the analyst massaging input.
"""
from __future__ import annotations


def normalize_phone(raw: str) -> dict | None:
    """Return ``{e164, region, country}`` for freeform phone input, or None."""
    import phonenumbers

    raw = raw.strip()
    if not raw:
        return None

    region: str | None = None

    # Detect a country name (e.g. "Denmark") anywhere in the input; longest first
    # so "Dominican Republic" isn't matched as "Dominica".
    try:
        import pycountry
        low = raw.lower()
        for country in sorted(pycountry.countries, key=lambda c: -len(c.name)):
            if country.name.lower() in low:
                region = country.alpha_2
                low = low.replace(country.name.lower(), " ")
                raw = " ".join(low.split())
                break
    except ImportError:
        pass

    # "00" international prefix -> "+".
    raw = raw.lstrip()
    if raw.startswith("00"):
        raw = "+" + raw[2:]

    try:
        number = phonenumbers.parse(raw, region) if region else phonenumbers.parse(raw, None)
    except phonenumbers.NumberParseException:
        return None

    if not phonenumbers.is_possible_number(number):
        return None

    e164 = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
    detected_region = phonenumbers.region_code_for_number(number)
    national = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL)

    country = None
    if detected_region:
        try:
            import pycountry
            country = pycountry.countries.get(alpha_2=detected_region)
            country = country.name if country else None
        except ImportError:
            country = None

    return {"e164": e164, "region": detected_region, "country": country, "national": national}


# --- Danish static enrichment (indicative; number portability may differ) ----

_DK_MOBILE_CARRIERS = [
    ((20, 23), "TDC / Telia"),
    ((25, 27), "TDC"),
    ((30, 31), "TDC"),
    ((40, 42), "Telenor"),
    ((50, 53), "TDC / 3"),
    ((60, 61), "TDC"),
    ((71, 72), "Telenor"),
    ((81, 81), "TDC"),
    ((91, 93), "3 (Three)"),
]

_DK_AREA_CODES = [
    ((32, 39), "Copenhagen"),
    ((42, 49), "Zealand"),
    ((54, 59), "South Jutland"),
    ((62, 66), "Funen / Odense"),
    ((69, 69), "Funen"),
    ((72, 79), "North Jutland"),
    ((86, 87), "Aarhus"),
    ((96, 99), "North Jutland"),
]


def dk_enrichment(national: str) -> dict:
    """Return a Danish carrier/area hint from the national number, or ``{}``."""
    digits = "".join(ch for ch in national if ch.isdigit())
    if not digits or len(digits) < 8:
        return {}
    try:
        prefix = int(digits[:2])
    except ValueError:
        return {}
    for (lo, hi), carrier in _DK_MOBILE_CARRIERS:
        if lo <= prefix <= hi:
            return {"mobile_carrier_hint": carrier}
    for (lo, hi), area in _DK_AREA_CODES:
        if lo <= prefix <= hi:
            return {"area_hint": area}
    return {}


def phone_directories(e164: str) -> list[tuple[str, str]]:
    """Danish/EU + global reverse-lookup directories (clickable, keyless)."""
    digits = "".join(ch for ch in e164 if ch.isdigit())
    return [
        ("Krak (DK)", f"https://www.krak.dk/telefon/{digits}"),
        ("De Gule Sider (DK)", f"https://www.degulesider.dk/soeg?q={digits}"),
        ("118.dk (DK)", f"https://www.118.dk/soeg?q={digits}"),
        ("Proff (DK/EU)", f"https://www.proff.dk/firma?query={digits}"),
        ("Truecaller", f"https://www.truecaller.com/search/{digits}"),
        ("Numlookup", f"https://www.numlookup.com/{digits}"),
        ("DuckDuckGo", f"https://duckduckgo.com/?q=%22{digits}%22"),
    ]
