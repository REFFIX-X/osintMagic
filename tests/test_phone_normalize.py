"""Tests for intelligent phone normalization + DK enrichment."""
from osintmagic.utils.phone import dk_enrichment, normalize_phone, phone_directories


def test_e164_form():
    n = normalize_phone("+45 61608441")
    assert n and n["e164"] == "+4561608441"
    assert n["region"] == "DK"


def test_leading_00_prefix():
    n = normalize_phone("004561608441")
    assert n and n["e164"] == "+4561608441"


def test_country_name_form():
    n = normalize_phone("Denmark 61608441")
    assert n and n["e164"] == "+4561608441"
    assert n["country"] == "Denmark"


def test_us_number():
    n = normalize_phone("+1 650 253 0000")
    assert n and n["e164"] == "+16502530000"
    assert n["region"] == "US"


def test_unparseable_returns_none():
    assert normalize_phone("not a phone") is None
    assert normalize_phone("") is None
    assert normalize_phone("123") is None


def test_dk_mobile_carrier_hint():
    assert dk_enrichment("61 60 84 41")["mobile_carrier_hint"] == "TDC"
    assert dk_enrichment("22 33 44 55")["mobile_carrier_hint"] == "TDC / Telia"
    assert dk_enrichment("42 00 11 22")["mobile_carrier_hint"] == "Telenor"


def test_dk_area_hint():
    assert dk_enrichment("32 12 34 56")["area_hint"] == "Copenhagen"
    assert dk_enrichment("86 12 34 56")["area_hint"] == "Aarhus"


def test_phone_directories():
    links = phone_directories("+4561608441")
    labels = [l for l, _ in links]
    assert "Krak (DK)" in labels
    assert "Truecaller" in labels
    assert all(u.startswith("http") for _, u in links)
