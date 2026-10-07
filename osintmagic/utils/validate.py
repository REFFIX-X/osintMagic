"""Input validators for the supported target types."""
from __future__ import annotations

import ipaddress
import re

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def is_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value.strip()))


def is_username(value: str) -> bool:
    return bool(_USERNAME_RE.match(value.strip()))


def is_domain(value: str) -> bool:
    v = value.strip().lower().rstrip(".")
    return bool(_DOMAIN_RE.match(v))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    """True only for globally-routable unicast addresses (rejects private,
    loopback, link-local, multicast and reserved ranges)."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return ip.is_global and not ip.is_private


def is_phone(value: str) -> bool:
    """Lenient input gate: looks like a phone number (6-15 digits, common separators).

    Deliberately does not require libphonenumber to judge it "possible" — the
    Number Info source does the strict parse and reports its own verdict.
    """
    v = value.strip()
    if not re.match(r"^\+?[0-9\s().-]{6,24}$", v):
        return False
    digits = re.sub(r"\D", "", v)
    return 6 <= len(digits) <= 15
