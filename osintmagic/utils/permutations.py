"""Username and email candidate generation.

``expand_variants`` implements Sherlock's ``{?}`` wildcard; ``name_candidates``
and ``email_candidates`` turn a real name into plausible handles/addresses for
the person module.
"""
from __future__ import annotations

import re

_SEPARATORS = ("", "_", "-", ".")

_COMMON_EMAIL_DOMAINS = ("gmail.com", "outlook.com", "yahoo.com", "protonmail.com")


def _clean(part: str) -> str:
    return re.sub(r"[^a-z0-9._-]", "", part.lower())


def expand_variants(username: str) -> list[str]:
    """Expand a ``{?}`` wildcard into the four Sherlock separators."""
    if "{?}" not in username:
        return [username]
    return [username.replace("{?}", sep) for sep in _SEPARATORS]


def name_candidates(first: str, last: str, middle: str = "") -> list[str]:
    """Generate candidate usernames from a person's name (deduped, ordered)."""
    f = _clean(first)
    l = _clean(last)
    m = _clean(middle)
    if not f and not l:
        return []

    fi = f[0] if f else ""
    li = l[0] if l else ""

    parts: list[tuple[str, ...]] = []
    for sep in _SEPARATORS:
        parts.append((f, l))
        if fi:
            parts.append((fi, l))
        if fi and li:
            parts.append((fi, li))
        if li:
            parts.append((f, li))
        if sep:
            # only build dotted/underscored/dashed forms here; bare forms already above
            parts.append((f, sep, l))
            if fi:
                parts.append((fi, sep, l))
            if fi and li:
                parts.append((fi, sep, li))
            if li:
                parts.append((f, sep, li))

    out: list[str] = []
    seen: set[str] = set()
    for p in parts:
        candidate = "".join(p).strip("._-")
        if candidate and candidate not in seen:
            seen.add(candidate)
            out.append(candidate)

    # Single-name and reversed-name fallbacks.
    for extra in (f, l, (l + f) if (f and l) else ""):
        if extra and extra not in seen:
            seen.add(extra)
            out.append(extra)

    if m and f and l:
        for cand in ((f + m + l), (fi + m + l), (f + m + li)):
            if cand not in seen:
                seen.add(cand)
                out.append(cand)

    return out


def email_candidates(first: str, last: str, middle: str = "") -> list[str]:
    """Generate plausible email addresses across common free providers."""
    f = _clean(first)
    l = _clean(last)
    m = _clean(middle)
    if not f and not l:
        return []

    fi = f[0] if f else ""
    li = l[0] if l else ""

    local_parts: list[str] = []
    for sep in _SEPARATORS:
        local_parts.append(sep.join([p for p in (f, l) if p]))
        if fi:
            local_parts.append(sep.join([p for p in (fi, l) if p]))
        if li:
            local_parts.append(sep.join([p for p in (f, li) if p]))
        if fi and li:
            local_parts.append(sep.join([p for p in (fi, li) if p]))
    if m and f and l:
        local_parts.append(f + m + l)
        local_parts.append(fi + m + l)
        local_parts.append(f + m + li)

    out: list[str] = []
    seen: set[str] = set()
    for lp in local_parts:
        lp = lp.strip("._-")
        if not lp:
            continue
        for domain in _COMMON_EMAIL_DOMAINS:
            email = f"{lp}@{domain}"
            if email not in seen:
                seen.add(email)
                out.append(email)
    return out


def dork_queries(full_name: str) -> list[str]:
    """Google-dork style queries for a person (rendered copyable in the UI)."""
    n = full_name.strip()
    q = f'"{n}"'
    return [
        q,
        f'site:linkedin.com/in "{n}"',
        f'site:github.com "{n}"',
        f'site:twitter.com "{n}"',
        f'site:instagram.com "{n}"',
        f'intitle:"{n}"',
        f'"{n}" email',
        f'"{n}" phone',
    ]


def domain_dorks(domain: str) -> list[str]:
    """Google-dork queries for a domain's attack surface (external recon).

    Organised by intent: files, directories, auth, secrets, code and third-party.
    """
    d = domain.strip().lower().rstrip("/")
    return [
        # discovery
        f"site:{d}",
        f"site:*:{d}",
        # exposed files / backups
        f"site:{d} filetype:pdf",
        f"site:{d} filetype:xlsx OR filetype:docx OR filetype:csv OR filetype:txt",
        f"site:{d} ext:env OR ext:log OR ext:sql OR ext:bak OR ext:old OR ext:conf",
        f"site:{d} ext:key OR ext:pem OR ext:crt OR ext:p12",
        # directory listings / paths
        f'site:{d} intitle:"index of"',
        f'site:{d} "index of /"',
        f'site:{d} inurl:backup OR inurl:old OR inurl:temp OR inurl:dump',
        # auth / admin surfaces
        f"site:{d} inurl:admin",
        f"site:{d} inurl:login OR inurl:signin OR inurl:signup",
        f"site:{d} inurl:api OR inurl:graphql OR inurl:swagger",
        f"site:{d} inurl:phpmyadmin OR inurl:jenkins OR inurl:dashboard",
        # secrets in code
        f'site:github.com "{d}" password OR secret OR api_key OR token',
        f'site:gitlab.com "{d}" password OR secret OR api_key',
        f'site:gist.github.com "{d}"',
        # third-party / leaks
        f'site:pastebin.com "{d}"',
        f'site:paste.ee OR site:controlc.com OR site:rentry.co "{d}"',
        f"site:trello.com OR site:atlassian.net \"{d}\"",
        f'"{d}" breach OR leaked OR dump',
        # outside the site
        f'"{d}" -site:{d}',
    ]


def username_dorks(username: str) -> list[str]:
    u = username.strip()
    return [
        f'"{u}"',
        f'site:github.com "{u}"',
        f'site:twitter.com OR site:x.com "{u}"',
        f'site:reddit.com "{u}"',
        f'site:pastebin.com "{u}"',
        f'"{u}" email OR @gmail.com OR @protonmail.com',
        f'intext:"{u}" password OR leak',
    ]


def email_dorks(email: str) -> list[str]:
    e = email.strip()
    return [
        f'"{e}"',
        f'site:pastebin.com OR site:paste.ee OR site:rentry.co "{e}"',
        f'site:github.com "{e}"',
        f'"{e}" password OR leak OR breach',
        f'intext:"{e}"',
    ]


# --- Typosquatting / brand-impersonation permutation engine -------------------

_KEYBOARD_ADJACENT = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
    "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "i": "ujko", "j": "huikmn",
    "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu", "z": "asx",
}

_HOMOGLYPHS = {
    "o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "t": "7",
    "b": "6", "g": "9", "m": "rn", "n": "m", "w": "vv", "d": "cl", "k": "ik",
}

_VOWELS = "aeiou"

_TLD_TYPOS = [
    "com", "net", "org", "co", "io", "info", "biz", "ru", "cn", "top",
    "xyz", "site", "online", "shop", "app", "store", "live", "co.uk", "com.br",
]

_COMMON_WORDS = [
    "-secure", "-login", "-support", "-help", "-account", "-verify", "-update",
    "-mail", "-portal", "-auth", "-service", "-official", "-www", "-app",
]


def _split_domain(domain: str) -> tuple[str, str]:
    """Return (first_label, rest) for a domain, tolerating sub-subdomains."""
    parts = domain.strip().lower().strip(".").split(".", 1)
    return (parts[0], parts[1] if len(parts) > 1 else "")


def domain_permutations(domain: str) -> list[tuple[str, str]]:
    """Generate typosquatting/lookalike candidates as ``(domain, fuzzer)`` pairs.

    Techniques mirror dnstwist: omission, repetition, replacement, transposition,
    insertion, addition, hyphenation, subdomain, vowel-swap, bitsquatting,
    homoglyph and TLD swap. Deduplicated and capped to bound DNS traffic.
    """
    domain = domain.strip().lower().strip(".")
    label, rest = _split_domain(domain)
    suffix = f".{rest}" if rest else ".com"
    out: dict[str, str] = {}

    def add(candidate: str, fuzzer: str) -> None:
        candidate = candidate.strip("-.").lower()
        if candidate and candidate != domain and candidate not in out:
            out[candidate] = fuzzer

    def with_label(new_label: str) -> str:
        return f"{new_label}{suffix}"

    for i in range(len(label)):
        add(with_label(label[:i] + label[i + 1:]), "omission")          # omission
        add(with_label(label[:i] + label[i] * 2 + label[i + 1:]), "repetition")  # repetition
        for ch in _KEYBOARD_ADJACENT.get(label[i], ""):
            add(with_label(label[:i] + ch + label[i + 1:]), "replacement")  # replacement
        if i < len(label) - 1:
            swapped = label[:i] + label[i + 1] + label[i] + label[i + 2:]
            add(with_label(swapped), "transposition")                   # transposition
        code = ord(label[i])
        for bit in range(8):
            flipped = chr(code ^ (1 << bit))
            if flipped.isalnum():
                add(with_label(label[:i] + flipped + label[i + 1:]), "bitsquatting")
        if label[i] in _HOMOGLYPHS:
            add(with_label(label[:i] + _HOMOGLYPHS[label[i]] + label[i + 1:]), "homoglyph")
        if label[i] in _VOWELS:
            for v in _VOWELS:
                if v != label[i]:
                    add(with_label(label[:i] + v + label[i + 1:]), "vowel-swap")

    for ch in "abcdefghijklmnopqrstuvwxyz0123456789":
        for i in range(len(label) + 1):
            add(with_label(label[:i] + ch + label[i:]), "insertion")   # insertion

    for word in _COMMON_WORDS:
        add(f"{label}{word}{suffix}", "addition")                       # addition

    add(f"{label}-{rest or 'com'}", "hyphenation")                       # hyphenation
    add(f"{label}.{rest or 'com'}", "subdomain")                        # subdomain

    base = rest.split(".")[-1] if rest else "com"
    for tld in _TLD_TYPOS:
        if tld != base:
            add(f"{label}.{tld}", "tld-swap")                           # TLD swap

    return sorted(out.items(), key=lambda kv: kv[0])


def phone_dorks(phone: str) -> list[str]:
    """Google-dork queries for a phone number (keyless public lookups)."""
    p = phone.strip()
    digits = re.sub(r"\D", "", p)
    return [
        f'"{p}"',
        f'"{digits}"',
        f'site:facebook.com "{digits}"',
        f'site:linkedin.com "{digits}"',
        f'site:instagram.com "{digits}"',
        f'site:krak.dk OR site:degulesider.dk OR site:118.dk "{digits}"',
        f'site:proff.dk OR site:cvrapi.dk OR site:virk.dk "{digits}"',
        f'site:truecaller.com OR site:numlookup.com "{digits}"',
        f'"{digits}" name OR cvr OR virksomhed',
        f'"{p}" OR "{digits}"',
    ]


_PEOPLE_SEARCH_ENGINES = (
    ("FamilyTreeNow", "https://www.familytreenow.com/search/results?first={first}&last={last}"),
    ("Judyrecords", "https://www.judyrecords.com/#!/search?f={first}&l={last}"),
    ("OpenSanctions", "https://www.opensanctions.org/search/?q={name}"),
    ("IDCrawl", "https://www.idcrawl.com/{first}-{last}"),
    ("Social Searcher", "https://www.social-searcher.com/google-social-search/?q={name}"),
    ("PeekYou", "https://www.peekyou.com/{first}_{last}"),
    ("GitHub", "https://github.com/search?q={name}&type=users"),
    ("Reddit", "https://www.reddit.com/search/?q=%22{name}%22"),
    ("DuckDuckGo", "https://duckduckgo.com/?q={name}"),
)


def people_search_links(first: str, last: str, full_name: str) -> list[tuple[str, str]]:
    """Keyless people-search links pre-filled with the name (no scraping)."""
    first = _clean(first)
    last = _clean(last)
    name = full_name.strip().replace(" ", "%20")
    links = []
    for label, template in _PEOPLE_SEARCH_ENGINES:
        url = (template
               .replace("{first}", first)
               .replace("{last}", last)
               .replace("{name}", name))
        links.append((label, url))
    return links


def levenshtein(a: str, b: str) -> int:
    """Edit distance (used for lookalike-domain and sender similarity)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def similarity(a: str, b: str) -> float:
    """Normalised similarity in [0, 1] from edit distance."""
    longest = max(len(a), len(b))
    return 1.0 if longest == 0 else 1.0 - levenshtein(a, b) / longest
