"""Domain recon (keyless subset of theHarvester).

Five independent sources: crt.sh + CertSpotter (certificate transparency),
Wayback Machine CDX (historic subdomains), DNS records (with SPF/DMARC parsing),
and RDAP/whois. Each runs in isolation so one failing provider never blocks the
others.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

from ..http_client import HttpError, get
from ..models import Finding, SourceResult
from ..registry import source
from .base import DataSource


def _subdomain_findings(provider: str, domain: str, subs: set[str]) -> list[Finding]:
    return [
        Finding(
            source=f"{provider}",
            category="domain",
            status="found",
            url=f"https://{s}",
            detail={"type": "subdomain", "provider": provider},
        )
        for s in sorted(subs)
    ]


def _parse_ct_date(value: str | None):
    if not value:
        return None
    from datetime import datetime, timezone
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


@source(category="domain", name="crt.sh")
class CrtshSource(DataSource):
    """Subdomain discovery plus certificate-level analysis.

    Beyond enumerating names, flags phishing indicators present in the CT log:
    wildcard certs, recently-issued certs, and an unexpectedly long tail of
    certificate authorities (a CA issuing very few certs for the domain while a
    dominant CA issues most is a weak but useful anomaly signal).
    """

    def check(self, target: str) -> SourceResult:
        domain = target.lower().rstrip(".")
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            data = json.loads(get(url, timeout=12).text)
        except (HttpError, json.JSONDecodeError) as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        from collections import Counter
        from datetime import datetime, timedelta, timezone

        subs: set[str] = set()
        issuers: Counter = Counter()
        wildcards = 0
        recent = 0
        now = datetime.now(timezone.utc)
        for cert in data:
            issuers[cert.get("issuer_name", "Unknown CA")] += 1
            for name_value in (cert.get("name_value") or "").split("\n"):
                nv = name_value.strip().lower()
                if not nv:
                    continue
                if nv.startswith("*."):
                    wildcards += 1
                plain = nv.lstrip("*.")
                if plain and plain != domain and plain.endswith("." + domain):
                    subs.add(plain)
            nb = _parse_ct_date(cert.get("not_before"))
            if nb and (now - nb) <= timedelta(days=90):
                recent += 1

        findings = _subdomain_findings("crt.sh", domain, subs)

        if issuers:
            dominant = issuers.most_common(1)[0][1]
            long_tail = {ca for ca, n in issuers.items() if n <= 2 and n < dominant}
            findings.append(Finding(
                source=self.name, category=self.category, status="info",
                detail={"type": "CT issuers", "value": len(issuers),
                        "top": issuers.most_common(3),
                        "unexpected_cas": sorted(long_tail) if long_tail else None,
                        "note": "unusual CAs may indicate external/phishing issuance" if long_tail else None},
            ))
        findings.append(Finding(
            source=self.name, category=self.category, status="info",
            detail={"type": "CT wildcard certs", "value": wildcards},
        ))
        findings.append(Finding(
            source=self.name, category=self.category, status="info",
            detail={"type": "CT recent certs (90d)", "value": recent},
        ))
        return SourceResult(source=self.name, category=self.category, findings=findings)


@source(category="domain", name="CertSpotter")
class CertSpotterSource(DataSource):
    def check(self, target: str) -> SourceResult:
        domain = target.lower().rstrip(".")
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        try:
            data = json.loads(get(url, timeout=12).text)
        except (HttpError, json.JSONDecodeError) as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        subs: set[str] = set()
        for item in data:
            for dns_name in item.get("dns_names", []):
                nv = dns_name.strip().lstrip("*.").lower()
                if nv and nv != domain and nv.endswith("." + domain):
                    subs.add(nv)
        return SourceResult(
            source=self.name, category=self.category,
            findings=_subdomain_findings("certspotter", domain, subs),
        )


@source(category="domain", name="Wayback Machine")
class WaybackSource(DataSource):
    def check(self, target: str) -> SourceResult:
        domain = target.lower().rstrip(".")
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=200"
        )
        try:
            data = json.loads(get(url, timeout=15).text)
        except (HttpError, json.JSONDecodeError) as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        subs: set[str] = set()
        for row in data[1:]:
            host = urlparse(row[0]).hostname
            if host and host.lower().endswith("." + domain):
                subs.add(host.lower())
        return SourceResult(
            source=self.name, category=self.category,
            findings=_subdomain_findings("wayback", domain, subs),
        )


_DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
    "mail", "dkim", "mandrill", "mailchimp", "sendgrid", "amazonses", "zoho", "smtp",
)


def _auth_assessment(spf: bool, dmarc: bool) -> str:
    if spf and dmarc:
        return "SPF and DMARC present"
    if spf and not dmarc:
        return "SPF present but DMARC missing (spoofing exposure)"
    if dmarc and not spf:
        return "DMARC present but SPF missing"
    return "no SPF or DMARC found (spoofing exposure)"


def _txt_strings(answer) -> list[str]:
    out = []
    for rdata in answer:
        out.append("".join(
            s.decode() if isinstance(s, bytes) else s for s in rdata.strings
        ))
    return out


@source(category="domain", name="DNS Records")
class DnsSource(DataSource):
    def check(self, target: str) -> SourceResult:
        domain = target.lower().rstrip(".")
        try:
            import dns.resolver
        except ImportError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        findings: list[Finding] = []

        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                for answer in dns.resolver.resolve(domain, rtype, lifetime=8):
                    if rtype == "TXT":
                        for txt in _txt_strings([answer]):
                            findings.append(self._record("TXT", txt))
                            if txt.startswith("v=spf1"):
                                findings.append(self._spf_finding(txt))
                    else:
                        findings.append(self._record(rtype, str(answer)))
            except Exception:
                continue  # a domain legitimately lacks some record types

        # DMARC policy from _dmarc.<domain>.
        has_dmarc = False
        try:
            for txt in _txt_strings(dns.resolver.resolve("_dmarc." + domain, "TXT", lifetime=8)):
                if txt.startswith("v=DMARC1"):
                    findings.append(self._record("DMARC", txt))
                    has_dmarc = True
        except Exception:
            pass

        # DKIM selectors — probe common ones (findings feed the auth posture).
        dkim_selectors = []
        for sel in _DKIM_SELECTORS:
            try:
                for txt in _txt_strings(dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT", lifetime=6)):
                    if "v=DKIM1" in txt or "p=" in txt:
                        findings.append(self._record("DKIM", f"selector={sel}"))
                        dkim_selectors.append(sel)
                        break
            except Exception:
                continue

        # Consolidated email-authentication posture.
        has_spf = any(f.detail.get("type") == "SPF" for f in findings)
        findings.append(
            Finding(
                source=self.name, category=self.category, status="info",
                detail={
                    "type": "Email auth posture",
                    "spf": has_spf,
                    "dmarc": has_dmarc,
                    "dkim_selectors": dkim_selectors or None,
                    "assessment": _auth_assessment(has_spf, has_dmarc),
                },
            )
        )

        return SourceResult(source=self.name, category=self.category, findings=findings)

    def _record(self, rtype: str, value: str) -> Finding:
        return Finding(
            source=self.name, category=self.category, status="info",
            detail={"type": rtype, "value": value},
        )

    def _spf_finding(self, spf: str) -> Finding:
        return Finding(
            source=self.name, category=self.category, status="info",
            detail={
                "type": "SPF",
                "value": spf,
                "includes": [t[8:] for t in spf.split() if t.startswith("include:")],
                "ip4": [t[4:] for t in spf.split() if t.startswith("ip4:")],
            },
        )


def _vcard_field(entity: dict, field: str) -> str | None:
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if isinstance(item, list) and item and item[0] == field and len(item) > 3:
            return str(item[3])
    return None


@source(category="domain", name="RDAP / Whois")
class RdapSource(DataSource):
    def check(self, target: str) -> SourceResult:
        domain = target.lower().rstrip(".")
        url = f"https://rdap.org/domain/{domain}"
        try:
            resp = get(url, timeout=15)
            if resp.status_code >= 400:
                return SourceResult(source=self.name, category=self.category, error=f"http {resp.status_code}")
            data = json.loads(resp.text)
        except (HttpError, json.JSONDecodeError) as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        detail: dict = {"type": "whois", "handle": data.get("handle"), "status": data.get("status")}
        for event in data.get("events", []):
            action = event.get("eventAction")
            if action in ("registration", "expiration", "last changed"):
                detail[action.replace(" ", "_")] = event.get("eventDate")

        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                detail["registrar"] = _vcard_field(entity, "fn")
            if "abuse" in roles:
                for vcard_item in (entity.get("vcardArray") or [None, []])[1]:
                    if isinstance(vcard_item, list) and vcard_item and vcard_item[0] == "email" and len(vcard_item) > 3:
                        detail["abuse_email"] = str(vcard_item[3])

        return SourceResult(
            source=self.name, category=self.category,
            findings=[Finding(source=self.name, category=self.category, status="info", detail=detail)],
        )


@source(category="domain", name="Zone Transfer (AXFR)")
class ZoneTransferSource(DataSource):
    """Attempt an unauthenticated DNS zone transfer against each nameserver.

    A successful AXFR is a misconfiguration that leaks the full zone (every
    host and record). Queries the domain's own authoritative servers only.
    """

    def check(self, target: str) -> SourceResult:
        domain = target.lower().rstrip(".")
        try:
            import dns.query
            import dns.resolver
            import dns.zone
        except ImportError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        try:
            nameservers = [str(a).rstrip(".") for a in dns.resolver.resolve(domain, "NS", lifetime=8)]
        except Exception as exc:
            return SourceResult(source=self.name, category=self.category, error=f"no NS records: {exc}")

        leaked: list[Finding] = []
        for ns in nameservers:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, lifetime=12))
            except Exception:
                continue  # transfer refused — the expected, secure outcome
            names = sorted(str(n) for n in zone.nodes)
            leaked.append(
                Finding(
                    source=self.name, category=self.category, status="found",
                    detail={"type": "AXFR", "nameserver": ns, "records": len(names), "sample": names[:50]},
                )
            )

        if leaked:
            return SourceResult(source=self.name, category=self.category, findings=leaked)
        return SourceResult(
            source=self.name, category=self.category,
            findings=[
                Finding(
                    source=self.name, category=self.category, status="info",
                    detail={"type": "AXFR", "result": "zone transfer refused", "nameservers": nameservers},
                )
            ],
        )


_BUCKET_SUFFIXES = ("", "-backup", "-dev", "-prod", "-staging", "-test", "-assets", "-data", "-files", "-media")
_BUCKET_PROVIDERS = ("s3", "gcp", "azure")


def _bucket_names(domain: str) -> list[str]:
    label = domain.split(".")[0]
    full_dash = domain.replace(".", "-")
    names: list[str] = []
    for base in (label, full_dash):
        for suffix in _BUCKET_SUFFIXES:
            candidate = base + suffix
            if candidate not in names:
                names.append(candidate)
    return names


def _probe_bucket(provider: str, bucket: str) -> str | None:
    """Return 'public' (listable), 'private' (name registered) or None.

    Classification uses the provider's XML error code, not the HTTP status
    alone: S3/GCP answer ``NoSuchBucket`` for a free name but
    ``AccessDenied``/``PermanentRedirect`` when the name is taken by someone.
    """
    if provider == "s3":
        url = f"https://{bucket}.s3.amazonaws.com/"
    elif provider == "gcp":
        url = f"https://storage.googleapis.com/{bucket}/"
    else:  # azure
        url = f"https://{bucket}.blob.core.windows.net/?comp=list"
    try:
        resp = get(url, timeout=7)
    except HttpError:
        return None  # includes Azure names that do not resolve at all

    body = resp.text
    if resp.status_code == 200:
        return "public"
    if "NoSuchBucket" in body or "NoSuchKey" in body:
        return None
    if "AccessDenied" in body or "PermanentRedirect" in body:
        return "private"
    if provider == "azure" and resp.status_code in (403, 409):
        return "private"
    return None


_BUCKET_URLS = {
    "s3": "https://{bucket}.s3.amazonaws.com/",
    "gcp": "https://storage.googleapis.com/{bucket}/",
    "azure": "https://{bucket}.blob.core.windows.net/",
}


@source(category="domain", name="Cloud Buckets")
class CloudBucketSource(DataSource):
    """Probe common S3 / GCP / Azure bucket names derived from the domain.

    A publicly-listable bucket is a real exposure; a name that merely resolves
    to a private bucket is only *globally registered* — its owner is not
    confirmed to be the target, so it is reported as low-confidence info.
    """

    def check(self, target: str) -> SourceResult:
        domain = target.lower().rstrip(".")
        findings: list[Finding] = []

        from concurrent.futures import ThreadPoolExecutor
        combos = [(provider, bucket) for bucket in _bucket_names(domain) for provider in _BUCKET_PROVIDERS]
        with ThreadPoolExecutor(max_workers=10) as ex:
            states = list(ex.map(lambda cb: (cb[0], cb[1], _probe_bucket(cb[0], cb[1])), combos))
        for provider, bucket, state in states:
            if state is None:
                continue
            public = state == "public"
            findings.append(
                Finding(
                    source=self.name, category=self.category,
                    status="found" if public else "info",
                    url=_BUCKET_URLS[provider].format(bucket=bucket),
                    detail={
                        "type": "bucket",
                        "provider": provider,
                        "access": state,
                        "ownership": "public listing" if public else "name registered (owner unconfirmed)",
                    },
                    confidence=0.8 if public else 0.4,
                )
            )
        if not findings:
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found", detail={"type": "bucket"})],
            )
        return SourceResult(source=self.name, category=self.category, findings=findings)


_CDN_HEADERS = {
    "cf-ray": "Cloudflare", "cf-cache-status": "Cloudflare", "server": None,
    "x-amz-cf-id": "Amazon CloudFront", "x-amz-cf-pop": "Amazon CloudFront",
    "x-azure-ref": "Azure Front Door", "x-fd-healthprobe": "Azure Front Door",
    "x-sucuri-id": "Sucuri", "x-sucuri-cache": "Sucuri",
    "x-fastly-request-id": "Fastly", "fastly-io-info": "Fastly",
    "x-vercel-id": "Vercel", "x-vercel-cache": "Vercel",
    "x-netlify": "Netlify",
    "x-iinfo": "Imperva Incapsula",
    "x-akamai-transformed": "Akamai", "akamai-grn": "Akamai",
    "x-cdn": "Generic CDN",
}

_SERVER_MARKERS = {
    "cloudflare": "Cloudflare", "sucuri": "Sucuri", "awselb": "AWS ELB",
    "amazons3": "Amazon S3", "gws": "Google Web Server", "gse": "Google",
    "akamaighost": "Akamai", "varnish": "Varnish", "nginx": "nginx",
    "apache": "Apache", "microsoft-iis": "IIS", "cloudfront": "Amazon CloudFront",
}


def _detect_waf_cdn(headers: dict[str, str]) -> list[str]:
    detected: set[str] = set()
    for key, provider in _CDN_HEADERS.items():
        if key not in headers:
            continue
        if key == "server":
            server = headers["server"].lower()
            for marker, name in _SERVER_MARKERS.items():
                if marker in server:
                    detected.add(name)
        elif provider:
            detected.add(provider)
    return sorted(detected)


@source(category="domain", name="WAF / CDN")
class WafCdnSource(DataSource):
    """Identify a fronting WAF/CDN from response headers."""

    def check(self, target: str) -> SourceResult:
        domain = target.lower().rstrip(".")
        try:
            resp = get(f"https://{domain}/", timeout=12)
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        detected = _detect_waf_cdn(resp.headers)
        if not detected:
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found", detail={"type": "waf_cdn"})],
            )
        return SourceResult(
            source=self.name, category=self.category,
            findings=[
                Finding(
                    source=self.name, category=self.category, status="info",
                    detail={"type": "waf_cdn", "provider": provider},
                )
                for provider in detected
            ],
        )


_TECH_BODY_MARKERS = {
    "wp-content": "WordPress", "wp-includes": "WordPress",
    "/sites/default/files": "Drupal", "drupal-settings-json": "Drupal",
    "joomla": "Joomla", "/media/jui/": "Joomla",
    "/_next/": "Next.js", "__next_data__": "Next.js",
    "data-reactroot": "React", "ng-version": "Angular", "__nuxt": "Nuxt",
    "cdn.shopify.com": "Shopify", "shopify.theme": "Shopify",
    "wix.com": "Wix", "squarespace": "Squarespace",
    "hs-scripts.com": "HubSpot", "googletagmanager.com": "Google Tag Manager",
    "cdn.jsdelivr.net": "jsDelivr", "cdnjs.cloudflare.com": "cdnjs",
    "static.parastorage.com": "Wix", "assets.website-files.com": "Webflow",
}
_TECH_HEADER_MARKERS = {
    "x-powered-by": "X-Powered-By", "x-generator": "X-Generator",
    "x-drupal-cache": "Drupal", "x-aspnet-version": "ASP.NET",
    "x-shopify-stage": "Shopify", "x-magento-tags": "Magento",
}


def _detect_tech(headers: dict[str, str], body: str) -> list[str]:
    detected: set[str] = set()
    lowered = body.lower()
    for marker, name in _TECH_BODY_MARKERS.items():
        if marker in lowered:
            detected.add(name)
    for header, name in _TECH_HEADER_MARKERS.items():
        if header in headers:
            detected.add(name)
    server = headers.get("server")
    if server:
        for marker, name in _SERVER_MARKERS.items():
            if marker in server.lower():
                detected.add(name)
    return sorted(detected)


@source(category="domain", name="Tech Fingerprint")
class TechFingerprintSource(DataSource):
    """Identify CMS, frameworks and server software from HTML + headers."""

    def check(self, target: str) -> SourceResult:
        domain = target.lower().rstrip(".")
        try:
            resp = get(f"https://{domain}/", timeout=12)
        except HttpError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        detected = _detect_tech(resp.headers, resp.text)
        if not detected:
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found", detail={"type": "tech"})],
            )
        return SourceResult(
            source=self.name, category=self.category,
            findings=[
                Finding(source=self.name, category=self.category, status="info", detail={"type": "tech", "name": name})
                for name in detected
            ],
        )


_SUBDOMAIN_WORDLIST = (
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "admin", "api", "dev",
    "development", "staging", "stage", "test", "testing", "qa", "uat", "prod",
    "portal", "dashboard", "app", "apps", "mobile", "cms", "blog", "shop", "store",
    "cdn", "assets", "static", "media", "img", "images", "files", "download",
    "docs", "wiki", "help", "support", "status", "monitor", "metrics", "git",
    "gitlab", "jenkins", "ci", "build", "registry", "docker", "k8s", "vpn",
    "remote", "bastion", "proxy", "gateway", "dns", "ns1", "ns2", "mx", "mail1",
    "intranet", "internal", "partner", "auth", "sso", "login", "accounts", "db",
    "database", "sql", "mysql", "postgres", "mongo", "redis", "elastic", "search",
    "queue", "old", "new", "backup", "archive", "temp", "demo", "sandbox", "lab",
    "corp", "office", "owa", "exchange", "sharepoint", "drive", "cloud", "host",
    "server", "web1", "web2", "lb", "api-dev", "api-staging", "internal-api",
)


def _is_internal(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


@source(category="domain", name="Subdomain Brute-force")
class SubdomainEnumSource(DataSource):
    """Wordlist subdomain discovery with wildcard-DNS guard.

    A wildcard record makes every random name resolve; without detecting it first
    every brute-force hit would be a false positive, so that is checked up front.
    """

    WORKERS = 30

    def check(self, target: str) -> SourceResult:
        domain = target.lower().rstrip(".")
        try:
            import dns.resolver
        except ImportError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        import uuid

        wildcard_ips: set[str] = set()
        probe = f"{uuid.uuid4().hex[:12]}.{domain}"
        try:
            wildcard_ips = {str(r) for r in dns.resolver.resolve(probe, "A", lifetime=4)}
        except Exception:
            pass

        def resolve(name: str) -> list[str]:
            try:
                return [str(r) for r in dns.resolver.resolve(name, "A", lifetime=3)]
            except Exception:
                return []

        from concurrent.futures import ThreadPoolExecutor

        findings: list[Finding] = []
        names = [f"{word}.{domain}" for word in _SUBDOMAIN_WORDLIST]
        with ThreadPoolExecutor(max_workers=self.WORKERS) as ex:
            for name, ips in zip(names, ex.map(resolve, names)):
                if not ips:
                    continue
                if wildcard_ips and set(ips).issubset(wildcard_ips):
                    continue  # wildcard catch-all, not a real host
                internal = any(_is_internal(ip) for ip in ips)
                findings.append(
                    Finding(
                        source=self.name, category=self.category, status="found",
                        url=f"https://{name}",
                        detail={
                            "type": "subdomain", "ip": ips,
                            "note": "resolves to internal address" if internal else None,
                        },
                    )
                )

        if wildcard_ips:
            findings.insert(0, Finding(
                source=self.name, category=self.category, status="info",
                detail={"type": "wildcard DNS", "value": ", ".join(sorted(wildcard_ips)),
                        "note": "all unmatched names resolve — brute-force filtered"},
            ))
        if not findings:
            return SourceResult(
                source=self.name, category=self.category,
                findings=[Finding(source=self.name, category=self.category, status="not_found", detail={"type": "subdomain"})],
            )
        return SourceResult(source=self.name, category=self.category, findings=findings)


_SRV_SERVICES = (
    "_sip._tcp", "_sip._udp", "_sips._tcp", "_ldap._tcp", "_kerberos._tcp",
    "_autodiscover._tcp", "_xmpp-server._tcp", "_sipfederationtls._tcp",
    "_imap._tcp", "_caldavs._tcp", "_vpn._tcp", "_gc._tcp",
)


@source(category="domain", name="DNSSEC / SRV")
class DnsSecuritySource(DataSource):
    """DNSSEC deployment and SRV service discovery."""

    def check(self, target: str) -> SourceResult:
        domain = target.lower().rstrip(".")
        try:
            import dns.resolver
        except ImportError as exc:
            return SourceResult(source=self.name, category=self.category, error=str(exc))

        findings: list[Finding] = []

        has_dnskey = has_ds = False
        try:
            has_dnskey = bool(list(dns.resolver.resolve(domain, "DNSKEY", lifetime=6)))
        except Exception:
            pass
        try:
            has_ds = bool(list(dns.resolver.resolve(domain, "DS", lifetime=6)))
        except Exception:
            pass
        findings.append(Finding(
            source=self.name, category=self.category, status="info",
            detail={
                "type": "DNSSEC",
                "value": "enabled" if (has_dnskey or has_ds) else "not enabled",
                "dnskey": has_dnskey, "ds": has_ds,
            },
        ))

        for service in _SRV_SERVICES:
            try:
                answers = dns.resolver.resolve(f"{service}.{domain}", "SRV", lifetime=5)
            except Exception:
                continue
            for ans in answers:
                findings.append(Finding(
                    source=self.name, category=self.category, status="info",
                    detail={"type": "SRV", "value": f"{service} -> {ans.target.to_text().rstrip('.')}:{ans.port}"},
                ))

        return SourceResult(source=self.name, category=self.category, findings=findings)


@source(category="domain", name="Amass (deep)")
class AmassSource(DataSource):
    """Passive subdomain enumeration via OWASP Amass (optional binary)."""

    deep = True

    def check(self, target: str) -> SourceResult:
        from ..backends import run_amass

        domain = target.lower().rstrip(".")
        result = run_amass(domain)
        if not result["available"]:
            return SourceResult(source=self.name, category=self.category, error=result["reason"])
        if result["reason"]:
            return SourceResult(source=self.name, category=self.category, error=result["reason"])

        subs = set()
        for row in result["rows"]:
            name = (row.get("site") or "").rstrip(".").lower()
            if name and name != domain and name.endswith("." + domain):
                subs.add(name)
        return SourceResult(
            source=self.name, category=self.category,
            findings=_subdomain_findings("amass", domain, subs),
        )
