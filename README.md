# osintMagic

A **keyless** OSINT suite written in Python with a Streamlit web UI themed in
Monokai Pro. Gather public information about a **person, email, username,
domain or IP address** — no API keys, no paid services.

## Modules

| Module | What it does |
| --- | --- |
| **Target** | The default landing: start with a target and run the full OSINT pipeline. Everything is saved per target and accumulates across runs. |
| **Graph** | Pivot from one seed into a **connected entity graph** — people, accounts, emails, domains, IPs — with recursive cross-source correlation, identity resolution, and an interactive pyvis rendering. |
| **Watchlist** | Save targets and re-scan over time to see what's NEW (new accounts, domains, emails, infrastructure). |
| **Dossier** | One click runs the full external-recon workflow and correlates it into network / credential / technology phases, plus a **subdomain→IP→ASN enrichment + geo-map**, IOC summary and STIX export. |
| **Username** | 50-site fast scan + **deep scan via maigret** (2000+ sites, metadata extraction). |
| **Email** | 4 keyless probes + **deep scan via holehe** (120+ sites) + paste leaks. |
| **Email headers** | Parses raw headers: Received chain, From/Reply-To/Return-Path alignment, SPF/DKIM/DMARC, embedded URLs, lookalike sender. |
| **Phone** | E.164/region/carrier/type/timezone (libphonenumber), Facebook-breach check, carrier + SMS gateway, dorks. |
| **Instagram** | Public profile fields via Instagram's public endpoint (keyless, no login). |
| **Person** | Candidate usernames/emails, dorks, and keyless people-search links. |
| **Domain** | Subdomains (CT logs, Wayback, brute-force with wildcard guard), DNS + email-auth posture, whois, zone transfer, cloud buckets, WAF/CDN, tech fingerprint, DNSSEC/SRV. |
| **Typosquat** | Lookalike-domain generation + resolution + risk scoring (brand protection). |
| **IP** | Geolocation/ISP/ASN, RDAP network info, reverse DNS. |
| **Leaks** | Paste-site + leak-mention search with credential-pattern scanning. |
| **Dark web** | Ahmia search + optional `.onion` crawl via a local Tor daemon. |

## Install & run

```bash
pip install -r requirements.txt
streamlit run app.py
```

The app opens in your browser with the Monokai Pro theme. Pick a module on the
left, enter a target, and click scan.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

Tests use synthetic fixtures and make no network calls.

## Project structure

```
app.py                  Streamlit entry point
.streamlit/config.toml  Monokai Pro theme
osintmagic/             UI-agnostic core package
  engine.py             concurrent scan orchestrator
  registry.py           source catalog (@source / get_sources)
  http_client.py        httpx + curl_cffi transport
  sources/              username, email, domain, ip, person
  data/                 username_sites.json, email_sites.json
  exporters/            json, csv, html
  utils/                validation + permutations
ui/                     Streamlit theme, components, views
```

## Extending

**Add a username site** — append an entry to
`osintmagic/data/username_sites.json`:

```json
{"name": "Site", "url_user": "https://example.com/{}", "errorType": "status_code", "errorCode": 404}
```

**Add an email probe** — append an entry to `osintmagic/data/email_sites.json`
(`detect: "regex"` with `exists_re`/`not_exists_re`, or `detect: "cookie"`).

**Add a source** — subclass `osintmagic.sources.base.DataSource` and decorate it
with `@source(category=..., name=...)`; it is picked up automatically.

## Correlation, search and live output

- **Entity graph + pivoting** — the **Graph** module pivots from any seed across
  every module (username→profiles, email→accounts, domain→subdomains/whois-email,
  phone→carrier, name→candidates), digs into profile pages, links email local-parts
  back to usernames (**identity resolution**), and ties emails to their mail domain
  for further pivoting.
- **Monitoring over time** — the **Watchlist** snapshots a target's discovered
  entities and diffs each re-scan to surface what's NEW.
- **Live output log** — every scan streams a per-source log panel (`▶ scan …
  [n/N] source → N findings … ✔ done`), so you can watch exactly what the tool is
  doing.
- **Search engines** — DuckDuckGo, Bing, Mojeek and Brave, fanned out and
  deduplicated via `search_all` (a blocked engine is skipped gracefully). Used by
  the Leaks / paste / dark-web sources for broader coverage.
- **Dorks** — richer, intent-organised dorks: `domain_dorks` (files, backups,
  directory listings, admin/API surfaces, secrets-in-code, third-party leaks),
  plus `username_dorks` and `email_dorks`.

## Notes & caveats

- **Email probes are deliberately conservative.** Only endpoints verified to
  work keyless are shipped (Twitter/X, Spotify, Duolingo, Google); the deep scan
  uses holehe's 120+ sites. Many services require auth/CSRF/captcha, so individual
  probes are rate-limited — reported as such, not faked.
- **Username hit-rates vary.** The 50-site fast scan may miss login-walled or
  Cloudflare-fronted sites; the deep scan uses maigret (2000+ sites) for coverage.
- **Vendored tools (holehe, maigret) are heavy.** They are installed via
  `requirements.txt`; if absent or slow, the deep-scan source reports "not
  installed / timed out" rather than failing the scan.
- **Amass is optional.** It's a Go binary (not pip-installable); the Domain
  deep-scan uses it if `amass` is on PATH, and reports "not found" otherwise.
- **MailAccess was evaluated and skipped.** Its 357 email checks overlap holehe;
  its unique domain-harvest/find-email features require a heavy FastAPI/SQLAlchemy
  stack whose `greenlet` dependency is broken on Python 3.14.
- **Proxy support.** Set `OSINTMAGIC_PROXY` (e.g. `http://127.0.0.1:8080` or
  `socks5://127.0.0.1:9050`) to route all outbound requests through a proxy —
  useful to avoid IP-based rate limits. Applies to both httpx and curl_cffi.
- **Instagram is fragile.** It uses Instagram's public endpoint with no login; it
  can be rate-limited (429) from datacenter IPs and cannot see private accounts.
- **haveibeenzuckered's free JSON API has drifted** (returns an SPA page); the
  source degrades to a per-source error until the endpoint is updated.
- **Dark web requires a local Tor daemon** (`127.0.0.1:9050`); without it the
  `.onion` crawl no-ops, and Ahmia search is clearnet-only. Mind OPSEC.
- **Search-engine scraping is best-effort.** DuckDuckGo/Bing may rate-limit or
  block; those results are labelled low-confidence.
- **Cloud-bucket results distinguish ownership.** A publicly-listable bucket is
  `found`; a bucket *name* that merely resolves to a private bucket is only
  globally registered (owner unconfirmed), shown as low-confidence `info`.
- **Recon sources follow the external-reconnaissance workflow** from the
  `conducting-external-reconnaissance-with-osint` skill: enumeration, DNS/
  infra discovery, email-auth posture, dorking and technology profiling — all
  keyless. Steps needing paid keys (Shodan, Censys, SecurityTrails, Hunter,
  HIBP, DeHashed) or heavy infra (MISP, OpenCTI) are intentionally out of scope.

## Built with the cybersecurity skills library

Features were added by applying skills from
[`mukul975/Anthropic-Cybersecurity-Skills`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
(installed under `.claude/skills/`). The keyless-applicable ones:

| Skill | Applied as |
| --- | --- |
| `conducting-external-reconnaissance-with-osint` | Domain recon sources (AXFR, cloud buckets, WAF/CDN, tech fingerprint, dorks) |
| `analyzing-typosquatting-domains-with-dnstwist` + `performing-brand-monitoring-for-impersonation` | `Typosquat` module — pure-Python permutation engine + risk scoring |
| `performing-dns-enumeration-and-zone-transfer` | Subdomain brute-force with wildcard-DNS guard, DNSSEC/SRV, internal-IP flagging |
| `analyzing-email-headers-for-phishing-investigation` | `Email headers` module — delivery chain + SPF/DKIM/DMARC + lookalike sender |
| `performing-paste-site-monitoring-for-credentials` | Paste-site leak search + credential-pattern scanning |
| `collecting-indicators-of-compromise` | IOC extraction, defanging and STIX 2.1 export |
| `performing-open-source-intelligence-gathering` | `Dossier` module — four-phase correlation (network / credential / tech) |
| `analyzing-tls-certificate-transparency-logs` | crt.sh cert-level analysis: issuer anomalies, wildcard + recent certs |
| `monitoring-darkweb-sources` | Dark-web mention search via clearnet proxy (real .onion needs commercial access) |

Excluded (require paid keys or heavy infrastructure): Shodan, Censys,
SecurityTrails, Hunter.io, VirusTotal, HIBP, MISP, OpenCTI, SpiderFoot,
Pastebin PRO — plus offensive skills (C2, AD exploitation) that do not apply
to a read-only OSINT tool.
- This tool queries **public data only**. It does not bypass authentication,
  brute-force credentials, or access private profiles.

See `DISCLAIMER.md` before use.
