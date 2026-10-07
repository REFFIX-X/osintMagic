# osintMagic

**A keyless OSINT suite** — gather public information about a **person, email,
username, domain, phone or IP address** from one place. Built in Python with a
Streamlit web UI themed in Monokai Pro.

No API keys required out of the box. Optional keys (HIBP, Shodan, VirusTotal,
GitHub, numverify) unlock deeper sources when you add them.

---

## Highlights

- **Target-first workflow** — create a target once, then every module is scoped to
  it. Everything found is saved per target and accumulates across runs.
- **Connected entity graph** — pivot recursively across every source
  (username → profiles → emails → domains → whois) into one interactive graph.
- **Best-in-class coverage** — vendored keyless tools (holehe 120+ email sites,
  maigret 2000+ username sites) as opt-in deep scans.
- **Intelligent phone lookup** — accepts `+45 61608441`, `004561608441` or
  `Denmark 61608441`, auto-normalizes to E.164, and adds Danish/EU carrier and
  directory enrichment.
- **Live output log** — every scan streams a per-source log so you see exactly
  what it's doing.
- **Honest by design** — rate-limits and blocked engines are reported as such,
  never faked.

---

## Quick start

```bash
pip install -r requirements.txt
streamlit run app.py
```

The app opens in your browser. Create a target, then explore its modules.

Run the tests (no network required):

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

---

## Modules

| Module | What it does |
| --- | --- |
| **Target / Overview** | The default landing: create a target, run the full pipeline, and see the connected picture (graph, entities, IOCs, history). |
| **Graph** | Recursive cross-source pivot into an interactive entity graph (pyvis). |
| **Dossier** | Full external-recon workflow correlated into network / credential / technology phases, with subdomain→IP→ASN geo-map, IOC and STIX export. |
| **Username** | Fast pass (top 15 sites) or full ~50-site scan, plus a deep scan via maigret (2000+ sites). |
| **Email** | Keyless account probes (Twitter/X, Spotify, Duolingo, Google) plus a deep scan via holehe (120+ sites). |
| **Email headers** | Trace a message's origin: Received chain, From/Reply-To/Return-Path alignment, SPF/DKIM/DMARC. |
| **Phone** | Intelligent freeform parsing, E.164/region/carrier/type/timezone, Danish/EU carrier + area enrichment, reverse-search, directory links, dorks. |
| **Instagram** | Public profile fields via Instagram's public endpoint (no login). |
| **Person** | Candidate usernames/emails, dorks, and keyless people-search links from a name. |
| **Domain** | Subdomains (CT logs, Wayback, brute-force with wildcard guard), DNS + email-auth posture, whois, zone transfer, cloud buckets, WAF/CDN, tech fingerprint, DNSSEC/SRV. |
| **Typosquat** | Lookalike-domain generation, resolution and risk scoring (brand protection). |
| **IP** | Geolocation/ISP/ASN, RDAP network info, reverse DNS. |
| **Leaks** | On-demand paste-site + leak-mention search with credential-pattern scanning. |
| **Dark web** | Ahmia search + optional `.onion` crawl via a local Tor daemon. |

---

## Optional API keys

Everything works keyless by default. Add keys in **Settings** (sidebar) to unlock
the corresponding sources:

| Key | Unlocks |
| --- | --- |
| `HIBP_API_KEY` | HaveIBeenPwned breach lookup for email |
| `SHODAN_API_KEY` | Shodan host intelligence for IP (ports, org, ASN, vulns) |
| `VIRUSTOTAL_API_KEY` | VirusTotal domain reputation |
| `GITHUB_TOKEN` | GitHub user search |
| `NUMVERIFY_ACCESS_KEY` | numverify phone validation (carrier, location, line type) |

Keys are stored locally in `~/.osintmagic/keys.json` and never committed.

---

## Project structure

```
app.py                  Streamlit entry point (target hub)
.streamlit/config.toml  Monokai Pro theme
osintmagic/             UI-agnostic core package
  engine.py             concurrent scan orchestrator (global timeout, live log)
  registry.py           source catalog (@source / get_sources)
  http_client.py        httpx + curl_cffi transport (connection pool, cache, proxy)
  graph.py              entity graph + recursive pivoting
  targets.py            per-target persistence
  dossier.py            phase correlation + subdomain→IP→ASN enrichment
  keys.py               local API-key storage
  sources/              all scan sources (keyless + optional keyed)
  exporters/            json, csv, html, stix, graph
  utils/                validation, permutations, IOC extraction, phone parsing
ui/                     Streamlit theme, components, views
tests/                  pytest suite (no network)
```

## Extending

- **Add a username site** — append an entry to `osintmagic/data/username_sites.json`:

  ```json
  {"name": "Site", "url_user": "https://example.com/{}", "errorType": "status_code", "errorCode": 404}
  ```

- **Add an email probe** — append an entry to `osintmagic/data/email_sites.json`.

- **Add a source** — subclass `osintmagic.sources.base.DataSource` and decorate with
  `@source(category=..., name=...)`. Set `key_name=` to make it key-gated, or
  `on_demand=True` to exclude it from automatic scans.

---

## Limitations & caveats

- **Search-engine scraping is best-effort.** DuckDuckGo/Bing/Mojeek/Brave may
  rate-limit or block; those results are labelled low-confidence and reported as
  such rather than invented.
- **Email/username hit-rates vary.** Login-walled or Cloudflare-fronted sites may
  report false "not found". Deep scans (holehe/maigret) improve coverage but are
  slower.
- **Instagram is fragile** (rate-limited from datacenter IPs) and cannot see
  private accounts.
- **Dark web requires a local Tor daemon** (`127.0.0.1:9050`); without it the
  `.onion` crawl no-ops and Ahmia search is clearnet-only.
- **Vendored tools are heavy.** holehe/maigret are installed via
  `requirements.txt`; if absent or slow, the deep-scan source reports "not
  installed / timed out" rather than failing the scan. Amass is an optional Go
  binary used only if present on PATH.
- **Proxy support.** Set `OSINTMAGIC_PROXY` (e.g. `socks5://127.0.0.1:9050`) to
  route all outbound requests through a proxy.

## Security & ethics

This tool queries **public data only**. It does not bypass authentication,
brute-force credentials, or access private profiles. Use it lawfully and
responsibly — see `DISCLAIMER.md`.
