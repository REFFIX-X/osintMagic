"""Cross-source entity graph + recursive pivoting.

Seeds any target (email/username/phone/name/domain) and breadth-first pivots
across the existing sources, building a graph of typed entities (username, email,
domain, phone, name, url, ip, profile) linked by labelled edges. Reuses the
engine + registry + validators + IOC extraction so no new lookups are invented.
"""
from __future__ import annotations

import ipaddress
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .engine import run_scan
from .registry import get_sources
from .utils import iocs
from .utils.permutations import email_candidates, name_candidates
from .utils.validate import is_domain, is_email, is_ip, is_phone, is_username

_EMAIL_DOMAINS = ("gmail.com", "outlook.com", "yahoo.com", "protonmail.com")
_PIVOT_TIMEOUT = 90.0


@dataclass
class Entity:
    etype: str
    value: str
    source: str
    confidence: float = 1.0


@dataclass
class Edge:
    src: str
    dst: str
    label: str


def node_id(etype: str, value: str) -> str:
    return f"{etype}:{value}"


@dataclass
class GraphResult:
    seed: str
    depth: int
    nodes: dict[str, Entity] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_entity(self, entity: Entity) -> str:
        nid = node_id(entity.etype, entity.value)
        self.nodes.setdefault(nid, entity)
        return nid

    def add_edge(self, src: str, dst: str, label: str) -> None:
        if src == dst:
            return
        key = (src, dst, label)
        if any((e.src, e.dst, e.label) == key for e in self.edges):
            return
        self.edges.append(Edge(src, dst, label))


def classify_seed(value: str) -> str:
    """Detect the seed's entity type (order matters)."""
    v = value.strip()
    if is_email(v):
        return "email"
    if v.startswith(("http://", "https://")):
        return "url"
    if is_ip(v):
        return "ip"
    if is_domain(v):
        return "domain"
    if is_phone(v):
        return "phone"
    if " " in v:
        return "name"
    if is_username(v):
        return "username"
    return "username"


def classify_value(value: str) -> str | None:
    """Classify an extracted value, or None if unrecognised."""
    v = value.strip().rstrip(".").lower()
    if not v:
        return None
    if is_email(v):
        return "email"
    if v.startswith(("http://", "https://")):
        return "url"
    if is_domain(v):
        return "domain"
    if is_phone(v):
        return "phone"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if is_username(v) and len(v) >= 2:
        return "username"
    return None


def _extract_entities(text: str, source: str, confidence: float = 0.6) -> list[Entity]:
    found = iocs.extract_iocs(text)
    out: list[Entity] = []
    for etype in ("email", "domain", "ip", "url"):
        for value in found.get(etype, [])[:3]:
            out.append(Entity(etype, value, source, confidence))
    return out


def _username_email_candidates(username: str) -> list[Entity]:
    return [Entity("email", f"{username}@{d}", "candidate (generated)", 0.3) for d in _EMAIL_DOMAINS]


def _pivot_username(username: str, deep: bool, log=None) -> tuple[list[Entity], list[Edge]]:
    src = node_id("username", username)
    sources = [s for s in get_sources("username") if s.deep == deep]
    result = run_scan(sources, username, kind="username", log=log, timeout=_PIVOT_TIMEOUT)
    entities: list[Entity] = []
    edges: list[Edge] = []
    for sr in result.results:
        for f in sr.findings:
            if f.status == "found" and f.url:
                entities.append(Entity("profile", f.url, sr.source, f.confidence))
                edges.append(Edge(src, node_id("profile", f.url), f"profile on {sr.source}"))
            text = " ".join(str(v) for v in (f.detail or {}).values())
            for e in _extract_entities(text, sr.source, 0.5):
                entities.append(e)
                edges.append(Edge(src, node_id(e.etype, e.value), "associated"))
    for e in _username_email_candidates(username):
        entities.append(e)
        edges.append(Edge(src, node_id(e.etype, e.value), "candidate email"))
    return entities, edges


def _pivot_email(email: str, deep: bool, log=None) -> tuple[list[Entity], list[Edge]]:
    src = node_id("email", email)
    sources = [s for s in get_sources("email") if s.deep == deep]
    result = run_scan(sources, email, kind="email", log=log, timeout=_PIVOT_TIMEOUT)
    entities: list[Entity] = []
    edges: list[Edge] = []
    for sr in result.results:
        for f in sr.findings:
            site = (f.detail or {}).get("site") or sr.source
            if f.status == "found":
                entities.append(Entity("profile", site, sr.source, f.confidence))
                edges.append(Edge(src, node_id("profile", site), f"registered on {site}"))
            text = " ".join(str(v) for v in (f.detail or {}).values())
            for e in _extract_entities(text, sr.source, 0.5):
                entities.append(e)
                edges.append(Edge(src, node_id(e.etype, e.value), "associated"))

    # candidate username from local part
    local = email.split("@", 1)[0]
    if local and is_username(local):
        entities.append(Entity("username", local, "email local-part", 0.4))
        edges.append(Edge(src, node_id("username", local), "candidate username"))
    # the email's own domain is a pivot target too
    mail_domain = email.split("@", 1)[1] if "@" in email else None
    if mail_domain and is_domain(mail_domain):
        entities.append(Entity("domain", mail_domain, "email domain", 0.9))
        edges.append(Edge(src, node_id("domain", mail_domain), "mail domain"))
    return entities, edges


def _pivot_domain(domain: str, deep: bool, log=None) -> tuple[list[Entity], list[Edge]]:
    src = node_id("domain", domain)
    sources = [s for s in get_sources("domain") if s.deep == deep]
    result = run_scan(sources, domain, kind="domain", log=log, timeout=_PIVOT_TIMEOUT)
    entities: list[Entity] = []
    edges: list[Edge] = []
    for sr in result.results:
        for f in sr.findings:
            t = (f.detail or {}).get("type")
            if t == "subdomain" and f.url:
                host = urlparse(f.url).hostname
                if host:
                    host = host.rstrip(".").lower()
                    entities.append(Entity("domain", host, sr.source, f.confidence))
                    edges.append(Edge(src, node_id("domain", host), "subdomain of"))
            if t == "whois" and f.detail.get("abuse_email"):
                ae = f.detail["abuse_email"]
                entities.append(Entity("email", ae, "whois", 0.8))
                edges.append(Edge(src, node_id("email", ae), "whois abuse email"))
            text = " ".join(str(v) for v in (f.detail or {}).values())
            for e in _extract_entities(text, sr.source, 0.5):
                entities.append(e)
                edges.append(Edge(src, node_id(e.etype, e.value), "related"))
    return entities, edges


def _pivot_phone(phone: str, deep: bool, log=None) -> tuple[list[Entity], list[Edge]]:
    src = node_id("phone", phone)
    sources = [s for s in get_sources("phone") if s.deep == deep]
    result = run_scan(sources, phone, kind="phone", log=log, timeout=_PIVOT_TIMEOUT)
    entities: list[Entity] = []
    edges: list[Edge] = []
    for sr in result.results:
        for f in sr.findings:
            t = (f.detail or {}).get("type")
            if t == "phone_info" and f.detail.get("country"):
                entities.append(Entity("name", f.detail["country"], "phone country", 0.9))
                edges.append(Edge(src, node_id("name", f.detail["country"]), "located in"))
            if t == "facebook_breach" and f.status == "found":
                entities.append(Entity("profile", "facebook breach record", "haveibeenzuckered", 0.9))
                edges.append(Edge(src, node_id("profile", "facebook breach record"), "in FB breach"))
    return entities, edges


def _pivot_name(name: str, deep: bool, log=None) -> tuple[list[Entity], list[Edge]]:
    src = node_id("name", name)
    parts = [p for p in name.strip().split() if p]
    entities: list[Entity] = []
    edges: list[Edge] = []
    if len(parts) < 2:
        return entities, edges
    first, last = parts[0], parts[-1]
    middle = " ".join(parts[1:-1]) if len(parts) > 2 else ""
    for u in name_candidates(first, last, middle)[:12]:
        entities.append(Entity("username", u, "candidate (generated)", 0.3))
        edges.append(Edge(src, node_id("username", u), "candidate username"))
    for e in email_candidates(first, last, middle)[:12]:
        entities.append(Entity("email", e, "candidate (generated)", 0.3))
        edges.append(Edge(src, node_id("email", e), "candidate email"))
    return entities, edges


def _pivot_url(entity: Entity, deep: bool = False, log=None) -> tuple[list[Entity], list[Edge]]:
    """Dig into a profile/URL page: extract emails, domains and notable links."""
    from .http_client import HttpError, get

    url = entity.value
    if not url.startswith(("http://", "https://")):
        return [], []
    try:
        resp = get(url, timeout=10)
    except HttpError:
        return [], []

    src = node_id(entity.etype, url)
    entities: list[Entity] = []
    edges: list[Edge] = []
    found = iocs.extract_iocs(resp.text)
    for etype in ("email", "domain"):
        for value in found.get(etype, [])[:5]:
            e = Entity(etype, value, f"page ({urlparse(url).hostname})", 0.4)
            entities.append(e)
            edges.append(Edge(src, node_id(etype, value), "exposed on page"))
    # extract a username from the URL path (github.com/torvalds -> torvalds)
    host = urlparse(url).hostname or ""
    path_segments = [s for s in urlparse(url).path.strip("/").split("/") if s]
    if path_segments:
        candidate = path_segments[-1]
        if is_username(candidate) and candidate.lower() not in ("user", "users", "u", "p", "profile", "id"):
            entities.append(Entity("username", candidate, f"url ({host})", 0.5))
            edges.append(Edge(src, node_id("username", candidate), "username from URL"))
    return entities, edges


_PIVOTERS = {
    "username": _pivot_username,
    "email": _pivot_email,
    "domain": _pivot_domain,
    "phone": _pivot_phone,
    "name": _pivot_name,
}


def build_graph(
    seed: str,
    depth: int = 1,
    deep: bool = False,
    max_entities: int = 60,
    progress=None,
    log=None,
) -> GraphResult:
    """Breadth-first pivot from a seed into an entity graph."""
    seed_type = classify_seed(seed)
    graph = GraphResult(seed=seed, depth=depth)
    seed_entity = Entity(seed_type, seed, "seed", 1.0)
    graph.add_entity(seed_entity)

    frontier: deque[Entity] = deque([seed_entity])
    for level in range(depth):
        if not frontier or len(graph.nodes) >= max_entities:
            break
        next_frontier: list[Entity] = []
        for entity in frontier:
            if entity.etype in ("profile", "url"):
                pivot_fn = _pivot_url
            else:
                pivot_fn = _PIVOTERS.get(entity.etype)
            if pivot_fn is None:
                continue
            if log:
                log(f"◈ depth {level+1} — pivoting on {entity.etype} “{entity.value}”")
            try:
                if entity.etype in ("profile", "url"):
                    new_entities, new_edges = pivot_fn(entity, deep, log=log)
                else:
                    new_entities, new_edges = pivot_fn(entity.value, deep, log=log)
            except Exception:
                continue  # one pivot never kills the whole graph
            added = 0
            for e in new_entities:
                nid = node_id(e.etype, e.value)
                if nid in graph.nodes or len(graph.nodes) >= max_entities:
                    continue
                graph.add_entity(e)
                next_frontier.append(e)
                added += 1
            for edge in new_edges:
                if edge.src in graph.nodes and edge.dst in graph.nodes:
                    graph.add_edge(edge.src, edge.dst, edge.label)
            if log:
                log(f"   ↳ +{added} entities, {len(new_edges)} links")
            if progress:
                progress(len(graph.nodes), max_entities)
        frontier = deque(next_frontier)

    # Identity resolution: link an email whose local-part matches a known username.
    username_nodes = {e.value.lower(): nid for nid, e in graph.nodes.items() if e.etype == "username"}
    for nid, e in list(graph.nodes.items()):
        if e.etype != "email":
            continue
        local = e.value.split("@", 1)[0].lower()
        if local in username_nodes:
            graph.add_edge(nid, username_nodes[local], "same identity?")

    return graph
